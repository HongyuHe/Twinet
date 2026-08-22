package grade

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"gopkg.in/yaml.v3"
)

// Rubric maps assignment questions onto checks and point values.
//
// Keeping the weights in a versioned document rather than scattered through a
// grading script is the difference between "the rubric" being a thing you can
// read, diff and hand to a student, and being an emergent property of 1,700
// lines of Python with lines like `points += check_rpki_invalid(asn) * 0.5`.
type Rubric struct {
	APIVersion string         `yaml:"apiVersion" json:"apiVersion"`
	Kind       string         `yaml:"kind" json:"kind"`
	Metadata   RubricMeta     `yaml:"metadata" json:"metadata"`
	Questions  []QuestionSpec `yaml:"questions" json:"questions"`
}

// RubricMeta names the rubric.
type RubricMeta struct {
	Name  string  `yaml:"name" json:"name"`
	Total float64 `yaml:"total,omitempty" json:"total,omitempty"`
	Notes string  `yaml:"notes,omitempty" json:"notes,omitempty"`
	// SupportedInteriorKinds optionally constrains a rubric to shapes its
	// checks were authored for. An omitted list retains compatibility with
	// every topology, which preserves existing rubrics.
	SupportedInteriorKinds []model.InteriorKind `yaml:"supported_interior_kinds,omitempty" json:"supported_interior_kinds,omitempty"`
}

// QuestionSpec is one graded question.
type QuestionSpec struct {
	ID     string      `yaml:"id" json:"id"`
	Title  string      `yaml:"title" json:"title"`
	Points float64     `yaml:"points" json:"points"`
	Checks []CheckSpec `yaml:"checks" json:"checks"`
	// DependsOn names questions that must have earned marks before this one is
	// worth running. Without it, a student who has not configured OSPF sees a
	// cascade of BGP failures that tell them nothing they did not know.
	DependsOn []string `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	// Converge asks the runner to wait for the control plane to settle before
	// running this question's checks.
	Converge bool `yaml:"converge,omitempty" json:"converge,omitempty"`
	// ConvergeScope narrows what "settled" means: "ospf" waits only for the
	// interior, "bgp" for sessions and a stable table, and empty for both.
	//
	// It exists because waiting for the wrong thing quarantines a correct
	// submission. A question about the interior asked for convergence and got
	// a wait that included external sessions, so a student whose OSPF was
	// perfect and whose BGP was not yet written was reported as ungradeable
	// rather than marked on the question they had answered.
	ConvergeScope string `yaml:"converge_scope,omitempty" json:"converge_scope,omitempty" jsonschema:"enum=ospf,enum=bgp"`
}

// CheckSpec binds a registered check to a weight and arguments.
type CheckSpec struct {
	Check  string         `yaml:"check" json:"check"`
	Weight float64        `yaml:"weight,omitempty" json:"weight,omitempty"`
	Args   map[string]any `yaml:"args,omitempty" json:"args,omitempty"`
}

// LoadRubric reads and validates a rubric.
func LoadRubric(path string) (*Rubric, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rubric: %w", err)
	}
	var r Rubric
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &r, nil
}

// Validate reports every problem with a rubric at once.
func (r *Rubric) Validate() error {
	var problems []string
	if r.Kind != "" && r.Kind != "Rubric" {
		problems = append(problems, fmt.Sprintf("kind must be Rubric, got %q", r.Kind))
	}
	if len(r.Questions) == 0 {
		problems = append(problems, "no questions declared")
	}
	seen := map[string]bool{}
	seenInterior := map[model.InteriorKind]bool{}
	for _, kind := range r.Metadata.SupportedInteriorKinds {
		switch {
		case !kind.Valid():
			problems = append(problems, fmt.Sprintf(
				"metadata.supported_interior_kinds contains unknown kind %q (supported: %s)",
				kind, strings.Join(interiorKinds(), ", ")))
		case seenInterior[kind]:
			problems = append(problems, fmt.Sprintf(
				"metadata.supported_interior_kinds declares %q more than once", kind))
		}
		seenInterior[kind] = true
	}
	for i, q := range r.Questions {
		if q.ID == "" {
			problems = append(problems, fmt.Sprintf("questions[%d] has no id", i))
		}
		if seen[q.ID] {
			problems = append(problems, fmt.Sprintf("question %q is declared twice", q.ID))
		}
		seen[q.ID] = true
		if q.Points <= 0 {
			problems = append(problems, fmt.Sprintf("question %q has no points", q.ID))
		}
		if len(q.Checks) == 0 {
			problems = append(problems, fmt.Sprintf("question %q has no checks", q.ID))
		}
		var weight float64
		for j, c := range q.Checks {
			if _, ok := Lookup(c.Check); !ok {
				problems = append(problems, fmt.Sprintf(
					"question %q check[%d]: %q is not a registered check (see `twinet grade checks`)",
					q.ID, j, c.Check))
			}
			w := c.Weight
			if w == 0 {
				w = 1
			}
			weight += w
		}
		// Weights within a question must sum to one, or the question's point
		// value silently means something other than what it says.
		if len(q.Checks) > 0 && (weight < 0.999 || weight > 1.001) {
			problems = append(problems, fmt.Sprintf(
				"question %q: check weights sum to %.3f, not 1.0", q.ID, weight))
		}
	}
	// Dependencies are resolved as the questions are graded, in the order they
	// are declared, so a question may only depend on one that comes before it.
	//
	// A dependency on a later question was accepted and then ignored: when the
	// dependent question is graded, the one it depends on has no mark yet, and
	// the rule that a question with an unmet dependency is not graded reads a
	// missing mark as "met". A rubric could therefore say "isolation is only
	// worth marks once traffic flows" and grade isolation anyway, awarding the
	// mark to a network where nothing works at all -- which is the exact
	// failure `depends_on` exists to prevent. A cycle is the same defect in a
	// more obvious costume, and is refused by the same rule.
	position := map[string]int{}
	for i, q := range r.Questions {
		position[q.ID] = i
	}
	for i, q := range r.Questions {
		for _, dep := range q.DependsOn {
			switch {
			case !seen[dep]:
				problems = append(problems, fmt.Sprintf(
					"question %q depends on %q, which is not declared", q.ID, dep))
			case dep == q.ID:
				problems = append(problems, fmt.Sprintf(
					"question %q depends on itself", q.ID))
			case position[dep] > i:
				problems = append(problems, fmt.Sprintf(
					"question %q depends on %q, which is graded after it, so the dependency "+
						"would never apply; declare %q first", q.ID, dep, dep))
			}
		}
	}
	if total := r.MaxTotal(); r.Metadata.Total > 0 && (total < r.Metadata.Total-0.001 || total > r.Metadata.Total+0.001) {
		problems = append(problems, fmt.Sprintf(
			"metadata.total says %.2f but the questions sum to %.2f", r.Metadata.Total, total))
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("the rubric is not valid:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

func interiorKinds() []string {
	kinds := model.InteriorKinds()
	out := make([]string, len(kinds))
	for i, k := range kinds {
		out[i] = string(k)
	}
	return out
}

// RubricCompatibilityError identifies a bad author/infrastructure pairing,
// never student work. Callers should refuse the run before a zero can appear
// in a student's report.
type RubricCompatibilityError struct {
	Rubric      string
	Unsupported map[model.InteriorKind][]int
}

func (e *RubricCompatibilityError) Error() string {
	kinds := make([]string, 0, len(e.Unsupported))
	for kind := range e.Unsupported {
		kinds = append(kinds, string(kind))
	}
	sort.Strings(kinds)
	var parts []string
	for _, raw := range kinds {
		kind := model.InteriorKind(raw)
		asns := append([]int(nil), e.Unsupported[kind]...)
		sort.Ints(asns)
		ids := make([]string, len(asns))
		for i, asn := range asns {
			ids[i] = fmt.Sprintf("AS %d", asn)
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", kind, strings.Join(ids, ", ")))
	}
	name := e.Rubric
	if name == "" {
		name = "this rubric"
	}
	return fmt.Sprintf("%s does not support interior kind(s) %s; this is a rubric/topology author error, not a student deduction",
		name, strings.Join(parts, ", "))
}

// ValidateTopology refuses a rubric whose declared shape support does not
// cover every AS in the expanded lab. A legacy AS is explicit by definition.
func (r *Rubric) ValidateTopology(top *model.Topology) error {
	if len(r.Metadata.SupportedInteriorKinds) == 0 {
		return nil
	}
	if top == nil {
		return fmt.Errorf("cannot check rubric %q against a nil topology", r.Metadata.Name)
	}
	allowed := map[model.InteriorKind]bool{}
	for _, kind := range r.Metadata.SupportedInteriorKinds {
		allowed[kind] = true
	}
	unsupported := map[model.InteriorKind][]int{}
	for _, asn := range top.SortedASNs() {
		kind := top.ASes[asn].InteriorKind
		if kind == "" {
			kind = model.InteriorExplicit
		}
		if !allowed[kind] {
			unsupported[kind] = append(unsupported[kind], asn)
		}
	}
	if len(unsupported) > 0 {
		return &RubricCompatibilityError{Rubric: r.Metadata.Name, Unsupported: unsupported}
	}
	return nil
}

// MaxTotal is the sum of every question's points.
func (r *Rubric) MaxTotal() float64 {
	var t float64
	for _, q := range r.Questions {
		t += q.Points
	}
	return t
}

// RunOptions tune a grading run.
type RunOptions struct {
	// ConvergeTimeout bounds how long the runner waits for the control plane.
	ConvergeTimeout time.Duration
	// CheckTimeout bounds a single check.
	CheckTimeout time.Duration
	// Parallel bounds how many checks of one submission run at once. Checks
	// without active-probe conflicts run at once.
	Parallel int
	// ObservationParallel bounds passive collection requests made by the
	// controller. Node agents independently enforce their ExecProbe budget.
	ObservationParallel int
	// Progress receives a line per completed question.
	Progress func(string)
}

// Run grades one submission against a rubric.
func Run(ctx context.Context, r *Rubric, env *Env, opts RunOptions) *Report {
	start := time.Now()
	phases := &phaseRecorder{}
	rep := &Report{
		AS: env.AS, Lab: env.Topology.Name, Rubric: r.Metadata.Name,
		Manifest: env.Topology.Hash, GradedAt: time.Now().UTC(),
		MaxTotal: r.MaxTotal(),
	}
	rep.RubricNotes = r.Metadata.Notes
	if lab := env.Topology.Lab; lab != nil {
		rep.Course, rep.Term = lab.Metadata.Course, lab.Metadata.Term
	}
	if err := r.ValidateTopology(env.Topology); err != nil {
		// A rubric written for a different interior is an authoring failure.
		// Returning a held/error report rather than running checks prevents
		// it from being mistaken for a student-earned zero by direct library
		// callers that did not validate before invoking Run.
		rep.Err = err.Error()
		rep.NeedsReview = true
		rep.Duration = time.Since(start).Round(time.Millisecond).String()
		phases.append("grade", start, time.Now())
		rep.PhaseTimings = phases.list()
		return rep
	}
	if opts.ConvergeTimeout == 0 {
		opts.ConvergeTimeout = 90 * time.Second
	}
	if opts.CheckTimeout == 0 {
		opts.CheckTimeout = 120 * time.Second
	}
	if opts.Parallel <= 0 {
		opts.Parallel = 4
	}
	if opts.ObservationParallel <= 0 {
		opts.ObservationParallel = minInt(16, maxGradeWorkers(opts.Parallel*2, 4))
	}

	// Every declared convergence scope is waited once, concurrently, before
	// passive collection. Capturing before a later per-question wait would
	// freeze a transient route table and turn a correct, still-converging
	// submission into a deterministic false deduction.
	var convergenceByScope map[string]string
	phases.measure("convergence", func() {
		convergenceByScope = waitSnapshotConvergence(ctx, r.Questions, env, opts.ConvergeTimeout)
	})

	// Passive collection happens once after the convergence boundary. The
	// snapshot is shared by every copy of Env and later frozen into the
	// report. Dynamic checks opt out through Check.LiveObservations.
	var snapshot *ObservationSnapshot
	phases.measure("observation", func() {
		snapshot = collectObservationSnapshot(ctx, r, env, opts.ObservationParallel)
	})
	runEnv := *env
	runEnv.snapshot = snapshot
	earned := map[string]float64{}
	completed := make([]bool, len(r.Questions))
	questions := make([]QuestionResult, len(r.Questions))
	warnings := make([]string, len(r.Questions))

	for done := 0; done < len(r.Questions); {
		var ready []int
		for i, q := range r.Questions {
			if completed[i] {
				continue
			}
			if !dependenciesComplete(q, earned) {
				continue
			}
			if blocker := unmetDependency(q, earned); blocker != "" {
				questions[i] = QuestionResult{
					ID: q.ID, Title: q.Title, Points: q.Points, Status: StatusSkipped,
					Skipped: fmt.Sprintf("%s scored nothing, so this cannot be assessed", blocker),
				}
				completed[i] = true
				earned[q.ID] = 0
				done++
				continue
			}
			ready = append(ready, i)
		}
		if done == len(r.Questions) {
			break
		}
		if len(ready) == 0 {
			// Validate forbids dependency cycles, so this only happens after
			// context cancellation. Preserve the ungraded distinction rather
			// than manufacturing a zero.
			if err := ctxErr(ctx); err != nil {
				rep.Err = err.Error()
				break
			}
			rep.Err = "grading dependency scheduler made no progress"
			rep.NeedsReview = true
			break
		}

		var resultSets map[int][]Result
		phases.measure("checks", func() {
			resultSets = runChecksAcrossQuestions(ctx, r.Questions, ready, &runEnv, opts)
		})
		for _, i := range ready {
			q := r.Questions[i]
			qr := questionResult(q, resultSets[i])
			if note := convergenceNote(q, convergenceByScope); note != "" {
				warnings[i] = fmt.Sprintf("the network had not settled before %s: %s", q.ID, note)
				if qr.Note == "" {
					qr.Note = "the control plane had not converged when this was assessed, " +
						"which is usually the submission's own doing"
				} else {
					qr.Note += "; the control plane had not converged when this was assessed"
				}
			}
			if qr.NeedsReview {
				rep.NeedsReview = true
			}
			questions[i] = qr
			completed[i] = true
			earned[q.ID] = qr.Awarded
			done++
		}
		if err := ctxErr(ctx); err != nil {
			rep.Err = err.Error()
			break
		}
	}

	for i, q := range questions {
		if q.ID == "" {
			continue
		}
		rep.Questions = append(rep.Questions, q)
		rep.Total += q.Awarded
		if warnings[i] != "" {
			rep.Warnings = append(rep.Warnings, warnings[i])
		}
		if opts.Progress != nil {
			opts.Progress(fmt.Sprintf("%s %s %.2f/%.2f", q.ID, q.Status, q.Awarded, q.Points))
		}
	}
	if snapshot != nil {
		snapshot.Freeze()
		rep.Observation = snapshot
	}
	rep.Duration = time.Since(start).Round(time.Millisecond).String()
	phases.append("grade", start, time.Now())
	rep.PhaseTimings = phases.list()
	return rep
}

func unmetDependency(q QuestionSpec, earned map[string]float64) string {
	for _, dep := range q.DependsOn {
		if v, ok := earned[dep]; ok && v <= 0 {
			return dep
		}
	}
	return ""
}

func dependenciesComplete(q QuestionSpec, earned map[string]float64) bool {
	for _, dep := range q.DependsOn {
		if _, ok := earned[dep]; !ok {
			return false
		}
	}
	return true
}

// questionResult applies the pre-existing grading and quarantine rules after a
// scheduler wave has completed. Keeping it separate from scheduling makes the
// score independent of completion order.
func questionResult(q QuestionSpec, results []Result) QuestionResult {
	qr := QuestionResult{ID: q.ID, Title: q.Title, Points: q.Points, Results: results}
	var broken []string
	inapplicable := 0
	for _, result := range results {
		switch result.Status {
		case StatusError:
			broken = append(broken, result.Check)
		case StatusNotApplicable:
			inapplicable++
		}
	}
	qr.Awarded = awardFor(q, results)
	awarded := 0.0
	if q.Points > 0 {
		awarded = qr.Awarded / q.Points
	}
	qr.Status = statusFor(awarded)
	if len(broken) > 0 {
		sort.Strings(broken)
		qr.NeedsReview = true
		qr.Note = fmt.Sprintf("%d check(s) could not run (%s); this question needs a human before the mark stands",
			len(broken), strings.Join(broken, ", "))
		if len(broken) == len(q.Checks) {
			// Nothing about this question was assessed; it is not a zero.
			qr.Status = StatusError
		}
	}
	if len(broken)+inapplicable == len(q.Checks) && inapplicable > 0 {
		qr.NeedsReview = true
		qr.Status = StatusError
		qr.Note = fmt.Sprintf("none of the %d check(s) apply to this AS, so the question was "+
			"not assessed; the rubric does not fit this topology", len(q.Checks))
	}
	return qr
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxGradeWorkers(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// awardFor scores one question from its check results.
//
// Weighted, so a rubric can say that one check matters more than another, and
// with checks that could not run excluded from the weighting rather than scored
// zero. The second half is the important one: scoring a broken check zero turns
// the grader's own outage into the student's mark, and produces a number that
// looks exactly like a number they earned.
func awardFor(q QuestionSpec, results []Result) float64 {
	var awarded, weightSum float64
	for i, c := range q.Checks {
		if i >= len(results) {
			break
		}
		w := c.Weight
		if w == 0 {
			w = 1
		}
		if results[i].Status == StatusError || results[i].Status == StatusNotApplicable {
			continue
		}
		weightSum += w
		awarded += w * results[i].Score
	}
	if weightSum == 0 {
		// Every check failed to run. Award nothing for now; the question is
		// separately marked as needing a human, which is what stops this zero
		// being mistaken for a mark.
		return 0
	}
	return (awarded / weightSum) * q.Points
}

func statusFor(fraction float64) Status {
	switch {
	case fraction >= 0.999:
		return StatusPass
	case fraction <= 0.001:
		return StatusFail
	default:
		return StatusPartial
	}
}
