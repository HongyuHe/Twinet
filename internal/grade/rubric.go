package grade

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

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
	for _, q := range r.Questions {
		for _, dep := range q.DependsOn {
			if !seen[dep] {
				problems = append(problems, fmt.Sprintf(
					"question %q depends on %q, which is not declared", q.ID, dep))
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
	// within a question are independent, so this is safe.
	Parallel int
	// Progress receives a line per completed question.
	Progress func(string)
}

// Run grades one submission against a rubric.
func Run(ctx context.Context, r *Rubric, env *Env, opts RunOptions) *Report {
	start := time.Now()
	rep := &Report{
		AS: env.AS, Lab: env.Topology.Name, Rubric: r.Metadata.Name,
		Manifest: env.Topology.Hash, GradedAt: time.Now().UTC(),
		MaxTotal: r.MaxTotal(),
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

	earned := map[string]float64{}

	for _, q := range r.Questions {
		qr := QuestionResult{ID: q.ID, Title: q.Title, Points: q.Points}

		// A question whose prerequisites failed is skipped with an explanation,
		// rather than producing a cascade of derived failures.
		if blocker := unmetDependency(q, earned); blocker != "" {
			qr.Status = StatusSkipped
			qr.Skipped = fmt.Sprintf("%s scored nothing, so this cannot be assessed", blocker)
			rep.Questions = append(rep.Questions, qr)
			earned[q.ID] = 0
			continue
		}

		// Convergence is tracked per question rather than once globally: a
		// timeout before an early question must not be taken as licence to
		// skip the wait before a later one that depends on more state.
		if q.Converge {
			if err := waitForScope(ctx, env, q.ConvergeScope, opts.ConvergeTimeout); err != nil {
				// A network that will not settle is usually the submission.
				//
				// This flagged the whole report for review, and the release
				// guard then withheld every mark on it -- so a student whose
				// OSPF was simply not configured had their entire paper held
				// back rather than marked, which is a worse answer than the
				// low mark their work earns. The code elsewhere says exactly
				// this: student non-convergence is a mark, not an outage.
				//
				// It is recorded as a warning on the report either way, so a
				// marker reading it sees that the network had not settled. Only
				// an infrastructure failure -- a node that could not be reached
				// -- withholds the mark, and that is tracked separately.
				rep.Warnings = append(rep.Warnings,
					fmt.Sprintf("the network had not settled before %s: %v", q.ID, err))
				qr.Note = "the control plane had not converged when this was assessed, " +
					"which is usually the submission's own doing"
			}
		}

		results := runChecks(ctx, q, env, opts)

		var broken []string
		for i := range q.Checks {
			if results[i].Status == StatusError {
				broken = append(broken, results[i].Check)
			}
		}
		qr.Awarded = awardFor(q, results)
		awarded := 0.0
		if q.Points > 0 {
			awarded = qr.Awarded / q.Points
		}
		qr.Results = results
		qr.Status = statusFor(awarded)
		if len(broken) > 0 {
			sort.Strings(broken)
			qr.NeedsReview = true
			qr.Note = fmt.Sprintf("%d check(s) could not run (%s); this question needs a human before the mark stands",
				len(broken), strings.Join(broken, ", "))
			rep.NeedsReview = true
			if len(broken) == len(q.Checks) {
				// Nothing about this question was actually assessed, so it is
				// an error rather than a zero.
				qr.Status = StatusError
			}
		}
		earned[q.ID] = qr.Awarded

		rep.Total += qr.Awarded
		rep.Questions = append(rep.Questions, qr)
		if opts.Progress != nil {
			opts.Progress(fmt.Sprintf("%s %s %.2f/%.2f", q.ID, qr.Status, qr.Awarded, q.Points))
		}
		if err := ctxErr(ctx); err != nil {
			rep.Err = err.Error()
			break
		}
	}

	rep.Duration = time.Since(start).Round(time.Millisecond).String()
	return rep
}

// runChecks executes a question's checks, concurrently where possible.
func runChecks(ctx context.Context, q QuestionSpec, env *Env, opts RunOptions) []Result {
	results := make([]Result, len(q.Checks))
	sem := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup

	for i, cs := range q.Checks {
		c, ok := Lookup(cs.Check)
		if !ok {
			results[i] = Errored(cs.Check, fmt.Errorf("no such check"))
			continue
		}
		wg.Add(1)
		go func(i int, c *Check, cs CheckSpec) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			cctx, cancel := context.WithTimeout(ctx, opts.CheckTimeout)
			defer cancel()

			// Each check gets its own environment so its arguments cannot leak
			// into a sibling running concurrently.
			e := *env
			e.Args = cs.Args
			e.infraSeen = &infraTracker{}
			res := runCheck(cctx, c, &e)

			// A check that concluded anything while the machinery was failing
			// concluded it about the grader, not about the student. The
			// verdict is discarded rather than trusted, because a check that
			// absorbed an unreachable node into a "fail" turns an outage into
			// a mark and says nothing about it.
			if fail := e.infraSeen.failure(); fail != nil && res.Status != StatusError {
				res = Errored(cs.Check, fail)
			}

			// A check whose own deadline expired did not finish looking.
			//
			// Cancellation and deadline errors are deliberately excluded from
			// the infrastructure tracker, because a convergence predicate
			// timing out is a legitimate finding about the submission. But the
			// *check's* context expiring is not: it means the grader ran out
			// of time, and several checks absorb that into a zero or a partial
			// score. That is an outage turned into a mark, which is exactly
			// what the tracker above exists to prevent.
			if cctx.Err() != nil && res.Status != StatusError {
				res = Errored(cs.Check, fmt.Errorf(
					"this check ran out of time after %s, so what it found is what it had "+
						"managed to look at rather than a judgement about the submission: %w",
					opts.CheckTimeout, cctx.Err()))
			}
			results[i] = res
		}(i, c, cs)
	}
	wg.Wait()
	return results
}

func unmetDependency(q QuestionSpec, earned map[string]float64) string {
	for _, dep := range q.DependsOn {
		if v, ok := earned[dep]; ok && v <= 0 {
			return dep
		}
	}
	return ""
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
		if results[i].Status == StatusError {
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
