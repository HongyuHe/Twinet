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
			if err := WaitConverged(ctx, env, opts.ConvergeTimeout); err != nil {
				rep.Warnings = append(rep.Warnings,
					fmt.Sprintf("the network had not settled before %s: %v", q.ID, err))
				qr.NeedsReview = true
				qr.Note = "the control plane had not converged when this was assessed"
				rep.NeedsReview = true
			}
		}

		results := runChecks(ctx, q, env, opts)

		// A check that could not run is a fault in the grader, not in the
		// student. Scoring it zero would quietly turn our outage into their
		// mark, so its weight is excluded and the question is flagged for a
		// human instead.
		var awarded, weightSum float64
		var broken []string
		for i, c := range q.Checks {
			w := c.Weight
			if w == 0 {
				w = 1
			}
			if results[i].Status == StatusError {
				broken = append(broken, results[i].Check)
				continue
			}
			weightSum += w
			awarded += w * results[i].Score
		}
		switch {
		case weightSum > 0:
			awarded /= weightSum
		default:
			// Every check failed to run: award nothing yet and mark the whole
			// question as needing attention rather than as a zero.
			awarded = 0
		}
		qr.Awarded = awarded * q.Points
		qr.Results = results
		qr.Status = statusFor(awarded)
		if len(broken) > 0 {
			sort.Strings(broken)
			qr.NeedsReview = true
			qr.Note = fmt.Sprintf("%d check(s) could not run (%s); this question needs a human before the mark stands",
				len(broken), strings.Join(broken, ", "))
			rep.NeedsReview = true
			if weightSum == 0 {
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
			results[i] = runCheck(cctx, c, &e)
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
