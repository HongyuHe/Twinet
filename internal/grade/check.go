package grade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// Env is what a check is given to work with.
type Env struct {
	// Topology is the grading lab: the student's AS plus its synthetic
	// neighbours.
	Topology *model.Topology
	// AS is the autonomous system under test.
	AS int
	// infraSeen collects failures of the grading machinery during one check.
	infraSeen *infraTracker

	// Exec runs a command inside a device of the grading lab.
	Exec func(ctx context.Context, deviceID string, cmd []string) (rt.ExecResult, error)
	// Args are the check's parameters from the rubric.
	Args map[string]any
}

// Device resolves a device in the AS under test.
func (e *Env) Device(name string) (*model.Device, bool) {
	return e.Topology.DeviceInAS(e.AS, name)
}

// Routers returns the routers of the AS under test, in template order.
func (e *Env) Routers() []*model.Device {
	if as, ok := e.Topology.ASes[e.AS]; ok {
		return as.Routers
	}
	return nil
}

// Vtysh runs a vtysh command on a router and returns its output.
func (e *Env) Vtysh(ctx context.Context, device, command string) (string, error) {
	res, err := e.Exec(ctx, model.DeviceID(e.AS, device), []string{"vtysh", "-c", command})
	if err != nil {
		return "", e.infra(device, command, err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("vtysh -c %q exited %d: %s", command, res.ExitCode, firstLine(res.Stderr))
	}
	return res.Stdout, nil
}

// VtyshJSON runs a vtysh command that emits JSON and decodes it.
//
// Parsing FRR's structured output rather than its human text is what makes a
// check assert on facts instead of on formatting. The legacy grader scraped
// `show ip bgp` text and broke whenever FRR changed a column.
func (e *Env) VtyshJSON(ctx context.Context, device, command string, out any) error {
	s, err := e.Vtysh(ctx, device, command)
	if err != nil {
		return err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("%s produced no output on %s", command, device)
	}
	if err := json.Unmarshal([]byte(s), out); err != nil {
		return fmt.Errorf("%s on %s: %w", command, device, err)
	}
	return nil
}

// InfraError marks a failure of the grading machinery rather than of the
// submission: a node that could not be reached, a container that is not there,
// an agent that returned an error.
//
// The distinction is the most important one in this package. A check that
// treats an unreachable node as "the student did not configure OSPF" converts
// a platform outage into a zero, and nothing in the report says so. Every
// check must let this kind of error escape rather than absorbing it into a
// verdict.
type InfraError struct {
	Device string
	Op     string
	Err    error
}

func (e *InfraError) Error() string {
	return fmt.Sprintf("could not reach %s to run %q: %v", e.Device, e.Op, e.Err)
}

func (e *InfraError) Unwrap() error { return e.Err }

// IsInfra reports whether an error is a failure of the grading machinery.
func IsInfra(err error) bool {
	var ie *InfraError
	return errors.As(err, &ie)
}

// infra records that the machinery failed and returns the error to the caller.
//
// Recording it centrally is deliberate. Checks legitimately absorb errors --
// a router with OSPF unconfigured is a student failure, and its vtysh command
// failing is the evidence -- so relying on every one of them to distinguish
// that from an unreachable node means relying on every future one too. The
// runner instead asks afterwards whether the machinery failed at any point
// during the check, and overrides the verdict if it did.
func (e *Env) infra(device, op string, err error) error {
	ie := &InfraError{Device: device, Op: op, Err: err}
	// A deadline we imposed ourselves is not an infrastructure failure. A
	// convergence wait that runs out of budget cancels its own probe, and
	// recording that as the machinery breaking would quarantine every
	// submission that was merely slow to converge -- turning a timeout that
	// should be reported as "did not converge" into "the grader is broken".
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ie
	}
	if e.infraSeen != nil {
		e.infraSeen.record(ie)
	}
	return ie
}

// infraTracker collects machinery failures seen during one check.
type infraTracker struct {
	mu    sync.Mutex
	first *InfraError
	count int
}

func (t *infraTracker) record(e *InfraError) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.count++
	if t.first == nil {
		t.first = e
	}
}

func (t *infraTracker) failure() *InfraError {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.first
}

// ArgString reads a string argument.
func (e *Env) ArgString(key, def string) string {
	if v, ok := e.Args[key].(string); ok {
		return v
	}
	return def
}

// ArgInt reads an integer argument.
func (e *Env) ArgInt(key string, def int) int {
	switch v := e.Args[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return def
}

// ArgBool reads a boolean argument.
func (e *Env) ArgBool(key string, def bool) bool {
	if v, ok := e.Args[key].(bool); ok {
		return v
	}
	return def
}

// ArgStrings reads a list-of-strings argument.
func (e *Env) ArgStrings(key string) []string {
	raw, ok := e.Args[key].([]any)
	if !ok {
		if ss, ok := e.Args[key].([]string); ok {
			return ss
		}
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ArgPaths reads a list-of-paths argument, each path being a list of router
// names, as used by the load-balancing check.
func (e *Env) ArgPaths(key string) [][]string {
	raw, ok := e.Args[key].([]any)
	if !ok {
		return nil
	}
	var out [][]string
	for _, p := range raw {
		inner, ok := p.([]any)
		if !ok {
			continue
		}
		var path []string
		for _, h := range inner {
			if s, ok := h.(string); ok {
				path = append(path, s)
			}
		}
		if len(path) > 0 {
			out = append(out, path)
		}
	}
	return out
}

// CheckFunc is a graded assertion about a student's network.
type CheckFunc func(ctx context.Context, env *Env) Result

// Check is a registered check with its documentation.
type Check struct {
	Name string
	// Describe is shown in listings and in report headings.
	Describe string
	// Run performs the assertion.
	Run CheckFunc
}

// registry holds every known check. It is populated by init functions in the
// checks_*.go files, which keeps adding a course-specific check to one file.
var registry = map[string]*Check{}

// Register adds a check. Registering a duplicate name is a programming error.
func Register(c *Check) {
	if c.Name == "" {
		panic("grade: check with no name")
	}
	if _, dup := registry[c.Name]; dup {
		panic("grade: duplicate check " + c.Name)
	}
	registry[c.Name] = c
}

// Lookup finds a check by name.
func Lookup(name string) (*Check, bool) {
	c, ok := registry[name]
	return c, ok
}

// Checks returns every registered check, sorted.
func Checks() []*Check {
	out := make([]*Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// runCheck executes a check, converting a panic into an error result so one
// buggy check cannot take down a class-wide grading run.
func runCheck(ctx context.Context, c *Check, env *Env) (res Result) {
	start := time.Now()
	defer func() {
		if r := recover(); r != nil {
			res = Errored(c.Name, fmt.Errorf("the check panicked: %v", r))
		}
		res.Check = c.Name
		res.Duration = time.Since(start).Round(time.Millisecond).String()
	}()
	if err := ctxErr(ctx); err != nil {
		return Errored(c.Name, err)
	}
	return c.Run(ctx, env)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return strings.TrimSpace(s)
}
