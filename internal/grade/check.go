package grade

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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
		return "", err
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
