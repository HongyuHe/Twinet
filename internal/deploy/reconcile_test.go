package deploy

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/plan"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type reconcilerRuntime struct {
	rt.Runtime
	mu             sync.Mutex
	files          map[string][]byte
	marker         string
	expectedMarker string
	copies         int
	commands       int
}

func (r *reconcilerRuntime) CopyFrom(_ context.Context, _ string, path string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	body, ok := r.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), body...), nil
}

func (r *reconcilerRuntime) CopyTo(_ context.Context, _ string, path string, _ int64, body []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.copies++
	r.files[path] = append([]byte(nil), body...)
	return nil
}

func (r *reconcilerRuntime) Exec(_ context.Context, _ string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	body := strings.Join(cmd.Cmd, " ")
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case strings.Contains(body, "cat "+configurationMarker):
		if r.marker == "" {
			return rt.ExecResult{ExitCode: 1}, nil
		}
		return rt.ExecResult{Stdout: r.marker + "\n"}, nil
	case strings.Contains(body, "> "+configurationMarker):
		r.marker = r.expectedMarker
		return rt.ExecResult{}, nil
	case strings.Contains(body, "test -s /etc/frr/frr.conf"):
		if len(r.files["/etc/frr/frr.conf"]) > 0 {
			return rt.ExecResult{Stdout: "yes\n"}, nil
		}
		return rt.ExecResult{Stdout: "no\n"}, nil
	default:
		r.commands++
		return rt.ExecResult{}, nil
	}
}

func (r *reconcilerRuntime) resetMutations() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.copies = 0
	r.commands = 0
}

func (r *reconcilerRuntime) mutations() (copies, commands int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.copies, r.commands
}

type reconcilerRenderer struct {
	files map[string]FileSpec
	cmds  []Command
}

func (r reconcilerRenderer) Files(*model.Device) (map[string]FileSpec, error) {
	return r.files, nil
}

func (r reconcilerRenderer) Commands(*model.Device) ([]Command, error) {
	return r.cmds, nil
}

func (r reconcilerRenderer) Ready(*model.Device, rt.Runtime) *plan.Waiter { return nil }

func TestNoChangeConfigurationDoesNotCopyOrRunDaemonCommands(t *testing.T) {
	renderer := reconcilerRenderer{
		files: map[string]FileSpec{
			"/etc/twinet/platform.conf": {Content: []byte("platform=true\n"), Mode: 0o644},
		},
		cmds: []Command{{Args: []string{"daemonctl", "reload"}, Describe: "reload daemon"}},
	}
	runtime := &reconcilerRuntime{files: map[string][]byte{}}
	runtime.expectedMarker = ConfigHash(renderer.files, renderer.cmds)
	engine := &Engine{Runtime: runtime, Renderer: renderer}
	device := &model.Device{ID: "as1/R1", Container: "twinet-as1-r1"}

	if err := engine.configure(context.Background(), device); err != nil {
		t.Fatalf("initial configure: %v", err)
	}
	if copies, commands := runtime.mutations(); copies != 1 || commands != 1 {
		t.Fatalf("initial configure mutations = copies %d, commands %d; want 1, 1", copies, commands)
	}

	runtime.resetMutations()
	if err := engine.configure(context.Background(), device); err != nil {
		t.Fatalf("no-change configure: %v", err)
	}
	if copies, commands := runtime.mutations(); copies != 0 || commands != 0 {
		t.Fatalf("no-change configure mutated container: copies %d, commands %d", copies, commands)
	}
}

func TestCommandHashChangeRunsOnlyCommandsWhenFilesMatch(t *testing.T) {
	renderer := reconcilerRenderer{
		files: map[string]FileSpec{
			"/etc/twinet/platform.conf": {Content: []byte("platform=true\n"), Mode: 0o644},
		},
		cmds: []Command{{Args: []string{"daemonctl", "reload"}, Describe: "reload daemon"}},
	}
	runtime := &reconcilerRuntime{files: map[string][]byte{}}
	engine := &Engine{Runtime: runtime, Renderer: renderer}
	device := &model.Device{ID: "as1/R1", Container: "twinet-as1-r1"}
	runtime.expectedMarker = ConfigHash(renderer.files, renderer.cmds)
	if err := engine.configure(context.Background(), device); err != nil {
		t.Fatal(err)
	}

	renderer.cmds = []Command{{Args: []string{"daemonctl", "reload", "--new"}, Describe: "reload daemon"}}
	engine.Renderer = renderer
	runtime.expectedMarker = ConfigHash(renderer.files, renderer.cmds)
	runtime.resetMutations()
	if err := engine.configure(context.Background(), device); err != nil {
		t.Fatalf("changed command configure: %v", err)
	}
	if copies, commands := runtime.mutations(); copies != 0 || commands != 1 {
		t.Fatalf("changed command mutations = copies %d, commands %d; want 0, 1", copies, commands)
	}
}

func TestReconfigureDeviceReappliesCommandsDespiteCurrentMarker(t *testing.T) {
	renderer := reconcilerRenderer{
		files: map[string]FileSpec{
			"/etc/twinet/platform.conf": {Content: []byte("platform=true\n"), Mode: 0o644},
		},
		cmds: []Command{{Args: []string{"ip", "addr", "replace"}, Describe: "repair address"}},
	}
	hash := ConfigHash(renderer.files, renderer.cmds)
	runtime := &reconcilerRuntime{
		files: map[string][]byte{
			"/etc/twinet/platform.conf": []byte("platform=true\n"),
		},
		marker: hash, expectedMarker: hash,
	}
	engine := &Engine{Runtime: runtime, Renderer: renderer}
	device := &model.Device{ID: "as1/R1", Container: "twinet-as1-r1"}

	if err := engine.ReconfigureDevice(context.Background(), device); err != nil {
		t.Fatal(err)
	}
	if copies, commands := runtime.mutations(); copies != 0 || commands != 1 {
		t.Fatalf("semantic reconfiguration mutations = copies %d, commands %d; want 0, 1",
			copies, commands)
	}
}

func TestConfigureNeverOverwritesStudentOwnedFile(t *testing.T) {
	renderer := reconcilerRenderer{
		files: map[string]FileSpec{
			"/etc/frr/frr.conf": {Content: []byte("reference configuration\n"), Mode: 0o640},
		},
		cmds: []Command{{Args: []string{"daemonctl", "reload"}, Describe: "reload daemon"}},
	}
	runtime := &reconcilerRuntime{
		files: map[string][]byte{"/etc/frr/frr.conf": []byte("student configuration\n")},
	}
	runtime.expectedMarker = ConfigHash(renderer.files, renderer.cmds)
	engine := &Engine{Runtime: runtime, Renderer: renderer}
	device := &model.Device{
		ID: "as1/R1", Container: "twinet-as1-r1",
		Ifaces: []*model.Iface{{Owner: model.OwnerStudent}},
	}

	if err := engine.configure(context.Background(), device); err != nil {
		t.Fatal(err)
	}
	if copies, _ := runtime.mutations(); copies != 0 {
		t.Fatalf("student-owned configuration was copied over %d time(s)", copies)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if got := string(runtime.files["/etc/frr/frr.conf"]); got != "student configuration\n" {
		t.Fatalf("student configuration was overwritten: %q", got)
	}
}

func TestConfigHashIncludesFileContentAndCommands(t *testing.T) {
	files := map[string]FileSpec{"/x": {Content: []byte("one"), Mode: 0o644}}
	cmds := []Command{{Args: []string{"daemon", "reload"}}}
	first := ConfigHash(files, cmds)
	files["/x"] = FileSpec{Content: []byte("two"), Mode: 0o644}
	if got := ConfigHash(files, cmds); got == first {
		t.Fatal("different rendered file content produced the same hash")
	}
	files["/x"] = FileSpec{Content: []byte("one"), Mode: 0o644}
	cmds[0].Args = append(cmds[0].Args, "--changed")
	if got := ConfigHash(files, cmds); got == first {
		t.Fatalf("different rendered command produced the same hash %s", got)
	}
}
