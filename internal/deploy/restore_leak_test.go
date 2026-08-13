package deploy

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// The snapshot loader copies a complete routing configuration into the
// container and asks vtysh to read it. It left the file there.
//
// On a lab deployed at the reference that file is the answer, sitting in
// /etc/twinet where any root shell can read it -- and root inside the container
// is exactly what a student has, and what an agent being evaluated on
// root-cause analysis has. It was found on sampled routers of three autonomous
// systems on a live cluster.
func TestRestoreDoesNotLeaveTheConfigurationInTheContainer(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := &model.Device{ID: "as3/ATL", ASN: 3, Kind: model.KindRouter, Container: "twinet_as3_ATL"}
	if _, err := store.Put(state.Snapshot{
		Lab: "cos461", AS: 3, Device: d.ID, Kind: state.KindFRR,
		Content: []byte("router bgp 3\n neighbor 179.3.4.2 remote-as 4\n"),
	}); err != nil {
		t.Fatal(err)
	}

	fs := &fileTrackingRuntime{files: map[string]bool{}}
	if _, err := Restore(context.Background(), fs, d, "cos461", store); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.files["/etc/twinet/restore.conf"] {
		t.Error("the restored configuration is still in the container after the restore. " +
			"On a lab deployed at the reference that file is the answer, readable by " +
			"anyone with a shell on the router.")
	}
	if !fs.loaded {
		t.Error("the configuration was never loaded, so this proves nothing")
	}
}

// fileTrackingRuntime models the container's filesystem well enough to say
// whether a copied-in file is still there.
type fileTrackingRuntime struct {
	rt.Runtime
	mu     sync.Mutex
	files  map[string]bool
	loaded bool
}

func (f *fileTrackingRuntime) CopyTo(_ context.Context, _, path string, _ int64, _ []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = true
	return nil
}

func (f *fileTrackingRuntime) Exec(_ context.Context, _ string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	body := strings.Join(cmd.Cmd, " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Contains(body, "vtysh -f /etc/twinet/restore.conf") {
		f.loaded = true
	}
	if strings.Contains(body, "rm -f") {
		for _, field := range strings.Fields(body) {
			field = strings.Trim(field, ";\"'")
			if strings.HasPrefix(field, "/etc/twinet/") {
				delete(f.files, field)
			}
		}
	}
	return rt.ExecResult{}, nil
}
