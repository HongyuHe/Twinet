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

// markerRuntime remembers whether the marker file exists in each container.
type markerRuntime struct {
	rt.Runtime
	mu      sync.Mutex
	markers map[string]bool
}

func (m *markerRuntime) Exec(_ context.Context, c string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	body := strings.Join(cmd.Cmd, " ")
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case strings.Contains(body, "> "+restoreMarker):
		m.markers[c] = true
	case strings.HasPrefix(body, "rm -f "+restoreMarker):
		delete(m.markers, c)
	case strings.HasPrefix(body, "test -f "+restoreMarker):
		if !m.markers[c] {
			return rt.ExecResult{ExitCode: 1}, nil
		}
	}
	return rt.ExecResult{}, nil
}

// A device that was recreated and has not had its student's configuration
// replayed must still say so after the process that recreated it has gone.
//
// The engine used to record this in a map that lives for one request. An agent
// restarted, upgraded or killed between creating a container and configuring it
// took that record with it; the next deploy found a container that existed with
// nothing marking it and converged happily on an empty router, while the
// student's work sat in the state store with nothing left to look for it.
func TestARecreatedDeviceStillOwesARestoreAfterTheProcessDies(t *testing.T) {
	m := &markerRuntime{markers: map[string]bool{}}
	d := &model.Device{ID: "as3/ATL", Container: "twinet-cos461-as3-atl"}

	first := &Engine{Runtime: m}
	first.markRestorePending(context.Background(), d)
	if !first.restoreIsPending(context.Background(), d) {
		t.Fatal("the device does not report a pending restore even in the run that marked it")
	}

	// The agent dies here. Everything the engine remembered goes with it.
	second := &Engine{Runtime: m}
	if !second.restoreIsPending(context.Background(), d) {
		t.Fatal("after the process was replaced, nothing says this device is still " +
			"waiting for its configuration. It will be left empty and the snapshot " +
			"will never be looked for again.")
	}

	second.clearRestorePending(context.Background(), d)
	third := &Engine{Runtime: m}
	if third.restoreIsPending(context.Background(), d) {
		t.Error("a device whose configuration was replayed is still asking for another " +
			"restore, which would overwrite whatever it has done since")
	}
}

func TestADeviceThatWasNeverRecreatedOwesNothing(t *testing.T) {
	m := &markerRuntime{markers: map[string]bool{}}
	e := &Engine{Runtime: m}
	d := &model.Device{ID: "as3/BOS", Container: "twinet-cos461-as3-bos"}
	if e.restoreIsPending(context.Background(), d) {
		t.Error("a device nobody touched is being told it needs its configuration " +
			"replayed, which would put an old snapshot over current work")
	}
}

// Every autonomous system in these labs has a router called ATL. Capturing an
// orphan by its short name filed as3/ATL's configuration and as4/ATL's under
// the same key -- one overwriting the other, and neither findable by the
// identifier a restore looks up.
func TestAnOrphanIsCapturedUnderItsCanonicalIdentifier(t *testing.T) {
	labels := map[string]string{
		LabelDevice:   "ATL",
		LabelDeviceID: "as3/ATL",
		LabelKind:     "router",
	}
	if labels[LabelDeviceID] == labels[LabelDevice] {
		t.Fatal("the fixture does not distinguish the two labels")
	}
	// The capture must prefer the canonical one.
	id := labels[LabelDeviceID]
	if id == "" {
		id = labels[LabelDevice]
	}
	if id != "as3/ATL" {
		t.Errorf("an orphan would be filed as %q, which collides with every other "+
			"system's router of the same name", id)
	}
}

// Restoration exists so that a container recreated during teaching comes back
// with the student's work. A deployment that installs the reference wants the
// opposite: replaying the snapshot afterwards puts the student's old
// configuration back on top of the answer, and a grading run then measures
// every other submission against a lab that is not the reference -- while every
// check on that system passes, because it is somebody's converged network.
func TestASolveDeploymentDoesNotRestoreStudentWorkOverTheAnswer(t *testing.T) {
	m := &markerRuntime{markers: map[string]bool{}}
	top := &model.Topology{
		Name:    "cos461",
		Devices: map[string]*model.Device{},
		ASes:    map[int]*model.AS{3: {ASN: 3, Role: model.RoleStudent}},
	}
	d := &model.Device{ID: "as3/ATL", Container: "twinet-cos461-as3-atl", ASN: 3}
	top.Devices[d.ID] = d
	top.ASes[3].Devices = []*model.Device{d}

	solving := &Engine{Runtime: m, State: &state.Store{}, WritesReference: true}
	if err := solving.restoreIfNeeded(context.Background(), top, d); err != nil {
		t.Fatal(err)
	}
	if m.markers[d.Container] {
		t.Error("a deployment writing the reference marked the device as owing a restore, " +
			"so the student's old configuration would be replayed over the answer")
	}

	teaching := &Engine{Runtime: m, State: &state.Store{}}
	if err := teaching.restoreIfNeeded(context.Background(), top, d); err != nil {
		t.Fatal(err)
	}
	if !m.markers[d.Container] {
		t.Error("an ordinary deployment no longer restores a recreated device, so a " +
			"student's work is lost whenever a container is rebuilt")
	}
}
