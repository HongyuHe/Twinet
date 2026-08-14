package agent

import (
	"context"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// presenceRuntime answers whether each container exists.
type presenceRuntime struct {
	rt.Runtime
	present map[string]bool
	fail    bool
}

func (p *presenceRuntime) Inspect(_ context.Context, name string) (rt.Container, error) {
	if p.fail {
		return rt.Container{}, context.DeadlineExceeded
	}
	if p.present[name] {
		return rt.Container{State: rt.StateRunning}, nil
	}
	return rt.Container{State: rt.StateAbsent}, nil
}

func labOf(name string, containers ...string) *model.Topology {
	top := &model.Topology{Name: name, Lab: &model.Lab{}, Devices: map[string]*model.Device{}}
	for i, c := range containers {
		id := "as3/D" + string(rune('A'+i))
		top.Devices[id] = &model.Device{ID: id, Container: c, Node: "node-0"}
	}
	return top
}

// A lab whose containers have all gone is a lab that was removed and this node
// was never told. Its record kept the repair loop trying to rewire devices
// whose peers no longer exist, once a minute, for as long as the node was up.
func TestALabWithNothingLeftOfItIsForgotten(t *testing.T) {
	top := labOf("cos461-g7-abandoned", "a", "b")
	s := &Server{rt: &presenceRuntime{present: map[string]bool{}}}
	s.cfg.Node = "node-0"

	if !s.labIsGone(context.Background(), top) {
		t.Error("a lab with none of its containers left is still believed to be running, " +
			"so this node will keep trying to repair devices that do not exist")
	}
}

// A lab midway through deployment, or one whose containers are stopped, must
// not be forgotten: the record is what a restart needs to bring them back.
func TestALabWithAnythingLeftIsKept(t *testing.T) {
	top := labOf("cos461", "a", "b")
	s := &Server{rt: &presenceRuntime{present: map[string]bool{"b": true}}}
	s.cfg.Node = "node-0"

	if s.labIsGone(context.Background(), top) {
		t.Error("a lab that still has a container was forgotten; a redeploy would find " +
			"nothing recorded and nothing here would be repaired or preserved")
	}
}

// Unreadable is not absent. Guessing the other way throws away the record of a
// live lab because the runtime was momentarily busy.
func TestALabIsNotForgottenBecauseTheRuntimeWouldNotAnswer(t *testing.T) {
	top := labOf("cos461", "a")
	s := &Server{rt: &presenceRuntime{fail: true}}
	s.cfg.Node = "node-0"

	if s.labIsGone(context.Background(), top) {
		t.Error("a lab was forgotten because its containers could not be inspected")
	}
}

func TestForgettingALabClearsEverythingAboutIt(t *testing.T) {
	s := &Server{
		current:     map[string]*model.Topology{"gone": labOf("gone", "a"), "live": labOf("live", "b")},
		modes:       map[string]string{"gone": "solve", "live": "solve"},
		ungraded:    map[string]int{"gone": 3, "live": 4},
		peers:       map[string]map[string]string{"gone": {}, "live": {}},
		exempt:      map[string]*exemptions{"gone": {}, "live": {}},
		repairFails: map[string]int{"gone|as3/DA": 3, "live|as3/DA": 2},
	}
	s.forgetLab("gone")

	if _, ok := s.current["gone"]; ok {
		t.Error("the topology was kept")
	}
	if _, ok := s.exempt["gone"]; ok {
		t.Error("the fault exemptions were kept, so a device of a lab that no longer " +
			"exists could exempt a future lab of the same name")
	}
	if _, ok := s.repairFails["gone|as3/DA"]; ok {
		t.Error("the repair backoff was kept, so a lab redeployed under this name would " +
			"start out already given up on")
	}
	if _, ok := s.current["live"]; !ok {
		t.Error("forgetting one lab forgot another")
	}
	if s.repairFails["live|as3/DA"] != 2 {
		t.Error("forgetting one lab cleared another's repair state")
	}
}
