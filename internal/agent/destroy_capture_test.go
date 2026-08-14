package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// A node that does not know what a lab is cannot read anybody's work out of it.
// It used to destroy it anyway.
//
// The topology is held in memory and on disk, and the disk copy is what an
// agent reads after a restart. If that read fails, or the record was never
// written, the node comes up hosting a class's containers with no idea what
// they are, the capture step was skipped for want of a topology, and the
// containers were removed. A term's work, deleted, with the destroy reporting
// success.
func TestDestroyRefusesWhenItCannotCaptureWhatIsThere(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	newServer := func(names ...string) *Server {
		return &Server{
			rt:      &listingRuntime{names: names},
			store:   store,
			cfg:     Config{Node: "node-0"},
			current: map[string]*model.Topology{},
			modes:   map[string]string{},
		}
	}
	eng := &deploy.Engine{Node: "node-0", State: store}

	s := newServer("twinet-cos461-as3-atl", "twinet-cos461-as3-bos")
	eng.Runtime = s.rt
	err = s.captureBeforeDestroy(context.Background(), eng, "cos461")
	if err == nil {
		t.Fatal("destroying a lab this node has containers for but no record of was allowed, " +
			"so a restart that loses the topology record turns destroy into silent, " +
			"unrecoverable deletion of a class's work")
	}
	if !strings.Contains(err.Error(), "no record") {
		t.Errorf("the refusal does not say why: %v", err)
	}

	// A node that genuinely holds nothing must still be able to destroy, or a
	// lab can never be cleaned up from a machine that has already lost it.
	empty := newServer()
	eng.Runtime = empty.rt
	if err := empty.captureBeforeDestroy(context.Background(), eng, "cos461"); err != nil {
		t.Errorf("destroying a lab this node holds nothing of was refused: %v", err)
	}

	// And a lab deployed at the reference has nothing of anybody's to save, so
	// it must not be refused for the want of a capture it must not do.
	solved := newServer("twinet-cos461-as3-atl")
	solved.modes["cos461"] = string(render.ModeSolve)
	eng.Runtime = solved.rt
	if err := solved.captureBeforeDestroy(context.Background(), eng, "cos461"); err != nil {
		t.Errorf("destroying a lab holding the reference answer was refused: %v", err)
	}
}

// listingRuntime answers List and nothing else.
type listingRuntime struct {
	rt.Runtime
	names []string
}

func (l *listingRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	var out []rt.Container
	for _, n := range l.names {
		out = append(out, rt.Container{Name: n, State: rt.StateRunning,
			Labels: map[string]string{deploy.LabelLab: "cos461"}})
	}
	return out, nil
}
