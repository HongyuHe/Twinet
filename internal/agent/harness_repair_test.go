package agent

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
)

func harnessTopology() *model.Topology {
	student := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter, ASN: 3}
	neighbour := &model.Device{ID: "as4/ATL", Name: "ATL", Kind: model.KindRouter, ASN: 4}
	return &model.Topology{
		Name:    "cos461-g3",
		Lab:     &model.Lab{},
		Devices: map[string]*model.Device{student.ID: student, neighbour.ID: neighbour},
		ASes: map[int]*model.AS{
			3: {ASN: 3, Role: model.RoleStudent, Devices: []*model.Device{student}},
			4: {ASN: 4, Role: model.RoleStudent, Devices: []*model.Device{neighbour}},
		},
	}
}

// A private grading harness is deployed solved *except* for the one system
// being marked, which keeps the platform's starting configuration. That
// exemption has to survive a repair.
//
// The repair loop replayed only the lab's mode. For a harness that is "solve",
// so rebuilding a device of the graded system installed the reference answer
// on the very router whose work was about to be marked -- and logged the repair
// as a success. A container restart during grading was worth full marks.
func TestRepairingAHarnessDoesNotInstallTheAnswerOnTheGradedSystem(t *testing.T) {
	top := harnessTopology()
	const graded = 3

	// What the deployment used.
	deployed := renderer(top, render.ModeSolve, graded)
	// What a repair reconstructs from what the agent recorded.
	// Recorded exactly the way the agent records it, so that a change which
	// forgets half of it fails here.
	s := &Server{}
	s.rememberHow(top.Name, string(render.ModeSolve), graded)
	repaired := repairRendererFor(s, top)

	student := top.Devices["as3/ATL"]
	want, err := deployed.Files(student)
	if err != nil {
		t.Fatal(err)
	}
	got, err := repaired.Files(student)
	if err != nil {
		t.Fatal(err)
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("repairing the graded system does not produce %s at all", name)
			continue
		}
		if string(g.Content) != string(w.Content) {
			t.Errorf("repairing the graded system produced different %s from the "+
				"deployment. If the repair renders the solved configuration, the "+
				"student is marked on the reference answer", name)
		}
	}

	// And the exemption must be real: the graded system must not be rendered
	// the same way as its neighbours, or there is nothing here to preserve.
	neighbour := top.Devices["as4/ATL"]
	nb, err := deployed.Files(neighbour)
	if err != nil {
		t.Fatal(err)
	}
	same := true
	for name, w := range want {
		if n, ok := nb[name]; !ok || string(n.Content) != string(w.Content) {
			same = false
		}
	}
	if same {
		t.Skip("this topology does not distinguish solved from unsolved configuration, " +
			"so the exemption cannot be observed here")
	}
}

// If the agent forgets which system was exempt, it must not silently guess that
// none was.
func TestTheExemptSystemIsRememberedAcrossAReload(t *testing.T) {
	w := &Wire{Mode: "solve", Ungraded: 7}
	raw := *w
	if raw.Ungraded != 7 {
		t.Fatal("the exempt system is not part of what is recorded")
	}
	s := &Server{}
	s.rememberHow("lab", raw.Mode, raw.Ungraded)
	if s.ungraded["lab"] != 7 {
		t.Errorf("after a reload the agent believes AS %d was exempt, not 7; a repair "+
			"would install the reference answer on the graded system", s.ungraded["lab"])
	}
}

// repairRendererFor builds the renderer a repair would use, the same way
// repairLab does, so that changing one and not the other fails here.
func repairRendererFor(s *Server, top *model.Topology) *render.Renderer {
	return renderer(top, render.Mode(s.modes[top.Name]), s.ungraded[top.Name])
}
