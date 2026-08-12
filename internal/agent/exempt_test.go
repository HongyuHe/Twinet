package agent

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/state"
)

func serverWithStore(t *testing.T) *Server {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: st, exempt: map[string]*exemptions{}, repairFails: map[string]int{}}
	s.cfg.Node = "node-0"
	return s
}

// Stopping a routing daemon is a supported fault. The repair loop restarted it
// within the minute, so an episode kept open for somebody to diagnose lost its
// fault while the recorded ground truth went on saying the fault was live.
func TestADeviceBrokenOnPurposeIsLeftAlone(t *testing.T) {
	s := serverWithStore(t)
	if s.isExempt("cos461", "as3/ATL") {
		t.Fatal("a device nobody touched is already exempt from repair")
	}
	if err := s.setExempt(ExemptRequest{
		Lab: "cos461", Device: "as3/ATL", ID: "abc123", On: true}); err != nil {
		t.Fatal(err)
	}
	if !s.isExempt("cos461", "as3/ATL") {
		t.Error("a device with a live injected fault is not exempt, so the repair loop " +
			"will undo the fault while the episode says it is live")
	}
	if s.isExempt("cos461", "as3/BOS") {
		t.Error("exempting one device exempted another")
	}
	if s.isExempt("other", "as3/ATL") {
		t.Error("exempting a device of one lab exempted the same device of another")
	}
}

// A fault outlives the command that injected it: an episode held open for
// diagnosis, or a fault injected by hand for a class, must survive an agent
// restart. Anything less and the fault is repaired away the next time the
// agent is upgraded, with the ground truth still saying it is live.
func TestAnExemptionSurvivesTheAgentBeingRestarted(t *testing.T) {
	s := serverWithStore(t)
	if err := s.setExempt(ExemptRequest{
		Lab: "cos461", Device: "as3/ATL", ID: "abc123", On: true}); err != nil {
		t.Fatal(err)
	}

	// A new process, reading the same store.
	again := &Server{store: s.store, exempt: map[string]*exemptions{}}
	again.loadExemptions("cos461")
	if !again.isExempt("cos461", "as3/ATL") {
		t.Fatal("after a restart the node no longer knows this device is broken on " +
			"purpose, so it will repair the fault away")
	}
}

func TestResolvingAFaultLetsTheNodeLookAfterTheDeviceAgain(t *testing.T) {
	s := serverWithStore(t)
	for _, id := range []string{"one", "two"} {
		if err := s.setExempt(ExemptRequest{
			Lab: "cos461", Device: "as3/ATL", ID: id, On: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.setExempt(ExemptRequest{
		Lab: "cos461", Device: "as3/ATL", ID: "one", On: false}); err != nil {
		t.Fatal(err)
	}
	if !s.isExempt("cos461", "as3/ATL") {
		t.Error("resolving one of two faults on a device made it repairable while the " +
			"other fault is still live")
	}
	if err := s.setExempt(ExemptRequest{
		Lab: "cos461", Device: "as3/ATL", ID: "two", On: false}); err != nil {
		t.Fatal(err)
	}
	if s.isExempt("cos461", "as3/ATL") {
		t.Error("a device with no faults left on it is still exempt from repair, so a " +
			"real failure there would never be fixed")
	}
}

// Device identifiers repeat: every private grading harness contains as3/ATL,
// and so does the class lab. Keying repair state on the device alone meant
// three failed repairs in an abandoned harness switched off self-repair for the
// real device of the same name in the lab a class was being taught in.
func TestGivingUpOnOneLabDoesNotGiveUpOnAnother(t *testing.T) {
	s := serverWithStore(t)
	const id = "as3/ATL"
	for i := 0; i < repairAttemptsBeforeGivingUp; i++ {
		s.repairFailed("cos461-g7-abandoned", id, "rewiring failed", errNoPeer)
	}
	if !s.givingUpOn("cos461-g7-abandoned", id) {
		t.Fatal("the abandoned harness is still being retried")
	}
	if s.givingUpOn("cos461", id) {
		t.Error("giving up on a device in an abandoned harness also gave up on the " +
			"device of the same name in the class lab, so a real failure there will " +
			"never be repaired and its neighbours' students lose the marks")
	}
}

var errNoPeer = errPeerAbsent{}

type errPeerAbsent struct{}

func (errPeerAbsent) Error() string { return "the peer container is absent" }

var _ = model.KindRouter
