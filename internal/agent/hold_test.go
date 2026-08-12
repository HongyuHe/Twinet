package agent

import (
	"strings"

	"context"
	"github.com/HongyuHe/twinet/internal/model"
	"testing"
	"time"
)

// While a lab is held, the repair loop must leave it alone. Grading blanks and
// reloads devices, and a device mid-load looks exactly like a broken one; the
// loop rewiring it underneath the grader quarantined seven of eight students in
// one class run.
func TestAHeldLabIsLeftAlone(t *testing.T) {
	s := &Server{holds: map[string]*hold{}}
	if who := s.heldBy("cos461"); who != "" {
		t.Fatalf("an unheld lab reported a holder: %q", who)
	}
	s.holds["cos461"] = &hold{holder: "grading (pid 42)", until: time.Now().Add(time.Minute)}
	if who := s.heldBy("cos461"); who != "grading (pid 42)" {
		t.Errorf("a held lab did not name its holder: %q", who)
	}
	if who := s.heldBy("other"); who != "" {
		t.Errorf("holding one lab also held another: %q", who)
	}
}

// The hold is a lease, so a grader that dies cannot leave repairs switched off.
func TestALapsedHoldStopsHolding(t *testing.T) {
	s := &Server{holds: map[string]*hold{
		"cos461": {holder: "grading", until: time.Now().Add(-time.Second)},
	}}
	if who := s.heldBy("cos461"); who != "" {
		t.Fatalf("a hold that expired a second ago is still in force (%q). Nothing would "+
			"ever look after this lab again", who)
	}
	if _, ok := s.holds["cos461"]; ok {
		t.Error("the lapsed hold was left in the map")
	}
}

func TestAHoldIsCappedAndCanBeDropped(t *testing.T) {
	s := &Server{holds: map[string]*hold{}}
	s.applyHold(HoldRequest{Lab: "cos461", Holder: "grading", Seconds: 100000})
	h := s.holds["cos461"]
	if h == nil {
		t.Fatal("the hold was not taken")
	}
	if d := time.Until(h.until); d > (maxHoldSeconds+5)*time.Second {
		t.Errorf("a caller asked for %v and got it; one request could switch repairs off "+
			"for the life of the node", d)
	}
	s.applyHold(HoldRequest{Lab: "cos461", Seconds: 0})
	if who := s.heldBy("cos461"); who != "" {
		t.Errorf("the hold could not be dropped: %q", who)
	}
}

// A device whose peers no longer exist cannot be rewired. Retrying it every
// minute forever fills the log and hides the labs that can be repaired.
func TestRepairsThatCannotSucceedAreGivenUpOn(t *testing.T) {
	s := &Server{repairFails: map[string]int{}}
	const lab = "cos461"
	id := "as9/CHI_host"
	for i := 0; i < repairAttemptsBeforeGivingUp; i++ {
		if s.givingUpOn(lab, id) {
			t.Fatalf("gave up after %d attempts, before trying %d times",
				i, repairAttemptsBeforeGivingUp)
		}
		s.repairFailed(lab, id, "rewiring failed", context.DeadlineExceeded)
	}
	if !s.givingUpOn(lab, id) {
		t.Errorf("still retrying after %d consecutive failures", repairAttemptsBeforeGivingUp)
	}
	if s.givingUpOn(lab, "as9/MSP_host") {
		t.Error("giving up on one device also gave up on another")
	}
	s.repairSucceeded(lab, id)
	if s.givingUpOn(lab, id) {
		t.Error("a device that was repaired is still being ignored")
	}
}

// A hold is how a grading run says "leave this lab to me". It stopped the
// node's own repair loop and nothing else, so while a class was being marked a
// student could still open a shell on a router: read the reference solution off
// their neighbours, change the submission about to be graded, or break a system
// somebody else's mark depended on. None of it would appear in the marks.
func TestInteractiveAccessIsRefusedWhileALabIsGraded(t *testing.T) {
	s := &Server{
		holds:   map[string]*hold{},
		current: map[string]*model.Topology{"cos461": {Name: "cos461"}},
	}
	const container = "twinet-cos461-as3-atl"

	if why := s.refuseIfHeldByAnother(container, ""); why != "" {
		t.Fatalf("access to a lab nobody is grading was refused: %s", why)
	}

	s.applyHold(HoldRequest{Lab: "cos461", Holder: "grading (pid 42)",
		Token: "tok", Seconds: 60})

	why := s.refuseIfHeldByAnother(container, "")
	if why == "" {
		t.Fatal("a student can open a shell on a lab that is being graded")
	}
	if !strings.Contains(why, "cos461") || !strings.Contains(why, "pid 42") {
		t.Errorf("the refusal does not say which lab or who holds it: %q", why)
	}

	// The grader reaches the containers through this same door.
	if why := s.refuseIfHeldByAnother(container, "tok"); why != "" {
		t.Errorf("the holder was locked out of the lab it is grading: %s", why)
	}
	// Another lab on the same node is unaffected.
	if why := s.refuseIfHeldByAnother("twinet-advnet-as1-zuri", ""); why != "" {
		t.Errorf("holding one lab refused access to another: %s", why)
	}
}

// The longest matching lab name wins, or a private grading harness would be
// mistaken for the class lab it is named after.
func TestAHarnessIsNotMistakenForTheClassLab(t *testing.T) {
	s := &Server{
		holds: map[string]*hold{},
		current: map[string]*model.Topology{
			"cos461":             {Name: "cos461"},
			"cos461-g3-groupabc": {Name: "cos461-g3-groupabc"},
		},
	}
	if got := s.labOfContainer("twinet-cos461-g3-groupabc-as3-atl"); got != "cos461-g3-groupabc" {
		t.Errorf("the container was attributed to lab %q", got)
	}
	if got := s.labOfContainer("twinet-cos461-as3-atl"); got != "cos461" {
		t.Errorf("the container was attributed to lab %q", got)
	}
}
