package agent

import (
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestLargeTopologyGetsTheScaleConvergenceBudget(t *testing.T) {
	top := &model.Topology{Devices: map[string]*model.Device{}}
	for i := 0; i < 257; i++ {
		top.Devices[string(rune(i+1))] = &model.Device{}
	}
	if got := semanticConvergenceGraceFor(top); got != largeTopologySemanticGrace {
		t.Fatalf("large-topology grace = %s, want %s", got, largeTopologySemanticGrace)
	}
}

func TestRemoteSemanticDriftWaitsForPostCommitConvergence(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := &Server{
		now:                func() time.Time { return now },
		semanticGraceUntil: map[string]time.Time{"scale": now.Add(time.Minute)},
	}
	reason := "network semantics drifted: as3/SFO has no route to reference host address(es) 29.101.0.1"
	if s.semanticDriftActionable("scale", reason) {
		t.Fatal("ordinary remote convergence was repaired during the post-commit grace")
	}
	now = now.Add(2 * time.Minute)
	if !s.semanticDriftActionable("scale", reason) {
		t.Fatal("remote semantic drift remained hidden after the grace expired")
	}
}

func TestLocalSemanticDriftIsActionableDuringConvergenceGrace(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := &Server{
		now:                func() time.Time { return now },
		semanticGraceUntil: map[string]time.Time{"scale": now.Add(10 * time.Minute)},
	}
	reason := "network semantics drifted: as3/CHI is missing expected address 180.140.0.3/24"
	if !s.semanticDriftActionable("scale", reason) {
		t.Fatal("a missing local address was hidden by the routing convergence grace")
	}
}

func TestNewGenerationClearsPriorTerminalRepairState(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := repairKey("scale", "as3/CHI")
	s := &Server{
		now:                func() time.Time { return now },
		semanticGraceUntil: map[string]time.Time{},
		semanticCycles:     map[string]int{key: 3},
		repairTerminal:     map[string]string{key: "old generation"},
		repairFails:        map[string]int{key: 4},
		repairNext:         map[string]time.Time{key: now.Add(time.Hour)},
	}
	s.beginSemanticConvergenceGrace(&model.Topology{Name: "scale"})
	if len(s.semanticCycles) != 0 || len(s.repairTerminal) != 0 ||
		len(s.repairFails) != 0 || len(s.repairNext) != 0 {
		t.Fatalf("new generation retained old repair state: cycles=%v terminal=%v fails=%v next=%v",
			s.semanticCycles, s.repairTerminal, s.repairFails, s.repairNext)
	}
}
