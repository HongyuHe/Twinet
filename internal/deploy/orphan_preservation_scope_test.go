package deploy

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/state"
)

// What a preservation record is asked to prove, and what it is not.
//
// A prune that carries one is finishing a transition somebody else started,
// and the reason it may not simply read its candidates is that the transition
// wrote something into them -- the reference solution -- that is nobody's
// work. That is true of the containers the transition touched and false of the
// ones it never came near, and a rollback of a failed solve meets both in the
// same pass. So a record names the containers it wrote to, and the prune
// demands proof for exactly those: a candidate it may still read is read, a
// moment before it is removed, through the same guarded funnel as always.

// A prune carrying a record still reads what the record does not claim to have
// touched. Demanding proof for those too would strand every container a
// transition never went near.
func TestAPruneCarryingARecordStillReadsWhatTheRecordDidNotTouch(t *testing.T) {
	engine, top, runtime, store := orphanLab(t)
	orphan := orphanStandIn()
	orphanHolding(runtime, map[string][]string{"port_BOS": {"3.0.8.1/24"}})
	engine.PreservedOrphans = &OrphanPreservationSet{}

	removed, err := engine.PruneOrphans(context.Background(), top)
	if err != nil {
		t.Fatalf("a prune refused to remove a container it was allowed to read: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("a readable candidate was left behind: %v", removed)
	}
	facts := savedFacts(t, store, top.Name, orphan, state.KindAddrs)
	if !hasFact(facts, "addr inet port_BOS 3.0.8.1/24") {
		t.Fatalf("a prune carrying a record stopped saving what it read: %v", facts)
	}
}

// A container the transition wrote to is not read, and is not removed on the
// strength of nothing.
func TestAPruneNeitherReadsNorRemovesAContainerTheTransitionWroteTo(t *testing.T) {
	engine, top, runtime, store := orphanLab(t)
	orphan := orphanStandIn()
	orphanHolding(runtime, map[string][]string{"port_BOS": {"3.0.8.1/24"}})
	engine.PreservedOrphans = &OrphanPreservationSet{Unreadable: []string{"tw-atl"}}

	removed, err := engine.PruneOrphans(context.Background(), top)
	if err == nil {
		t.Fatal("a container holding the reference answer was removed on no evidence at all")
	}
	if len(removed) != 0 || len(runtime.removed) != 0 {
		t.Fatalf("the refusal came after %v / %v had been removed", removed, runtime.removed)
	}
	if !strings.Contains(err.Error(), "tw-atl") {
		t.Fatalf("the refusal does not name the container: %v", err)
	}
	if _, err := store.Current(top.Name, orphan.ID, state.KindFRR); err == nil {
		t.Fatal("a pass that may not read a container filed what was in it anyway")
	}
}

// The two ways a transition can entitle a removal: it preserved the container
// before it wrote anything, or it proved the container holds nothing that
// predates it.
func TestATransitionEntitlesARemovalByPreservationOrByProvenance(t *testing.T) {
	t.Run("proven to hold nothing that predates the transition", func(t *testing.T) {
		engine, top, runtime, store := orphanLab(t)
		orphan := orphanStandIn()
		orphanHolding(runtime, map[string][]string{"port_BOS": {"3.0.8.1/24"}})
		engine.PreservedOrphans = &OrphanPreservationSet{
			Unreadable: []string{"tw-atl"}, Removable: []string{"tw-atl"},
		}

		removed, err := engine.PruneOrphans(context.Background(), top)
		if err != nil {
			t.Fatalf("a prune refused to remove a container the transition created: %v", err)
		}
		if len(removed) != 1 {
			t.Fatalf("a container the transition created was left behind: %v", removed)
		}
		if _, err := store.Current(top.Name, orphan.ID, state.KindFRR); err == nil {
			t.Fatal("a container the transition wrote to was filed as a student's work")
		}
	})

	t.Run("preserved before the transition wrote anything", func(t *testing.T) {
		engine, top, runtime, store := orphanLab(t)
		orphan := orphanStandIn()
		orphanHolding(runtime, map[string][]string{"port_BOS": {"3.0.8.1/24"}})
		engine.PreservedOrphans = &OrphanPreservationSet{
			Unreadable: []string{"tw-atl"},
			Preserved:  []OrphanPreservation{{Container: "tw-atl", Device: "as3/ATL", Stored: true}},
		}

		removed, err := engine.PruneOrphans(context.Background(), top)
		if err != nil {
			t.Fatalf("a prune refused to remove what the transition preserved: %v", err)
		}
		if len(removed) != 1 {
			t.Fatalf("a preserved container was left behind: %v", removed)
		}
		if _, err := store.Current(top.Name, orphan.ID, state.KindFRR); err == nil {
			t.Fatal("a container that was already preserved was read again and refiled")
		}
	})
}

// A deployment that installs the reference solution reads nothing at all, so
// every candidate in front of it needs the record. This is the single-node
// resume path, and it must not have loosened.
func TestAReferenceWritingPruneStillDemandsProofForEveryCandidate(t *testing.T) {
	engine, top, runtime, store := orphanLab(t)
	orphanHolding(runtime, map[string][]string{"port_BOS": {"3.0.8.1/24"}})
	engine.WritesReference = true
	engine.PreservedOrphans = &OrphanPreservationSet{}

	if _, err := engine.PruneOrphans(context.Background(), top); err == nil {
		t.Fatal("a deployment writing the reference solution removed a container nothing " +
			"had preserved")
	}
	if len(runtime.removed) != 0 {
		t.Fatalf("the refusal came after %v had been removed", runtime.removed)
	}
	if _, err := store.Current(top.Name, orphanStandIn().ID, state.KindFRR); err == nil {
		t.Fatal("a deployment writing the reference solution read a container anyway")
	}

	engine.PreservedOrphans = &OrphanPreservationSet{
		Preserved: []OrphanPreservation{{Container: "tw-atl", Device: "as3/ATL", Stored: true}},
	}
	removed, err := engine.PruneOrphans(context.Background(), top)
	if err != nil {
		t.Fatalf("a solve refused to remove what it had preserved: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("a solve removed %v, want the container its record covers", removed)
	}
}
