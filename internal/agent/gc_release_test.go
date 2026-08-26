package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/netx"
	"github.com/HongyuHe/twinet/internal/state"
)

func TestCollectionReleasesAnIdentifierBeforeItStopsFencingIt(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := gcFenceServer(&now)
	server.gcFindOrphans = func(map[string]bool) ([]netx.Orphan, error) {
		return []netx.Orphan{{VNI: 4242, Owner: "abandoned"}}, nil
	}

	// A deployment that is blocked on the agent lock for the whole
	// destructive step is admitted the instant the fence is dropped. If the
	// collector releases ownership after that, it deletes the reservation
	// this deployment legitimately won.
	reserved := make(chan error, 1)
	server.gcRemoveOverlay = func(uint32) error {
		go func() {
			lease, err := server.acquireMutationLease(LeaseAcquireRequest{
				Lab: "arriving", TTLSeconds: 600,
			})
			if err != nil {
				reserved <- err
				return
			}
			for range 200 {
				_, reserveErr := server.reserveOverlays(OverlayReservationRequest{
					Lab: "arriving", Fence: lease.Fence, VNIs: []uint32{4242},
				})
				if reserveErr == nil {
					reserved <- nil
					return
				}
				time.Sleep(time.Millisecond)
			}
			reserved <- context.DeadlineExceeded
		}()
		time.Sleep(20 * time.Millisecond)
		return nil
	}
	if _, err := server.gcOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err := server.gcOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-reserved:
		if err != nil {
			t.Fatalf("the deployment never obtained the released identifier: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the racing deployment neither succeeded nor failed")
	}

	server.mu.Lock()
	claim, held := server.overlayClaims[4242]
	server.mu.Unlock()
	if !held {
		t.Fatal("the collector deleted a reservation a deployment had just been granted")
	}
	if claim.Lab != "arriving" {
		t.Fatalf("VNI 4242 is claimed by %q, not the deployment that reserved it", claim.Lab)
	}
}

func TestCollectionNeverReleasesAnotherLabsOwnership(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := gcFenceServer(&now)
	server.overlayClaims[4242] = overlayClaim{Lab: "someone-else", Generation: 7, Live: true}
	server.endOverlayCollection(4242, "abandoned")
	server.mu.Lock()
	claim, held := server.overlayClaims[4242]
	server.mu.Unlock()
	if !held || claim.Lab != "someone-else" {
		t.Fatal("a collection released ownership belonging to a different lab")
	}
}

func TestReclamationEventsAreFiledUnderTheirOwnScope(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)
	deployEphemeral(t, server, "harness", "grade-batch@host/1", 600)

	now = now.Add(20 * time.Minute)
	if summary := server.reapExpiredEphemeralLabs(context.Background()); len(summary.Reclaimed) != 1 {
		t.Fatalf("the harness was not reclaimed: %+v", summary)
	}
	events, _ := server.eventLog().after(0, "harness", 100)
	scoped := 0
	for _, event := range events {
		if event.Scope == "ephemeral" {
			scoped++
		}
		if event.Scope == "other" {
			t.Fatalf("a reclamation event lost its scope and is unfilterable: %+v", event)
		}
	}
	if scoped == 0 {
		t.Fatal("the only record of an autonomous lab removal has no scope of its own")
	}
}

func TestAnUpgradedAgentKeepsTheHistoryFromBeforeTheUpgrade(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// What an agent that predates the append log left on disk.
	legacy := []Event{
		{Sequence: 1, Node: "node-0", Scope: "deploy", Action: "before-upgrade-1"},
		{Sequence: 2, Node: "node-0", Scope: "deploy", Action: "before-upgrade-2"},
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutEventJournal(raw); err != nil {
		t.Fatal(err)
	}

	upgraded := &Server{cfg: Config{Node: "node-0", EventCapacity: 64}, store: store}
	upgraded.recordEvent("", "", "deploy", "", "after-upgrade", "success", "")

	// The restart that used to lose everything written before the upgrade.
	reopened, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Server{cfg: Config{Node: "node-0", EventCapacity: 64}, store: reopened}
	events, _ := restarted.eventLog().after(0, "", 100)
	actions := map[string]bool{}
	for _, event := range events {
		actions[event.Action] = true
	}
	for _, want := range []string{"before-upgrade-1", "before-upgrade-2", "after-upgrade"} {
		if !actions[want] {
			t.Fatalf("event %q did not survive the upgrade restart: %v", want, actions)
		}
	}

	// A second restart must be identical, which it only is once the legacy
	// file has actually been folded into the log rather than shadowed by it.
	again, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	third := &Server{cfg: Config{Node: "node-0", EventCapacity: 64}, store: again}
	events, _ = third.eventLog().after(0, "", 100)
	if len(events) != len(actions) {
		t.Fatalf("a second restart changed the retained history: %d events, want %d",
			len(events), len(actions))
	}
	if _, err := again.EventJournal(); err == nil {
		t.Fatal("the superseded array-form journal is still on disk and will be read again")
	}
}
