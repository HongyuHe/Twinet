package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/state"
)

// This is the failure this whole contract exists for, end to end and over the
// real wire format: a grading controller deploys a harness, heartbeats it for
// a while, and is then killed. Nothing tidies up after it. The node must
// notice on its own, take the lab away from its own repair loop, and return
// the containers, overlays, reservations and records to the cluster -- while a
// teaching lab beside it is untouched and remains deployable throughout.
func TestAKilledGradingControllerDoesNotLeaveAHarnessForever(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)

	destroyed := map[string]bool{}
	server.ephemeralDestroy = func(_ context.Context, lab string) error {
		destroyed[lab] = true
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/ephemeral", server.handleEphemeral)
	api := httptest.NewServer(mux)
	t.Cleanup(api.Close)

	heartbeat := func(lab string) (EphemeralResponse, int) {
		t.Helper()
		body, err := json.Marshal(EphemeralRequest{
			Lab: lab, Owner: "grade-batch@grader/4242", TTLSeconds: 600,
		})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.Post(api.URL+"/v1/ephemeral", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out EphemeralResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out, resp.StatusCode
	}

	// A class lab, deployed by a course and owned by nobody's process.
	server.mu.Lock()
	server.current["cos461"] = &model.Topology{Name: "cos461"}
	server.generations["cos461"] = generationState{Committed: "class-generation"}
	server.mu.Unlock()

	// The harness, deployed by a controller that says it is disposable. The
	// commit path is what records this in production; here it is the same
	// call the commit path makes.
	if err := server.noteEphemeralLease("harness-as3", "grade-batch@grader/4242", 600,
		"grade-generation"); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	server.current["harness-as3"] = &model.Topology{
		Name: "harness-as3", Ephemeral: true, EphemeralTTLSeconds: 600,
	}
	server.overlayClaims[9001] = overlayClaim{Lab: "harness-as3", Generation: 1, Live: true}
	if err := server.saveCoordinationLocked(); err != nil {
		server.mu.Unlock()
		t.Fatal(err)
	}
	server.mu.Unlock()

	// The controller is alive and marking submissions.
	for range 5 {
		now = now.Add(3 * time.Minute)
		if resp, code := heartbeat("harness-as3"); code != http.StatusOK || !resp.Ephemeral {
			t.Fatalf("a live controller's heartbeat was refused: status=%d resp=%+v", code, resp)
		}
		if summary := server.reapExpiredEphemeralLabs(context.Background()); len(summary.Reclaimed) > 0 {
			t.Fatalf("a live controller's harness was reclaimed: %+v", summary)
		}
	}

	// The repair loop picks the harness up, exactly as it does in production
	// once a device drifts. This lease is what answered `twinet destroy` with
	// a conflict for as long as the harness existed.
	repairCtx, cancelRepair := context.WithCancel(context.Background())
	opID, opDone, err := server.acquireOperation("harness-as3", "reconcile", cancelRepair)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-repairCtx.Done()
		server.releaseOperation("harness-as3", opID, opDone)
	}()

	// The controller is killed. No further heartbeat is ever sent.
	now = now.Add(11 * time.Minute)

	summary := server.reapExpiredEphemeralLabs(context.Background())
	if len(summary.Reclaimed) != 1 || summary.Reclaimed[0] != "harness-as3" {
		t.Fatalf("the abandoned harness was not reclaimed: %+v", summary)
	}
	if !destroyed["harness-as3"] {
		t.Fatal("the harness's containers and overlays were never removed")
	}
	if destroyed["cos461"] {
		t.Fatal("the class lab was destroyed")
	}

	server.mu.Lock()
	_, harnessCurrent := server.current["harness-as3"]
	_, classCurrent := server.current["cos461"]
	_, harnessLeased := server.ephemeral["harness-as3"]
	_, harnessGeneration := server.generations["harness-as3"]
	classGeneration := server.generations["cos461"]
	_, reservationHeld := server.overlayClaims[9001]
	server.mu.Unlock()

	if harnessCurrent || harnessLeased || harnessGeneration {
		t.Fatal("the reclaimed harness is still recorded on the node")
	}
	if reservationHeld {
		t.Fatal("the reclaimed harness kept its overlay reservation, so its identifier stays allocated")
	}
	if !classCurrent || classGeneration.Committed != "class-generation" {
		t.Fatal("reclaiming a harness disturbed the class lab beside it")
	}

	// The class lab is deployable immediately: nothing node-wide was taken.
	if _, _, err := server.acquireOperation("cos461", "apply", nil); err != nil {
		t.Fatalf("the class lab could not be deployed after reclamation: %v", err)
	}

	// A heartbeat from a controller that somehow returns is refused rather
	// than resurrecting the lab.
	if _, code := heartbeat("harness-as3"); code == http.StatusOK {
		t.Fatal("a returning controller resurrected a reclaimed harness")
	}

	// Nothing the node persisted brings it back after a restart either.
	reopened, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted := ephemeralTestServer(t, reopened, &now)
	restarted.loadCoordination()
	restarted.rehydrate()
	restarted.mu.Lock()
	_, resurrected := restarted.current["harness-as3"]
	restarted.mu.Unlock()
	if resurrected {
		t.Fatal("a reclaimed harness came back when the agent restarted")
	}
}
