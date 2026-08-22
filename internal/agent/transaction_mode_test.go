package agent

import (
	"encoding/json"
	"testing"

	"github.com/HongyuHe/twinet/internal/render"
	"github.com/HongyuHe/twinet/internal/state"
)

func TestPreparedTransactionPersistsPlatformSolveModeTransition(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := coordinationTestServer(t, store)
	server.rememberHow("lab", string(render.ModePlatform), 0)
	previous, err := json.Marshal(&Wire{Lab: "lab", Mode: string(render.ModePlatform)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutTopology("lab", previous); err != nil {
		t.Fatal(err)
	}
	lease, err := server.acquireMutationLease(LeaseAcquireRequest{Lab: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	requested, _ := json.Marshal(&Wire{Lab: "lab"})
	if err := server.prepareGeneration("lab", lease.Fence, "", "solve-generation",
		requested, string(render.ModeSolve), 0, nil, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := server.saveCoordinationLocked(); err != nil {
		t.Fatal(err)
	}
	restarted := coordinationTestServer(t, store)
	restarted.loadCoordination()
	tx := restarted.transactions["lab"]
	if tx.Mode != string(render.ModeSolve) || tx.PreviousMode != string(render.ModePlatform) {
		t.Fatalf("platform->solve mode contract lost across restart: %+v", tx)
	}
}

func TestPreparedTransactionPersistsHarnessSolveToPlatformTransition(t *testing.T) {
	server := coordinationTestServer(t, nil)
	server.rememberHow("lab", string(render.ModeSolve), 7)
	lease, err := server.acquireMutationLease(LeaseAcquireRequest{Lab: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(&Wire{Lab: "lab"})
	if err := server.prepareGeneration("lab", lease.Fence, "", "platform-generation",
		raw, string(render.ModePlatform), 0, nil, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	tx := server.transactions["lab"]
	if tx.Mode != string(render.ModePlatform) || tx.PreviousMode != string(render.ModeSolve) ||
		tx.PreviousUngraded != 7 {
		t.Fatalf("solve harness->platform contract lost: %+v", tx)
	}
}
