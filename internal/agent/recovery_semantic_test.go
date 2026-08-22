package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/state"
)

func TestCompletedRecoveryClearsRepairRetryState(t *testing.T) {
	server, _ := recoveryServer(t, nil)
	key := repairKey("cos461", "as1/R1")
	server.repairFails = map[string]int{key: repairAttemptsBeforeGivingUp}
	server.repairNext = map[string]time.Time{key: time.Now().Add(time.Hour)}
	server.partial = map[string]int{key: partialWiringGrace}
	server.recoveryRollback = func(context.Context, string, Fence, applyTransaction) error { return nil }
	lease, err := server.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}

	{
		store, err := state.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(&Wire{Lab: "lab", Mode: "platform"})
		if err != nil {
			t.Fatal(err)
		}
		server := &Server{store: store, rt: emptyStateRuntime{}}
		err = server.verifyRecoveredStudentState(context.Background(), applyTransaction{
			Previous: wire,
			Prestate: transactionInventory{Snapshots: []transactionSnapshot{{
				Device: "as5/MSP_host", Kind: string(state.KindAddrs), Digest: "missing",
			}}},
		})
		if err == nil || !strings.Contains(err.Error(), "is missing") {
			t.Fatalf("recovery accepted missing captured snapshot: %v", err)
		}
	}
	if _, err := server.recoverTransaction(context.Background(), "cos461", lease.Fence); err != nil {
		t.Fatal(err)
	}
	if len(server.repairFails) != 0 || len(server.repairNext) != 0 || len(server.partial) != 0 {
		t.Fatalf("recovery completed but stale repair state remained: fails=%v next=%v partial=%v",
			server.repairFails, server.repairNext, server.partial)
	}
}
