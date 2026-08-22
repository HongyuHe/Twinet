package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/HongyuHe/twinet/internal/render"
	"github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

func TestPreparedTransactionPersistsExactRollbackContract(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := coordinationTestServer(t, st)
	s.rememberHow("cos461", string(render.ModeSolve), 7)
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(&Wire{Lab: "cos461", Mode: string(render.ModePlatform)})
	prestate := transactionInventory{
		StateSafe: true,
		RuntimeSpecs: []transactionRuntimeSpec{{
			DeviceID: "svc/dns",
			Spec: runtime.Spec{
				Name: "twinet-cos461-svc-dns", Image: "svc:old",
				ReadOnlyRootfs: true,
				Tmpfs:          map[string]string{"/etc/bind": "rw,nosuid,nodev"},
				SecurityOpt:    []string{"no-new-privileges", "seccomp=old"},
			},
			Artifacts: []transactionArtifact{{
				Path: "/etc/bind/named.conf", Content: []byte("zone old {}"), Mode: 0o640,
				Digest: artifactDigest([]byte("zone old {}")),
			}},
		}},
	}
	if err := s.prepareGeneration("cos461", lease.Fence, "", "new-generation",
		raw, "platform", 0, nil, false, nil, nil, prestate); err != nil {
		t.Fatal(err)
	}
	after := coordinationTestServer(t, st)
	after.loadCoordination()
	got := after.transactions["cos461"].Prestate.RuntimeSpecs
	if len(got) != 1 || got[0].Spec.Tmpfs["/etc/bind"] == "" ||
		string(got[0].Artifacts[0].Content) != "zone old {}" {
		t.Fatalf("rollback contract did not survive restart: %+v", got)
	}
	tx := after.transactions["cos461"]
	if tx.PreviousMode != string(render.ModeSolve) || tx.PreviousUngraded != 7 {
		t.Fatalf("previous recovery mode was not persisted: %+v", tx)
	}
}

func TestForwardRecoveryRequiresExplicitStrategy(t *testing.T) {
	s, _ := recoveryServer(t, nil)
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.recoverTransactionStrategy(context.Background(), "cos461", lease.Fence, "unknown"); err == nil {
		t.Fatal("unknown recovery strategy was accepted")
	}
}
