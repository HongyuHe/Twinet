package agent

import (
	"encoding/json"
	"testing"
)

func TestRecoveredUntouchedSemanticDriftIsPersistedForCommit(t *testing.T) {
	tx := applyTransaction{
		Generation: "recovery-forward",
		Semantic:   []string{"as5/MSP_host"},
		// The host was not recreated or capture-dirty in the latest
		// transaction; its address drift predates the transaction.
		Touched:      nil,
		DirtyCapture: nil,
	}
	raw, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var after applyTransaction
	if err := json.Unmarshal(raw, &after); err != nil {
		t.Fatal(err)
	}
	ids := semanticTouchedDevices(after)
	if len(ids) != 1 || ids[0] != "as5/MSP_host" {
		t.Fatalf("recovered untouched semantic drift was dropped: %+v", after)
	}
}
