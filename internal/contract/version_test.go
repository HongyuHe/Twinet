package contract

import "testing"

func TestCompatibleRangesPermitRollingRevision(t *testing.T) {
	before := Range{Current: "1.0.0", MinCompatible: "1.0.0", MaxCompatible: "1.1.0"}
	after := Range{Current: "1.1.0", MinCompatible: "1.0.0", MaxCompatible: "1.1.0"}
	ok, err := before.Compatible(after)
	if err != nil || !ok {
		t.Fatalf("compatible rolling ranges = (%t, %v)", ok, err)
	}
}

func TestIncompatibleRangesAreRejected(t *testing.T) {
	before := Range{Current: "1.0.0", MinCompatible: "1.0.0", MaxCompatible: "1.0.0"}
	after := Range{Current: "2.0.0", MinCompatible: "2.0.0", MaxCompatible: "2.0.0"}
	ok, err := before.Compatible(after)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("disjoint renderer contracts were considered compatible")
	}
}
