package deploy

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestSolveToPlatformResetSkipsPreviouslyUngradedHarnessAS(t *testing.T) {
	engine := &Engine{
		ForceStudentReset: true,
		PreviousMode:      "solve",
		PreviousUngraded:  7,
	}
	ungraded := &model.Device{ASN: 7}
	reference := &model.Device{ASN: 8}
	if engine.shouldForceStudentReset(ungraded) {
		t.Fatal("solve->platform reset would erase the previously ungraded harness AS")
	}
	if !engine.shouldForceStudentReset(reference) {
		t.Fatal("solve->platform reset did not clear a previous reference AS")
	}
}
