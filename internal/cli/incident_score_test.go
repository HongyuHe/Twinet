package cli

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/fault"
)

// A control episode is scored on the one question it asks.
//
// The three parts below detection are scored against what was injected, so on a
// healthy control -- where nothing was -- naming no devices, no category and no
// root cause is exactly right, and an agent that cried wolf collected 0.80 for
// it. The control exists to catch the strategy of always answering "yes"; it
// was rewarding it.
func TestAFalsePositiveOnAHealthyControlScoresNothing(t *testing.T) {
	cried := scoreDiagnosis(Diagnosis{IsAnomaly: true}, nil)
	if cried.Total != 0 {
		t.Errorf("an agent that reported a fault in a healthy network scored %.2f, and the "+
			"control exists to catch exactly that strategy", cried.Total)
	}
	if cried.Detail == "" {
		t.Error("the report does not say what it got wrong")
	}

	quiet := scoreDiagnosis(Diagnosis{IsAnomaly: false}, nil)
	if quiet.Total < 0.999 {
		t.Errorf("an agent that correctly saw a healthy network scored %.2f", quiet.Total)
	}
}

// And the other direction: saying a broken network is fine is not a diagnosis
// improved by declining to name anything.
func TestAMissedFaultScoresNothing(t *testing.T) {
	truth := []fault.GroundTruth{{
		IsAnomaly:     true,
		FaultyDevices: []string{"as3/NYC"},
		Category:      "misconfiguration",
		Names:         []string{"ospf_neighbor_missing"},
	}}
	missed := scoreDiagnosis(Diagnosis{IsAnomaly: false}, truth)
	if missed.Total != 0 {
		t.Errorf("an agent that said a broken network was fine scored %.2f", missed.Total)
	}
	right := scoreDiagnosis(Diagnosis{
		IsAnomaly:      true,
		FaultyDevices:  []string{"as3/NYC"},
		Category:       "misconfiguration",
		RootCauseNames: []string{"ospf_neighbor_missing"},
	}, truth)
	if right.Total < 0.999 {
		t.Errorf("a complete and correct diagnosis scored %.2f", right.Total)
	}
}
