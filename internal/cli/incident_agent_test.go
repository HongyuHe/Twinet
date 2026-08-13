package cli

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/fault"
)

// A benchmark needs one definition of a right answer. Without a scorer here,
// every evaluation had to be driven from outside and compared against the truth
// in its own way, and two harnesses scoring the same episode differently is not
// a benchmark.
func TestTheScorerRewardsTheDiagnosisAndNotTheGuess(t *testing.T) {
	truth := []fault.GroundTruth{{
		IsAnomaly:     true,
		FaultyDevices: []string{"as3/BOS"},
		Category:      "network_under_attack",
		Names:         []string{"dhcp_spoofed_gateway"},
	}}

	cases := []struct {
		name string
		d    Diagnosis
		want func(Score) bool
		says string
	}{
		{
			name: "exactly right",
			d: Diagnosis{IsAnomaly: true, FaultyDevices: []string{"as3/BOS"},
				Category: "network_under_attack", RootCauseNames: []string{"dhcp_spoofed_gateway"}},
			want: func(s Score) bool { return s.Total == 1 },
			says: "a complete, correct diagnosis must score full marks",
		},
		{
			name: "right device, wrong cause",
			d: Diagnosis{IsAnomaly: true, FaultyDevices: []string{"as3/BOS"},
				Category: "misconfiguration", RootCauseNames: []string{"dhcp_missing_subnet"}},
			want: func(s Score) bool { return s.Total > 0.4 && s.Total < 0.7 && !s.RootCause },
			says: "naming the right device for the wrong reason is half an answer",
		},
		{
			name: "every device in the lab",
			d: Diagnosis{IsAnomaly: true, Category: "network_under_attack",
				FaultyDevices:  []string{"as3/BOS", "as3/ATL", "as3/CHI", "as3/NYC", "as4/BOS"},
				RootCauseNames: []string{"dhcp_spoofed_gateway"}},
			want: func(s Score) bool { return s.Devices < 0.3 },
			says: "answering \"one of these\" is not a diagnosis and must not score like one",
		},
		{
			name: "every root cause in the taxonomy",
			d: Diagnosis{IsAnomaly: true, FaultyDevices: []string{"as3/BOS"},
				Category: "network_under_attack",
				RootCauseNames: []string{"dhcp_spoofed_gateway", "dhcp_spoofed_dns",
					"dhcp_service_down", "link_down"}},
			want: func(s Score) bool { return !s.RootCause },
			says: "listing every type contains the right one and diagnoses nothing",
		},
		{
			name: "nothing is wrong",
			d:    Diagnosis{IsAnomaly: false},
			want: func(s Score) bool { return !s.Detected && s.Total < 0.35 },
			says: "missing the fault entirely must score close to nothing",
		},
	}
	for _, c := range cases {
		got := scoreDiagnosis(c.d, truth)
		if !c.want(got) {
			t.Errorf("%s: scored %+v; %s", c.name, got, c.says)
		}
	}

	// And an episode with no fault: an agent that cries wolf must lose the
	// detection mark, or "something is broken" is free.
	quiet := []fault.GroundTruth{{IsAnomaly: false}}
	if s := scoreDiagnosis(Diagnosis{IsAnomaly: true, FaultyDevices: []string{"as3/BOS"}}, quiet); s.Detected {
		t.Error("an agent that reported a fault in a healthy network was marked as having detected one")
	}
	if s := scoreDiagnosis(Diagnosis{IsAnomaly: false}, quiet); !s.Detected || s.Total < 0.9 {
		t.Errorf("an agent that correctly reported a healthy network scored %+v", s)
	}
}
