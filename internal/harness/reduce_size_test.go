package harness

import "testing"

// Breadth and depth were the same setting, so the only way to make a harness
// smaller was to cut autonomous systems off it -- and a rubric that checks a
// session with a particular peer then fails a correct submission. Reduction
// keeps every system and shrinks each neighbour to the part of it the target
// can see.
func TestReducingKeepsEveryASAndFewDevices(t *testing.T) {
	top := classTopology(t)
	full, err := Slice(top, 3, Options{})
	if err != nil {
		t.Fatal(err)
	}
	small, err := Slice(top, 3, Options{Reduce: true, KeepHosts: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(small.ASes) != len(full.ASes) {
		t.Errorf("reducing dropped %d autonomous system(s); a rubric that checks a "+
			"session with a particular peer would fail a correct submission",
			len(full.ASes)-len(small.ASes))
	}
	if len(small.Devices) >= len(full.Devices) {
		t.Errorf("reducing did not make the harness smaller: %d devices against %d",
			len(small.Devices), len(full.Devices))
	}
	// The target is what is being marked, so it is kept whole.
	if a, b := len(small.ASes[3].Devices), len(top.ASes[3].Devices); a != b {
		t.Errorf("the system under test lost devices: %d of %d", a, b)
	}
	t.Logf("full harness %d devices / %d links; reduced %d devices / %d links",
		len(full.Devices), len(full.Links), len(small.Devices), len(small.Links))
}
