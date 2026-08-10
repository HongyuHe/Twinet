package harness

import "testing"

func TestHarnessSizesAreReported(t *testing.T) {
	full := classTopology(t)
	for _, d := range []int{0, 1, 2} {
		for _, kh := range []bool{false, true} {
			h, err := Slice(full, 3, Options{Depth: d, KeepHosts: kh})
			if err != nil {
				t.Fatal(err)
			}
			s := h.Stats()
			t.Logf("depth=%d hosts=%v -> %d devices, %d links, ASes %v",
				d, kh, s.Devices, s.Links, h.SortedASNs())
		}
	}
}
