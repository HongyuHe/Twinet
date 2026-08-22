package cli

import "testing"

func TestLogicalLinksNeverSubtractsManifestWorkFromZero(t *testing.T) {
	cases := []struct {
		endpoints, cross, want int
	}{
		{0, 33, 0},
		{1, 0, 1},
		{2, 2, 1},
		{3, 2, 2},
		{2, 33, 1},
	}
	for _, c := range cases {
		if got := logicalLinks(c.endpoints, c.cross); got != c.want {
			t.Errorf("logicalLinks(%d, %d) = %d, want %d", c.endpoints, c.cross, got, c.want)
		}
	}
}
