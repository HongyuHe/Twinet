package runtime

import "testing"

// Manifests are written in Kubernetes style; Docker rejects those suffixes.
// Getting this wrong fails every container creation, so it is worth pinning.
func TestParseMemory(t *testing.T) {
	cases := map[string]int64{
		"512Mi":    512 << 20,
		"512M":     512 << 20,
		"2Gi":      2 << 30,
		"2G":       2 << 30,
		"1024m":    1024 << 20,
		"64MiB":    64 << 20,
		"10485760": 10485760,
	}
	for in, want := range cases {
		got, err := ParseMemory(in)
		if err != nil {
			t.Errorf("ParseMemory(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseMemory(%q) = %d, want %d", in, got, want)
		}
	}
	for _, bad := range []string{"512Xi", "lots", "1Mi", "-5Gi"} {
		if _, err := ParseMemory(bad); err == nil {
			t.Errorf("ParseMemory(%q) should have failed", bad)
		}
	}
	if v, err := ParseMemory(""); err != nil || v != 0 {
		t.Errorf("empty memory should be unset, got %d, %v", v, err)
	}
}
