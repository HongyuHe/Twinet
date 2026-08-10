package deploy

import (
	"strings"
	"testing"
)

func TestCleanRunningConfigStripsVtyshPreamble(t *testing.T) {
	// vtysh prints a banner before the configuration and then refuses to read
	// it back. Capturing it means every restore fails on its first line, and
	// the failure only surfaces later, when a container is replaced and a
	// class's work is due to be replayed into it.
	raw := "Building configuration...\n\nCurrent configuration:\n!\nfrr version 10.0\n!\nrouter bgp 3\n exit\n!\n"
	got := cleanRunningConfig(raw)
	for _, bad := range []string{"Building configuration", "Current configuration"} {
		if strings.Contains(got, bad) {
			t.Errorf("captured configuration still contains %q:\n%s", bad, got)
		}
	}
	if !strings.HasPrefix(got, "!") && !strings.HasPrefix(got, "frr version") {
		t.Errorf("configuration does not start at the first real line:\n%q", got)
	}
	if !strings.Contains(got, "router bgp 3") {
		t.Errorf("configuration body was lost:\n%q", got)
	}
	// A configuration with no preamble must survive untouched.
	plain := "frr version 10.0\nrouter bgp 3\n exit"
	if cleanRunningConfig(plain) != plain {
		t.Errorf("a clean configuration was altered: %q", cleanRunningConfig(plain))
	}
}
