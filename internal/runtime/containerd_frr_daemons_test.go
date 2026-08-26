package runtime

import (
	"strings"
	"testing"
)

func daemonNames(daemons []frrDaemon) []string {
	out := make([]string, 0, len(daemons))
	for _, daemon := range daemons {
		out = append(out, daemon.name)
	}
	return out
}

func has(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}

// TestFRRInfrastructureDaemonsStartWhateverTheFileSays pins the rule this
// backend has to share with FRR's own init script, which forces zebra, mgmtd
// and staticd on regardless of /etc/frr/daemons.
//
// Starting only what the file enables left mgmtd out. mgmtd owns interface
// configuration from FRR 9.1 on, so every `interface X` / `ip address A/B` in a
// router's configuration was refused with "mgmtd is not running" while the
// daemons vtysh could reach accepted the rest. The router ran a full daemon
// set, answered on every vty, held the right OSPF and BGP configuration, and
// had no address on any interface.
func TestFRRInfrastructureDaemonsStartWhateverTheFileSays(t *testing.T) {
	profile, daemons := parseFRRDaemonsFile(`zebra=yes
bgpd=yes
ospfd=yes
ripd=no
zebra_options="  -A 127.0.0.1 -s 90000000"
frr_profile="traditional"
`)
	if profile != "traditional" {
		t.Fatalf("profile = %q", profile)
	}
	names := daemonNames(daemons)
	for _, want := range []string{"zebra", "mgmtd", "staticd"} {
		if !has(names, want) {
			t.Fatalf("%s was not started for a file that does not mention it: %v", want, names)
		}
	}
	if has(names, "ripd") {
		t.Fatalf("a disabled routing daemon was started: %v", names)
	}

	// Naming them off does not turn them off either: FRR would start them, and
	// a supervisor that did not would differ from every other backend.
	_, daemons = parseFRRDaemonsFile("zebra=no\nmgmtd=no\nstaticd=no\nbgpd=yes\n")
	names = daemonNames(daemons)
	for _, want := range []string{"zebra", "mgmtd", "staticd"} {
		if !has(names, want) {
			t.Fatalf("%s stayed down after being disabled by hand: %v", want, names)
		}
	}
}

func TestFRRDaemonOptionsAndOrderFollowTheFile(t *testing.T) {
	_, daemons := parseFRRDaemonsFile(`zebra=yes
bgpd=yes
ospfd=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
mgmtd_options="  -A 127.0.0.1"
bgpd_options="   -A 127.0.0.1 -M rpki"
`)
	names := daemonNames(daemons)
	if len(names) < 2 || names[0] != "zebra" || names[1] != "mgmtd" {
		t.Fatalf("FRR's start order is zebra then mgmtd, got %v", names)
	}
	for _, daemon := range daemons {
		switch daemon.name {
		case "zebra":
			if strings.Join(daemon.options, " ") != "-A 127.0.0.1 -s 90000000" {
				t.Fatalf("zebra options = %v", daemon.options)
			}
		case "mgmtd":
			if strings.Join(daemon.options, " ") != "-A 127.0.0.1" {
				t.Fatalf("mgmtd options = %v", daemon.options)
			}
		}
	}
}

// TestConfigurationDaemonsStartBeforeTheProtocols keeps the sequencing that
// makes the first pass of the integrated configuration land: a protocol daemon
// registers with mgmtd and zebra as it comes up.
func TestConfigurationDaemonsStartBeforeTheProtocols(t *testing.T) {
	script := frrStarterScript("traditional", []frrDaemon{
		{name: "zebra"}, {name: "mgmtd"}, {name: "staticd"},
		{name: "bgpd"}, {name: "ospfd"},
	})
	positions := map[string]int{}
	for _, daemon := range []string{"zebra", "mgmtd", "staticd", "bgpd", "ospfd"} {
		index := strings.Index(script, "/usr/lib/frr/"+daemon)
		if index < 0 {
			t.Fatalf("%s is never started:\n%s", daemon, script)
		}
		positions[daemon] = index
	}
	if positions["mgmtd"] > positions["bgpd"] || positions["staticd"] > positions["ospfd"] {
		t.Fatalf("a protocol daemon starts before FRR's configuration plane:\n%s", script)
	}
	for _, line := range strings.Split(script, "\n") {
		for _, sequential := range []string{"zebra", "mgmtd", "staticd"} {
			if strings.Contains(line, "/usr/lib/frr/"+sequential) && strings.HasSuffix(line, "&") {
				t.Fatalf("%s is started in the background:\n%s", sequential, script)
			}
		}
	}
	if !strings.Contains(script, "/usr/lib/frr/bgpd' '-F' 'traditional' '-d' &") {
		t.Fatalf("routing daemons are no longer started in parallel:\n%s", script)
	}
}
