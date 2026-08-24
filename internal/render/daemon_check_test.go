package render

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// frrinit.sh reports success whether or not the daemons come up. So a router
// could be deployed with no routing process at all while every device reported
// healthy and the lab reported zero failures.
//
// It is not theoretical. Two routers out of 212 were found in exactly that
// state in a class-scale lab, and the only symptom was a grading run timing out
// four hops away with "1 of 62 sessions not established" — a message that points
// at the autonomous system being graded rather than at the neighbour that had no
// bgpd. Nobody would find that by reading configuration, because every
// configuration involved was correct.
//
// The script is extracted from the rendered plan and actually run here, against
// a stub pidof, because a test that merely looked for the string would pass
// against a script that does nothing.
func TestARouterWithNoRoutingDaemonFailsItsDeployment(t *testing.T) {
	script := daemonCheckScript(t)

	cases := []struct {
		what    string
		pidof   string
		wantErr bool
	}{
		{
			what:    "both daemons are running",
			pidof:   "exit 0",
			wantErr: false,
		},
		{
			// Nothing running and starting them does not help: the stub
			// frrinit.sh below is absent, so the start fails.
			what:    "nothing is running and it cannot be started",
			pidof:   "exit 1",
			wantErr: true,
		},
		{
			what:    "zebra is up but bgpd is not",
			pidof:   `case "$1" in zebra) exit 0;; *) exit 1;; esac`,
			wantErr: true,
		},
		{
			// The check used to look for zebra and bgpd only, so this router
			// passed its deployment. OSPF would then never converge, iBGP
			// would never come up because the loopbacks were unreachable, and
			// the report said every device was healthy.
			what:    "everything is up except ospfd",
			pidof:   `case "$1" in ospfd) exit 1;; *) exit 0;; esac`,
			wantErr: true,
		},
		{
			what:    "ldpd is absent from a non-MPLS AS",
			pidof:   `case "$1" in ldpd) exit 1;; *) exit 0;; esac`,
			wantErr: false,
		},
	}

	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			dir := t.TempDir()
			stub := filepath.Join(dir, "pidof")
			if err := os.WriteFile(stub, []byte("#!/bin/sh\n"+c.pidof+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			// A stub ps, so the watchfrr sweep does not read the real
			// process table of the machine running the test.
			if err := os.WriteFile(filepath.Join(dir, "ps"),
				[]byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", "-c", script)
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
			err := cmd.Run()

			switch {
			case c.wantErr && err == nil:
				t.Errorf("the deployment succeeded when %s.\n"+
					"A router with no routing process has every session with it sitting "+
					"Active, and the failure appears on its neighbours rather than on it.", c.what)
			case !c.wantErr && err != nil:
				t.Errorf("the deployment failed when %s: %v.\n"+
					"A check that refuses a healthy router gets switched off.", c.what, err)
			}
		})
	}
}

// The daemons a router is checked for have to be the daemons it was told to
// run. Listing them a second time in the checking code is how they drift apart.
func TestEveryEnabledDaemonIsChecked(t *testing.T) {
	script := daemonCheckScript(t)
	enabled := EnabledDaemons()
	if len(enabled) < 3 {
		t.Fatalf("only %d daemons parsed out of the daemons file: %v", len(enabled), enabled)
	}

	for _, d := range enabled {
		if !strings.Contains(script, d) {
			t.Errorf("%s is enabled in the daemons file but the deployment never "+
				"checks whether it is running", d)
		}
	}

	for _, off := range []string{"ripd", "isisd", "pimd", "babeld"} {
		for _, on := range enabled {
			if on == off {
				t.Errorf("%s is disabled in the daemons file but was parsed as enabled", off)
			}
		}
	}
}

func TestMPLSEnablesAndChecksLDP(t *testing.T) {
	as := &model.AS{ASN: 1, MPLS: model.MPLSSpec{Enabled: true}}
	script := daemonCheckScriptForAS(t, as)
	if !strings.Contains(script, "ldpd") {
		t.Fatal("an MPLS router enables LDP but its deployment does not check ldpd")
	}
}

// The shell container deliberately lacks CAP_SYS_ADMIN. Starting/probing FRR
// in it would recreate the exact repeated-deploy failure the sidecar exists to
// prevent, so both lifecycle commands must be explicitly routed to the private
// control container by deploy.Engine.
func TestFRRLifecycleCommandsUseThePrivateControlContainer(t *testing.T) {
	top := &model.Topology{
		Name: "t",
		Lab:  &model.Lab{},
		ASes: map[int]*model.AS{1: {ASN: 1}},
	}
	d := &model.Device{ID: "as1/R", ASN: 1, Kind: model.KindRouter, Name: "R"}
	top.ASes[1].Devices = []*model.Device{d}
	top.ASes[1].Routers = []*model.Device{d}

	cmds, err := (&Renderer{Top: top}).Commands(d)
	if err != nil {
		t.Fatal(err)
	}
	var started, checked bool
	for _, cmd := range cmds {
		switch cmd.Describe {
		case "start FRR":
			started = cmd.FRRControl
		case "check the routing daemons are running":
			checked = cmd.FRRControl
		}
	}
	if !started || !checked {
		t.Fatalf("FRR start/check must target private control: start=%t check=%t", started, checked)
	}
}

// A daemon that has simply died is the common case, and the operator's response
// is to re-run the deploy. If that only reported the problem again they would
// have nothing left to do but destroy the container, which loses the student's
// work — so the deploy starts it.
func TestADeadDaemonIsStartedRatherThanOnlyReported(t *testing.T) {
	script := daemonCheckScript(t)
	dir := t.TempDir()

	// pidof fails until frrinit.sh has been run, then succeeds: which is what
	// starting a dead daemon looks like.
	flag := filepath.Join(dir, "started")
	write(t, filepath.Join(dir, "pidof"),
		"#!/bin/sh\n[ -f "+flag+" ] && exit 0\nexit 1\n")
	write(t, filepath.Join(dir, "ps"), "#!/bin/sh\nexit 0\n")

	initDir := filepath.Join(dir, "usr", "lib", "frr")
	if err := os.MkdirAll(initDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(initDir, "frrinit.sh"), "#!/bin/sh\ntouch "+flag+"\n")

	// The script calls frrinit.sh by absolute path, so the test runs it with
	// that path rewritten to the stub.
	script = strings.ReplaceAll(script, "/usr/lib/frr/frrinit.sh",
		filepath.Join(initDir, "frrinit.sh"))

	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	if err := cmd.Run(); err != nil {
		t.Fatalf("a router whose daemons had died failed its deployment instead of "+
			"having them started: %v.\nRe-running the deploy is what an operator does "+
			"about a dead daemon; if that only reports the problem again, the only "+
			"remaining move is to destroy the container and lose the work in it.", err)
	}
	if _, err := os.Stat(flag); err != nil {
		t.Error("frrinit.sh was never run, so the daemons were not started")
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// daemonCheckScript pulls the check out of the plan a real router gets, so the
// test cannot drift away from what actually runs.
func daemonCheckScript(t *testing.T) string {
	return daemonCheckScriptForAS(t, &model.AS{ASN: 1})
}

func daemonCheckScriptForAS(t *testing.T, as *model.AS) string {
	t.Helper()
	top := &model.Topology{
		Name:  "t",
		Lab:   &model.Lab{},
		ASes:  map[int]*model.AS{1: as},
		Links: nil,
	}
	d := &model.Device{ID: "as1/R", ASN: 1, Kind: model.KindRouter, Name: "R"}
	as.Devices = []*model.Device{d}
	as.Routers = []*model.Device{d}

	r := &Renderer{Top: top}
	cmds, err := r.Commands(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cmds {
		if strings.Contains(c.Describe, "routing daemons are running") {
			if len(c.Args) < 3 {
				t.Fatalf("the daemon check is not a shell command: %v", c.Args)
			}
			return c.Args[2]
		}
	}
	t.Fatal("no command checks that the routing daemons are running, so a router " +
		"with no bgpd deploys cleanly and breaks its neighbours instead of itself")
	return ""
}
