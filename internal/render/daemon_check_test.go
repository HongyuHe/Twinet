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
			what:    "nothing is running",
			pidof:   "exit 1",
			wantErr: true,
		},
		{
			what:    "zebra is up but bgpd is not",
			pidof:   `case "$1" in zebra) exit 0;; *) exit 1;; esac`,
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			dir := t.TempDir()
			stub := filepath.Join(dir, "pidof")
			if err := os.WriteFile(stub, []byte("#!/bin/sh\n"+c.pidof+"\n"), 0o755); err != nil {
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

// daemonCheckScript pulls the check out of the plan a real router gets, so the
// test cannot drift away from what actually runs.
func daemonCheckScript(t *testing.T) string {
	t.Helper()
	top := &model.Topology{
		Name:  "t",
		Lab:   &model.Lab{},
		ASes:  map[int]*model.AS{1: {ASN: 1}},
		Links: nil,
	}
	d := &model.Device{ID: "as1/R", ASN: 1, Kind: model.KindRouter, Name: "R"}
	top.ASes[1].Devices = []*model.Device{d}
	top.ASes[1].Routers = []*model.Device{d}

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
