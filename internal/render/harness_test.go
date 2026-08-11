package render

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

func courseTopology(t *testing.T) *model.Topology {
	t.Helper()
	l, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	return r.Topology
}

// A grading harness has to do two contradictory-looking things at once: build a
// correct internet around the submission, and leave the submission's own AS
// untouched. Getting this wrong is silent and expensive in both directions. If
// the neighbours are left unconfigured, a correct student is marked against
// sessions that were never going to come up. If the graded AS is solved, every
// student scores full marks for work the platform did.
func TestHarnessSolvesEveryoneExceptTheGradedAS(t *testing.T) {
	top := courseTopology(t)
	const graded = 3
	r := NewHarness(top, graded)

	var checkedGraded, checkedOther bool
	for _, d := range top.SortedDevices() {
		if d.Kind != model.KindRouter {
			continue
		}
		files, err := r.Files(d)
		if err != nil {
			t.Fatalf("%s: %v", d.ID, err)
		}
		spec, ok := files["/etc/frr/frr.conf"]
		if !ok {
			continue
		}
		body := string(spec.Content)
		cfg, err := Router(top, d)
		if err != nil {
			t.Fatalf("%s: %v", d.ID, err)
		}
		expected := strings.TrimSpace(cfg.Expected)

		switch {
		case d.ASN == graded:
			if expected != "" && strings.Contains(body, expected) {
				t.Errorf("%s is the graded AS but was handed the reference solution", d.ID)
			}
			checkedGraded = true
		case d.ASN != 0 && expected != "":
			if !strings.Contains(body, expected) {
				t.Errorf("%s is a neighbour and should have been solved, but was left unconfigured", d.ID)
			}
			checkedOther = true
		}
	}
	if !checkedGraded || !checkedOther {
		t.Fatalf("test did not exercise both cases (graded=%v, other=%v)", checkedGraded, checkedOther)
	}
}

func TestPlainModesAreUnaffected(t *testing.T) {
	top := courseTopology(t)
	for _, mode := range []Mode{ModePlatform, ModeSolve} {
		r := New(top, mode)
		for _, d := range top.SortedDevices() {
			if got := r.modeFor(d); got != mode {
				t.Fatalf("mode %s leaked into %s as %s", mode, d.ID, got)
			}
		}
	}
}

// FRR allows one inbound route-map per neighbour and keeps the last statement
// it is given. Emitting origin validation as a second map therefore silently
// replaced the relationship policy -- or, depending on order, silently
// discarded the validation -- while the configuration looked correct at a
// glance and every router reported itself configured to validate.
func TestOneInboundRouteMapPerNeighbour(t *testing.T) {
	top := courseTopology(t)
	checked := 0
	for _, d := range top.SortedDevices() {
		if d.Kind != model.KindRouter {
			continue
		}
		cfg, err := Router(top, d)
		if err != nil {
			t.Fatalf("%s: %v", d.ID, err)
		}
		perNeighbour := map[string][]string{}
		for _, line := range strings.Split(cfg.Platform+cfg.Expected, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			// neighbor <addr> route-map <name> in
			if len(f) == 5 && f[0] == "neighbor" && f[2] == "route-map" && f[4] == "in" {
				perNeighbour[f[1]] = append(perNeighbour[f[1]], f[3])
			}
		}
		for addr, maps := range perNeighbour {
			checked++
			if len(maps) > 1 {
				t.Errorf("%s gives neighbour %s %d inbound route-maps (%s); "+
					"FRR keeps only the last, so the others never run",
					d.ID, addr, len(maps), strings.Join(maps, ", "))
			}
		}
	}
	if checked == 0 {
		t.Fatal("no inbound route-maps were found, so this proves nothing")
	}
}

// Origin validation has to be reachable from the map that is actually applied.
// Rejecting invalid routes is only half of it: a router accepting only what is
// explicitly valid would black-hole most of the real internet, and a check
// testing for rejection alone would award full marks for exactly that mistake.
func TestValidationIsPartOfTheAppliedPolicy(t *testing.T) {
	top := courseTopology(t)

	var withCache int
	for _, d := range top.SortedDevices() {
		if d.Kind != model.KindRouter || d.ASN == 0 {
			continue
		}
		cfg, err := Router(top, d)
		if err != nil {
			t.Fatal(err)
		}
		body := cfg.Platform + cfg.Expected
		if !strings.Contains(body, "rpki cache") {
			continue
		}
		withCache++

		// Every map named on an inbound statement must carry both halves.
		for _, line := range strings.Split(body, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) != 5 || f[0] != "neighbor" || f[2] != "route-map" || f[4] != "in" {
				continue
			}
			name := f[3]
			clauses := routeMapBody(body, name)
			if !strings.Contains(clauses, "match rpki invalid") {
				t.Errorf("%s applies %s inbound, which never rejects an invalid origin", d.ID, name)
			}
			if !strings.Contains(clauses, "match rpki notfound") {
				t.Errorf("%s applies %s inbound, which does not keep routes with no ROA", d.ID, name)
			}
		}
	}
	if withCache == 0 {
		t.Fatal("no router has a validator configured, so this proves nothing")
	}
}

// routeMapBody returns every clause of a named route-map.
func routeMapBody(cfg, name string) string {
	var out []string
	in := false
	for _, line := range strings.Split(cfg, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "route-map "+name+" "):
			in = true
		case strings.HasPrefix(t, "route-map "):
			in = false
		}
		if in {
			out = append(out, t)
		}
	}
	return strings.Join(out, "\n")
}

// The policy applied to a neighbour must be named after what that neighbour is
// to us, not after what we are to it.
//
// Getting this backwards inverts the economics of the whole network: a customer
// prefers its provider over its own customers, paying for traffic it was being
// paid to carry, and a provider refuses to give its customer full transit. It
// was backwards, and because the grading checks derived the relationship the
// same way, the inverted configuration was the one that scored full marks.
func TestPolicyIsNamedAfterTheNeighbourNotOurselves(t *testing.T) {
	top := courseTopology(t)

	checked := 0
	for _, d := range top.SortedDevices() {
		if d.Kind != model.KindRouter {
			continue
		}
		cfg, err := Router(top, d)
		if err != nil {
			t.Fatalf("%s: %v", d.ID, err)
		}
		body := cfg.Platform + cfg.Expected

		for _, i := range d.Ifaces {
			if i.Link == nil || !i.Link.InterAS || i.Peer == nil || i.Peer.Addr4 == "" {
				continue
			}
			want := i.Link.PeerRelationship(i)
			addr := addrOf(i.Peer.Addr4)

			var applied string
			for _, line := range strings.Split(body, "\n") {
				f := strings.Fields(strings.TrimSpace(line))
				if len(f) == 5 && f[0] == "neighbor" && f[1] == addr && f[2] == "route-map" && f[4] == "in" {
					applied = f[3]
				}
			}
			if applied == "" {
				continue
			}
			checked++
			wantSuffix := strings.ToUpper(string(want))
			if !strings.HasSuffix(applied, wantSuffix) {
				t.Errorf("%s applies %s to %s, but that neighbour is our %s",
					d.ID, applied, addr, want)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no inter-AS policy was inspected, so this proves nothing")
	}
	t.Logf("checked %d inter-AS import policies", checked)
}
