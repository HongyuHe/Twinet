package harness

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

func classTopology(t *testing.T) *model.Topology {
	t.Helper()
	lab, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	res, err := expand.Expand(lab.Lab)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	return res.Topology
}

func TestSliceKeepsTargetWholeAndShrinksTheRest(t *testing.T) {
	full := classTopology(t)
	h, err := Slice(full, 3, Options{Depth: 2, KeepHosts: true})
	if err != nil {
		t.Fatalf("slice: %v", err)
	}

	// Every device of the target must survive. A missing internal router
	// would fail an IGP check for a reason that has nothing to do with the
	// student's work.
	for _, d := range full.ASes[3].Devices {
		if _, ok := h.Devices[d.ID]; !ok {
			t.Errorf("target device %s was dropped from the harness", d.ID)
		}
	}

	fs, hs := full.Stats(), h.Stats()
	if hs.Devices >= fs.Devices {
		t.Errorf("harness is not smaller: %d devices vs %d", hs.Devices, fs.Devices)
	}
	if hs.Devices < len(full.ASes[3].Devices) {
		t.Errorf("harness smaller than the target AS itself")
	}
	t.Logf("harness %s: %d devices, %d links (from %d, %d)",
		h.Name, hs.Devices, hs.Links, fs.Devices, fs.Links)
}

func TestSliceIsolatesIdentifiers(t *testing.T) {
	full := classTopology(t)
	a, err := Slice(full, 3, Options{Depth: 2})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Slice(full, 4, Options{Depth: 2})
	if err != nil {
		t.Fatal(err)
	}

	// Two harnesses may legitimately contain the same AS. What they must not
	// share is a container name or a VXLAN identifier, because sharing either
	// means one submission's deployment silently reconfigures another's.
	names := map[string]string{}
	for _, d := range a.Devices {
		names[d.Container] = a.Name
	}
	for _, d := range b.Devices {
		if from, ok := names[d.Container]; ok {
			t.Fatalf("container %s appears in both %s and %s", d.Container, from, b.Name)
		}
	}

	vnis := map[uint32]bool{}
	for _, l := range a.Links {
		vnis[l.VNI] = true
	}
	for _, l := range b.Links {
		if vnis[l.VNI] {
			t.Fatalf("VNI %d is used by two harnesses at once", l.VNI)
		}
	}
}

func TestSliceDoesNotMutateTheClassTopology(t *testing.T) {
	full := classTopology(t)
	before := full.Stats()
	beforeCount := before.Devices + before.Links
	beforeHash := full.Hash
	firstContainer := full.ASes[3].Devices[0].Container

	h, err := Slice(full, 3, Options{Depth: 2, KeepHosts: true})
	if err != nil {
		t.Fatal(err)
	}
	// Mutating the harness is the whole point of a harness; it must not reach
	// back into the class topology that other submissions are sliced from.
	for _, d := range h.Devices {
		d.Image = "mutated"
		for _, i := range d.Ifaces {
			i.Addr4 = "0.0.0.0/32"
		}
	}

	if got := full.Stats(); got.Devices+got.Links != beforeCount {
		t.Errorf("class topology changed after slicing: %d+%d, want %d",
			got.Devices, got.Links, beforeCount)
	}
	if full.Hash != beforeHash {
		t.Errorf("class topology hash changed after slicing")
	}
	if full.ASes[3].Devices[0].Container != firstContainer {
		t.Errorf("class container name changed: %s", full.ASes[3].Devices[0].Container)
	}
	for _, d := range full.Devices {
		if d.Image == "mutated" {
			t.Fatalf("device %s in the class topology was mutated through the harness", d.ID)
		}
	}
}

func TestSliceKeepsBothEndsOfEveryLink(t *testing.T) {
	full := classTopology(t)
	h, err := Slice(full, 5, Options{Depth: 2, KeepHosts: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range h.Links {
		for _, side := range []*model.Iface{l.A, l.B} {
			id := devID(side)
			if _, ok := h.Devices[id]; !ok {
				t.Errorf("link %s terminates on %s, which is not deployed", l.ID, id)
			}
			if side.Device == nil || side.Device != h.Devices[id] {
				t.Errorf("link %s side %s points at a device outside the harness", l.ID, side.Name)
			}
		}
	}
}

func TestSliceRetainsTransitObservabilityAtDepthTwo(t *testing.T) {
	full := classTopology(t)
	// Depth 2 must reach an AS that is not directly connected to the target,
	// otherwise no check can observe whether the student re-advertises a route
	// it learned, and a missing export policy would be marked correct.
	h, err := Slice(full, 3, Options{Depth: 2})
	if err != nil {
		t.Fatal(err)
	}
	direct := map[int]bool{}
	for _, l := range full.Links {
		if !l.InterAS {
			continue
		}
		if asnOf(l.A) == 3 {
			direct[asnOf(l.B)] = true
		}
		if asnOf(l.B) == 3 {
			direct[asnOf(l.A)] = true
		}
	}
	found := false
	for asn := range h.ASes {
		if asn != 3 && !direct[asn] {
			found = true
		}
	}
	if !found {
		t.Errorf("depth 2 harness contains only direct neighbours: %v", h.SortedASNs())
	}
}

func TestNeighboursAreNeverGradedAsStudents(t *testing.T) {
	full := classTopology(t)
	h, err := Slice(full, 3, Options{Depth: 2})
	if err != nil {
		t.Fatal(err)
	}
	for asn, as := range h.ASes {
		if asn == 3 {
			continue
		}
		if as.Role == model.RoleStudent {
			t.Errorf("AS %d is still marked as a student AS in a harness for AS 3", asn)
		}
		if as.OwnerGroup != "" {
			t.Errorf("AS %d still carries owner group %q", asn, as.OwnerGroup)
		}
	}
}

func TestHarnessNameIsSafeAndUnique(t *testing.T) {
	if got := harnessName("cos461", 3, ""); got != "cos461-g3" {
		t.Errorf("harnessName with no suffix = %q", got)
	}
	// A name must be safe to use as a container name and an overlay prefix.
	for _, suffix := range []string{"attempt 2", "Group/../etc", strings.Repeat("x", 80)} {
		got := harnessName("cos461", 3, suffix)
		for _, bad := range []string{"/", "..", " ", ":"} {
			if strings.Contains(got, bad) {
				t.Errorf("harnessName(%q) = %q contains %q", suffix, got, bad)
			}
		}
	}

	// Distinct submissions must stay distinct however they are written.
	// Sanitising and truncating alone collapses these onto one another, and
	// two submissions sharing a harness name share container names and overlay
	// identifiers, so one deployment reconfigures the other's routers.
	colliding := []string{
		"group 7 (late)", "group-7-late", "group_7_late",
		strings.Repeat("x", 30) + "a", strings.Repeat("x", 30) + "b",
		"Ann", "ann", "a.n.n",
	}
	seen := map[string]string{}
	for _, s := range colliding {
		got := harnessName("cos461", 3, s)
		if prev, ok := seen[got]; ok {
			t.Errorf("submissions %q and %q both produce harness %q", prev, s, got)
		}
		seen[got] = s
	}
}

func TestSliceRejectsUnknownAS(t *testing.T) {
	full := classTopology(t)
	if _, err := Slice(full, 9999, Options{}); err == nil {
		t.Fatal("expected an error for an AS that is not in the lab")
	}
}

func TestFullBreadthKeepsEverythingButStillIsolates(t *testing.T) {
	full := classTopology(t)
	a, err := Slice(full, 3, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Slice(full, 4, Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Full breadth is the default because it is the only setting that cannot
	// fail a correct submission for a reason the student cannot see. A check
	// that names a peer, or a route from a particular origin, must find it.
	if len(a.Devices) != len(full.Devices) || len(a.Links) != len(full.Links) {
		t.Fatalf("full breadth lost part of the topology: %d/%d devices, %d/%d links",
			len(a.Devices), len(full.Devices), len(a.Links), len(full.Links))
	}
	if len(a.ASes) != len(full.ASes) {
		t.Fatalf("full breadth lost ASes: %v vs %v", a.SortedASNs(), full.SortedASNs())
	}

	// Isolation must not depend on the harness being smaller. Two full-breadth
	// harnesses contain the same ASes and must still share nothing.
	names := map[string]bool{}
	for _, d := range a.Devices {
		names[d.Container] = true
	}
	for _, d := range b.Devices {
		if names[d.Container] {
			t.Fatalf("container %s is shared by two full-breadth harnesses", d.Container)
		}
	}
	vnis := map[uint32]bool{}
	for _, l := range a.Links {
		vnis[l.VNI] = true
	}
	shared := 0
	for _, l := range b.Links {
		if vnis[l.VNI] {
			shared++
		}
	}
	if shared > 0 {
		t.Fatalf("%d VXLAN identifiers are shared by two harnesses", shared)
	}

	// Only the target may be marked as a student AS, so no other group's
	// configuration is ever what is being graded.
	students := 0
	for _, as := range a.ASes {
		if as.Role == model.RoleStudent {
			students++
		}
	}
	if students != 1 {
		t.Errorf("full-breadth harness has %d student ASes, want exactly 1", students)
	}
}
