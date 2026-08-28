package harness

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
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

func TestSyntheticSliceCollapsesReferenceInteriorsWithoutDroppingOrigins(t *testing.T) {
	full := classTopology(t)
	before := full.Stats()
	beforeHash := full.Hash
	h, err := Slice(full, 3, Options{Synthetic: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(h.ASes); got != len(full.ASes) {
		t.Fatalf("synthetic slice retained %d ASes, want all %d origins", got, len(full.ASes))
	}
	if got := len(h.ASes[3].Devices); got != len(full.ASes[3].Devices) {
		t.Fatalf("target lost devices: got %d, want %d", got, len(full.ASes[3].Devices))
	}
	for asn, as := range h.ASes {
		if asn == 3 || as.Role == model.RoleIXP {
			continue
		}
		if len(as.Routers) != 1 {
			t.Errorf("AS %d retained %d synthetic routers, want one", asn, len(as.Routers))
		}
		if as.Block == "" {
			t.Errorf("AS %d lost its origin block", asn)
		}
	}
	if got := len(h.Devices); got > 42 {
		t.Fatalf("synthetic harness has %d devices, want roughly 40 rather than 121", got)
	}
	seen := map[string]bool{}
	for _, d := range h.SortedDevices() {
		names := map[string]bool{}
		for _, iface := range d.Ifaces {
			names[iface.Name] = true
		}
		for _, iface := range d.Ifaces {
			if len(iface.Name) > 15 {
				t.Errorf("%s interface %q exceeds IFNAMSIZ", d.ID, iface.Name)
			}
			if iface.Parent != "" && !names[iface.Parent] {
				t.Errorf("%s retained child interface %q after dropping parent %q",
					d.ID, iface.Name, iface.Parent)
			}
			key := d.ID + "/" + iface.Name
			if seen[key] {
				t.Errorf("synthetic collapse gave %s two interfaces named %q", d.ID, iface.Name)
			}
			seen[key] = true
		}
		if !d.IsRouter() {
			continue
		}
		if _, err := render.Router(h, d); err != nil {
			t.Errorf("synthetic router %s cannot render: %v", d.ID, err)
		}
	}
	t.Logf("synthetic harness %d devices / %d links (from %d devices)",
		len(h.Devices), len(h.Links), len(full.Devices))
	if got := full.Stats(); got.Devices != before.Devices || got.Links != before.Links || full.Hash != beforeHash {
		t.Fatalf("synthetic slicing mutated class topology: got %+v/%s, want %+v/%s",
			got, full.Hash, before, beforeHash)
	}
}

func TestSyntheticSliceKeepHostsRetainsRemoteDataPlaneWitnesses(t *testing.T) {
	full := classTopology(t)
	h, err := Slice(full, 3, Options{Synthetic: true, KeepHosts: true})
	if err != nil {
		t.Fatal(err)
	}
	for asn, as := range h.ASes {
		if asn == 3 || as.Role == model.RoleIXP {
			continue
		}
		var hosts []*model.Device
		for _, device := range as.Devices {
			if device.Kind == model.KindHost {
				hosts = append(hosts, device)
			}
		}
		if len(hosts) != 1 {
			t.Errorf("AS %d retained %d data-plane witnesses, want one", asn, len(hosts))
			continue
		}
		host := hosts[0]
		attached := false
		for _, iface := range host.Ifaces {
			if iface.Peer != nil && iface.Peer.Device != nil &&
				iface.Peer.Device.ASN == asn && iface.Peer.Device.IsRouter() {
				attached = true
			}
		}
		if !attached {
			t.Errorf("AS %d witness %s is not attached to its collapsed router", asn, host.ID)
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

func TestSlicePreservesGeneratedInteriorMetadata(t *testing.T) {
	l, err := manifest.Load("../../examples/clos")
	if err != nil {
		t.Fatal(err)
	}
	full, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	h, err := Slice(full.Topology, 42, Options{})
	if err != nil {
		t.Fatal(err)
	}
	as := h.ASes[42]
	if as.InteriorKind != model.InteriorClos || !as.Distributable {
		t.Errorf("harness lost Clos metadata: kind=%q distributable=%v", as.InteriorKind, as.Distributable)
	}
	if len(as.PlacementGroups) != len(full.Topology.ASes[42].PlacementGroups) {
		t.Errorf("harness has %d groups, class topology has %d",
			len(as.PlacementGroups), len(full.Topology.ASes[42].PlacementGroups))
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

func TestNeighboursKeepPolicyRolesWithoutRemainingGradeable(t *testing.T) {
	full := classTopology(t)
	h, err := Slice(full, 3, Options{Depth: 2})
	if err != nil {
		t.Fatal(err)
	}
	for asn, as := range h.ASes {
		if asn == 3 {
			continue
		}
		if as.Role != full.ASes[asn].Role {
			t.Errorf("AS %d policy role changed from %q to %q", asn, full.ASes[asn].Role, as.Role)
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
	for id, original := range full.Devices {
		copied := a.Devices[id]
		if copied == nil {
			t.Fatalf("full breadth lost device %s", id)
		}
		for _, expected := range original.Ifaces {
			actual, ok := copied.IfaceByName(expected.Name)
			if !ok {
				t.Fatalf("full breadth lost interface %s:%s", id, expected.Name)
			}
			if actual.Addr4 != expected.Addr4 || actual.Addr6 != expected.Addr6 ||
				actual.Owner != expected.Owner || actual.Role != expected.Role {
				t.Fatalf("full breadth changed %s:%s: got %+v, want %+v",
					id, expected.Name, actual, expected)
			}
		}
	}
	for _, device := range a.SortedDevices() {
		if device.Kind != model.KindService {
			continue
		}
		service, replica, ok := a.ServiceByDevice(device)
		if !ok || service == nil {
			t.Fatalf("service device %s lost its declaration in the harness", device.ID)
		}
		if replica != nil && replica.Device != device {
			t.Fatalf("service replica %s points outside the harness", replica.ID)
		}
	}
	for name, service := range a.Services {
		original := full.Services[name]
		if original == nil {
			continue
		}
		if service.Config == nil {
			service.Config = map[string]string{}
		}
		service.Config["__harness_test"] = "harness-only"
		if original.Config["__harness_test"] == "harness-only" {
			t.Fatalf("service %s config is shared with the class topology", name)
		}
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

	// Only the target retains an owner group, so no other system is gradeable;
	// policy roles remain unchanged because region/relationship semantics use
	// them.
	gradeable := 0
	for asn, as := range a.ASes {
		if as.OwnerGroup != "" {
			gradeable++
			if asn != 3 {
				t.Errorf("non-target AS %d retains gradeable owner %q", asn, as.OwnerGroup)
			}
		}
	}
	if gradeable != 1 {
		t.Errorf("full-breadth harness has %d gradeable ASes, want exactly 1", gradeable)
	}
}
