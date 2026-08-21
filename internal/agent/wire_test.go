package agent

import (
	"encoding/json"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
)

// The wire form is the control-plane-to-agent contract. If a round trip is
// lossy, a node would build a subtly different network from the one the
// operator described, which is the hardest possible class of bug to notice.
func TestWireRoundTrip(t *testing.T) {
	l, err := manifest.Load("../../examples/demo")
	if err != nil {
		t.Skipf("demo lab unavailable: %v", err)
	}
	if d := l.Validate(); d.HasErrors() {
		t.Fatalf("demo lab is invalid: %v", d.Err())
	}
	res, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	top := res.Topology
	if _, err := place.Place(top, place.Options{}); err != nil {
		t.Fatal(err)
	}

	// Serialise, send over the wire as JSON, and rebuild.
	raw, err := json.Marshal(Serialise(top))
	if err != nil {
		t.Fatal(err)
	}
	var w Wire
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	got, err := w.Rehydrate()
	if err != nil {
		t.Fatalf("rehydrate: %v", err)
	}

	if got.Name != top.Name || got.Hash != top.Hash {
		t.Errorf("identity lost: %s/%s vs %s/%s", got.Name, got.Hash, top.Name, top.Hash)
	}
	if len(got.Devices) != len(top.Devices) {
		t.Fatalf("device count %d, want %d", len(got.Devices), len(top.Devices))
	}
	if len(got.Links) != len(top.Links) {
		t.Fatalf("link count %d, want %d", len(got.Links), len(top.Links))
	}
	if len(got.ASes) != len(top.ASes) {
		t.Fatalf("AS count %d, want %d", len(got.ASes), len(top.ASes))
	}

	for id, want := range top.Devices {
		g, ok := got.Devices[id]
		if !ok {
			t.Fatalf("device %s missing after round trip", id)
		}
		if g.Container != want.Container || g.Image != want.Image ||
			g.Node != want.Node || g.Kind != want.Kind || g.ASN != want.ASN {
			t.Errorf("device %s changed: %+v", id, g)
		}
		if len(g.Ifaces) != len(want.Ifaces) {
			t.Fatalf("device %s has %d interfaces, want %d", id, len(g.Ifaces), len(want.Ifaces))
		}
		for i := range want.Ifaces {
			a, b := want.Ifaces[i], g.Ifaces[i]
			if a.Name != b.Name || a.Addr4 != b.Addr4 || a.MAC != b.MAC ||
				a.Owner != b.Owner || a.VLAN != b.VLAN || a.Trunk != b.Trunk ||
				a.Role != b.Role || a.Parent != b.Parent {
				t.Errorf("device %s interface %s changed: %+v vs %+v", id, a.Name, b, a)
			}
			// The peer graph must be rebuilt, not just the flat fields.
			if (a.Peer == nil) != (b.Peer == nil) {
				t.Errorf("device %s interface %s: peer link lost", id, a.Name)
			}
			if a.Peer != nil && b.Peer != nil &&
				(a.Peer.Device.ID != b.Peer.Device.ID || a.Peer.Name != b.Peer.Name) {
				t.Errorf("device %s interface %s: peer changed to %s:%s",
					id, a.Name, b.Peer.Device.ID, b.Peer.Name)
			}
		}
	}

	byID := map[string]*model.Link{}
	for _, l := range top.Links {
		byID[l.ID] = l
	}
	for _, g := range got.Links {
		w, ok := byID[g.ID]
		if !ok {
			t.Fatalf("unexpected link %s after round trip", g.ID)
		}
		if g.VNI != w.VNI || g.Subnet != w.Subnet || g.Segment != w.Segment ||
			g.InterAS != w.InterAS || g.Rel != w.Rel || !g.Props.Equal(w.Props) {
			t.Errorf("link %s changed: %+v", g.ID, g)
		}
	}
}

func TestRehydrateRejectsDanglingReferences(t *testing.T) {
	w := &Wire{
		Lab: "x",
		Devices: []WireDev{{ID: "a", Name: "a", Kind: "router",
			Ifaces: []WireIface{{Name: "eth0", Owner: "platform", Role: "intra-as"}}}},
		Links: []WireLink{{ID: "l", ADevice: "a", AIface: "eth0",
			BDevice: "ghost", BIface: "eth0"}},
	}
	if _, err := w.Rehydrate(); err == nil {
		t.Fatal("expected an error for a link pointing at a device that does not exist")
	}
}

func TestRehydrateRequiresLabName(t *testing.T) {
	if _, err := (&Wire{}).Rehydrate(); err == nil {
		t.Fatal("expected an error for a wire topology with no lab name")
	}
}

// Reconstructing a minimal Lab on the far side and copying across the fields
// the agent was known to need is a bug generator: a new manifest field arrives
// empty, the renderer produces something subtly different from what the author
// wrote, and nothing reports it. It cost a debugging session over an RPKI
// payload that was correct on the controller and empty on the node.
func TestTheWholeManifestSurvivesTheWire(t *testing.T) {
	l, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatal(err)
	}

	res, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(Serialise(res.Topology))
	if err != nil {
		t.Fatal(err)
	}
	var w Wire
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	got, err := w.Rehydrate()
	if err != nil {
		t.Fatal(err)
	}

	want := l.Lab
	if len(got.Lab.RPKI.NotFound) != len(want.RPKI.NotFound) {
		t.Errorf("rpki.not_found did not survive: %v vs %v", got.Lab.RPKI.NotFound, want.RPKI.NotFound)
	}
	if len(got.Lab.RPKI.Invalid) != len(want.RPKI.Invalid) {
		t.Errorf("rpki.invalid did not survive: %v vs %v", got.Lab.RPKI.Invalid, want.RPKI.Invalid)
	}
	if got.Lab.Access.Listen != want.Access.Listen {
		t.Errorf("access.listen did not survive: %q vs %q", got.Lab.Access.Listen, want.Access.Listen)
	}
	if len(got.Lab.Services) != len(want.Services) {
		t.Errorf("services did not survive: %d vs %d", len(got.Lab.Services), len(want.Services))
	}
	if got.Lab.Addressing.InterAS != want.Addressing.InterAS {
		t.Errorf("addressing did not survive: %q vs %q", got.Lab.Addressing.InterAS, want.Addressing.InterAS)
	}
}

func TestReplicatedServicePlacementSurvivesTheWire(t *testing.T) {
	l, err := manifest.Load("../../examples/scale")
	if err != nil {
		t.Fatal(err)
	}
	res, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := place.Place(res.Topology, place.Options{}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(Serialise(res.Topology))
	if err != nil {
		t.Fatal(err)
	}
	var wire Wire
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	got, err := wire.Rehydrate()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dns", "rpki", "matrix", "measurement"} {
		wantService, gotService := res.Topology.Services[name], got.Services[name]
		if gotService == nil || len(gotService.Replicas) != len(wantService.Replicas) {
			t.Fatalf("%s replicas lost across wire: want %#v got %#v", name, wantService, gotService)
		}
		for asn, replica := range wantService.Attachments {
			if gotService.Attachments[asn] != replica {
				t.Errorf("%s AS %d attachment = %q, want %q", name, asn, gotService.Attachments[asn], replica)
			}
		}
	}
}
