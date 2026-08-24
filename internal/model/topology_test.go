package model

import (
	"strings"
	"testing"
)

// Names derived here end up as container names, overlay identifiers and file
// paths across a cluster. Two labs colliding on one means each reconfigures the
// other's routers, and nothing reports it.
func TestContainerNamesAreUniqueAcrossLabsAndASes(t *testing.T) {
	seen := map[string]string{}
	for _, lab := range []string{"cos461", "cos461-g3", "scale"} {
		for _, asn := range []int{0, 1, 3, 140} {
			for _, name := range []string{"MSP", "msp", "ATL", "dns"} {
				got := ContainerName(lab, asn, name)
				key := lab + "|" + string(rune(asn)) + "|" + strings.ToLower(name)
				if prev, ok := seen[got]; ok && prev != key {
					t.Errorf("%s is produced by both %s and %s", got, prev, key)
				}
				seen[got] = key
				if strings.ContainsAny(got, " /:\\") {
					t.Errorf("container name %q contains a character a container name may not", got)
				}
			}
		}
	}
}

func TestContainerNamesFitContainerdWithControlSuffix(t *testing.T) {
	prefix := strings.Repeat("scale-grading-long-", 4)
	first := ContainerName(prefix+"a", 3, "measurement-node-0")
	second := ContainerName(prefix+"b", 3, "measurement-node-0")
	for _, name := range []string{first, second} {
		if len(name) > 72 {
			t.Fatalf("primary container name has %d bytes: %q", len(name), name)
		}
		if len(name+"-frr") > 76 {
			t.Fatalf("control container name has %d bytes: %q", len(name+"-frr"), name+"-frr")
		}
	}
	if first == second {
		t.Fatalf("long distinct identities collapsed to %q", first)
	}
}

// The identity is order-independent so both ends of a link compute the same
// value without talking to each other. That is what lets two nodes derive the
// same overlay identifier with no coordination.
func TestLinkIdentityDoesNotDependOnWhichEndAsks(t *testing.T) {
	a := MakeLinkID("as3/MSP", "port_ATL", "as3/ATL", "port_MSP")
	b := MakeLinkID("as3/ATL", "port_MSP", "as3/MSP", "port_ATL")
	if a != b {
		t.Errorf("the two ends of a link disagree about its identity:\n  %s\n  %s", a, b)
	}
	// Different links must stay different, including ones that differ only by
	// interface: a router can have two links to the same neighbour.
	c := MakeLinkID("as3/MSP", "port_ATL2", "as3/ATL", "port_MSP2")
	if a == c {
		t.Error("two distinct links share an identity")
	}
}

func TestDeviceIdentityRoundTrips(t *testing.T) {
	top := &Topology{Devices: map[string]*Device{}, ASes: map[int]*AS{}}
	d := &Device{ID: DeviceID(3, "MSP"), Name: "MSP", ASN: 3, Kind: KindRouter}
	top.Devices[d.ID] = d
	top.ASes[3] = &AS{ASN: 3, Devices: []*Device{d}}

	if got, ok := top.Device("as3/MSP"); !ok || got != d {
		t.Errorf("a device cannot be found by the identity it was given")
	}
	if got, ok := top.DeviceInAS(3, "MSP"); !ok || got != d {
		t.Errorf("a device cannot be found by AS and name")
	}
	if _, ok := top.Device("as3/NOPE"); ok {
		t.Error("an unknown device was found")
	}
}

// Sorting is what makes a deployment reproducible: the same manifest must
// produce the same plan in the same order every time, or a redeployment
// shuffles work between nodes.
func TestOrderingIsDeterministic(t *testing.T) {
	top := &Topology{Devices: map[string]*Device{}, ASes: map[int]*AS{}}
	for _, spec := range []struct {
		asn  int
		name string
	}{{10, "ATL"}, {3, "MSP"}, {3, "ATL"}, {2, "ALL"}} {
		d := &Device{ID: DeviceID(spec.asn, spec.name), Name: spec.name, ASN: spec.asn}
		top.Devices[d.ID] = d
		if top.ASes[spec.asn] == nil {
			top.ASes[spec.asn] = &AS{ASN: spec.asn}
		}
	}
	var first []string
	for i := 0; i < 20; i++ {
		var order []string
		for _, d := range top.SortedDevices() {
			order = append(order, d.ID)
		}
		if first == nil {
			first = order
			continue
		}
		for j := range order {
			if order[j] != first[j] {
				t.Fatalf("device order is not stable:\n  %v\n  %v", first, order)
			}
		}
	}
	asns := top.SortedASNs()
	for i := 1; i < len(asns); i++ {
		if asns[i-1] > asns[i] {
			t.Errorf("AS numbers are not sorted: %v", asns)
		}
	}
}

func TestRelationshipInverseIsSymmetric(t *testing.T) {
	for _, r := range []Relationship{RelProvider, RelCustomer, RelPeer} {
		if got := r.Inverse().Inverse(); got != r {
			t.Errorf("%s inverted twice is %s", r, got)
		}
	}
	if RelProvider.Inverse() != RelCustomer {
		t.Error("a provider's inverse should be a customer")
	}
	if RelPeer.Inverse() != RelPeer {
		t.Error("a peer's inverse should be a peer")
	}
}

func TestStatsCountWhatTheyClaim(t *testing.T) {
	top := &Topology{Devices: map[string]*Device{}, ASes: map[int]*AS{}}
	kinds := []DeviceKind{KindRouter, KindRouter, KindHost, KindSwitch}
	for i, k := range kinds {
		d := &Device{ID: DeviceID(3, string(rune('A'+i))), Name: string(rune('A' + i)), ASN: 3, Kind: k, Node: "node-0"}
		top.Devices[d.ID] = d
	}
	top.ASes[3] = &AS{ASN: 3}
	s := top.Stats()
	if s.Devices != 4 || s.Routers != 2 || s.Hosts != 1 || s.Switches != 1 {
		t.Errorf("stats miscount: %+v", s)
	}
	if s.ASes != 1 {
		t.Errorf("AS count is %d, want 1", s.ASes)
	}
}
