package netx

import (
	"fmt"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func fdbEntry(vni uint32, peer string) externalFDBEntry {
	return externalFDBEntry{
		Neigh: netlink.Neigh{
			IP:           net.ParseIP(peer),
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0},
			VNI:          int(vni),
		},
		SourceVNI: vni,
	}
}

// A node pair carries one trunk, and that trunk carries every cross-node link
// between those two nodes. Replacing it -- the only way to move a receive
// socket a peer has already moved -- deletes all of them at once. A converged
// eighty-four autonomous system lab lost a hundred and ten cross-node
// bindings to a single link's repair, and the marks of every system behind
// them went with it.
func TestTrunkReplacementRecordsEveryBindingItIsCarrying(t *testing.T) {
	entries := make([]externalFDBEntry, 0, 110)
	vlanFor := map[uint32]uint16{}
	for i := uint32(0); i < 110; i++ {
		vni := 7000 + i
		entries = append(entries, fdbEntry(vni, "10.0.1.2"))
		vlanFor[vni] = uint16(i + 1)
	}
	carried := carriedBindingsFrom(entries, vlanFor)
	if len(carried) != 110 {
		t.Fatalf("recorded %d of 110 bindings; the rest would be destroyed with the trunk", len(carried))
	}
	for i, binding := range carried {
		want := uint32(7000 + i)
		if binding.VNI != want {
			t.Fatalf("binding %d = VNI %d, want %d (the snapshot must be deterministic)", i, binding.VNI, want)
		}
		if binding.VLAN != uint16(i+1) || binding.Peer.String() != "10.0.1.2" {
			t.Fatalf("binding %d = %#v, want its recorded VLAN and peer", i, binding)
		}
	}
}

func TestCarriedBindingsIgnoreEntriesThatAreNotLogicalLinks(t *testing.T) {
	learned := fdbEntry(7001, "10.0.1.2")
	learned.HardwareAddr = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	noSource := fdbEntry(0, "10.0.1.2")
	noPeer := fdbEntry(7003, "")
	unmapped := fdbEntry(7004, "10.0.1.2")
	entries := []externalFDBEntry{
		learned, noSource, noPeer, unmapped,
		fdbEntry(7002, "10.0.1.2"), fdbEntry(7002, "10.0.1.2"),
	}
	carried := carriedBindingsFrom(entries, map[uint32]uint16{7001: 1, 7002: 2, 7003: 3})
	if len(carried) != 1 || carried[0].VNI != 7002 {
		t.Fatalf("carried = %#v, want only the deduplicated VNI 7002 logical binding", carried)
	}
}

func TestMergeCarriedBindingsKeepsThePreReplacementTruth(t *testing.T) {
	first := carriedBindingsFrom([]externalFDBEntry{
		fdbEntry(7001, "10.0.1.2"), fdbEntry(7002, "10.0.1.2"),
	}, map[uint32]uint16{7001: 1, 7002: 2})
	// A retry observes the object it has just created: empty, plus whatever a
	// racing writer put back. It must not overwrite the recorded truth.
	second := carriedBindingsFrom([]externalFDBEntry{
		fdbEntry(7002, "10.0.9.9"), fdbEntry(7003, "10.0.1.2"),
	}, map[uint32]uint16{7002: 9, 7003: 3})
	merged := mergeCarriedBindings(first, second)
	if len(merged) != 3 {
		t.Fatalf("merged = %#v, want three bindings", merged)
	}
	if merged[1].VNI != 7002 || merged[1].VLAN != 2 || merged[1].Peer.String() != "10.0.1.2" {
		t.Fatalf("merged VNI 7002 = %#v, want the pre-replacement VLAN and peer", merged[1])
	}
}

func TestRestoredBindingsSkipOnlyTheRequestedVNI(t *testing.T) {
	carried := carriedBindingsFrom([]externalFDBEntry{
		fdbEntry(7001, "10.0.1.2"), fdbEntry(7002, "10.0.1.2"), fdbEntry(7003, "10.0.1.2"),
	}, map[uint32]uint16{7001: 1, 7002: 2, 7003: 3})
	restore := carriedBindingsToRestore(carried, 7002)
	if len(restore) != 2 || restore[0].VNI != 7001 || restore[1].VNI != 7003 {
		t.Fatalf("restore set = %#v, want every carried binding except the requested one", restore)
	}
	if got := len(carriedBindingsToRestore(carried, 0)); got != 3 {
		t.Fatalf("restore set without a requested VNI = %d bindings, want 3", got)
	}
}

func TestRepairedTrunkRestoresBindingsBeforeTheCallerInstallsItsOwn(t *testing.T) {
	// The order matters: the caller's own binding is installed by
	// EnsureMultiplexOverlay after the pair is ready, so restoring the
	// carried set first cannot overwrite the authoritative mapping.
	carried := carriedBindingsFrom([]externalFDBEntry{fdbEntry(7001, "10.0.1.2")},
		map[uint32]uint16{7001: 1})
	if got := fmt.Sprint(carriedBindingsToRestore(carried, 7001)); got != "[]" {
		t.Fatalf("restore set = %s, want the requested VNI left to the caller", got)
	}
}
