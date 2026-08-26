package netx

import (
	"testing"
)

func bridge(name, alias string, index int) bridgeLink {
	return bridgeLink{Name: name, Alias: alias, Index: index, Bridge: true}
}

func port(name string, index, master int) bridgeLink {
	return bridgeLink{Name: name, Index: index, MasterIndex: master}
}

func names(bridges []OrphanBridge) []string {
	out := make([]string, 0, len(bridges))
	for _, b := range bridges {
		out = append(out, b.Name)
	}
	return out
}

func TestAnUnaliasedEmptyPairBridgeIsCollectable(t *testing.T) {
	links := []bridgeLink{bridge("twbp0123456789a", "", 10)}
	got := orphanBridges(links, map[string]bool{"cos461": true})
	if len(got) != 1 || got[0].Name != "twbp0123456789a" {
		t.Fatalf("an unaliased empty Twinet bridge was not found: %v", names(got))
	}
	if got[0].Owner != "" || got[0].VNI != 0 {
		t.Fatalf("a pair bridge was reported with an owner or a VNI: %+v", got[0])
	}
}

func TestABridgeWithAnythingAttachedIsPreserved(t *testing.T) {
	links := []bridgeLink{
		bridge("twbp0123456789a", "", 10),
		port("veth-something", 11, 10),
	}
	if got := orphanBridges(links, nil); len(got) != 0 {
		t.Fatalf("a bridge with a port on it was collected: %v", names(got))
	}
}

func TestAPairBridgeWhoseVxlanStillExistsIsPreserved(t *testing.T) {
	links := []bridgeLink{
		bridge("twbp0123456789a", "", 10),
		{Name: "twvp0123456789a", Index: 11, Vxlan: true},
	}
	if got := orphanBridges(links, nil); len(got) != 0 {
		t.Fatalf("a repairable pair was collected: %v", names(got))
	}
}

func TestALegacyBridgeWhoseVxlanStillExistsIsLeftToTheOverlayCollector(t *testing.T) {
	links := []bridgeLink{
		bridge("twbr1001", "", 10),
		{Name: "twvx1001", Index: 11, Vxlan: true},
	}
	if got := orphanBridges(links, nil); len(got) != 0 {
		t.Fatalf("a bridge that still has its tunnel was collected here: %v", names(got))
	}
}

func TestALegacyBridgeLeftWithoutItsVxlanIsCollectableWithItsVNI(t *testing.T) {
	got := orphanBridges([]bridgeLink{bridge("twbr1001", "", 10)}, nil)
	if len(got) != 1 || got[0].VNI != 1001 {
		t.Fatalf("a stranded legacy bridge was not found with its identifier: %+v", got)
	}
}

func TestALiveLabsBridgeIsPreservedEvenWhenItLooksEmpty(t *testing.T) {
	// A deploy in flight legitimately has a bridge with nothing on it yet.
	links := []bridgeLink{bridge("twbr1001", ownerAlias("cos461"), 10)}
	if got := orphanBridges(links, map[string]bool{"cos461": true}); len(got) != 0 {
		t.Fatalf("a live lab's bridge was collected: %v", names(got))
	}
	if got := orphanBridges(links, map[string]bool{"other": true}); len(got) != 1 {
		t.Fatalf("a dead lab's stranded bridge was not found: %v", names(got))
	}
}

func TestAnAliasThisBuildCannotReadIsPreserved(t *testing.T) {
	for _, alias := range []string{"someone-elses-record", "twinet:", "twinet:pair:!!!"} {
		links := []bridgeLink{bridge("twbr1001", alias, 10)}
		if got := orphanBridges(links, nil); len(got) != 0 {
			t.Fatalf("a bridge with an unreadable alias %q was collected", alias)
		}
	}
}

func TestABridgeThatIsNotTwinetsIsNeverConsidered(t *testing.T) {
	links := []bridgeLink{
		bridge("docker0", "", 10),
		bridge("br-1234567890ab", "", 11),
		bridge("twbpNOTHEX12345", "", 12),
		bridge("twbr", "", 13),
		bridge("twbrx1", "", 14),
	}
	if got := orphanBridges(links, nil); len(got) != 0 {
		t.Fatalf("a bridge Twinet did not name was collected: %v", names(got))
	}
}

func TestAnEnslavedBridgeIsPreserved(t *testing.T) {
	link := bridge("twbr1001", "", 10)
	link.MasterIndex = 99
	if got := orphanBridges([]bridgeLink{link}, nil); len(got) != 0 {
		t.Fatal("a bridge that is itself a port of something else was collected")
	}
}

func TestRemovingABridgeRefusesAnythingNotTwinetsByName(t *testing.T) {
	for _, name := range []string{"docker0", "br0", "", "twvx1001", "twbp"} {
		if err := RemoveOrphanBridge(name, nil); err == nil {
			t.Fatalf("removing %q was permitted", name)
		}
	}
}

func TestBridgeOwnershipDistinguishesMissingFromUnreadable(t *testing.T) {
	if owner, collectable := bridgeOwnership(""); !collectable || owner != "" {
		t.Fatal("a missing ownership record must be collectable with no owner")
	}
	if owner, collectable := bridgeOwnership(ownerAlias("cos461")); !collectable || owner != "cos461" {
		t.Fatalf("a Twinet alias did not resolve: owner=%q collectable=%t", owner, collectable)
	}
	if _, collectable := bridgeOwnership("kubernetes"); collectable {
		t.Fatal("somebody else's ownership record was treated as ours")
	}
}
