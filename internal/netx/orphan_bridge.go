package netx

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
)

// A bridge whose ownership alias is missing is invisible to every collector
// Twinet has.
//
// FindOrphans enumerates VXLAN devices and reads the lab from their alias;
// RemoveEmptyMultiplexOverlays enumerates pair bridges and reads the pair from
// theirs. Neither sees a bridge that has no alias at all -- which is what is
// left after a create that was interrupted between LinkAdd and LinkSetAlias,
// after a VXLAN is deleted while its bridge survives, or after an external
// tool clears the alias. Those bridges are permanent: they hold no traffic,
// they belong to nobody, and nothing will ever look at them again.
//
// Collecting them safely turns on their names being Twinet's own and
// deterministic. twbr<vni> and twbp<11 hex> are not names another tool
// produces by accident, so a bridge carrying one was created here. That is
// enough to identify the object; it is deliberately not enough to delete it.
// Deletion additionally requires the bridge to be demonstrably carrying
// nothing: no enslaved link of any kind, and no ownership claim naming a lab
// that is still live. Anything ambiguous -- an alias this build cannot parse,
// a port whose purpose is unknown, an unreadable link table -- is preserved.

var (
	legacyBridgeName  = regexp.MustCompile(`^twbr([0-9]{1,10})$`)
	multiplexPairName = regexp.MustCompile(`^twbp[0-9a-f]{11}$`)
)

// OrphanBridge is a Twinet-named bridge that is carrying nothing and is owned
// by no live lab.
type OrphanBridge struct {
	Name string `json:"name"`
	// Owner is the lab named by the bridge's alias, when it has a readable
	// one. An empty owner means the bridge carries no ownership record at all,
	// which is the case this exists for.
	Owner string `json:"owner,omitempty"`
	// VNI is set for a legacy twbr<vni> bridge, so a caller can release the
	// identifier's reservation along with the object.
	VNI uint32 `json:"vni,omitempty"`
	// Ports is always zero for a returned orphan; it is retained so a caller
	// reading the record cannot mistake an occupied bridge for a collectable
	// one if this ever reports both.
	Ports int `json:"ports"`
}

// FindOrphanBridges lists Twinet-named bridges that are demonstrably orphaned.
//
// live names the labs this node is hosting. A bridge whose alias names one of
// them is preserved even if it currently looks empty, because a deploy that is
// mid-flight legitimately has a bridge with nothing on it yet.
func FindOrphanBridges(live map[string]bool) ([]OrphanBridge, error) {
	links, err := listHostLinks()
	if err != nil {
		return nil, fmt.Errorf("list host interfaces: %w", err)
	}
	return orphanBridgesFromLinks(links, live), nil
}

// bridgeLink is the minimal projection of a host link this analysis needs. It
// exists so the decision can be tested exhaustively without netlink.
type bridgeLink struct {
	Name        string
	Alias       string
	Index       int
	MasterIndex int
	Bridge      bool
	Vxlan       bool
}

func orphanBridgesFromLinks(links []netlink.Link, live map[string]bool) []OrphanBridge {
	projected := make([]bridgeLink, 0, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		_, isBridge := link.(*netlink.Bridge)
		_, isVxlan := link.(*netlink.Vxlan)
		projected = append(projected, bridgeLink{
			Name: attrs.Name, Alias: attrs.Alias, Index: attrs.Index,
			MasterIndex: attrs.MasterIndex, Bridge: isBridge, Vxlan: isVxlan,
		})
	}
	return orphanBridges(projected, live)
}

func orphanBridges(links []bridgeLink, live map[string]bool) []OrphanBridge {
	ports := map[int]int{}
	names := map[string]bool{}
	for _, link := range links {
		names[link.Name] = true
		if link.MasterIndex != 0 {
			ports[link.MasterIndex]++
		}
	}
	var out []OrphanBridge
	for _, link := range links {
		if !link.Bridge {
			continue
		}
		owner, collectable := bridgeOwnership(link.Alias)
		if !collectable {
			// The alias exists and is not Twinet's. Somebody else's record on
			// a Twinet-looking name is exactly the ambiguity to preserve.
			continue
		}
		if owner != "" && live[owner] {
			continue
		}
		if ports[link.Index] > 0 {
			continue
		}
		// A bridge enslaved to something else is part of a topology this
		// analysis does not understand.
		if link.MasterIndex != 0 {
			continue
		}
		switch {
		case multiplexPairName.MatchString(link.Name):
			// A pair bridge whose VXLAN still exists is not an orphan even
			// when the VXLAN is detached: the pair can still be repaired.
			if names[multiplexVxlanFor(link.Name)] {
				continue
			}
			out = append(out, OrphanBridge{Name: link.Name, Owner: owner})
		case legacyBridgeName.MatchString(link.Name):
			vni, ok := legacyBridgeVNI(link.Name)
			if !ok {
				continue
			}
			// FindOrphans owns any bridge that still has its VXLAN; this path
			// is only for the bridge left behind after the VXLAN is gone.
			if names[VxlanName(vni)] {
				continue
			}
			out = append(out, OrphanBridge{Name: link.Name, Owner: owner, VNI: vni})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// bridgeOwnership reports the lab an alias names and whether the alias is one
// this build is entitled to act on. An empty alias is Twinet's own missing
// record and is collectable; an alias in any other format is not.
func bridgeOwnership(alias string) (string, bool) {
	trimmed := strings.TrimSpace(alias)
	if trimmed == "" {
		return "", true
	}
	if !strings.HasPrefix(trimmed, aliasPrefix) {
		return "", false
	}
	if strings.HasPrefix(trimmed, pairAliasPrefix) {
		// A pair alias that does not decode is a record this build cannot
		// read, not an absent one.
		key, ok := pairKeyFromAlias(trimmed)
		if !ok {
			return "", false
		}
		return key.lab, true
	}
	owner := ownerFromAlias(trimmed)
	if owner == "" {
		// A twinet: alias this build cannot decode is ambiguous, not empty.
		return "", false
	}
	return owner, true
}

func multiplexVxlanFor(bridge string) string {
	return "twvp" + strings.TrimPrefix(bridge, "twbp")
}

func legacyBridgeVNI(name string) (uint32, bool) {
	match := legacyBridgeName.FindStringSubmatch(name)
	if match == nil {
		return 0, false
	}
	value, err := strconv.ParseUint(match[1], 10, 32)
	if err != nil || value > maxVNI {
		return 0, false
	}
	return uint32(value), true
}

// RemoveOrphanBridge deletes one bridge after proving, immediately before the
// deletion and from the kernel rather than from a caller's earlier
// observation, that it is still the empty unowned object it was reported as.
//
// The re-proof is the point. A collection decision made from a scan is stale
// by the time it is acted on, and the object it names may by then have been
// claimed by a deploy that is wiring a lab into it.
func RemoveOrphanBridge(name string, live map[string]bool) error {
	if !multiplexPairName.MatchString(name) && !legacyBridgeName.MatchString(name) {
		return fmt.Errorf("refusing to remove %q: not a Twinet bridge name", name)
	}
	h, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("open host netlink handle: %w", err)
	}
	defer h.Close()
	link, err := h.LinkByName(name)
	if err != nil {
		if IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("re-resolve orphan bridge %s: %w", name, err)
	}
	bridge, ok := link.(*netlink.Bridge)
	if !ok {
		return fmt.Errorf("refusing to remove %q: it is no longer a bridge", name)
	}
	owner, collectable := bridgeOwnership(bridge.Attrs().Alias)
	if !collectable {
		return fmt.Errorf("refusing to remove %q: it carries an ownership record this build cannot read", name)
	}
	if owner != "" && live[owner] {
		return fmt.Errorf("refusing to remove %q: lab %q claimed it", name, owner)
	}
	links, err := listHandleLinks(h)
	if err != nil {
		return fmt.Errorf("list host interfaces: %w", err)
	}
	for _, other := range links {
		if other.Attrs().MasterIndex == bridge.Attrs().Index {
			return fmt.Errorf("refusing to remove %q: %s was attached to it",
				name, other.Attrs().Name)
		}
	}
	if err := h.LinkDel(bridge); err != nil && !IsNotFound(err) {
		return fmt.Errorf("delete orphan bridge %s: %w", name, err)
	}
	return nil
}
