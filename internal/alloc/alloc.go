// Package alloc derives every allocated resource as a pure function of the
// topology.
//
// This is what lets Twinet run without a state store. VXLAN identifiers, MAC
// addresses, container names and published ports are not handed out by a
// registry that must be persisted and kept consistent; they are *computed*, so
// two agents on two machines independently arrive at the same answer, a
// controller crash loses nothing, and a redeploy is bit-for-bit identical.
//
// The legacy platform instead cached container PIDs in groups/docker_pid.map,
// a file that was `source`d as bash and was wrong the moment any container
// restarted.
package alloc

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"strings"
)

// VNI range. 0-4095 are avoided by convention (they collide with VLAN-ish
// tooling expectations and some hardware reserves the low range), and the top
// of the 24-bit space is left free for manual/debug tunnels.
const (
	vniMin = 4096
	vniMax = 16_000_000
)

// VNI derives a VXLAN network identifier for a link.
//
// Collisions are astronomically unlikely (birthday bound over ~16M values
// gives ~0.03% at 2,000 links) but not impossible, so callers pass an
// increasing salt until the value is unused; the probe order is deterministic,
// so every node computes the same sequence.
func VNI(lab, linkID string, salt int) uint32 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(lab))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(linkID))
	if salt > 0 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(salt))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(b[:])
	}
	return uint32(h.Sum64()%(vniMax-vniMin)) + vniMin
}

// AssignVNIs allocates a unique VNI for every link ID, resolving the rare
// collision by re-probing with an increasing salt. Input order does not matter:
// IDs are processed in sorted order so the result is stable.
func AssignVNIs(lab string, linkIDs []string) map[string]uint32 {
	sorted := append([]string{}, linkIDs...)
	sortStrings(sorted)
	used := make(map[uint32]bool, len(sorted))
	out := make(map[string]uint32, len(sorted))
	for _, id := range sorted {
		for salt := 0; ; salt++ {
			v := VNI(lab, id, salt)
			if !used[v] {
				used[v] = true
				out[id] = v
				break
			}
		}
	}
	return out
}

// MAC derives a stable, locally administered unicast MAC address for an
// interface. Bit 1 of the first octet is set (locally administered) and bit 0
// is clear (unicast), so 0x02 is a safe fixed prefix.
func MAC(lab, deviceID, iface string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(lab))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(deviceID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(iface))
	sum := h.Sum64()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], sum)
	return fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4])
}

// LinkAltname derives the ownership tag stamped onto both halves of a veth
// pair, so an orphaned interface left behind by a crash can be identified and
// removed without consulting any external state.
//
// The kernel limits an altname to IFALIASZ-1 (255) bytes, but keeping it short
// makes `ip link` output readable.
func LinkAltname(lab, linkID string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(lab))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(linkID))
	return fmt.Sprintf("tw-%x", h.Sum64())
}

// TempIfName derives the transient name a veth half carries between creation in
// the root namespace and renaming inside the container. It must be unique on
// the host and fit in IFNAMSIZ-1 = 15 bytes.
func TempIfName(lab, linkID string, side byte) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(lab))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(linkID))
	return fmt.Sprintf("tw%011x%c", h.Sum64()&0xFFFFFFFFFFF, side)
}

// BridgeName derives the name of the per-link bridge used to join a veth to a
// VXLAN tunnel for cross-node links. Must fit in IFNAMSIZ-1 = 15 bytes.
func BridgeName(vni uint32) string { return fmt.Sprintf("twbr%d", vni) }

// VxlanName derives the name of the VXLAN netdev for a link.
func VxlanName(vni uint32) string { return fmt.Sprintf("twvx%d", vni) }

// LegacyPort returns the published SSH port for an AS under the legacy
// "ssh -p 2000+ASN" scheme the mini-Internet used, preserved for compatibility
// with existing course instructions.
func LegacyPort(base, asn int) int { return base + asn }

// Netns derives the named network namespace label used when Twinet needs a
// persistent netns handle. Container namespaces are addressed by PID path
// instead; this is only for host-side constructs.
func Netns(lab, name string) string {
	return "tw-" + sanitize(lab) + "-" + sanitize(name)
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

func sortStrings(s []string) {
	// Small, dependency-free insertion sort keeps this package free of imports
	// beyond the standard library essentials and is plenty fast for link counts.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
