package fault

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// baselineKey is where the pre-injection fingerprint is kept in the injection
// record. It shares the State map with the fault's own bookkeeping, so it is
// named to be unmistakable and is skipped when a fault's state is printed.
const (
	// addedKey and removedKey record what the injection itself changed: the
	// lines it introduced and the lines it took away.
	//
	// Comparing whole fingerprints does not work once two faults are active at
	// once, because each one's baseline was taken while the other was already
	// in place, and every resolve then reports the other fault as contamination.
	// Recording the delta makes the check exact and independent: this fault is
	// clean when what it added is gone and what it removed is back, whatever
	// else may be happening on the device.
	addedKey   = "__added"
	removedKey = "__removed"
	// versionKey records which fingerprint the delta was taken with.
	//
	// The fingerprint will be refined, and a record written by an older build
	// cannot be compared against one taken by a newer. Without this, changing
	// the fingerprint would make every injection already in flight permanently
	// unresolvable: the residue check would report a difference that no undo
	// could remove, and the only way out would be to destroy the lab.
	versionKey = "__baseline_version"
	// fingerprintVersion changes whenever the fields compared change.
	fingerprintVersion = "2"
)

// fingerprint records the parts of a device's configuration a fault could
// disturb, so that resolving can be held to "the device is as it was" rather
// than the much weaker "the fault predicate is now false".
//
// The two are not the same, and the gap between them destroyed a lab. A fault
// that pointed a host's default route at a dead neighbour resolved by deleting
// the default route; when no baseline had been recorded it put nothing back.
// Its verifier asked "is the route via the wrong gateway?", the answer was no,
// and the resolve was reported as clean -- while the host was left with no
// default route at all. The damage surfaced days later as one unreachable host
// in a grading run, with nothing left to connect it to the fault that caused it.
//
// Only statically configured state is included. Routes learned from BGP or
// OSPF move on their own, so comparing them would report a difference on every
// healthy network and the check would be turned off within a week.
func fingerprint(ctx context.Context, e *Env, deviceID string) string {
	out, code := e.Try(ctx, deviceID, fingerprintScript())

	if code != 0 && strings.TrimSpace(out) == "" {
		// A device that cannot be read has no usable baseline. Recording an
		// empty one would make every later comparison trivially equal, which
		// is the failure this whole mechanism exists to prevent.
		return ""
	}
	// P4 table entries and an OVS controller endpoint are forwarding state,
	// not ordinary Linux configuration. Without them a table-delete or
	// southbound-port fault could resolve its predicate while leaving the
	// switch's actual data/control plane different from its baseline.
	//
	// BMv2 counter values intentionally do not participate: they change as
	// traffic flows and are evidence, not configuration.
	if e != nil && e.Topology != nil {
		if d, ok := e.Topology.Device(deviceID); ok {
			switch {
			case d.Kind == model.KindP4 && d.P4 != nil:
				if p4, p4Code := e.Try(ctx, deviceID, fmt.Sprintf(
					"printf 'table_dump %s\\n' | simple_switch_CLI --thrift-port %d 2>/dev/null | "+
						"grep -v -E 'packets|bytes' | sed -E 's/(Entry )?handle:?[[:space:]]*[0-9]+/handle:<id>/; s/Dumping entry 0x[0-9a-fA-F]+/Dumping entry <id>/'",
					shellQuote(d.P4.Table), d.P4.ThriftPort)); p4Code == 0 {
					out += "\n---\np4-table\n" + p4
				}
			case d.Kind == model.KindSwitch && d.OpenFlowController != "":
				if ovs, ovsCode := e.Try(ctx, deviceID,
					"ovs-vsctl get-controller br0 2>/dev/null; ovs-vsctl get-fail-mode br0 2>/dev/null"); ovsCode == 0 {
					out += "\n---\novs-controller\n" + ovs
				}
			}
		}
	}
	return normaliseFingerprint(out)
}

// normaliseFingerprint removes ordering and whitespace differences that carry
// no meaning, so that a comparison reports only real change.
func normaliseFingerprint(out string) string {
	sections := strings.Split(out, "---")
	for i, sec := range sections {
		lines := []string{}
		for _, l := range strings.Split(sec, "\n") {
			l = strings.TrimSpace(l)
			if l == "" {
				continue
			}
			lines = append(lines, l)
		}
		sort.Strings(lines)
		sections[i] = strings.Join(lines, "\n")
	}
	return strings.Join(sections, "\n---\n")
}

func truncateLines(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	out := append([]string{}, in[:n]...)
	return append(out, fmt.Sprintf("and %d more", len(in)-n))
}

// splitLines returns the meaningful lines of a fingerprint as a set.
func splitLines(fp string) map[string]bool {
	out := map[string]bool{}
	for _, l := range strings.Split(fp, "\n") {
		if l = strings.TrimSpace(l); l != "" && l != "---" {
			out[l] = true
		}
	}
	return out
}

// delta reports what the second fingerprint has that the first did not, and
// what the first had that the second does not.
func delta(before, after string) (added, removed []string) {
	was, now := splitLines(before), splitLines(after)
	for l := range now {
		if !was[l] {
			added = append(added, l)
		}
	}
	for l := range was {
		if !now[l] {
			removed = append(removed, l)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// residue reports how a device still differs from where the injection found it,
// considering only the lines this injection was responsible for.
func residue(added, removed []string, now string) string {
	cur := splitLines(now)
	var stillThere, stillMissing []string
	for _, l := range added {
		if cur[l] {
			stillThere = append(stillThere, l)
		}
	}
	for _, l := range removed {
		if !cur[l] {
			stillMissing = append(stillMissing, l)
		}
	}
	var parts []string
	if len(stillThere) > 0 {
		parts = append(parts, "still in place: "+strings.Join(truncateLines(stillThere, 3), "; "))
	}
	if len(stillMissing) > 0 {
		parts = append(parts, "not put back: "+strings.Join(truncateLines(stillMissing, 3), "; "))
	}
	return strings.Join(parts, " / ")
}

// splitNonEmpty splits a recorded line list, tolerating an absent record.
func splitNonEmpty(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// fingerprintScript is the shell that reads the state a fault could disturb.
func fingerprintScript() string {
	return strings.Join([]string{
		// Addresses, without the lifetime counters that change on their own.
		// The interface index moves when a device is recreated, and an IPv6
		// link-local address is derived from the MAC, so both are dropped:
		// they are consequences of other state rather than state in their own
		// right.
		`ip -o addr show 2>/dev/null | sed -e 's/ valid_lft.*//' -e 's/^[0-9]*: //' | grep -v 'inet6 fe80:'`,
		`echo ---`,
		// Administrative link state: up/down, MTU, and the ARP flag.
		`ip -o link show 2>/dev/null | sed -e 's/\\\\.*//' -e 's/^[0-9]*: //'`,
		`echo ---`,
		// Statically configured routes only. Anything a routing protocol
		// installed is expected to move.
		`ip -o route show 2>/dev/null | grep -v 'proto \(bgp\|ospf\|zebra\|babel\|isis\|rip\)' | sort`,
		`echo ---`,
		`ip -o -6 route show 2>/dev/null | grep -v 'proto \(bgp\|ospf\|zebra\|ra\|kernel\)' | sort`,
		`echo ---`,
		// Packet filter rules. Only the rules themselves: iptables-save also
		// prints the table header, chain policies and COMMIT, and those appear
		// the first time any rule is added, which would be reported forever
		// after as state a fault left behind.
		`iptables-save 2>/dev/null | grep '^-A' | sort`,
		`echo ---`,
		// tc invents a fresh random seed and reports a live refcnt every time a
		// qdisc is created, so restoring shaping exactly reproduces the
		// configuration under a different seed. Comparing those would report
		// every shaping fault as unresolvable.
		`tc qdisc show 2>/dev/null | sed -e 's/ seed [0-9]*//' -e 's/ refcnt [0-9]*//' | sort`,
		`echo ---`,
		// The resolver, which several end-host faults rewrite.
		`cat /etc/resolv.conf 2>/dev/null | sort`,
	}, "; ")
}
