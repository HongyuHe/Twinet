package deploy

import (
	"net/netip"
	"sort"
	"strings"
)

// Kernel routes, parsed into facts a person could type back.
//
// `ip route show` prints more than `ip route replace` accepts. A route that
// FRR installed through a nexthop object carries the kernel-assigned
// `nhid <N>`, and iproute2 refuses that id beside the via/dev it prints next
// to it -- "Nexthop specification and nexthop id are mutually exclusive". A
// multipath route is printed over several lines, or under `-o` on one line
// with a literal backslash where the newline was, and feeding either back
// gives `either "to" is duplicate, or " nexthop" is a garbage`.
//
// Both were captured verbatim. FRR installs OSPF and BGP routes through
// nexthop groups by default, so essentially every router snapshot taken from a
// converged lab was unreplayable, and the next deployment failed on its first
// restore and never converged. The snapshot was not wrong about what the
// device had; it was written in the kernel's spelling rather than the user's.
//
// So a captured route is parsed into its fields, the kernel's own bookkeeping
// is dropped, and what is left is rendered in one deterministic order that
// iproute2 accepts -- including ECMP, which becomes a single
// `... nexthop via A dev X weight 1 nexthop via B dev Y weight 1`.

// routeTypes are the leading keywords iproute2 prints for a route that is not
// a plain unicast one.
var routeTypes = map[string]bool{
	"unicast": true, "local": true, "broadcast": true, "multicast": true,
	"anycast": true, "blackhole": true, "unreachable": true, "prohibit": true,
	"throw": true, "nat": true,
}

// routeTypesWithoutNexthop forward nothing, so they are complete -- and
// replayable -- with a destination alone.
var routeTypesWithoutNexthop = map[string]bool{
	"blackhole": true, "unreachable": true, "prohibit": true, "throw": true,
}

// routeValueKeys carry exactly one value and are accepted back verbatim.
var routeValueKeys = map[string]bool{
	"table": true, "metric": true, "src": true, "tos": true, "dsfield": true,
	"scope": true, "realms": true, "from": true, "weight": true,
}

// routeMetricKeys are per-route metrics, which iproute2 prints -- and accepts
// -- either as "<name> <value>" or, when the kernel is told not to adjust
// them, as "<name> lock <value>".
var routeMetricKeys = map[string]bool{
	"mtu": true, "advmss": true, "window": true, "cwnd": true, "initcwnd": true,
	"initrwnd": true, "ssthresh": true, "rtt": true, "rttvar": true,
	"rto_min": true, "hoplimit": true, "reordering": true, "quickack": true,
	"congctl": true, "fastopen_no_cookie": true, "features": true,
}

// routeDropKeys are printed with a value that belongs to the kernel rather
// than to whoever asked for the route. `nhid` is the one that matters: it
// names a nexthop object this replay cannot recreate, and the route is already
// fully described by the via/dev/nexthop fields printed beside it.
var routeDropKeys = map[string]bool{
	"nhid": true, "proto": true, "protocol": true, "pref": true,
	"expires": true, "error": true, "users": true, "age": true, "iif": true,
}

// routeDropFlags are runtime decoration: link state, route-cache bookkeeping,
// and hardware offload status.
var routeDropFlags = map[string]bool{
	"dead": true, "linkdown": true, "cache": true, "offload": true,
	"trap": true, "rt_offload": true, "rt_trap": true, "unresolved": true,
	"notify": true,
}

// routeKeepFlags are valueless attributes a user can ask for, so they are part
// of the route's meaning and must survive.
var routeKeepFlags = map[string]bool{"onlink": true, "pervasive": true}

// routeAttrs holds a route's attributes in a form that renders deterministically.
type routeAttrs struct {
	keyed map[string]string
	flags map[string]bool
	// extra keeps tokens this parser does not recognise. Guessing that an
	// unknown keyword is decoration and dropping it would restore a route that
	// is not the one that was captured.
	extra []string
}

func (a *routeAttrs) set(key, value string) {
	if a.keyed == nil {
		a.keyed = map[string]string{}
	}
	a.keyed[key] = value
}

func (a *routeAttrs) flag(name string) {
	if a.flags == nil {
		a.flags = map[string]bool{}
	}
	a.flags[name] = true
}

func (a routeAttrs) tokens() []string {
	keys := make([]string, 0, len(a.keyed))
	for key := range a.keyed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, 2*len(keys)+len(a.flags)+len(a.extra))
	for _, key := range keys {
		out = append(out, key)
		out = append(out, strings.Fields(a.keyed[key])...)
	}
	flags := make([]string, 0, len(a.flags))
	for name := range a.flags {
		flags = append(flags, name)
	}
	sort.Strings(flags)
	out = append(out, flags...)
	return append(out, a.extra...)
}

// routeNexthop is one path of a multipath route.
type routeNexthop struct {
	via   string
	dev   string
	attrs routeAttrs
}

func (n routeNexthop) String() string {
	parts := []string{"nexthop"}
	if n.via != "" {
		parts = append(parts, "via", n.via)
	}
	if n.dev != "" {
		parts = append(parts, "dev", n.dev)
	}
	return strings.Join(append(parts, n.attrs.tokens()...), " ")
}

// routeFact is one route reduced to the portable semantics a user can ask for.
type routeFact struct {
	kind     string
	dest     string
	via      string
	dev      string
	attrs    routeAttrs
	nexthops []routeNexthop
}

// routeFields tokenises one printed route. `ip -o` writes the newline that
// separates a multipath route's nexthops as a literal backslash, which arrives
// either as its own field or glued to the field before it ("pref medium\").
// No route field legitimately contains one, so they are simply removed.
func routeFields(line string) []string {
	fields := strings.Fields(line)
	out := fields[:0]
	for _, field := range fields {
		field = strings.Trim(field, `\`)
		if field == "" {
			continue
		}
		out = append(out, field)
	}
	return out
}

// routeEntries splits printed route output into one entry per route. A
// multipath route continues on the lines that begin with "nexthop", whether
// iproute2 wrapped them onto their own line or ran them together after a
// backslash.
func routeEntries(raw string) []string {
	var entries []string
	for _, line := range strings.Split(raw, "\n") {
		fields := routeFields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "nexthop" {
			if len(entries) == 0 {
				continue
			}
			entries[len(entries)-1] += " " + strings.Join(fields, " ")
			continue
		}
		entries = append(entries, strings.Join(fields, " "))
	}
	return entries
}

// parseRouteFact reads one printed route, reporting false for a line that is
// not a route at all.
func parseRouteFact(entry string) (routeFact, bool) {
	fields := routeFields(entry)
	if len(fields) == 0 {
		return routeFact{}, false
	}
	var fact routeFact
	if routeTypes[fields[0]] {
		if fields[0] != "unicast" {
			fact.kind = fields[0]
		}
		fields = fields[1:]
	}
	if len(fields) == 0 || !routeDestination(fields[0]) {
		return routeFact{}, false
	}
	fact.dest = fields[0]

	chunks := splitAtNexthop(fields[1:])
	fact.via, fact.dev, fact.attrs = parseRouteAttrs(chunks[0])
	for _, chunk := range chunks[1:] {
		var hop routeNexthop
		hop.via, hop.dev, hop.attrs = parseRouteAttrs(chunk)
		if hop.via == "" && hop.dev == "" {
			continue
		}
		fact.nexthops = append(fact.nexthops, hop)
	}
	fact.normalize()
	return fact, true
}

// routeDestination reports whether a field is the destination of a route.
func routeDestination(field string) bool {
	if field == "default" {
		return true
	}
	if _, err := netip.ParsePrefix(field); err == nil {
		return true
	}
	_, err := netip.ParseAddr(field)
	return err == nil
}

// splitAtNexthop separates a route's own attributes from its paths. The first
// chunk is always the route level, even when it is empty.
func splitAtNexthop(fields []string) [][]string {
	chunks := [][]string{nil}
	for _, field := range fields {
		if field == "nexthop" {
			chunks = append(chunks, nil)
			continue
		}
		chunks[len(chunks)-1] = append(chunks[len(chunks)-1], field)
	}
	return chunks
}

// parseRouteAttrs reads the attributes of a route or of one of its nexthops.
func parseRouteAttrs(fields []string) (via, dev string, attrs routeAttrs) {
	for i := 0; i < len(fields); i++ {
		key := fields[i]
		switch {
		case key == "via":
			// A nexthop may be given in the other family: "via inet6 fe80::1".
			if i+2 < len(fields) && (fields[i+1] == "inet" || fields[i+1] == "inet6") {
				via = fields[i+1] + " " + fields[i+2]
				i += 2
				continue
			}
			if i+1 < len(fields) {
				via = fields[i+1]
				i++
			}
		case key == "dev":
			if i+1 < len(fields) {
				dev = fields[i+1]
				i++
			}
		case key == "encap":
			value, consumed := parseRouteEncap(fields[i+1:])
			if consumed > 0 {
				attrs.set("encap", value)
				i += consumed
			}
		case routeDropKeys[key]:
			i++ // its value is the kernel's, not the user's
		case routeDropFlags[key]:
		case routeKeepFlags[key]:
			attrs.flag(key)
		case routeMetricKeys[key]:
			if i+2 < len(fields) && fields[i+1] == "lock" {
				attrs.set(key, "lock "+fields[i+2])
				i += 2
				continue
			}
			if i+1 < len(fields) {
				attrs.set(key, fields[i+1])
				i++
			}
		case routeValueKeys[key]:
			if i+1 < len(fields) {
				attrs.set(key, fields[i+1])
				i++
			}
		default:
			attrs.extra = append(attrs.extra, key)
		}
	}
	return via, dev, attrs
}

// parseRouteEncap keeps an encapsulation verbatim. Its parameters are
// type-specific -- MPLS labels, a seg6 segment list, an IP tunnel's endpoints
// -- so it is copied through to the next route-level keyword rather than
// interpreted, which keeps `encap mpls 100/200` and its kind intact without
// this parser having to know every encapsulation iproute2 supports.
func parseRouteEncap(fields []string) (string, int) {
	var value []string
	for _, field := range fields {
		if len(value) > 0 && routeEncapBoundary(field) {
			break
		}
		value = append(value, field)
	}
	return strings.Join(value, " "), len(value)
}

func routeEncapBoundary(field string) bool {
	switch field {
	case "via", "dev", "nexthop", "encap":
		return true
	}
	return routeValueKeys[field] || routeMetricKeys[field] ||
		routeDropKeys[field] || routeDropFlags[field] || routeKeepFlags[field]
}

func (f *routeFact) normalize() {
	// One nexthop is a plain route: that is how the kernel prints it back, so
	// keeping the two spellings apart would make an exact restore look
	// different from the state it was restored from.
	if len(f.nexthops) == 1 && f.via == "" && f.dev == "" {
		hop := f.nexthops[0]
		f.via, f.dev = hop.via, hop.dev
		for key, value := range hop.attrs.keyed {
			// A single path carries all the traffic whatever its weight says.
			if key == "weight" {
				continue
			}
			if _, taken := f.attrs.keyed[key]; !taken {
				f.attrs.set(key, value)
			}
		}
		for name := range hop.attrs.flags {
			f.attrs.flag(name)
		}
		f.attrs.extra = append(f.attrs.extra, hop.attrs.extra...)
		f.nexthops = nil
	}
	// Equal-cost paths are a set. The kernel prints them in the order they
	// were installed, which a routing daemon does not repeat across a restart,
	// and an order that changes without the route changing would make an exact
	// restore fail verification.
	sort.Slice(f.nexthops, func(i, j int) bool {
		return f.nexthops[i].String() < f.nexthops[j].String()
	})
}

func (f routeFact) String() string {
	var parts []string
	if f.kind != "" {
		parts = append(parts, f.kind)
	}
	parts = append(parts, f.dest)
	if f.via != "" {
		parts = append(parts, "via", f.via)
	}
	if f.dev != "" {
		parts = append(parts, "dev", f.dev)
	}
	parts = append(parts, f.attrs.tokens()...)
	for _, hop := range f.nexthops {
		parts = append(parts, hop.String())
	}
	return strings.Join(parts, " ")
}

// replayable reports whether this route can be asked for again.
//
// A route the kernel resolved only through a nexthop object it did not
// describe -- no via, no dev, no paths -- cannot be reconstructed by any
// command. Emitting one anyway names a destination and nothing else, which
// iproute2 rejects, and a rejected command fails the whole restore and with it
// the deployment. Such a route is dropped instead: it was never something a
// student typed, and a routing daemon reinstalls it within seconds.
func (f routeFact) replayable() bool {
	if f.dest == "" {
		return false
	}
	if routeTypesWithoutNexthop[f.kind] {
		return true
	}
	return f.via != "" || f.dev != "" || len(f.nexthops) > 0
}

// replayRank orders routes so that each one is asked for only after what it
// needs is already there: interface routes first, then routes through a
// gateway that those interface routes make reachable, and the default route
// last.
func (f routeFact) replayRank() int {
	switch {
	case f.dest == "default":
		return 2
	case f.via != "" || len(f.nexthops) > 0:
		return 1
	default:
		return 0
	}
}

// kernelOwned reports a route the kernel maintains itself.
//
// It creates one fe80::/64 entry per interface as soon as that interface has a
// link-local address, and does so again on the replacement container, so
// replaying them adds nothing -- and cannot be done faithfully anyway: every
// interface shares the one prefix, so each `ip -6 route replace` overwrites the
// last and the device that came first loses its entry. The O7 contract already
// says a link-local address must not change a snapshot digest; the route the
// kernel derives from it is the same fact.
func (f routeFact) kernelOwned() bool {
	if f.kind != "" || f.via != "" || len(f.nexthops) > 0 {
		return false
	}
	prefix, err := netip.ParsePrefix(f.dest)
	return err == nil && prefix.Bits() == 64 && prefix.Addr().IsLinkLocalUnicast()
}

// portableRoute reduces one printed route to the fact worth preserving. It
// reports false for a line that is not a route, for a route no command could
// ask for, and for one the kernel keeps for itself.
func portableRoute(entry string) (routeFact, bool) {
	fact, ok := parseRouteFact(entry)
	if !ok || !fact.replayable() || fact.kernelOwned() {
		return routeFact{}, false
	}
	return fact, true
}

// canonicalRoute reduces one printed route to portable facts. It returns ""
// for a line that is not a route and for a route no command could ask for.
func canonicalRoute(line string) string {
	fact, ok := portableRoute(line)
	if !ok {
		return ""
	}
	return fact.String()
}
