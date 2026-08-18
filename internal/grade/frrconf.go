package grade

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// frrConfig gives the grader a structured view of a router's running
// configuration.
//
// Several checks used to search the whole configuration for a keyword. That
// awards marks for writing a route-map, not for applying one: a student can
// define a perfectly correct policy, never attach it to a neighbour, and score
// full credit for behaviour their router does not have. Worse, the mark is
// indistinguishable from a correct answer, so nobody finds out.
type frrConfig struct {
	raw       string
	routeMaps map[string][]string // name -> body lines across all sequences
	// neighborMaps records, per neighbour and address family, the route-maps
	// bound in each direction.
	//
	// The address family is part of the key because a binding governs only the
	// family it was written in. Flattening them let the last one parsed stand
	// for all of them, and FRR prints IPv6 after IPv4: a policy bound inbound
	// under `address-family ipv6 unicast` was read as the policy on the IPv4
	// session, which is a route-map the router never runs on the routes being
	// asked about.
	neighborMaps map[nbrKey]map[string]string // (addr, af) -> direction -> map name
	// neighborAttrs records other per-neighbour settings, e.g. "route-reflector-client".
	neighborAttrs map[string][]string
	// peerGroups names the peer-groups the configuration declares. A group is
	// a template, not a session: nothing peers with it, so it must never be
	// graded as though something did.
	peerGroups map[string]bool
	// groupOf maps a neighbour to the peer-group it belongs to, which is where
	// its settings come from when it does not state them itself.
	groupOf map[string]string
	// localAS is the AS number the BGP process runs as, which is what tells an
	// internal session from an external one.
	localAS int
}

// nbrKey identifies a neighbour's settings within one address family.
type nbrKey struct {
	addr string
	af   string
}

// ipv4Unicast is the family a `neighbor` line belongs to when it appears
// outside any `address-family` block, which is where FRR prints the IPv4
// unicast bindings by default.
const ipv4Unicast = "ipv4 unicast"

func parseFRR(cfg string) *frrConfig {
	f := &frrConfig{
		raw:           cfg,
		routeMaps:     map[string][]string{},
		neighborMaps:  map[nbrKey]map[string]string{},
		neighborAttrs: map[string][]string{},
		peerGroups:    map[string]bool{},
		groupOf:       map[string]string{},
	}
	var currentMap string
	af := ipv4Unicast
	for _, line := range strings.Split(cfg, "\n") {
		t := strings.TrimSpace(line)
		fields := strings.Fields(t)
		if len(fields) == 3 && fields[0] == "router" && fields[1] == "bgp" {
			if n, err := strconv.Atoi(fields[2]); err == nil {
				f.localAS = n
			}
			af = ipv4Unicast
		}
		if len(fields) >= 2 && fields[0] == "address-family" {
			af = strings.Join(fields[1:], " ")
			continue
		}
		if t == "exit-address-family" {
			af = ipv4Unicast
			continue
		}
		switch {
		case len(fields) >= 3 && fields[0] == "route-map":
			// "route-map NAME permit 10"
			//
			// The header is kept with the body. Without it a caller reading a
			// map cannot tell a deny clause from a permit one, and the
			// direction of a clause is what decides what it does: a check
			// looking only for "match rpki invalid" gave the mark to a permit
			// clause, which lets the very routes the question is about through.
			currentMap = fields[1]
			f.routeMaps[currentMap] = append(f.routeMaps[currentMap], t)
			continue
		case t == "exit" || t == "!" || t == "":
			currentMap = ""
			continue
		case len(fields) >= 2 && fields[0] == "neighbor":
			addr := fields[1]
			// "neighbor NAME peer-group" declares a template; "neighbor ADDR
			// peer-group NAME" makes a session use one.
			if len(fields) == 3 && fields[2] == "peer-group" {
				f.peerGroups[addr] = true
			}
			if len(fields) == 4 && fields[2] == "peer-group" {
				f.groupOf[addr] = fields[3]
				// A configuration may name a group before declaring it, and a
				// name used as a group is a group whether or not the
				// declaration was seen.
				f.peerGroups[fields[3]] = true
			}
			// "neighbor X route-map NAME in|out"
			if len(fields) >= 5 && fields[2] == "route-map" {
				dir := fields[4]
				k := nbrKey{addr: addr, af: af}
				if f.neighborMaps[k] == nil {
					f.neighborMaps[k] = map[string]string{}
				}
				// FRR keeps only the last binding per direction, so a later
				// line replaces an earlier one exactly as the router does.
				f.neighborMaps[k][dir] = fields[3]
			}
			f.neighborAttrs[addr] = append(f.neighborAttrs[addr], strings.Join(fields[2:], " "))
			currentMap = ""
			continue
		}
		if currentMap != "" {
			f.routeMaps[currentMap] = append(f.routeMaps[currentMap], t)
		}
	}
	return f
}

// mapFor returns the route-map bound to a neighbour in one direction, in the
// IPv4 unicast family.
func (f *frrConfig) mapFor(addr, dir string) string {
	return f.mapForAF(addr, ipv4Unicast, dir)
}

// mapForAF returns the route-map that governs a session in one direction of one
// address family, resolving peer-group inheritance the way the router does.
//
// A neighbour that states nothing takes its group's binding, and a neighbour
// that states its own overrides the group's. Reading only the lines written
// against the address got this wrong in both directions at once. A student who
// wrote a correct policy once on a peer-group and pointed every session at it
// -- which is how this is done in practice -- was marked as having no policy at
// all. And a student who put a correct-looking policy on the group and then
// overrode it on the session with one that filters nothing was marked as having
// the group's: the grader read a route-map the router does not run.
func (f *frrConfig) mapForAF(addr, af, dir string) string {
	if m, ok := f.neighborMaps[nbrKey{addr: addr, af: af}]; ok && m[dir] != "" {
		return m[dir]
	}
	if g := f.groupOf[addr]; g != "" {
		if m, ok := f.neighborMaps[nbrKey{addr: g, af: af}]; ok {
			return m[dir]
		}
	}
	return ""
}

// mapBody returns the body of a route-map, following continue/call chains one
// level so that a policy split across helper maps is still seen.
func (f *frrConfig) mapBody(name string) string {
	if name == "" {
		return ""
	}
	lines := f.routeMaps[name]
	body := strings.Join(lines, "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) == 2 && fields[0] == "call" {
			body += "\n" + strings.Join(f.routeMaps[fields[1]], "\n")
		}
	}
	return body
}

// appliedBody returns the combined body of every route-map bound to a
// neighbour in the given direction, which is what actually governs the
// announcements crossing that session.
func (f *frrConfig) appliedBody(addr, dir string) string {
	return f.mapBody(f.mapFor(addr, dir))
}

// hasNeighbor reports whether the configuration mentions a neighbour at all.
//
// A peer-group is not a neighbour. Nothing peers with a template, so counting
// one as a session would let a group named after the address the check is
// looking for stand in for a session that was never configured.
func (f *frrConfig) hasNeighbor(addr string) bool {
	if f.peerGroups[addr] {
		return false
	}
	_, ok := f.neighborAttrs[addr]
	return ok
}

// effectiveAttrs merges a neighbour's own settings with those it inherits from
// its peer-group.
//
// FRR inherits per setting and a setting written on the member replaces the
// group's, so the merge is keyed on the setting name. Without it a session that
// takes its `remote-as` from its group looked like a session with no remote AS
// at all, and was left out of the set of external sessions that must be
// guarded -- while the group, which is not a session, was put into it.
func (f *frrConfig) effectiveAttrs(addr string) string {
	own := f.neighborAttrs[addr]
	g := f.groupOf[addr]
	if g == "" {
		return strings.Join(own, "\n")
	}
	defined := map[string]bool{}
	for _, a := range own {
		if k := settingKey(a); k != "" {
			defined[k] = true
		}
	}
	merged := append([]string{}, own...)
	for _, a := range f.neighborAttrs[g] {
		if k := settingKey(a); k == "" || defined[k] {
			continue
		}
		merged = append(merged, a)
	}
	return strings.Join(merged, "\n")
}

// settingKey names the setting a neighbour line configures, so that a member's
// line can be told to override the same setting on its group and no other.
func settingKey(attr string) string {
	f := strings.Fields(attr)
	if len(f) == 0 {
		return ""
	}
	// A route-map binding overrides only the direction it names: a member that
	// sets its own inbound policy still inherits the group's outbound one.
	if f[0] == "route-map" && len(f) >= 3 {
		return "route-map " + f[2]
	}
	return f[0]
}

// ipOnly drops the prefix length from an address written as "3.101.0.1/24".
// FRR names a neighbour by its address alone, so the two forms must be
// reconciled before they can be compared.
func ipOnly(addr string) string {
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		return addr[:i]
	}
	return addr
}

// routeServerOn finds the address of the exchange's route server on the segment
// an interface is attached to.
//
// At an exchange the members share an L2 fabric rather than peering
// point-to-point, so the interface on the far side of a member's link is a
// switch port, not the route server. Using the far side's address made the
// grader look for a policy bound to a neighbour that does not exist, and it
// failed the reference solution -- whose configuration was right.
func routeServerOn(top *model.Topology, i *model.Iface) (string, int) {
	if i.Link == nil {
		return "", 0
	}
	seg := i.Link.Segment
	for _, l := range top.Links {
		if l.Segment == "" || l.Segment != seg {
			continue
		}
		for _, side := range []*model.Iface{l.A, l.B} {
			if side == nil || side.Device == nil || side.Addr4 == "" {
				continue
			}
			as := top.ASes[side.Device.ASN]
			if as == nil || as.Role != model.RoleIXP {
				continue
			}
			return ipOnly(side.Addr4), side.Device.ASN
		}
	}
	return "", 0
}

// runningConfigs reads the configuration of every router in the AS under test.
//
// An absence-based check concludes something from what it does not find: "no
// forbidden network is advertised into OSPF", "nothing denies routes without a
// ROA". If a router's configuration could not be read, then what the check did
// not find includes everything on that router, and the conclusion is unfounded.
//
// Three such checks used to skip the unreadable router and pass anyway, so a
// submission whose FRR was not running at all scored full marks on every
// question phrased as a prohibition -- and the mark was indistinguishable from
// a correct answer, so nobody had any reason to look. Reading every router up
// front, and refusing to conclude anything if one is missing, is what makes
// "we did not see it" mean "it is not there".
func runningConfigs(ctx context.Context, env *Env) (map[string]string, error) {
	routers := env.Routers()
	if len(routers) == 0 {
		return nil, fmt.Errorf("AS %d has no routers", env.AS)
	}
	cfgs := make(map[string]string, len(routers))
	var unreadable []string
	for _, r := range routers {
		out, err := env.Vtysh(ctx, r.Name, "show running-config")
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		cfgs[r.Name] = out
	}
	if len(unreadable) > 0 {
		sort.Strings(unreadable)
		return cfgs, fmt.Errorf("the configuration of %d of %d routers could not be read, so "+
			"nothing can be concluded from its absence:\n%s",
			len(unreadable), len(routers), strings.Join(unreadable, "\n"))
	}
	return cfgs, nil
}

// asPathListLen counts the terms of a named AS-path access-list.
//
// A route-map that matches a list nobody defined, or one with no terms, never
// matches anything -- and the check that only looked for the words "match
// as-path" gave full marks for exactly that.
func (c *frrConfig) asPathListLen(name string) int {
	n := 0
	for _, line := range strings.Split(c.raw, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		// bgp as-path access-list NAME seq N permit|deny REGEX
		if len(f) >= 5 && f[0] == "bgp" && f[1] == "as-path" && f[2] == "access-list" && f[3] == name {
			n++
			continue
		}
		// ip as-path access-list NAME permit|deny REGEX
		if len(f) >= 5 && f[0] == "ip" && f[1] == "as-path" && f[2] == "access-list" && f[3] == name {
			n++
		}
	}
	return n
}

// externalNeighbours lists the neighbours in another autonomous system.
//
// A route-map that guards against invalid origins has to be attached to the
// sessions that bring routes in from outside; one attached to nothing, or to an
// internal session, does not run on anything that could be invalid.
func (f *frrConfig) externalNeighbours() []string {
	var out []string
	for addr := range f.neighborAttrs {
		// A peer-group is a template, not a session. It was being graded as
		// one: a group carrying `remote-as` appeared here in place of its
		// members, so the check read the group's policy and never looked at
		// the sessions, which are free to override it.
		if f.peerGroups[addr] {
			continue
		}
		body := f.effectiveAttrs(addr)
		if !strings.Contains(body, "remote-as") {
			continue
		}
		// "remote-as internal" and "remote-as <own asn>" are iBGP.
		if strings.Contains(body, "remote-as internal") {
			continue
		}
		// Compared as a field, not as a substring.
		//
		// "remote-as 10" contains "remote-as 1", so in AS 1 every neighbour in
		// AS 10, 100 or 140 was classified as internal -- and a check that
		// requires every *external* session to be guarded then skipped exactly
		// the sessions that matter.
		if f.localAS != 0 && hasRemoteAS(body, f.localAS) {
			continue
		}
		out = append(out, addr)
	}
	sort.Strings(out)
	return out
}

// denyMatches reports whether a route-map body contains a deny clause that
// matches the given condition.
//
// The direction of a clause is what decides what it does. Looking only for the
// words of the match awarded the mark to a permit clause, which lets the very
// routes the question is about straight through.
func denyMatches(body, condition string) bool {
	// Route-maps are evaluated in sequence order, first match wins, and a
	// clause with no match statements matches everything.
	//
	// This walked the clauses in the order they appeared and asked only
	// whether *some* deny clause mentioned the condition. So a permit at
	// sequence 10 that matches every route, followed by a deny at 20 that
	// matches invalid origins, counted as protection -- when the deny is
	// unreachable and the policy accepts everything.
	type clause struct {
		seq     int
		deny    bool
		matches []string
	}
	var clauses []clause
	cur := -1
	for _, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(strings.ToLower(line))
		switch {
		case strings.HasPrefix(t, "route-map "):
			f := strings.Fields(t)
			seq := 0
			if len(f) >= 4 {
				seq, _ = strconv.Atoi(f[3])
			}
			clauses = append(clauses, clause{seq: seq, deny: len(f) >= 3 && f[2] == "deny"})
			cur = len(clauses) - 1
		case strings.HasPrefix(t, "match ") && cur >= 0:
			clauses[cur].matches = append(clauses[cur].matches, t)
		}
	}
	sort.SliceStable(clauses, func(i, j int) bool { return clauses[i].seq < clauses[j].seq })

	want := strings.ToLower(condition)
	for _, c := range clauses {
		// A clause with no match statements matches everything, so nothing
		// after it is ever reached.
		if len(c.matches) == 0 {
			return false
		}
		// A permit clause reached first is a way in. Route-maps stop at the
		// first clause that matches, so `permit 4: match ip address
		// prefix-list EVERYTHING-BUT-THE-ONE-THEY-TEST` in front of the deny
		// admits every invalid route but the one the grader knows about. A
		// preceding permit is only harmless when nothing it matches on could
		// be true of a route in the state being denied -- which is to say,
		// when it selects on the validation state itself.
		if !c.deny && !onlyValidationMatches(c.matches, want) {
			return false
		}
		for _, m := range c.matches {
			if !strings.Contains(m, want) {
				continue
			}
			// FRR requires every match in a clause to hold, so a second one
			// narrows the first. A deny clause that matches `rpki invalid`
			// *and* a prefix list rejects invalid routes from that list and
			// accepts every other invalid route -- which was measured as full
			// protection, because the check stopped at the words it was
			// looking for and the one announcement it then tested was on the
			// list. A condition narrowed by something else is not that
			// condition.
			if len(c.matches) > 1 {
				return false
			}
			return c.deny
		}
	}
	return false
}

// onlyValidationMatches reports whether every match in a clause selects on the
// RPKI validation state, and on a state other than the one being asked about.
//
// Such a clause cannot be the way an invalid route gets in: it does not match
// one. Anything else -- a prefix list, an AS path, a community -- can be true
// of an invalid route as easily as of a valid one.
func onlyValidationMatches(matches []string, want string) bool {
	for _, m := range matches {
		t := strings.TrimSpace(strings.ToLower(m))
		if !strings.HasPrefix(t, "match rpki ") || strings.Contains(t, want) {
			return false
		}
	}
	return len(matches) > 0
}

// hasRemoteAS reports whether a neighbour's settings name this AS number,
// comparing the number as a whole field.
func hasRemoteAS(body string, asn int) bool {
	want := strconv.Itoa(asn)
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "remote-as" && f[i+1] == want {
				return true
			}
		}
	}
	return false
}
