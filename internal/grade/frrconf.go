package grade

import (
	"context"
	"fmt"
	"sort"
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
	// neighborMaps records, per neighbour address, the route-maps bound to it
	// in each direction.
	neighborMaps map[string]map[string]string // addr -> direction -> map name
	// neighborAttrs records other per-neighbour settings, e.g. "route-reflector-client".
	neighborAttrs map[string][]string
}

func parseFRR(cfg string) *frrConfig {
	f := &frrConfig{
		raw:           cfg,
		routeMaps:     map[string][]string{},
		neighborMaps:  map[string]map[string]string{},
		neighborAttrs: map[string][]string{},
	}
	var currentMap string
	for _, line := range strings.Split(cfg, "\n") {
		t := strings.TrimSpace(line)
		fields := strings.Fields(t)
		switch {
		case len(fields) >= 3 && fields[0] == "route-map":
			// "route-map NAME permit 10"
			currentMap = fields[1]
			if _, ok := f.routeMaps[currentMap]; !ok {
				f.routeMaps[currentMap] = nil
			}
			continue
		case t == "exit" || t == "!" || t == "":
			currentMap = ""
			continue
		case len(fields) >= 2 && fields[0] == "neighbor":
			addr := fields[1]
			// "neighbor X route-map NAME in|out"
			if len(fields) >= 5 && fields[2] == "route-map" {
				dir := fields[4]
				if f.neighborMaps[addr] == nil {
					f.neighborMaps[addr] = map[string]string{}
				}
				// FRR keeps only the last binding per direction, so a later
				// line replaces an earlier one exactly as the router does.
				f.neighborMaps[addr][dir] = fields[3]
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

// mapFor returns the route-map bound to a neighbour in one direction.
func (f *frrConfig) mapFor(addr, dir string) string {
	if m, ok := f.neighborMaps[addr]; ok {
		return m[dir]
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
func (f *frrConfig) hasNeighbor(addr string) bool {
	_, ok := f.neighborAttrs[addr]
	return ok
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
