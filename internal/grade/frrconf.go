package grade

import (
	"strings"
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
