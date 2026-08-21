package svc

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

// The connectivity matrix and the looking glass.
//
// Both were per-container daemons in the platform this replaces: a matrix
// container that fanned a hundred concurrent pings out of one process, and a
// looking-glass loop inside every one of a thousand routers writing a text file
// every thirty seconds. Both are collectors, so both belong in the control
// plane: the work is spread across the agents that are already next to the
// containers, the output is structured rather than scraped, and no router needs
// a background process at all.

// Reach is the state of one ordered AS pair.
type Reach string

const (
	// ReachOK means the destination answered and the path respects the
	// business relationships.
	ReachOK Reach = "ok"
	// ReachInvalid means the destination answered but the path violates the
	// relationships, which is the orange cell students chase.
	ReachInvalid Reach = "invalid"
	// ReachDown means no answer.
	ReachDown Reach = "down"
	// ReachUnknown means the probe itself could not run.
	ReachUnknown Reach = "unknown"
)

// Cell is one matrix entry.
type Cell struct {
	From   int     `json:"from"`
	To     int     `json:"to"`
	State  Reach   `json:"state"`
	RTTms  float64 `json:"rtt_ms,omitempty"`
	Detail string  `json:"detail,omitempty"`
}

// Matrix is a full connectivity snapshot.
type Matrix struct {
	Lab       string    `json:"lab"`
	TakenAt   time.Time `json:"taken_at"`
	Duration  string    `json:"duration"`
	ASNs      []int     `json:"asns"`
	Cells     []Cell    `json:"cells"`
	Reachable int       `json:"reachable"`
	Total     int       `json:"total"`
}

// Percent is the share of pairs that are reachable.
func (m *Matrix) Percent() float64 {
	if m.Total == 0 {
		return 0
	}
	return 100 * float64(m.Reachable) / float64(m.Total)
}

// Prober runs a reachability probe from one device.
type Prober func(ctx context.Context, deviceID string, target string) (bool, float64, error)

// BatchProbeResult is one target result returned by a single source-side
// container exec. Err means the target's probe could not run; Reachable=false
// with no Err means the target did not answer.
type BatchProbeResult struct {
	Reachable bool
	RTTms     float64
	Err       error
}

// SourceBatchProber probes every supplied target from one source using at
// most one container exec. The map keys are ASNs, not addresses, so an omitted
// key is detectable as unknown rather than silently becoming down.
type SourceBatchProber func(ctx context.Context, deviceID string,
	targets map[int]string) (map[int]BatchProbeResult, error)

// BatchPathResult is one source-side route-policy observation.
type BatchPathResult struct {
	Path []int
	Err  error
}

// SourceBatchPathProbe obtains the path observations for every supplied
// target using at most one additional container exec from that source.
type SourceBatchPathProbe func(ctx context.Context, deviceID string,
	targets map[int]string) (map[int]BatchPathResult, error)

// MatrixTargets picks, for each AS, the address every other AS should be able
// to reach: the host attached to its first router, which is inside the AS's own
// advertised prefix and therefore only reachable if routing genuinely works.
func MatrixTargets(top *model.Topology) map[int]string {
	out := map[int]string{}
	for _, asn := range top.SortedASNs() {
		as := top.ASes[asn]
		if as.Role == model.RoleIXP {
			continue
		}
		for _, d := range as.Devices {
			if d.Kind != model.KindHost || d.L2Domain != "" {
				continue
			}
			for _, i := range d.Ifaces {
				if i.Addr4 == "" {
					continue
				}
				out[asn] = strings.SplitN(i.Addr4, "/", 2)[0]
				break
			}
			if out[asn] != "" {
				break
			}
		}
	}
	return out
}

// matrixSource picks the device each AS probes from.
func matrixSource(top *model.Topology, asn int) string {
	as, ok := top.ASes[asn]
	if !ok {
		return ""
	}
	for _, d := range as.Devices {
		if d.Kind == model.KindHost && d.L2Domain == "" {
			return d.ID
		}
	}
	return ""
}

// BuildMatrix probes every ordered AS pair concurrently.
//
// The fan-out is bounded but wide: at class scale this is thousands of probes,
// and running them from one container in sequence is what made the previous
// matrix minutes stale.
func BuildMatrix(ctx context.Context, top *model.Topology, probe Prober, parallel int) *Matrix {
	return BuildMatrixWithPaths(ctx, top, probe, nil, parallel)
}

// PathProbe returns the AS path the source uses to reach an autonomous system,
// origin last, excluding the source itself.
type PathProbe func(ctx context.Context, deviceID string, to int) ([]int, error)

// BuildMatrixWithPaths additionally marks pairs whose route violates the
// business relationships the topology declares.
func BuildMatrixWithPaths(ctx context.Context, top *model.Topology, probe Prober,
	path PathProbe, parallel int) *Matrix {
	if parallel <= 0 {
		parallel = 64
	}
	start := time.Now()
	targets := MatrixTargets(top)
	asns := make([]int, 0, len(targets))
	for a := range targets {
		asns = append(asns, a)
	}
	sort.Ints(asns)

	type job struct{ from, to int }
	var jobs []job
	for _, a := range asns {
		for _, b := range asns {
			if a != b {
				jobs = append(jobs, job{a, b})
			}
		}
	}

	cells := make([]Cell, len(jobs))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			c := Cell{From: j.from, To: j.to, State: ReachUnknown}
			src := matrixSource(top, j.from)
			if src == "" {
				c.Detail = "no probe source in this AS"
				cells[i] = c
				return
			}
			ok, rtt, err := probe(ctx, src, targets[j.to])
			switch {
			case err != nil:
				c.State, c.Detail = ReachUnknown, err.Error()
			case ok:
				c.State, c.RTTms = ReachOK, rtt
				// Reachable is not the same as correct.
				//
				// ReachInvalid was declared as "the orange cell students
				// chase" and never produced by anything, so the matrix could
				// only ever say up or down -- and a network reachable through
				// a path that gives somebody free transit looked exactly like
				// a correct one. When the caller can supply the path, it is
				// checked against the relationships the topology declares.
				if path != nil {
					p, perr := path(ctx, src, j.to)
					switch {
					case perr != nil:
						c.Detail = "the path could not be read: " + perr.Error()
					case len(p) > 0:
						if why := violatesRelationships(top, j.from, p); why != "" {
							c.State, c.Detail = ReachInvalid, why
						}
					}
				}
			default:
				c.State = ReachDown
			}
			cells[i] = c
		}(i, j)
	}
	wg.Wait()

	m := &Matrix{
		Lab: top.Name, TakenAt: time.Now().UTC(),
		Duration: time.Since(start).Round(time.Millisecond).String(),
		ASNs:     asns, Cells: cells, Total: len(cells),
	}
	for _, c := range cells {
		if c.State == ReachOK {
			m.Reachable++
		}
	}
	return m
}

// BuildMatrixWithSourceBatches computes the same reachability and policy
// verdicts as BuildMatrixWithPaths while asking each source AS for its entire
// target set at once. A refresh of N ASes therefore uses at most two container
// execs per source (one reachability batch and one route-policy batch), not
// O(N²) execs. Errors remain unknown rather than becoming false down cells.
func BuildMatrixWithSourceBatches(ctx context.Context, top *model.Topology,
	probe SourceBatchProber, path SourceBatchPathProbe, parallel int,
) *Matrix {
	if parallel <= 0 {
		parallel = 32
	}
	start := time.Now()
	targets := MatrixTargets(top)
	asns := make([]int, 0, len(targets))
	for asn := range targets {
		asns = append(asns, asn)
	}
	sort.Ints(asns)

	type sourceResult struct {
		cells []Cell
	}
	results := make([]sourceResult, len(asns))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for index, from := range asns {
		wg.Add(1)
		go func(index, from int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			source := matrixSource(top, from)
			want := make(map[int]string, len(asns)-1)
			for _, to := range asns {
				if to != from {
					want[to] = targets[to]
				}
			}
			result := sourceResult{cells: make([]Cell, 0, len(want))}
			if source == "" {
				for _, to := range asns {
					if to != from {
						result.cells = append(result.cells, Cell{
							From: from, To: to, State: ReachUnknown,
							Detail: "no probe source in this AS",
						})
					}
				}
				results[index] = result
				return
			}
			if probe == nil {
				for _, to := range asns {
					if to != from {
						result.cells = append(result.cells, Cell{
							From: from, To: to, State: ReachUnknown,
							Detail: "no source batch prober is configured",
						})
					}
				}
				results[index] = result
				return
			}
			probes, probeErr := probe(ctx, source, want)
			var paths map[int]BatchPathResult
			var pathErr error
			if path != nil && probeErr == nil {
				paths, pathErr = path(ctx, source, want)
			}
			for _, to := range asns {
				if to == from {
					continue
				}
				cell := Cell{From: from, To: to, State: ReachUnknown}
				switch {
				case probeErr != nil:
					cell.Detail = probeErr.Error()
				case probes == nil:
					cell.Detail = "source batch probe returned no results"
				default:
					observation, found := probes[to]
					switch {
					case !found:
						cell.Detail = "source batch probe did not report this target"
					case observation.Err != nil:
						cell.Detail = observation.Err.Error()
					case !observation.Reachable:
						cell.State = ReachDown
					default:
						cell.State, cell.RTTms = ReachOK, observation.RTTms
						if path != nil {
							switch {
							case pathErr != nil:
								cell.Detail = "the path could not be read: " + pathErr.Error()
							case paths == nil:
								cell.Detail = "the path batch returned no results"
							case paths[to].Err != nil:
								cell.Detail = "the path could not be read: " + paths[to].Err.Error()
							case len(paths[to].Path) > 0:
								if why := violatesRelationships(top, from, paths[to].Path); why != "" {
									cell.State, cell.Detail = ReachInvalid, why
								}
							}
						}
					}
				}
				result.cells = append(result.cells, cell)
			}
			results[index] = result
		}(index, from)
	}
	wg.Wait()

	cells := make([]Cell, 0, len(asns)*(len(asns)-1))
	for _, result := range results {
		cells = append(cells, result.cells...)
	}
	m := &Matrix{
		Lab: top.Name, TakenAt: time.Now().UTC(),
		Duration: time.Since(start).Round(time.Millisecond).String(),
		ASNs:     asns, Cells: cells, Total: len(cells),
	}
	for _, cell := range cells {
		if cell.State == ReachOK {
			m.Reachable++
		}
	}
	return m
}

// JSON renders the matrix.
func (m *Matrix) JSON() ([]byte, error) { return json.MarshalIndent(m, "", "  ") }

// ---------------------------------------------------------------------------
// Looking glass
// ---------------------------------------------------------------------------

// LookingGlass is a routing snapshot of one router.
type LookingGlass struct {
	AS      int       `json:"as"`
	Router  string    `json:"router"`
	TakenAt time.Time `json:"taken_at"`
	// Routes is the BGP table, prefix to paths.
	Routes map[string][]LGPath `json:"routes"`
	Err    string              `json:"error,omitempty"`
}

// LGPath is one path for one prefix.
type LGPath struct {
	Path      string `json:"path"`
	NextHop   string `json:"next_hop"`
	LocalPref int    `json:"local_pref"`
	Best      bool   `json:"best"`
	Origin    string `json:"origin,omitempty"`
	Community string `json:"community,omitempty"`
}

// Collector fetches a router's BGP table as raw JSON.
type Collector func(ctx context.Context, deviceID string) ([]byte, error)

// CollectLookingGlass gathers routing state across the lab.
func CollectLookingGlass(ctx context.Context, top *model.Topology, c Collector, parallel int) []LookingGlass {
	if parallel <= 0 {
		parallel = 32
	}
	var routers []*model.Device
	for _, asn := range top.SortedASNs() {
		routers = append(routers, top.ASes[asn].Routers...)
	}

	out := make([]LookingGlass, len(routers))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, r := range routers {
		wg.Add(1)
		go func(i int, r *model.Device) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			lg := LookingGlass{AS: r.ASN, Router: r.Name, TakenAt: time.Now().UTC(),
				Routes: map[string][]LGPath{}}
			raw, err := c(ctx, r.ID)
			if err != nil {
				lg.Err = err.Error()
				out[i] = lg
				return
			}
			if err := parseBGPTable(raw, &lg); err != nil {
				lg.Err = err.Error()
			}
			out[i] = lg
		}(i, r)
	}
	wg.Wait()
	return out
}

// parseBGPTable decodes FRR's `show ip bgp json`.
func parseBGPTable(raw []byte, lg *LookingGlass) error {
	var doc struct {
		Routes map[string][]struct {
			Path      string `json:"path"`
			LocalPref int    `json:"locPrf"`
			BestPath  bool   `json:"bestpath"`
			Origin    string `json:"origin"`
			Nexthops  []struct {
				IP string `json:"ip"`
			} `json:"nexthops"`
			Community *struct {
				String string `json:"string"`
			} `json:"community"`
		} `json:"routes"`
	}
	s := strings.TrimSpace(string(raw))
	if i := strings.IndexByte(s, '{'); i > 0 {
		s = s[i:]
	}
	if s == "" {
		return fmt.Errorf("the router returned no output")
	}
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		return fmt.Errorf("parse BGP table: %w", err)
	}
	for prefix, paths := range doc.Routes {
		for _, p := range paths {
			lp := LGPath{Path: strings.TrimSpace(p.Path), LocalPref: p.LocalPref,
				Best: p.BestPath, Origin: p.Origin}
			if len(p.Nexthops) > 0 {
				lp.NextHop = p.Nexthops[0].IP
			}
			if p.Community != nil {
				lp.Community = p.Community.String
			}
			lg.Routes[prefix] = append(lg.Routes[prefix], lp)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// BGP policy analyzer
// ---------------------------------------------------------------------------

// Leak is a detected violation of the business relationships.
type Leak struct {
	AS       int    `json:"as"`
	Router   string `json:"router"`
	Prefix   string `json:"prefix"`
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

// AnalysePolicy infers policy violations from the collected routing state.
//
// The analyzer in the platform this replaces parsed looking-glass *text* and
// had no access to the topology, so it could only guess at relationships. Here
// it reads structured paths and the relationships are declared in the model, so
// a route leak is detected by definition rather than by heuristic.
func AnalysePolicy(top *model.Topology, lgs []LookingGlass) []Leak {
	// Which AS is a customer of which, from the model.
	customersOf := map[int]map[int]bool{}
	relOf := map[[2]int]model.Relationship{}
	for _, l := range top.Links {
		if !l.InterAS || l.A == nil || l.B == nil {
			continue
		}
		a, b := l.A.Device.ASN, l.B.Device.ASN
		relOf[[2]int{a, b}] = l.Rel
		relOf[[2]int{b, a}] = l.Rel.Inverse()
		if l.Rel == model.RelProvider {
			if customersOf[a] == nil {
				customersOf[a] = map[int]bool{}
			}
			customersOf[a][b] = true
		}
		if l.Rel == model.RelCustomer {
			if customersOf[b] == nil {
				customersOf[b] = map[int]bool{}
			}
			customersOf[b][a] = true
		}
	}

	var leaks []Leak
	for _, lg := range lgs {
		if lg.Err != "" {
			continue
		}
		for prefix, paths := range lg.Routes {
			for _, p := range paths {
				if !p.Best || p.Path == "" {
					continue
				}
				hops := strings.Fields(p.Path)
				// A valley-free path rises through providers, crosses at most
				// one peer link, then descends through customers. Two peer
				// links, or a peer link after a descent, means somebody is
				// providing transit they never agreed to.
				if v, why := valleyFree(hops, relOf); !v {
					leaks = append(leaks, Leak{
						AS: lg.AS, Router: lg.Router, Prefix: prefix,
						Path: p.Path, Kind: "route-leak", Detail: why,
						Severity: "warning",
					})
				}
			}
		}
	}
	sort.Slice(leaks, func(i, j int) bool {
		if leaks[i].AS != leaks[j].AS {
			return leaks[i].AS < leaks[j].AS
		}
		return leaks[i].Prefix < leaks[j].Prefix
	})
	return leaks
}

// valleyFree checks an AS path against the Gao-Rexford shape.
func valleyFree(hops []string, relOf map[[2]int]model.Relationship) (bool, string) {
	if len(hops) < 3 {
		return true, ""
	}
	peerSeen := false
	descending := false
	for i := 0; i+1 < len(hops); i++ {
		a, b := atoiSafe(hops[i]), atoiSafe(hops[i+1])
		if a == 0 || b == 0 {
			continue
		}
		rel, ok := relOf[[2]int{a, b}]
		if !ok {
			continue
		}
		switch rel {
		case model.RelPeer:
			if peerSeen {
				return false, fmt.Sprintf("the path crosses two peer links (AS%d-AS%d)", a, b)
			}
			if descending {
				return false, fmt.Sprintf("a peer link appears after a customer link (AS%d-AS%d)", a, b)
			}
			peerSeen = true
		case model.RelCustomer:
			descending = true
		case model.RelProvider:
			if peerSeen || descending {
				return false, fmt.Sprintf("the path climbs to a provider after peering or descending (AS%d-AS%d)", a, b)
			}
		}
	}
	return true, ""
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// violatesRelationships reports why an AS path is not valley-free, or "" when
// it is.
//
// Gao-Rexford: from the source, a path may climb to providers, cross at most
// one peering, and then descend to customers. Anything else means somebody on
// the path is providing transit they are not paid for -- which is exactly what
// the export policy exercises are about, and what an orange cell in the
// original mini-Internet's matrix meant.
func violatesRelationships(top *model.Topology, from int, path []int) string {
	rel := relationshipMap(top)
	if relationshipMapForTest != nil {
		rel = relationshipMapForTest
	}
	const (
		climbing = iota
		crossed
		descending
	)
	state := climbing
	prev := from
	for _, next := range path {
		if next == prev {
			continue // prepends
		}
		r, ok := rel[prev][next]
		if !ok {
			// Not adjacent in the model: an exchange sits between them, or the
			// path crosses a system this lab does not describe. Nothing can be
			// concluded, so nothing is claimed.
			prev = next
			continue
		}
		switch r {
		case model.RelProvider:
			if state != climbing {
				return fmt.Sprintf("AS %d reaches its provider AS %d after already "+
					"leaving the customer cone, so somebody on this path is carrying "+
					"transit they are not paid for", prev, next)
			}
		case model.RelPeer:
			if state != climbing {
				return fmt.Sprintf("the path crosses the peering between AS %d and AS %d "+
					"after having already crossed one, which no correct export policy allows",
					prev, next)
			}
			state = crossed
		case model.RelCustomer:
			state = descending
		}
		prev = next
	}
	return ""
}

// relationshipMapForTest lets the valley-free rule be tested against a set of
// relationships directly, rather than against a topology built to produce them.
var relationshipMapForTest map[int]map[int]model.Relationship

// relationshipMap says what each AS is to each of its neighbours.
func relationshipMap(top *model.Topology) map[int]map[int]model.Relationship {
	out := map[int]map[int]model.Relationship{}
	for _, l := range top.Links {
		if l.A == nil || l.B == nil || l.A.Device == nil || l.B.Device == nil {
			continue
		}
		a, b := l.A.Device.ASN, l.B.Device.ASN
		if a == b || a == 0 || b == 0 {
			continue
		}
		if out[a] == nil {
			out[a] = map[int]model.Relationship{}
		}
		if out[b] == nil {
			out[b] = map[int]model.Relationship{}
		}
		out[a][b] = l.PeerRelationship(l.A)
		out[b][a] = l.PeerRelationship(l.B)
	}
	return out
}
