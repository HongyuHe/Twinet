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
