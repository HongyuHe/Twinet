package render

import (
	"container/heap"
	"sort"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

// The reference solution must contain the OSPF costs that make the
// load-balancing question's three paths equal. Without them `twinet solve`
// silently produces a network that fails the platform's own rubric.
func TestReferenceSolutionSetsECMPCosts(t *testing.T) {
	top := loadCOS461(t)
	d, ok := top.DeviceInAS(3, "ATL")
	if !ok {
		t.Fatal("AS3 has no router ATL")
	}
	cfg, err := Router(top, d)
	if err != nil {
		t.Fatal(err)
	}
	all := cfg.Platform + cfg.Expected
	for _, want := range []string{"ip ospf cost 20", "ip ospf cost 10"} {
		if !strings.Contains(all, want) {
			t.Errorf("the reference config for ATL lacks %q\n---\n%s", want, all)
		}
	}
}

// TestReferenceECMPArithmetic is the important one: it computes shortest paths
// through the real topology under the reference costs and asserts that exactly
// the three prescribed paths are equal-cost.
//
// The costs were wrong once in a way that no amount of "is the line present"
// testing would have caught: two map keys were written in the opposite order to
// the lookup, so their costs silently defaulted and one of the three paths never
// appeared. Checking the arithmetic against the topology catches that class of
// mistake, and also fails loudly if the topology is edited without revisiting
// the answer.
func TestReferenceECMPArithmetic(t *testing.T) {
	top := loadCOS461(t)

	adj := map[string]map[string]int{}
	for _, l := range top.Links {
		if l.InterAS || l.A.Device.ASN != 3 || l.B.Device.ASN != 3 {
			continue
		}
		if !l.A.Device.IsRouter() || !l.B.Device.IsRouter() {
			continue
		}
		a, b := l.A.Device.Name, l.B.Device.Name
		if adj[a] == nil {
			adj[a] = map[string]int{}
		}
		if adj[b] == nil {
			adj[b] = map[string]int{}
		}
		// A cost applies to the outgoing interface; the reference gives both
		// directions the same value.
		adj[a][b] = LinkCost(a, b)
		adj[b][a] = LinkCost(a, b)
	}
	if len(adj) == 0 {
		t.Fatal("no intra-AS router links found")
	}

	const src, dst = "ATL", "BOS"
	want := [][]string{
		{"ATL", "BOS"},
		{"ATL", "PHY", "BOS"},
		{"ATL", "PHY", "NYC", "BOS"},
	}

	best, ok := dijkstra(adj, src)[dst]
	if !ok {
		t.Fatalf("no path from %s to %s", src, dst)
	}

	for _, p := range want {
		c := pathCost(adj, p)
		if c != best {
			t.Errorf("path %s costs %d but the shortest path costs %d; all three prescribed paths must tie",
				strings.Join(p, "-"), c, best)
		}
	}

	// No other simple path may tie, or the network offers four equal paths
	// while the assignment asks for three.
	var extras []string
	for _, p := range allSimplePaths(adj, src, dst, 6) {
		if pathCost(adj, p) != best || containsPath(want, p) {
			continue
		}
		extras = append(extras, strings.Join(p, "-"))
	}
	sort.Strings(extras)
	if len(extras) > 0 {
		t.Errorf("these unintended paths also cost %d: %s", best, strings.Join(extras, ", "))
	}
}

func loadCOS461(t *testing.T) *model.Topology {
	t.Helper()
	l, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Skipf("cos461 lab unavailable: %v", err)
	}
	if d := l.Validate(); d.HasErrors() {
		t.Fatalf("cos461 lab is invalid: %v", d.Err())
	}
	res, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	return res.Topology
}

func pathCost(adj map[string]map[string]int, path []string) int {
	total := 0
	for i := 0; i+1 < len(path); i++ {
		c, ok := adj[path[i]][path[i+1]]
		if !ok {
			return -1
		}
		total += c
	}
	return total
}

func containsPath(set [][]string, p []string) bool {
	for _, q := range set {
		if len(q) != len(p) {
			continue
		}
		same := true
		for i := range q {
			if q[i] != p[i] {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}

// allSimplePaths enumerates simple paths up to a hop limit, which is ample for
// an eight-router backbone and keeps the test instant.
func allSimplePaths(adj map[string]map[string]int, src, dst string, maxHops int) [][]string {
	var out [][]string
	var walk func(cur string, path []string, seen map[string]bool)
	walk = func(cur string, path []string, seen map[string]bool) {
		if len(path) > maxHops {
			return
		}
		if cur == dst && len(path) > 1 {
			out = append(out, append([]string{}, path...))
			return
		}
		next := make([]string, 0, len(adj[cur]))
		for n := range adj[cur] {
			next = append(next, n)
		}
		sort.Strings(next)
		for _, n := range next {
			if seen[n] {
				continue
			}
			seen[n] = true
			walk(n, append(path, n), seen)
			delete(seen, n)
		}
	}
	walk(src, []string{src}, map[string]bool{src: true})
	return out
}

// dijkstra returns shortest-path distances from src.
func dijkstra(adj map[string]map[string]int, src string) map[string]int {
	dist := map[string]int{src: 0}
	pq := &nodeHeap{{src, 0}}
	heap.Init(pq)
	for pq.Len() > 0 {
		cur := heap.Pop(pq).(nodeDist)
		if d, ok := dist[cur.name]; ok && cur.dist > d {
			continue
		}
		for n, w := range adj[cur.name] {
			nd := cur.dist + w
			if d, ok := dist[n]; !ok || nd < d {
				dist[n] = nd
				heap.Push(pq, nodeDist{n, nd})
			}
		}
	}
	return dist
}

type nodeDist struct {
	name string
	dist int
}

type nodeHeap []nodeDist

func (h nodeHeap) Len() int           { return len(h) }
func (h nodeHeap) Less(i, j int) bool { return h[i].dist < h[j].dist }
func (h nodeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *nodeHeap) Push(x any)        { *h = append(*h, x.(nodeDist)) }
func (h *nodeHeap) Pop() any {
	old := *h
	n := len(old)
	v := old[n-1]
	*h = old[:n-1]
	return v
}
