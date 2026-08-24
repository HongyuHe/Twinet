package place

import (
	"sort"

	"github.com/HongyuHe/twinet/internal/model"
)

// affinityGraph counts, for each pair of autonomous systems, how many links run
// between them.
//
// This is the graph the placer partitions. Every edge it can keep inside one
// node is a veth pair instead of a VXLAN tunnel: no encapsulation, no MTU
// reduction, no dependence on the fabric being up, and nothing to go wrong when
// a node is rebooted. The package documentation calls minimising these the
// point of AS-granular placement, and for a long time nothing did it -- both
// strategies simply put each AS on whichever node was emptiest, which is the
// arrangement that maximises them.
type affinityGraph struct {
	// peers[a][b] is the number of links between AS a and AS b.
	peers map[int]map[int]int
	// svc[a][node] is the number of service links AS a can keep local by
	// joining a replica on node. legacySvc retains the historic front-node
	// pull for a singleton whose placement has not yet been assigned.
	svc       map[int]map[string]int
	legacySvc map[int]int
}

func buildAffinity(top *model.Topology) *affinityGraph {
	g := &affinityGraph{
		peers: map[int]map[int]int{}, svc: map[int]map[string]int{}, legacySvc: map[int]int{},
	}
	for _, l := range top.Links {
		a, b := l.A, l.B
		if a == nil || b == nil || a.Device == nil || b.Device == nil {
			continue
		}
		x, y := a.Device.ASN, b.Device.ASN
		if x == y {
			continue
		}
		if x == 0 || y == 0 {
			// A service link. A scalable replica already carries its preferred
			// node during expansion, so its pull rewards local attachment
			// rather than concentrating every AS on FrontNode.
			var service *model.Device
			if x == 0 && y != 0 {
				service = a.Device
				if service.Node != "" {
					if g.svc[y] == nil {
						g.svc[y] = map[string]int{}
					}
					g.svc[y][service.Node]++
				} else {
					g.legacySvc[y]++
				}
			} else if y == 0 && x != 0 {
				service = b.Device
				if service.Node != "" {
					if g.svc[x] == nil {
						g.svc[x] = map[string]int{}
					}
					g.svc[x][service.Node]++
				} else {
					g.legacySvc[x]++
				}
			}
			continue
		}
		if g.peers[x] == nil {
			g.peers[x] = map[int]int{}
		}
		if g.peers[y] == nil {
			g.peers[y] = map[int]int{}
		}
		g.peers[x][y]++
		g.peers[y][x]++
	}
	return g
}

// degree is how many inter-AS links an AS has, used to decide which one to
// place first.
func (g *affinityGraph) degree(asn int) int {
	n := 0
	for _, c := range g.peers[asn] {
		n += c
	}
	return n
}

// pull is how many links AS asn would keep local by joining node n.
func (g *affinityGraph) pull(asn int, n string, byAS map[int]string, front string) int {
	score := 0
	for peer, count := range g.peers[asn] {
		if byAS[peer] == n {
			score += count
		}
	}
	score += g.svc[asn][n]
	if n == front {
		score += g.legacySvc[asn]
	}
	return score
}

// orderForLocality returns the unplaced ASes in the order the partitioner
// should consider them.
//
// Weight-descending order, which is right for bin-packing alone, is wrong here:
// it walks the peering graph in an arbitrary order, so by the time an AS is
// placed most of its neighbours are still unplaced and there is no locality to
// exploit. Growing outwards from a seed instead means each AS is placed while
// its neighbours are known, which is what makes the greedy choice informative.
//
// Ties are broken by AS number throughout, so the order -- and therefore the
// placement -- is identical for the same manifest on every run. A placement
// that shuffled between runs would rebuild containers students are working in.
func orderForLocality(free []int, g *affinityGraph, weight map[int]demand) []int {
	remaining := map[int]bool{}
	for _, a := range free {
		remaining[a] = true
	}
	// Seeds: highest degree first, then heaviest, then lowest AS number.
	seeds := append([]int(nil), free...)
	sort.SliceStable(seeds, func(i, j int) bool {
		di, dj := g.degree(seeds[i]), g.degree(seeds[j])
		if di != dj {
			return di > dj
		}
		if weight[seeds[i]].Containers != weight[seeds[j]].Containers {
			return weight[seeds[i]].Containers > weight[seeds[j]].Containers
		}
		return seeds[i] < seeds[j]
	})

	order := make([]int, 0, len(free))
	// linked counts, for each AS still waiting, how many links it has to
	// already-ordered ASes. The frontier is grown by that count.
	linked := map[int]int{}
	for _, seed := range seeds {
		if !remaining[seed] {
			continue
		}
		remaining[seed] = false
		order = append(order, seed)
		for p, c := range g.peers[seed] {
			if remaining[p] {
				linked[p] += c
			}
		}
		for {
			next, bestLink, bestWeight := 0, 0, 0
			for asn := range remaining {
				l := linked[asn]
				if l == 0 {
					continue
				}
				w := weight[asn].Containers
				if next == 0 || l > bestLink ||
					(l == bestLink && w > bestWeight) ||
					(l == bestLink && w == bestWeight && asn < next) {
					next, bestLink, bestWeight = asn, l, w
				}
			}
			if next == 0 {
				break
			}
			remaining[next] = false
			delete(linked, next)
			order = append(order, next)
			for p, c := range g.peers[next] {
				if remaining[p] {
					linked[p] += c
				}
			}
		}
	}
	return order
}

// refine improves a placement by moving and swapping autonomous systems between
// nodes while keeping the cluster balanced.
//
// A single greedy pass places each AS knowing only the ones before it, so it
// commits early to choices that later ASes make bad. Local search repairs that:
// every move that keeps more links inside a node, and leaves the load no less
// even than the bound allows, is taken. It is the difference between a
// partition that is merely better than round-robin and one close to what the
// topology permits.
//
// Deterministic throughout -- ASes in ascending order, nodes in name order,
// strictly improving moves only, with an iteration cap -- so the same manifest
// yields the same placement on every run and redeploying never shuffles a group
// onto a different machine.
func refine(names []string, byAS map[int]string, g *affinityGraph, weight map[int]demand,
	loads map[string]demand, caps map[string]demand, hasCap map[string]bool,
	placementWeights map[string]float64, pinned map[int]string, front string,
	tolerance float64, nominal int,
) int {

	movable := make([]int, 0, len(byAS))
	for asn := range byAS {
		if _, isPinned := pinned[asn]; !isPinned {
			movable = append(movable, asn)
		}
	}
	sort.Ints(movable)
	if len(movable) < 2 {
		return 0
	}

	// The ceiling every node must stay under: an even share, widened by the
	// tolerance the strategy allows. A placement that already exceeds it --
	// because a pin does, say -- is not made worse, but neither is it used as
	// licence to go further.
	// The greedy placement is the balance baseline. Deriving an "even share"
	// by dividing the worst aggregate pressure by node count is invalid for
	// heterogeneous capacities: the smallest node's capacity is applied to
	// all cluster demand and permits the refinement to overload larger peers.
	ceiling := 0.0
	for _, n := range names {
		ceiling = max(ceiling,
			placementPressure(loads[n], caps[n], hasCap[n], nominal, placementWeights[n]))
	}
	ceiling += tolerance

	// local counts the links AS asn keeps inside node n.
	local := func(asn int, n string, at map[int]string) int {
		score := 0
		for peer, c := range g.peers[asn] {
			if at[peer] == n {
				score += c
			}
		}
		score += g.svc[asn][n]
		if n == front {
			score += g.legacySvc[asn]
		}
		return score
	}
	within := func(l demand, n string) bool {
		return fits(demand{}, l, caps[n], hasCap[n]) &&
			placementPressure(l, caps[n], hasCap[n], nominal, placementWeights[n]) <= ceiling+1e-9
	}

	moved := 0
	for round := 0; round < 8; round++ {
		improved := false

		// Moves: one AS to a different node.
		for _, asn := range movable {
			from := byAS[asn]
			gain, to := 0, ""
			for _, n := range names {
				if n == from {
					continue
				}
				delta := local(asn, n, byAS) - local(asn, from, byAS)
				if delta <= gain {
					continue
				}
				if !within(loads[n].add(weight[asn]), n) {
					continue
				}
				gain, to = delta, n
			}
			if to == "" {
				continue
			}
			byAS[asn] = to
			loads[from] = loads[from].sub(weight[asn])
			loads[to] = loads[to].add(weight[asn])
			improved, moved = true, moved+1
		}

		// Swaps: two ASes exchange nodes. This reaches arrangements a move
		// cannot, because on a balanced cluster there is often no room to move
		// into until something moves out.
		for i := 0; i < len(movable); i++ {
			for j := i + 1; j < len(movable); j++ {
				x, y := movable[i], movable[j]
				nx, ny := byAS[x], byAS[y]
				if nx == ny {
					continue
				}
				before := local(x, nx, byAS) + local(y, ny, byAS)
				byAS[x], byAS[y] = ny, nx
				after := local(x, ny, byAS) + local(y, nx, byAS)
				if after <= before {
					byAS[x], byAS[y] = nx, ny
					continue
				}
				lx := loads[nx].sub(weight[x]).add(weight[y])
				ly := loads[ny].sub(weight[y]).add(weight[x])
				if !within(lx, nx) || !within(ly, ny) {
					byAS[x], byAS[y] = nx, ny
					continue
				}
				loads[nx], loads[ny] = lx, ly
				improved, moved = true, moved+1
			}
		}

		if !improved {
			break
		}
	}
	return moved
}
