package deploy

import (
	"fmt"
	"sync/atomic"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
)

// overlayPlanBuilds counts full topology scans performed to derive multiplex
// overlay parameters. Deriving them is a pure function of the placed topology,
// so a deployment must scan once rather than once per cross-node link; the
// counter lets a test assert that bound directly instead of inferring it from
// wall-clock timing.
var overlayPlanBuilds atomic.Int64

// OverlayPlanBuilds reports how many times multiplex overlay parameters have
// been derived from a full topology scan in this process.
func OverlayPlanBuilds() int64 { return overlayPlanBuilds.Load() }

// overlayPairPlan is the immutable multiplex assignment for one node pair.
type overlayPairPlan struct {
	// vnis keeps the scan order of the pair's cross-node VNIs so VLAN
	// assignment reports the same first offending VNI a rescan would.
	vnis  []uint32
	has   map[uint32]bool
	mtu   int
	vlans map[uint32]uint16
	// vlanErr defers an assignment failure until the pair is queried, which
	// is where a per-call rescan would have surfaced it.
	vlanErr error
	// zeroVNIErr records the first cross-node link on this pair that carries
	// no VNI. A rescan returns it before any other result for this pair.
	zeroVNIErr error
}

// overlayPlan is every deployment-wide multiplex overlay parameter for one
// topology: the bridge VLAN per cross-node VNI, the outer MTU per node pair,
// and the deconflicted UDP port per node pair.
//
// The values depend only on the placed topology, never on node-local state,
// which is what lets both endpoint agents derive identical parameters. Because
// they are immutable for a topology, they are derived once per topology rather
// than rescanned for every cross-node link.
type overlayPlan struct {
	pairs map[string]*overlayPairPlan
	ports map[string]int
	// scanErr stops the scan exactly where a per-call rescan would have
	// stopped, so pairs discovered after it stay unpopulated.
	scanErr  error
	portsErr error
}

// newOverlayPlan derives every overlay parameter in one pass over the links.
// Failures are deferred rather than returned so that a pair-specific problem
// stays pair-specific, matching a per-call rescan exactly.
func newOverlayPlan(top *model.Topology) *overlayPlan {
	overlayPlanBuilds.Add(1)
	p := &overlayPlan{pairs: map[string]*overlayPairPlan{}}
	if top == nil {
		return p
	}
	order := make([]string, 0, 8)
	for _, link := range top.Links {
		if link == nil || !link.CrossNode() || link.A == nil || link.B == nil ||
			link.A.Device == nil || link.B.Device == nil {
			continue
		}
		a, b := link.A.Device.Node, link.B.Device.Node
		pairID, err := netx.MultiplexPairID(a, b)
		if err != nil {
			p.scanErr = fmt.Errorf("cross-node link %s: %w", link.ID, err)
			break
		}
		pair := p.pairs[pairID]
		if pair == nil {
			pair = &overlayPairPlan{has: map[uint32]bool{}}
			p.pairs[pairID] = pair
			order = append(order, pairID)
		}
		if link.VNI == 0 {
			if pair.zeroVNIErr == nil {
				pair.zeroVNIErr = fmt.Errorf("cross-node link %s has no VNI", link.ID)
			}
			continue
		}
		pair.vnis = append(pair.vnis, link.VNI)
		pair.has[link.VNI] = true
		if linkMTU(link) > pair.mtu {
			pair.mtu = linkMTU(link)
		}
	}
	allPairs := make([][2]string, 0, len(order))
	for _, pairID := range order {
		pair := p.pairs[pairID]
		if pair.mtu == 0 {
			pair.mtu = 1500
		}
		pair.vlans, pair.vlanErr = netx.AssignOverlayVLANs(pair.vnis)
		a, b, ok := splitPairID(pairID)
		if !ok {
			continue
		}
		allPairs = append(allPairs, [2]string{a, b})
	}
	if p.scanErr != nil {
		// A rescan would have returned before reaching port assignment, so
		// leaving ports empty keeps every query on this topology reporting the
		// scan failure rather than a port that was never deconflicted.
		return p
	}
	p.ports, p.portsErr = netx.AssignMultiplexPorts(top.Name, allPairs)
	return p
}

func splitPairID(id string) (string, string, bool) {
	for i := range len(id) {
		if id[i] == 0 {
			return id[:i], id[i+1:], true
		}
	}
	return "", "", false
}

// parameters returns the one bridge VLAN, outer MTU, and UDP port for a node
// pair, in the same evaluation order a full rescan used.
func (p *overlayPlan) parameters(first, second string, target uint32) (uint16, int, int, error) {
	pairID, pairIDErr := netx.MultiplexPairID(first, second)
	pair := p.pairs[pairID]
	if pairIDErr != nil {
		pair = nil
	}
	if pair != nil && pair.zeroVNIErr != nil {
		return 0, 0, 0, pair.zeroVNIErr
	}
	if p.scanErr != nil {
		return 0, 0, 0, p.scanErr
	}
	if pair == nil || !pair.has[target] {
		return 0, 0, 0, fmt.Errorf("VNI %d is not a cross-node link between %s and %s",
			target, first, second)
	}
	if pair.vlanErr != nil {
		return 0, 0, 0, pair.vlanErr
	}
	vlan := pair.vlans[target]
	if vlan == 0 {
		return 0, 0, 0, fmt.Errorf("no VLAN assigned to VNI %d", target)
	}
	if p.portsErr != nil {
		return 0, 0, 0, p.portsErr
	}
	if pairIDErr != nil {
		return 0, 0, 0, pairIDErr
	}
	port := p.ports[pairID]
	if port == 0 {
		return 0, 0, 0, fmt.Errorf("no UDP port assigned to node pair %s/%s", first, second)
	}
	return vlan, pair.mtu, port, nil
}

// overlayPlanFor returns this Engine's cached overlay parameters for a
// topology, deriving them once. Every caller within one deployment sees the
// same immutable assignment, so wiring 186 cross-node links no longer costs
// 186 scans of 2927 links.
func (e *Engine) overlayPlanFor(top *model.Topology) *overlayPlan {
	if e == nil {
		return newOverlayPlan(top)
	}
	e.overlayMu.Lock()
	defer e.overlayMu.Unlock()
	if e.overlayPlan != nil && e.overlayPlanTop == top {
		return e.overlayPlan
	}
	p := newOverlayPlan(top)
	e.overlayPlan = p
	e.overlayPlanTop = top
	return p
}

// multiplexParameters computes the one bridge VLAN, outer MTU, and UDP port
// for a link's node pair. Both endpoint agents run this against the same full
// topology, so VLAN and port collision resolution stays symmetric.
func (e *Engine) multiplexParameters(top *model.Topology, first, second string, target uint32) (
	uint16, int, int, error,
) {
	return e.overlayPlanFor(top).parameters(first, second, target)
}

// multiplexParameters derives the parameters without a cache. It exists for
// callers that hold no Engine; deployment paths use the Engine method so the
// derivation stays linear in the number of links.
func multiplexParameters(top *model.Topology, first, second string, target uint32) (
	uint16, int, int, error,
) {
	return newOverlayPlan(top).parameters(first, second, target)
}
