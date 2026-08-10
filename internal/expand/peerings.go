package expand

import (
	"fmt"
	"math/rand"
	"sort"

	"github.com/HongyuHe/twinet/internal/model"
)

// resolvePeeringLinks produces the final list of inter-AS links: either the
// explicitly declared ones, or the output of a generator, with per-link
// overrides applied on top.
//
// This replaces the legacy platform's aslevel_links.txt (a 6.5 KB positional
// file whose tenth column was *either* a subnet *or* a comma-separated list of
// AS numbers depending on the peer's kind) and the generate_connections.py
// script that produced it.
func (e *expander) resolvePeeringLinks() ([]model.PeeringLink, error) {
	var links []model.PeeringLink

	if g := e.lab.Peerings.Generator; g != nil {
		gen, err := e.generate(g)
		if err != nil {
			return nil, fmt.Errorf("peerings.generator: %w", err)
		}
		links = gen
	}
	links = append(links, e.lab.Peerings.Links...)

	// Deduplicate: an explicit link wins over a generated one with the same key.
	byKey := map[string]model.PeeringLink{}
	order := []string{}
	for _, l := range links {
		k := l.Key()
		if _, seen := byKey[k]; !seen {
			order = append(order, k)
		}
		byKey[k] = l
	}

	// Overrides patch an existing link rather than adding one.
	for i, o := range e.lab.Peerings.Overrides {
		k := o.Key()
		base, ok := byKey[k]
		if !ok {
			return nil, fmt.Errorf("peerings.overrides[%d]: no link %s to override; declare it under peerings.links instead", i, k)
		}
		byKey[k] = mergePeering(o, base)
	}

	out := make([]model.PeeringLink, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k])
	}
	return out, nil
}

func mergePeering(over, base model.PeeringLink) model.PeeringLink {
	out := base
	if over.Rel != "" {
		out.Rel = over.Rel
	}
	if over.Subnet != "" {
		out.Subnet = over.Subnet
	}
	out.LinkProps = over.Merge(base.LinkProps)
	return out
}

// generate builds an Internet-like AS topology.
//
// The shape reproduces the pedagogy of the mini-Internet: a Tier-1 clique at
// the top, tiers of transit providers beneath it, stubs at the bottom, and
// regional IXPs that every AS in a region peers at. Crucially it also injects
// the deliberately slow provider and customer links that assignment question
// 2.5 asks students to discover and engineer around.
func (e *expander) generate(g *model.PeeringGenerator) ([]model.PeeringLink, error) {
	if g.Kind != "tiered-internet" {
		return nil, fmt.Errorf("unknown generator kind %q (supported: tiered-internet)", g.Kind)
	}
	if len(g.Tiers) == 0 {
		return nil, fmt.Errorf("tiers must not be empty")
	}
	for ti, tier := range g.Tiers {
		if len(tier) == 0 {
			return nil, fmt.Errorf("tiers[%d] is empty", ti)
		}
	}

	seed := g.Seed
	if seed == 0 {
		seed = 461 // deterministic by default; topologies must be reproducible
	}
	rng := rand.New(rand.NewSource(seed))

	ports := e.portNames()
	var out []model.PeeringLink

	// Tier-1 clique: every top-tier AS peers with every other.
	top := g.Tiers[0]
	for i := 0; i < len(top); i++ {
		for j := i + 1; j < len(top); j++ {
			out = append(out, model.PeeringLink{
				A: top[i], APort: ports.peerA,
				B: top[j], BPort: ports.peerA,
				Rel: model.RelPeer,
			})
		}
	}

	// Provider/customer edges between consecutive tiers. Each AS in tier n+1
	// takes two providers from tier n, so there is always a backup path and
	// so local-pref actually has something to choose between.
	for ti := 0; ti+1 < len(g.Tiers); ti++ {
		upper, lower := g.Tiers[ti], g.Tiers[ti+1]
		custPorts := []string{ports.custA, ports.custB}
		provPorts := []string{ports.provA, ports.provB}
		for li, c := range lower {
			for k := 0; k < 2; k++ {
				p := upper[(li*2+k)%len(upper)]
				if p == c {
					p = upper[(li*2+k+1)%len(upper)]
				}
				out = append(out, model.PeeringLink{
					A: p, APort: custPorts[k%len(custPorts)],
					B: c, BPort: provPorts[k%len(provPorts)],
					Rel: model.RelProvider,
				})
			}
		}
	}

	// Lateral peer links within a tier, between adjacent ASes, so students see
	// a peer relationship that is not an IXP.
	for _, tier := range g.Tiers[1:] {
		for i := 0; i+1 < len(tier); i += 2 {
			out = append(out, model.PeeringLink{
				A: tier[i], APort: ports.peerA,
				B: tier[i+1], BPort: ports.peerA,
				Rel: model.RelPeer,
			})
		}
	}

	// IXPs: every non-IXP AS joins the IXP of its region.
	if len(g.IXPs) > 0 {
		asns := e.top.SortedASNs()
		for _, asn := range asns {
			as := e.top.ASes[asn]
			if as.Role == model.RoleIXP {
				continue
			}
			ixp := g.IXPs[regionIndex(as.Region, asn)%len(g.IXPs)]
			out = append(out, model.PeeringLink{
				A: asn, APort: ports.ixp,
				B:   ixp,
				Rel: model.RelPeer,
			})
		}
	}

	// The slow links. Exactly one provider link and one customer link per AS
	// are marked high-delay, which is what question 2.5 is built around.
	if g.SlowLink != nil && g.SlowLink.PerAS > 0 {
		delay := orDefault(g.SlowLink.Delay, "25ms")
		byAS := map[int][]int{} // asn -> indices of its provider/customer links
		for i, l := range out {
			if l.Rel != model.RelProvider {
				continue
			}
			byAS[l.A] = append(byAS[l.A], i)
			byAS[l.B] = append(byAS[l.B], i)
		}
		marked := map[int]bool{}
		asns := make([]int, 0, len(byAS))
		for a := range byAS {
			asns = append(asns, a)
		}
		sort.Ints(asns)
		for _, a := range asns {
			cand := byAS[a]
			n := 0
			for _, idx := range cand {
				if n >= g.SlowLink.PerAS {
					break
				}
				if marked[idx] {
					continue
				}
				out[idx].Delay = delay
				marked[idx] = true
				n++
			}
			// If every candidate was already slow, pick one at random to keep
			// the invariant "each AS has at least one slow neighbour".
			if n == 0 && len(cand) > 0 {
				out[cand[rng.Intn(len(cand))]].Delay = delay
			}
		}
	}

	return out, nil
}

// portNames picks the external attachment point names to use, falling back to
// whatever the templates actually declare so a generator works with any
// template that follows the convention.
type extPortNames struct{ provA, provB, custA, custB, peerA, ixp string }

func (e *expander) portNames() extPortNames {
	p := extPortNames{
		provA: "provider_a", provB: "provider_b",
		custA: "customer_a", custB: "customer_b",
		peerA: "peer_a", ixp: "ixp",
	}
	// Verify against a representative student template; if names differ, fall
	// back to empty so resolveEndpoint uses the single-router default.
	for _, asn := range e.top.SortedASNs() {
		as := e.top.ASes[asn]
		if as.Role != model.RoleStudent || len(as.ExtPorts) == 0 {
			continue
		}
		has := func(n string) bool { _, ok := as.ExtPorts[n]; return ok }
		if !has(p.provA) {
			p.provA = ""
		}
		if !has(p.provB) {
			p.provB = ""
		}
		if !has(p.custA) {
			p.custA = ""
		}
		if !has(p.custB) {
			p.custB = ""
		}
		if !has(p.peerA) {
			p.peerA = ""
		}
		if !has(p.ixp) {
			p.ixp = ""
		}
		break
	}
	return p
}

func regionIndex(region string, asn int) int {
	if region == "" {
		return asn
	}
	n := 0
	for _, r := range region {
		n = n*31 + int(r)
	}
	if n < 0 {
		n = -n
	}
	return n
}
