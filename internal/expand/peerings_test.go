package expand

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

// The traffic-engineering exercise asks a student to prefer a fast neighbour
// over a slow one of the same relationship class. The invariant that matters is
// therefore not "each AS has a slow link" but "each AS has both a slow link and
// a fast one of the same class".
//
// Marking one link per AS does not give that: a link is shared by two ASes and
// either may mark it, so an AS whose neighbours each marked the link they share
// with it has nothing fast left to compare against and the question has no
// correct answer. That was invisible from the manifest -- the generator did
// exactly what it said, the lab looked right, and the reference solution simply
// could not score the mark.
func TestEveryASHasBothASlowAndAFastNeighbour(t *testing.T) {
	l, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	top := res.Topology

	byAS := map[int]map[model.Relationship]*counts{}

	for _, as := range top.ASes {
		if as.Role != model.RoleStudent {
			continue
		}
		for _, r := range as.Routers {
			for _, i := range r.Ifaces {
				if i.Link == nil || !i.Link.InterAS || i.Peer == nil {
					continue
				}
				rel := i.Link.Rel
				if i.Link.B == i {
					rel = rel.Inverse()
				}
				if rel != model.RelProvider && rel != model.RelCustomer {
					continue
				}
				if byAS[as.ASN] == nil {
					byAS[as.ASN] = map[model.Relationship]*counts{}
				}
				if byAS[as.ASN][rel] == nil {
					byAS[as.ASN][rel] = &counts{}
				}
				if i.Link.Props.Delay == "25ms" {
					byAS[as.ASN][rel].slow++
				} else {
					byAS[as.ASN][rel].fast++
				}
			}
		}
	}

	if len(byAS) == 0 {
		t.Fatal("no student AS has provider or customer links; the lab cannot pose the question")
	}
	comparable := 0
	for asn, rels := range byAS {
		for rel, c := range rels {
			if c.slow > 0 && c.fast == 0 {
				t.Errorf("AS %d has %d slow %s neighbour(s) and no fast one, so the "+
					"traffic-engineering question has no correct answer", asn, c.slow, rel)
			}
			if c.slow > 0 && c.fast > 0 {
				comparable++
			}
		}
		t.Logf("AS %d: %v", asn, describe(rels))
	}
	if comparable == 0 {
		t.Error("no AS has a slow and a fast neighbour of the same class to compare")
	}
}

func describe(rels map[model.Relationship]*counts) map[string]string {
	out := map[string]string{}
	for r, c := range rels {
		out[string(r)] = fmtCounts(c)
	}
	return out
}

type counts = struct{ slow, fast int }

func fmtCounts(c *counts) string {
	return string(rune('0'+c.slow)) + " slow / " + string(rune('0'+c.fast)) + " fast"
}
