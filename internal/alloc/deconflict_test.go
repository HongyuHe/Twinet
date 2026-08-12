package alloc

import (
	"fmt"
	"testing"
)

// A hundred grading harnesses of three hundred links each draw thirty thousand
// identifiers from sixteen million. The birthday bound makes a collision close
// to certain rather than rare, and two labs sharing a tunnel is not a degraded
// lab: it is two labs whose packets appear in each other's networks.
func TestConcurrentLabsCollideWithoutDeconfliction(t *testing.T) {
	links := make([]string, 300)
	for i := range links {
		links[i] = fmt.Sprintf("as%d/R%d:port_A|as%d/R%d:port_B", i, i, i+1, i+1)
	}

	seen := map[uint32]string{}
	collisions := 0
	for lab := 0; lab < 100; lab++ {
		name := fmt.Sprintf("cos461-g%d", lab)
		for _, v := range AssignVNIs(name, links) {
			if other, ok := seen[v]; ok && other != name {
				collisions++
			}
			seen[v] = name
		}
	}
	if collisions == 0 {
		t.Skip("no collision arose in this configuration; the guarantee below is what matters")
	}
	t.Logf("%d cross-lab collisions among 100 concurrent labs without deconfliction", collisions)
}

func TestDeconflictLeavesNoSharedIdentifier(t *testing.T) {
	links := make([]string, 300)
	for i := range links {
		links[i] = fmt.Sprintf("as%d/R%d:port_A|as%d/R%d:port_B", i, i, i+1, i+1)
	}

	inUse := map[uint32]string{}
	for lab := 0; lab < 100; lab++ {
		name := fmt.Sprintf("cos461-g%d", lab)
		assigned, _ := Deconflict(name, AssignVNIs(name, links), inUse)

		for id, v := range assigned {
			if owner, ok := inUse[v]; ok && owner != name {
				t.Fatalf("lab %s was given VNI %d for %s, which lab %s already owns",
					name, v, id, owner)
			}
			inUse[v] = name
		}
		// Every link must still have exactly one identifier: a deconfliction
		// that dropped or merged links would break the topology it protects.
		if len(assigned) != len(links) {
			t.Fatalf("lab %s ended with %d identifiers for %d links", name, len(assigned), len(links))
		}
		distinct := map[uint32]bool{}
		for _, v := range assigned {
			distinct[v] = true
		}
		if len(distinct) != len(links) {
			t.Fatalf("lab %s reused an identifier within itself", name)
		}
	}
	t.Logf("100 labs of %d links each hold %d distinct identifiers with no overlap", len(links), len(inUse))
}

func TestRedeployKeepsTheSameIdentifiers(t *testing.T) {
	links := []string{"as1/A:p|as2/B:p", "as2/B:q|as3/C:q"}
	first := AssignVNIs("cos461", links)

	inUse := map[uint32]string{}
	for _, v := range first {
		inUse[v] = "cos461"
	}
	// Re-deploying the same lab must not renumber its own fabric, or every
	// redeployment would tear down and rebuild every tunnel.
	second, moved := Deconflict("cos461", AssignVNIs("cos461", links), inUse)
	if moved != 0 {
		t.Errorf("redeploying a lab moved %d of its own identifiers", moved)
	}
	for id, v := range first {
		if second[id] != v {
			t.Errorf("link %s moved from VNI %d to %d on redeploy", id, v, second[id])
		}
	}
}

// A lab that had to move a colliding identifier must be given the same
// replacement every time it is deployed.
//
// The candidate search refused any identifier already in use, including the
// one this lab had been given on the previous deploy -- which is in use by the
// very link being re-placed. So each deploy chose a different identifier, tore
// down the tunnel and built a new one, and a cross-node link went down for as
// long as that took on a lab nothing had changed about.
func TestARemappedIdentifierIsStableAcrossDeploys(t *testing.T) {
	const lab, link = "cos461", "as3/ATL:port_BOS|as4/CHI:port_ATL"

	original := VNI(lab, link, 0)
	// Somebody else holds the identifier this link would derive.
	world := map[uint32]string{original: "someone-else"}

	first, moved := Deconflict(lab, map[string]uint32{link: original}, world)
	if moved != 1 {
		t.Fatalf("a colliding identifier was not moved (%d)", moved)
	}
	got := first[link]
	if got == original {
		t.Fatal("the collision was not resolved")
	}

	// The next deploy: the world now shows that identifier as ours.
	world[got] = lab
	second, _ := Deconflict(lab, map[string]uint32{link: original}, world)
	if second[link] != got {
		t.Errorf("the same link was given %d and then %d. Every deploy would destroy "+
			"and rebuild this tunnel, taking the link down each time on a lab nothing "+
			"had changed about", got, second[link])
	}
}
