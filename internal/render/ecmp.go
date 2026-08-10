package render

import (
	"github.com/HongyuHe/twinet/internal/model"
)

// ecmpCosts is the reference answer to the load-balancing question.
//
// The assignment asks for traffic between ATL and BOS to be split over exactly
// three paths: ATL-BOS, ATL-PHY-BOS and ATL-PHY-NYC-BOS. With uniform costs the
// direct link is the only shortest path, so the reference answer raises the
// direct link and tunes the two paths through PHY until all three are equal:
//
//	ATL-BOS                     = 20
//	ATL-PHY + PHY-BOS           = 10 + 10       = 20
//	ATL-PHY + PHY-NYC + NYC-BOS = 10 + 5 + 5    = 20
//
// Every other link keeps the default cost, so no fourth path becomes equal by
// accident. TestReferenceECMPArithmetic checks both properties against the real
// topology rather than trusting this comment.
//
// This lives beside the renderer rather than in the grader because it is an
// answer, not a test: `twinet solve` applies it and `twinet grade` then checks
// it, which is how the platform verifies that it and its own rubric agree.
//
// Keys are written in whatever order reads naturally and canonicalised at
// startup. Writing them unsorted while looking them up sorted silently drops a
// cost, and the only symptom is a path that never appears.
var ecmpCosts = canonicalise(map[[2]string]int{
	{"ATL", "BOS"}: 20,
	{"ATL", "PHY"}: 10,
	{"PHY", "BOS"}: 10,
	{"PHY", "NYC"}: 5,
	{"NYC", "BOS"}: 5,
})

// defaultOSPFCost is what every unlisted link carries.
const defaultOSPFCost = 10

func canonicalise(in map[[2]string]int) map[[2]string]int {
	out := make(map[[2]string]int, len(in))
	for k, v := range in {
		out[costKey(k[0], k[1])] = v
	}
	return out
}

func costKey(a, b string) [2]string {
	if a > b {
		a, b = b, a
	}
	return [2]string{a, b}
}

// ecmpCost returns the reference cost for an interface, or zero for the default.
func ecmpCost(i *model.Iface) int {
	if i.Link == nil || i.Peer == nil || i.Role != model.RoleIntraAS {
		return 0
	}
	return ecmpCosts[costKey(i.Device.Name, i.Peer.Device.Name)]
}

// LinkCost is the cost the reference solution gives a link between two named
// routers, exposed so tests can verify the answer is arithmetically correct
// rather than merely present.
func LinkCost(a, b string) int {
	if c, ok := ecmpCosts[costKey(a, b)]; ok {
		return c
	}
	return defaultOSPFCost
}
