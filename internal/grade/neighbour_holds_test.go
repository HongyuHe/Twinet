package grade

import (
	"context"
	"fmt"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// The inbound half of policy.traffic_engineering used to read a foreign AS
// number in the advertised path as proof that the announcement had been
// thrown away:
//
//	"the path advertised to the slow AS1 contains 99, which is not this AS: a
//	 path through a neighbour's own number is a loop to it and the
//	 announcement is discarded, so the slow link stops being a backup at all"
//
// Two of those claims are about a network nobody looked at. 99 is not AS 1's
// number, AS 1 sees no loop, and on the live lab AS 1 accepted the route and
// chose it as best. The mark was deducted for something that had not happened.
// The survival of the announcement is now measured at the neighbour.
func TestAnAnnouncementTheNeighbourAcceptedIsNotReportedAsDiscarded(t *testing.T) {
	env := fakeNeighbourEnv(map[string]string{
		// AS 1 holds it, learnt straight from us, padded with a number that
		// belongs to nobody in the lab.
		"ALL": `{"paths":[{"aspath":{"string":"3 99 99 99"}}]}`,
	})
	held, readable := neighbourHoldsOurs(context.Background(), env, 1, "3.0.0.0/8")
	if !readable {
		t.Fatal("the neighbour was readable but reported otherwise")
	}
	if !held {
		t.Fatal("an announcement the neighbour accepted was reported as not surviving")
	}
}

// The soundness half. Prepending the neighbour's *own* number really is a loop
// to it, and the route dies on arrival -- but the neighbour may still hold the
// prefix through somebody else, so "does AS 1 have 3.0.0.0/8" answers yes and
// excuses the very thing the question forbids. The link the question calls a
// backup carries nothing. A route learnt from us begins with our number.
func TestAPrefixHeldOnlyThroughAThirdASIsNotOurAnnouncement(t *testing.T) {
	env := fakeNeighbourEnv(map[string]string{
		// Reached the long way round, through AS 2. Nothing of ours survived.
		"ALL": `{"paths":[{"aspath":{"string":"2 3 3 3"}}]}`,
	})
	held, readable := neighbourHoldsOurs(context.Background(), env, 1, "3.0.0.0/8")
	if !readable {
		t.Fatal("the neighbour was readable but reported otherwise")
	}
	if held {
		t.Fatal("a prefix held only through a third AS was counted as our announcement surviving")
	}
}

// The ordinary correct answer: our own number, padded, learnt from us.
func TestOurOwnPrependsAreOurAnnouncement(t *testing.T) {
	env := fakeNeighbourEnv(map[string]string{
		"ALL": `{"paths":[{"aspath":{"string":"3 3 3 3"}}]}`,
	})
	if held, readable := neighbourHoldsOurs(context.Background(), env, 1, "3.0.0.0/8"); !held || !readable {
		t.Fatalf("a correct prepend was not recognised: held=%v readable=%v", held, readable)
	}
}

// A neighbour nobody can read yields no evidence either way. Reporting "the
// slow link is not the backup" because the grader could not open a session is
// the failure the previous ninety-six findings kept turning up, so the caller
// is told the difference between "no" and "could not tell".
func TestAnUnreadableNeighbourIsNotAVerdict(t *testing.T) {
	env := fakeNeighbourEnv(nil)
	if held, readable := neighbourHoldsOurs(context.Background(), env, 1, "3.0.0.0/8"); held || readable {
		t.Fatalf("an unreadable neighbour produced a verdict: held=%v readable=%v", held, readable)
	}
}

func fakeNeighbourEnv(replies map[string]string) *Env {
	return &Env{
		Topology: &model.Topology{ASes: map[int]*model.AS{
			1: {ASN: 1, Routers: []*model.Device{{ID: "as1/ALL", Name: "ALL", ASN: 1}}},
			3: {ASN: 3, Routers: []*model.Device{{ID: "as3/MSP", Name: "MSP", ASN: 3}}},
		}},
		AS: 3,
		Exec: func(_ context.Context, id string, cmd []string) (rt.ExecResult, error) {
			for name, out := range replies {
				if id == name || id == fmt.Sprintf("as1/%s", name) {
					return rt.ExecResult{Stdout: out}, nil
				}
			}
			return rt.ExecResult{ExitCode: 1, Stderr: "no such command"}, nil
		},
	}
}
