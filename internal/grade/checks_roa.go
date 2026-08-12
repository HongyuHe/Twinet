package grade

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

func init() {
	Register(&Check{
		Name:     "rpki.roa_published",
		Describe: "the validator holds a ROA authorising this AS to originate its own prefix",
		Run:      checkROAPublished,
	})
}

// checkROAPublished verifies that this AS's prefix is covered by a ROA naming
// this AS as its origin.
//
// Whether this is worth marks depends on the course. In a lab where the
// platform publishes every system's ROA -- which is what the COS-461 example
// does, so that everybody else's routes validate -- it would award the mark to
// everybody for something nobody did, and it is left out of that rubric for
// exactly that reason. It belongs in a rubric where publication is the
// student's own action.
//
// The exercise asks students to publish a ROA for their own address block, and
// nothing checked it. The other RPKI checks are about *reacting* to validation
// state -- refusing invalid routes, keeping not-found ones -- and they can all
// pass on an AS that has published nothing at all, because a network with no
// ROA of its own still sees everybody else's.
//
// It is read from the validator's own table, through the router's session with
// it, so it is the same data the routing policy acts on. A ROA in a file
// somewhere that the validator has not served is not a published ROA.
func checkROAPublished(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok || as.Block == "" {
		return Errored("rpki.roa_published",
			fmt.Errorf("AS %d has no address block in the lab", env.AS))
	}

	// One system is deliberately left without a ROA so that the rest of the
	// internet has a not-found route to keep, which is what makes
	// rpki.notfound_preserved mean anything. Marking its owner down for the
	// lab's own choice would be a mark for something they were never asked to
	// do -- and the lab already declares which system it is, so nobody has to
	// keep the two in step by hand.
	if env.Topology.Lab != nil {
		for _, asn := range env.Topology.Lab.RPKI.NotFound {
			if asn == env.AS {
				return Pass("rpki.roa_published", Evidence{
					Observed: fmt.Sprintf("AS %d is the system this lab deliberately leaves "+
						"without a ROA, so that everybody else has a not-found route to keep",
						env.AS),
					Detail: "declared as rpki.not_found in the manifest",
				})
			}
		}
	}

	var (
		table string
		asked string
		err   error
	)
	for _, r := range env.Routers() {
		table, err = env.Vtysh(ctx, r.Name, "show rpki prefix-table")
		if err == nil {
			asked = r.Name
			break
		}
	}
	if asked == "" {
		return Errored("rpki.roa_published",
			fmt.Errorf("no router of AS %d could be asked for the validator's table: %w", env.AS, err))
	}

	want := strings.SplitN(as.Block, "/", 2)
	network := want[0]
	length := ""
	if len(want) == 2 {
		length = want[1]
	}

	// Lines read: PREFIX LENGTH - MAXLEN ORIGIN-AS
	var mine, others []string
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		if f[0] != network {
			continue
		}
		origin := f[len(f)-1]
		if length != "" && f[1] != length {
			continue
		}
		if n, cerr := strconv.Atoi(origin); cerr == nil && n == env.AS {
			mine = append(mine, strings.TrimSpace(line))
			continue
		}
		others = append(others, strings.TrimSpace(line))
	}

	if len(mine) > 0 {
		return Pass("rpki.roa_published", Evidence{
			Observed: fmt.Sprintf("the validator holds a ROA authorising AS %d to originate %s",
				env.AS, as.Block),
			Detail:  strings.Join(mine, "\n"),
			Command: "show rpki prefix-table",
		})
	}
	if len(others) > 0 {
		return Fail("rpki.roa_published", Evidence{
			Expected: fmt.Sprintf("a ROA for %s with origin AS %d", as.Block, env.AS),
			Observed: "the validator holds a ROA for this prefix, but authorising a different AS",
			Detail:   strings.Join(others, "\n"),
			Hint: "the origin AS in the ROA has to be the one that announces the prefix, " +
				"or your own announcement is invalid to everybody who checks",
			Command: "show rpki prefix-table",
		})
	}
	return Fail("rpki.roa_published", Evidence{
		Expected: fmt.Sprintf("a ROA for %s with origin AS %d", as.Block, env.AS),
		Observed: "the validator holds no ROA for this prefix at all",
		Hint: "publish a ROA for your own block; without one your announcement is " +
			"not-found to everybody, and a network that rejects not-found cannot reach you",
		Command: "show rpki prefix-table",
	})
}
