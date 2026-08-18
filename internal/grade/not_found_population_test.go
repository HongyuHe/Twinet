package grade

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// popEnv builds an AS with two routers, one of which answers the RPKI prefix
// table and one of which returns an empty one, as a router with no validator
// session does.
func popEnv(t *testing.T, notFound []int, served string) *Env {
	t.Helper()
	topo := &model.Topology{
		ASes: map[int]*model.AS{
			3: {ASN: 3, Block: "3.0.0.0/8", Routers: []*model.Device{
				{ID: "as3-MSP", Name: "MSP"},
				{ID: "as3-BOS", Name: "BOS"},
			}},
			1: {ASN: 1, Block: "1.0.0.0/8"},
			2: {ASN: 2, Block: "2.0.0.0/8"},
			4: {ASN: 4, Block: "4.0.0.0/8"},
		},
		Lab: &model.Lab{RPKI: model.RPKISpec{NotFound: notFound}},
	}
	return &Env{
		Topology: topo,
		AS:       3,
		Exec: func(_ context.Context, id string, cmd []string) (rt.ExecResult, error) {
			if len(cmd) < 3 || !strings.Contains(cmd[2], "rpki prefix-table") {
				return rt.ExecResult{}, nil
			}
			// MSP has no session and prints nothing; BOS has been served.
			if id == "as3-MSP" {
				return rt.ExecResult{Stdout: ""}, nil
			}
			return rt.ExecResult{Stdout: served}, nil
		},
	}
}

const servedTable = `Prefix                   Prefix Length  Origin-AS
2.0.0.0                    8 -   8          2
4.0.0.0                    8 -   8          4
`

// The lab's declaration decides the population, so a router with no validator
// session cannot change what the check examines.
func TestNotFoundPopulationFollowsTheLab(t *testing.T) {
	env := popEnv(t, []int{1}, servedTable)
	got, err := notFoundPopulation(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got["1.0.0.0/8"] != 1 {
		t.Fatalf("want only 1.0.0.0/8 from AS 1, got %v", got)
	}
}

// The router that answers first used to decide the answer. Every router is now
// pooled, so the one with no session no longer empties the baseline.
func TestROAPrefixesPoolsEveryRouter(t *testing.T) {
	env := popEnv(t, nil, servedTable)
	covered, readable := roaPrefixes(context.Background(), env)
	if !readable {
		t.Fatal("tables were readable but readable was false")
	}
	if !covered["2.0.0.0/8"] || !covered["4.0.0.0/8"] {
		t.Fatalf("MSP's empty table hid BOS's ROAs: %v", covered)
	}
}

// Without a declaration and with nothing served anywhere, the population is not
// "everybody": that is unestablished, and saying so is the only honest answer.
func TestNotFoundPopulationRefusesAnEmptyBaseline(t *testing.T) {
	env := popEnv(t, nil, "")
	_, err := notFoundPopulation(context.Background(), env)
	if err == nil {
		t.Fatal("an empty ROA table was read as nobody having published one")
	}
	if !strings.Contains(err.Error(), "cannot be established") {
		t.Fatalf("error should say what could not be established, got %q", err)
	}
}

// With no declaration but a readable, non-empty table, the served prefixes are
// excluded and the rest form the population.
func TestNotFoundPopulationFallsBackToTheTable(t *testing.T) {
	env := popEnv(t, nil, servedTable)
	got, err := notFoundPopulation(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got["1.0.0.0/8"] != 1 {
		t.Fatalf("want only the unserved 1.0.0.0/8, got %v", got)
	}
}
