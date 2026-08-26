package grade

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// commandLog records every command the grader sent to every device, so a test
// can assert on what was asked as well as on what was concluded.
type commandLog struct {
	mu  sync.Mutex
	cmd map[string][][]string
}

func newCommandLog() *commandLog { return &commandLog{cmd: map[string][][]string{}} }

func (l *commandLog) record(device string, command []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cmd[device] = append(l.cmd[device], append([]string(nil), command...))
}

func (l *commandLog) forDevice(device string) [][]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([][]string(nil), l.cmd[device]...)
}

// devices names everything that was sent anything, so an audit can cover a
// whole AS without being told which routers it contains.
func (l *commandLog) devices() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Sorted(maps.Keys(l.cmd))
}

// frrOnly words are FRR's, and a device that does not run FRR does not have
// them: the first three are how FRR is asked a question, the last two how it
// is given a configuration. They are searched for inside the whole command
// line because a passive survey legitimately coalesces several native
// commands into one shell.
var frrOnly = []string{"vtysh", "show ip bgp", "show running-config", "frr-reload.py", "/etc/frr"}

func assertNoFRRCommands(t *testing.T, log *commandLog, device string) {
	t.Helper()
	for _, command := range log.forDevice(device) {
		line := strings.Join(command, " ")
		for _, word := range frrOnly {
			if strings.Contains(line, word) {
				t.Fatalf("%s does not run FRR but was sent %q", device, line)
			}
		}
	}
}

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
// The survival of the announcement is now measured at the neighbour -- and the
// neighbour of the lab this course ships runs BIRD, so it is measured through
// the vendor-neutral state API rather than through FRR's command line.
func TestAnAnnouncementTheNeighbourAcceptedIsNotReportedAsDiscarded(t *testing.T) {
	forEachNeighbourNOS(t, func(t *testing.T, nos string) {
		// AS 1 holds it, learnt straight from us, padded with a number that
		// belongs to nobody in the lab.
		env, _ := fakeNeighbourEnv(nos, map[string]string{"3.0.0.0/8": "3 99 99 99"})
		held, readable := neighbourHoldsOurs(context.Background(), env, 1, "3.0.0.0/8")
		if !readable {
			t.Fatal("the neighbour was readable but reported otherwise")
		}
		if !held {
			t.Fatal("an announcement the neighbour accepted was reported as not surviving")
		}
	})
}

// The soundness half. Prepending the neighbour's *own* number really is a loop
// to it, and the route dies on arrival -- but the neighbour may still hold the
// prefix through somebody else, so "does AS 1 have 3.0.0.0/8" answers yes and
// excuses the very thing the question forbids. The link the question calls a
// backup carries nothing. A route learnt from us begins with our number.
func TestAPrefixHeldOnlyThroughAThirdASIsNotOurAnnouncement(t *testing.T) {
	forEachNeighbourNOS(t, func(t *testing.T, nos string) {
		// Reached the long way round, through AS 2. Nothing of ours survived.
		env, _ := fakeNeighbourEnv(nos, map[string]string{"3.0.0.0/8": "2 3 3 3"})
		held, readable := neighbourHoldsOurs(context.Background(), env, 1, "3.0.0.0/8")
		if !readable {
			t.Fatal("the neighbour was readable but reported otherwise")
		}
		if held {
			t.Fatal("a prefix held only through a third AS was counted as our announcement surviving")
		}
	})
}

// The ordinary correct answer: our own number, padded, learnt from us.
func TestOurOwnPrependsAreOurAnnouncement(t *testing.T) {
	forEachNeighbourNOS(t, func(t *testing.T, nos string) {
		env, _ := fakeNeighbourEnv(nos, map[string]string{"3.0.0.0/8": "3 3 3 3"})
		if held, readable := neighbourHoldsOurs(context.Background(), env, 1, "3.0.0.0/8"); !held || !readable {
			t.Fatalf("a correct prepend was not recognised: held=%v readable=%v", held, readable)
		}
	})
}

// A neighbour nobody can read yields no evidence either way. Reporting "the
// slow link is not the backup" because the grader could not open a session is
// the failure the previous ninety-six findings kept turning up, so the caller
// is told the difference between "no" and "could not tell".
func TestAnUnreadableNeighbourIsNotAVerdict(t *testing.T) {
	forEachNeighbourNOS(t, func(t *testing.T, nos string) {
		env, _ := fakeNeighbourEnv(nos, nil)
		if held, readable := neighbourHoldsOurs(context.Background(), env, 1, "3.0.0.0/8"); held || readable {
			t.Fatalf("an unreadable neighbour produced a verdict: held=%v readable=%v", held, readable)
		}
	})
}

// A prefix the neighbour holds is recognised however its table spells it. The
// two providers do not agree on the text of a route, and a string comparison
// would report a route that is plainly there as missing.
func TestTheNeighbourTableIsMatchedByPrefixNotBySpelling(t *testing.T) {
	forEachNeighbourNOS(t, func(t *testing.T, nos string) {
		env, _ := fakeNeighbourEnv(nos, map[string]string{"3.0.0.0/8": "3 3"})
		if held, readable := neighbourHoldsOurs(context.Background(), env, 1, " 3.0.0.0/8 "); !held || !readable {
			t.Fatalf("an equivalent prefix was not matched: held=%v readable=%v", held, readable)
		}
	})
}

// The regression this file exists for.
//
// The question was asked with `vtysh -c "show ip bgp <prefix> json"`,
// hard-coded, of whatever autonomous system happened to be on the other side
// of the slow link. In the lab this course actually ships that is AS 1 or
// AS 2, and both of them run BIRD: the binary is not in the image, the exec
// fails as a transport error, and a transport error is recorded as a fault of
// the grading machinery. The reference solution -- the one answer that is
// correct by construction -- was therefore quarantined rather than marked.
func TestNoFRRCommandIsSentToABIRDNeighbour(t *testing.T) {
	env, log := fakeNeighbourEnv("bird", map[string]string{"3.0.0.0/8": "3 3 3 3"})
	held, readable := neighbourHoldsOurs(context.Background(), env, 1, "3.0.0.0/8")
	if !held || !readable {
		t.Fatalf("BIRD evidence was not assessed: held=%v readable=%v", held, readable)
	}
	if len(log.forDevice("as1/ALL")) == 0 {
		t.Fatal("the neighbour was never asked anything at all")
	}
	assertNoFRRCommands(t, log, "as1/ALL")
}

// And the machinery must not be told it broke. A BIRD neighbour that answers
// is not an infrastructure failure, and recording one is what turned a correct
// grade into a report nobody could release.
func TestReadingABIRDNeighbourIsNotAnInfrastructureFailure(t *testing.T) {
	env, _ := fakeNeighbourEnv("bird", map[string]string{"3.0.0.0/8": "3 3 3 3"})
	tracker := &infraTracker{}
	env.infraSeen = tracker
	if held, _ := neighbourHoldsOurs(context.Background(), env, 1, "3.0.0.0/8"); !held {
		t.Fatal("BIRD evidence was not assessed")
	}
	if fail := tracker.failure(); fail != nil {
		t.Fatalf("reading a BIRD neighbour was recorded as a grading fault: %v", fail)
	}
}

func forEachNeighbourNOS(t *testing.T, run func(*testing.T, string)) {
	t.Helper()
	for _, nos := range []string{model.DefaultNOS, "bird"} {
		t.Run(nos, func(t *testing.T) { run(t, nos) })
	}
}

// fakeNeighbourEnv builds a two-AS lab whose AS 1 runs the named NOS and
// answers that NOS's own commands with the given AS path per prefix.
func fakeNeighbourEnv(neighbourNOS string, paths map[string]string) (*Env, *commandLog) {
	log := newCommandLog()
	neighbour := &model.Device{
		ID: "as1/ALL", Name: "ALL", ASN: 1, Kind: model.KindRouter, NOS: neighbourNOS,
	}
	env := &Env{
		Topology: &model.Topology{ASes: map[int]*model.AS{
			1: {ASN: 1, Routers: []*model.Device{neighbour}, Devices: []*model.Device{neighbour}},
			3: {ASN: 3, Routers: []*model.Device{{
				ID: "as3/MSP", Name: "MSP", ASN: 3, Kind: model.KindRouter,
			}}},
		}},
		AS: 3,
		Exec: func(_ context.Context, id string, cmd []string) (rt.ExecResult, error) {
			log.record(id, cmd)
			if id != "as1/ALL" || len(paths) == 0 {
				return rt.ExecResult{ExitCode: 1, Stderr: "no such command"}, nil
			}
			line := strings.Join(cmd, " ")
			switch {
			case strings.Contains(line, "show ip bgp json"):
				return rt.ExecResult{Stdout: frrRoutesJSON(paths)}, nil
			case strings.Contains(line, "show route all"):
				return rt.ExecResult{Stdout: birdRoutesText(paths)}, nil
			}
			return rt.ExecResult{ExitCode: 1, Stderr: "no such command"}, nil
		},
	}
	return env, log
}

// frrRoutesJSON is the document `vtysh -c "show ip bgp json"` produces.
func frrRoutesJSON(paths map[string]string) string {
	var b strings.Builder
	b.WriteString(`{"routes":{`)
	first := true
	for prefix, path := range paths {
		if !first {
			b.WriteString(",")
		}
		first = false
		fmt.Fprintf(&b, `%q:[{"valid":true,"bestpath":true,"path":%q,"peerId":"192.0.2.2"}]`,
			prefix, path)
	}
	b.WriteString("}}")
	return b.String()
}

// birdRoutesText is what `birdc show route all` prints for the same tables.
func birdRoutesText(paths map[string]string) string {
	var b strings.Builder
	for prefix, path := range paths {
		fmt.Fprintf(&b, "%s          unicast [ebgp_3 00:00:05] * (100)\n", prefix)
		b.WriteString("\tvia 192.0.2.2 on ext_3_MSP\n")
		b.WriteString("\tType: BGP univ\n")
		fmt.Fprintf(&b, "\tBGP.as_path: %s\n", path)
	}
	return b.String()
}
