package grade

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	"github.com/HongyuHe/twinet/internal/nos"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// A student AS running BIRD has to be gradeable against the same rubric as one
// running FRR: the vendor-neutral questions must produce the same verdict, and
// the questions that are only expressible in FRR's own CLI must say so instead
// of erroring, failing, or quietly disappearing from the denominator.
//
// Everything here goes through the real NOS provider. The exec function is the
// audit: any FRR binary reaching a BIRD router fails the test.

// birdStudentLab builds a two-AS lab whose student AS runs BIRD on two
// interior routers with an eBGP session to a staff FRR neighbour.
func birdStudentLab() *model.Topology {
	atl := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter, ASN: 3, NOS: "bird"}
	chi := &model.Device{ID: "as3/CHI", Name: "CHI", Kind: model.KindRouter, ASN: 3, NOS: "bird"}
	all := &model.Device{ID: "as1/ALL", Name: "ALL", Kind: model.KindRouter, ASN: 1}

	interior := &model.Link{Subnet: "3.201.0.0/24"}
	atlInt := &model.Iface{Device: atl, Name: "int_CHI", Role: model.RoleIntraAS, Addr4: "3.201.0.1/24", Link: interior}
	chiInt := &model.Iface{Device: chi, Name: "int_ATL", Role: model.RoleIntraAS, Addr4: "3.201.0.2/24", Link: interior}
	interior.A, interior.B = atlInt, chiInt
	atlInt.Peer, chiInt.Peer = chiInt, atlInt

	external := &model.Link{InterAS: true, Rel: model.RelProvider, Subnet: "179.1.2.0/24"}
	atlExt := &model.Iface{Device: atl, Name: "ext_1_ALL", Role: model.RoleInterAS, Addr4: "179.1.2.1/24", Link: external}
	allExt := &model.Iface{Device: all, Name: "ext_3_ATL", Role: model.RoleInterAS, Addr4: "179.1.2.2/24", Link: external}
	external.A, external.B = atlExt, allExt
	atlExt.Peer, allExt.Peer = allExt, atlExt

	atl.Ifaces = []*model.Iface{atlInt, atlExt}
	chi.Ifaces = []*model.Iface{chiInt}
	all.Ifaces = []*model.Iface{allExt}

	return &model.Topology{
		Name: "mixed-student", Hash: "mixed-student-hash",
		Devices: map[string]*model.Device{atl.ID: atl, chi.ID: chi, all.ID: all},
		Links:   []*model.Link{interior, external},
		ASes: map[int]*model.AS{
			1: {ASN: 1, Role: model.RoleStaff, Block: "1.0.0.0/8",
				Routers: []*model.Device{all}, Devices: []*model.Device{all}},
			3: {ASN: 3, Role: model.RoleStudent, Block: "3.0.0.0/8",
				Routers: []*model.Device{atl, chi}, Devices: []*model.Device{atl, chi}},
		},
	}
}

// birdLabExec answers the native commands each provider issues, and records
// every command so the audit below can prove no FRR binary reached BIRD.
//
// The observation snapshot coalesces a device's whole survey into one
// marker-delimited shell, so the helper answers that form too: the point of
// this fixture is that the real batching path serves a BIRD device, not that
// batching is switched off for it.
func birdLabExec(t *testing.T, log *commandLog) func(context.Context, string, []string) (rt.ExecResult, error) {
	t.Helper()
	const neighbors = `BIRD 2.0.12 ready.
ospf4:
Router ID       Pri          State      DTime   Interface  Router IP
3.151.0.2         1     Full/PtP       00:36   int_CHI    3.201.0.2
`
	const chiNeighbors = `BIRD 2.0.12 ready.
ospf4:
Router ID       Pri          State      DTime   Interface  Router IP
3.151.0.1         1     Full/PtP       00:35   int_ATL    3.201.0.1
`
	const protocols = `BIRD 2.0.12 ready.
Name       Proto      Table      State  Since         Info
ebgp_ext_1_ALL BGP    ---        up     2026-08-26 06:00:12  Established
  BGP state:          Established
    Neighbor address: 179.1.2.2
    Neighbor AS:      1
  Channel ipv4
    State:          UP
    Routes:         4 imported, 1 filtered, 2 exported, 4 preferred
    Route change stats:     received   rejected   filtered    ignored   accepted
      Import updates:              9          0          1          0          8
      Export updates:             11          3          2        ---          6
`
	return func(_ context.Context, device string, command []string) (rt.ExecResult, error) {
		log.record(device, command)
		joined := strings.Join(command, " ")
		answer := func(joined string) rt.ExecResult {
			switch {
			case strings.Contains(joined, "show ospf neighbors") && device == "as3/CHI":
				return rt.ExecResult{Stdout: chiNeighbors}
			case strings.Contains(joined, "show ospf neighbors"):
				return rt.ExecResult{Stdout: neighbors}
			case strings.Contains(joined, "show protocols all"):
				return rt.ExecResult{Stdout: protocols}
			case strings.Contains(joined, "show ip bgp summary json"):
				return rt.ExecResult{Stdout: `{"ipv4Unicast":{"peers":{"179.1.2.1":` +
					`{"remoteAs":3,"state":"Established","pfxRcd":2,"pfxSnt":4,` +
					`"msgRcvd":9,"msgSent":11}}}}`}
			case strings.Contains(joined, "show ip bgp json"):
				return rt.ExecResult{Stdout: `{"routes":{}}`}
			case strings.Contains(joined, "address show"):
				return rt.ExecResult{Stdout: "[]"}
			case strings.Contains(joined, "route show"):
				return rt.ExecResult{Stdout: "[]"}
			case strings.Contains(joined, "sysctl"):
				return rt.ExecResult{Stdout: "1\n"}
			default:
				return rt.ExecResult{}
			}
		}
		if len(command) == 3 && command[0] == "sh" && strings.Contains(command[2], "__TWINET_OBS_") {
			return emulateObservationBatch(command[2], answer), nil
		}
		return answer(joined), nil
	}
}

// emulateObservationBatch answers the marker-delimited survey shell the
// observation snapshot builds, without needing a shell to run it.
func emulateObservationBatch(script string, answer func(string) rt.ExecResult) rt.ExecResult {
	marker := observationMarkerRE.FindString(script)
	if marker == "" {
		return rt.ExecResult{}
	}
	var out strings.Builder
	index := 0
	for _, line := range strings.Split(script, "\n") {
		body, ok := strings.CutPrefix(line, "out=$(")
		if !ok {
			continue
		}
		body, _, ok = strings.Cut(body, " 2>&1); rc=$?;")
		if !ok {
			continue
		}
		result := answer(strings.ReplaceAll(body, "'", ""))
		fmt.Fprintf(&out, "%s_%d_RC=%d\n%s\n%s_%d_END\n",
			marker, index, result.ExitCode, strings.TrimRight(result.Stdout, "\n"), marker, index)
		index++
	}
	return rt.ExecResult{Stdout: out.String()}
}

var observationMarkerRE = regexp.MustCompile(`__TWINET_OBS_[0-9a-f]+`)

func birdLabEnv(t *testing.T, log *commandLog) *Env {
	t.Helper()
	return &Env{Topology: birdStudentLab(), AS: 3, Exec: birdLabExec(t, log)}
}

// assertNoFRRCommandReachedBIRD audits every device in the student AS against
// the shared list of FRR's own words, without having to name its routers. It
// insists the trail is non-empty: an audit over commands that were never
// recorded proves nothing, which is what an unsynchronised recorder silently
// degraded into when the grader surveyed devices concurrently.
func assertNoFRRCommandReachedBIRD(t *testing.T, log *commandLog) {
	t.Helper()
	audited := 0
	for _, device := range log.devices() {
		if !strings.HasPrefix(device, "as3/") {
			continue
		}
		assertNoFRRCommands(t, log, device)
		audited++
	}
	if audited == 0 {
		t.Fatal("no command to the BIRD student AS was recorded, so the audit checked nothing")
	}
}

// The interior adjacency question is vendor-neutral, and its liveness evidence
// -- the remaining dead time -- is published by both NOSes. It has to read the
// same on BIRD as on FRR.
func TestBIRDStudentASOSPFAdjacencyReadsThroughTheProvider(t *testing.T) {
	log := newCommandLog()
	env := birdLabEnv(t, log)

	timers := deadTimers(context.Background(), env)
	if got := timers["ATL"]["int_CHI"]; got != 36000 {
		t.Fatalf("ATL's dead timer toward CHI = %d, want 36000", got)
	}
	if got := timers["CHI"]["int_ATL"]; got != 35000 {
		t.Fatalf("CHI's dead timer toward ATL = %d, want 35000", got)
	}
	// Hello intervals are an FRR-only refinement. Skipping them must not taint
	// the check: an unknown interval is taken to be the shortest one, which
	// makes the liveness window stricter rather than looser.
	if intervals := helloIntervals(context.Background(), env); len(intervals) != 0 {
		t.Fatalf("hello intervals were read from a NOS that does not publish them: %#v", intervals)
	}
	assertNoFRRCommandReachedBIRD(t, log)
}

// A BIRD session's counters have to reach the eBGP check, or a route refresh
// that moved them reads as one that moved nothing -- which the check reports
// as a session "held open by a timer and carrying nothing".
func TestBIRDStudentASBGPSessionCountersReachTheChecks(t *testing.T) {
	log := newCommandLog()
	env := birdLabEnv(t, log)

	summary, err := bgpSummary(context.Background(), env, "ATL")
	if err != nil {
		t.Fatal(err)
	}
	peer, ok := summary.IPv4Unicast.Peers["179.1.2.2"]
	if !ok {
		t.Fatalf("the BIRD session did not reach the summary: %#v", summary)
	}
	if peer.RemoteAs != 1 || !strings.EqualFold(peer.State, "Established") {
		t.Fatalf("session = %#v", peer)
	}
	if peer.PfxRcd != 4 || peer.PfxSnt != 2 {
		t.Errorf("prefixes = %d received / %d sent, want 4/2", peer.PfxRcd, peer.PfxSnt)
	}
	if peer.MsgRcvd != 9 || peer.MsgSent != 6 {
		t.Errorf("updates = %d received / %d sent, want 9/6", peer.MsgRcvd, peer.MsgSent)
	}
	assertNoFRRCommandReachedBIRD(t, log)
}

// The audit is only worth as much as the trail it reads. Grading fans out over
// devices, so concurrent appends to an unguarded recorder would drop entries --
// and a dropped entry is a forbidden command the audit silently misses, which
// is a worse failure than a noisy one.
func TestTheCommandAuditLosesNothingUnderConcurrency(t *testing.T) {
	const writers, each = 16, 64
	log := newCommandLog()

	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range each {
				log.record(fmt.Sprintf("as3/R%d", w), []string{"birdc", "show", fmt.Sprint(i)})
			}
		}(w)
	}
	wg.Wait()

	if devices := log.devices(); len(devices) != writers {
		t.Fatalf("the trail names %d devices, want %d: whole devices were lost",
			len(devices), writers)
	}
	for w := range writers {
		device := fmt.Sprintf("as3/R%d", w)
		commands := log.forDevice(device)
		if len(commands) != each {
			t.Fatalf("%s recorded %d commands, want %d: entries were lost",
				device, len(commands), each)
		}
		for i, command := range commands {
			if want := fmt.Sprint(i); command[2] != want {
				t.Fatalf("%s command %d = %q, want %q: the trail is not what ran",
					device, i, command[2], want)
			}
		}
	}
	// What a reader gets back is its own copy, so an assertion can range over
	// the trail while the run that produced it is still writing to it.
	stolen := log.forDevice("as3/R0")
	stolen[0] = []string{"vtysh", "-c", "show running-config"}
	assertNoFRRCommandReachedBIRD(t, log)
}

// The whole rubric, run against the BIRD student AS. The vendor-neutral
// questions must be assessed; the FRR-only ones must come back explicitly
// unsupported, with the question marked for review rather than scored as if
// the check had never existed.
func TestBIRDStudentASGradesTheUnchangedRubricSubset(t *testing.T) {
	log := newCommandLog()
	env := birdLabEnv(t, log)

	rubric := &Rubric{
		Metadata: RubricMeta{Name: "mixed-student"},
		Questions: []QuestionSpec{
			{ID: "q1", Title: "Interior routing", Points: 1,
				Checks: []CheckSpec{{Check: "ospf.full_adjacency"}}},
			{ID: "q2", Title: "External sessions", Points: 1,
				Checks: []CheckSpec{{Check: "bgp.ebgp_established"}}},
			{ID: "q3", Title: "Forbidden OSPF statements", Points: 1,
				Checks: []CheckSpec{{Check: "config.no_forbidden_ospf"}}},
			{ID: "q4", Title: "Origin validation", Points: 1,
				Checks: []CheckSpec{{Check: "rpki.invalid_rejected"}}},
		},
	}
	report := Run(context.Background(), rubric, env, RunOptions{CheckTimeout: 20 * time.Second})

	byID := map[string]QuestionResult{}
	for _, q := range report.Questions {
		byID[q.ID] = q
	}
	for _, id := range []string{"q3", "q4"} {
		q, ok := byID[id]
		if !ok {
			t.Fatalf("%s is missing from the report entirely, so it silently left the "+
				"denominator", id)
		}
		if len(q.Results) != 1 || q.Results[0].Status != StatusUnsupported {
			t.Fatalf("%s = %#v, want one explicitly unsupported check", id, q.Results)
		}
		if !q.NeedsReview || q.Note == "" {
			t.Fatalf("%s dropped out of the mark without saying so: %#v", id, q)
		}
		if q.Awarded != 0 || q.Points != 1 {
			t.Fatalf("%s awarded %v of %v for a check that never ran", id, q.Awarded, q.Points)
		}
		if !strings.Contains(q.Results[0].Err, "bird") {
			t.Errorf("%s does not name the NOS that cannot answer it: %q", id, q.Results[0].Err)
		}
	}
	// The vendor-neutral questions were actually assessed -- neither errored
	// nor declared unsupported.
	for _, id := range []string{"q1", "q2"} {
		q, ok := byID[id]
		if !ok {
			t.Fatalf("%s is missing from the report", id)
		}
		for _, result := range q.Results {
			if result.Status == StatusUnsupported || result.Status == StatusError {
				t.Fatalf("%s was not assessed on BIRD: %#v", id, result)
			}
		}
	}
	assertNoFRRCommandReachedBIRD(t, log)
}

// A check with a declared feature requirement must refuse before it runs, so
// no vendor CLI is attempted at all.
func TestDeclaredFeatureRequirementsRefuseBeforeRunning(t *testing.T) {
	for _, name := range []string{
		"rpki.invalid_rejected", "rpki.notfound_preserved",
		"multicast.pim_enabled", "multicast.delivery",
		"mpls.ldp_adjacencies", "vpn.label_switched",
	} {
		check, ok := registry[name]
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		if len(check.Requires) == 0 {
			t.Errorf("%s declares no NOS feature requirement, so it would be attempted on "+
				"a NOS that cannot answer it", name)
		}
	}
	// And the requirement is real: BIRD declares none of them.
	provider, ok := nos.Lookup("bird")
	if !ok {
		t.Fatal("the BIRD provider is not registered")
	}
	for _, feature := range []nos.Feature{nos.FeatureRPKI, nos.FeatureMulticast, nos.FeatureMPLS} {
		if provider.Capabilities().Supports(feature) {
			t.Errorf("BIRD claims %q, which Twinet does not render, apply and observe for it", feature)
		}
	}
}

// A verdict reached from less evidence than the check was designed around must
// be carried into the question rather than scored as an ordinary pass.
func TestReducedEvidenceMarksTheQuestionForReview(t *testing.T) {
	q := QuestionSpec{ID: "q", Title: "Traffic engineering", Points: 1,
		Checks: []CheckSpec{{Check: "policy.traffic_engineering"}}}
	full := questionResult(q, []Result{Pass("policy.traffic_engineering", Evidence{})})
	if full.NeedsReview {
		t.Fatalf("an ordinary pass was marked for review: %#v", full)
	}
	reduced := questionResult(q, []Result{{
		Check: "policy.traffic_engineering", Status: StatusPass, Score: 1,
		Reduced: []string{"as3/ATL runs bird, which does not express a routing table"},
	}})
	if !reduced.NeedsReview || !strings.Contains(reduced.Note, "reduced evidence") {
		t.Fatalf("a pass from reduced evidence was not flagged: %#v", reduced)
	}
	if reduced.Awarded != 1 {
		t.Fatalf("reduced evidence changed the mark rather than flagging it: %v", reduced.Awarded)
	}
}

// The observation snapshot has to ask each provider for its own commands, or a
// BIRD device is surveyed with FRR's.
func TestObservationCommandsComeFromTheProvider(t *testing.T) {
	top := birdStudentLab()
	bird, _ := top.Device("as3/ATL")
	frr, _ := top.Device("as1/ALL")

	for _, word := range flatten(stateCommands(bird, netstate.All)) {
		if word == "vtysh" {
			t.Fatalf("a BIRD device is surveyed with vtysh: %v", stateCommands(bird, netstate.All))
		}
	}
	found := false
	for _, word := range flatten(stateCommands(frr, netstate.All)) {
		if word == "vtysh" {
			found = true
		}
	}
	if !found {
		t.Fatal("an FRR device is no longer surveyed with vtysh")
	}
}

func flatten(commands [][]string) []string {
	var out []string
	for _, command := range commands {
		out = append(out, command...)
	}
	return out
}
