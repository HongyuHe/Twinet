package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
)

func canonicalLab(t *testing.T) *model.Topology {
	t.Helper()
	loaded, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if _, err := place.Place(result.Topology, place.Options{}); err != nil {
		t.Fatalf("place: %v", err)
	}
	return result.Topology
}

func studentASes(top *model.Topology) []int {
	var out []int
	for _, asn := range top.SortedASNs() {
		if top.ASes[asn].Role == model.RoleStudent {
			out = append(out, asn)
		}
	}
	return out
}

// The reported defect, at the level the operator meets it: the documented
// command is `twinet -m examples/cos461 grade run --out <dir>` with no --as.
// Canonical placement packs all 212 containers onto one node, the shipped
// default read all eight student systems against that one agent, every check
// ran out of its two-minute budget, and all eight reports were quarantined at
// a provisional 7.00/10 -- while `--as 3` alone scored 10.00/10.00.
func TestCanonicalLabIsNotGradedEightWideAgainstOneAgent(t *testing.T) {
	top := canonicalLab(t)
	targets := studentASes(top)
	if len(targets) != 8 {
		t.Fatalf("the canonical lab has %d student systems, expected 8", len(targets))
	}

	packed := map[string]int{}
	for _, device := range top.Devices {
		packed[device.Node]++
	}
	if len(packed) == 0 {
		t.Fatal("the canonical lab placed no devices")
	}
	// The live cluster packs this lab onto one node: `inspect --placement`
	// reported node-0 holding all 212 containers and 0 of 299 links crossing
	// the fabric, because pack-by-as trades balance for locality and the whole
	// lab fits one machine. Placement here depends on inventory the test
	// cannot read, so the packed case is stated rather than hoped for.
	const node = "node-0"
	for _, device := range top.Devices {
		device.Node = node
	}

	footprints := make([]grade.RunFootprint, 0, len(targets))
	for _, as := range targets {
		footprints = append(footprints, grade.Footprint(top, as))
	}
	plan := grade.PlanConcurrency(grade.ConcurrencyRequest{
		Footprints: footprints,
		// What the live agents advertise for exec_probe on this cluster.
		Budgets:       []grade.NodeExecBudget{{Node: node, Limit: 56, Known: true, Source: "node " + node}},
		CheckParallel: 8,
	})

	if plan.Width >= len(targets) {
		t.Fatalf("all %d systems would again be read against %s at once: %s",
			len(targets), node, plan.Reason)
	}
	if plan.Width < 1 {
		t.Fatalf("the canonical lab would not be graded at all: %s", plan.Reason)
	}
	// Every student system peers with the staff transit ASes and the exchange
	// route servers, so the footprints must overlap: a plan that saw them as
	// independent would be measuring the wrong thing.
	shared := map[string]int{}
	for _, footprint := range footprints {
		for _, device := range footprint.Devices {
			shared[device]++
		}
	}
	most := 0
	for _, count := range shared {
		if count > most {
			most = count
		}
	}
	if most < 2 {
		t.Fatalf("no device is read by more than one grade, which the canonical rubric requires")
	}
	t.Logf("canonical width %d: %s", plan.Width, plan.Reason)
}

// The same lab, one system at a time, is the configuration that scored
// 10.00/10.00 live. Asking for one target must stay exactly that and must not
// acquire a capacity explanation nobody needs.
func TestASingleTargetIsUnaffectedByCapacityPlanning(t *testing.T) {
	top := canonicalLab(t)
	plan := grade.PlanConcurrency(grade.ConcurrencyRequest{
		Footprints:    []grade.RunFootprint{grade.Footprint(top, 3)},
		Budgets:       []grade.NodeExecBudget{{Node: "node-0", Limit: 56, Known: true}},
		CheckParallel: 8,
	})
	if plan.Width != 1 {
		t.Fatalf("one target planned at width %d", plan.Width)
	}

	// And the command must not spend a cluster round trip deciding it: there
	// is no width to choose, and `--as 3` is the path the scale benchmark and
	// the operator guide both use.
	var out bytes.Buffer
	gate, scheduling := planGradeRun(context.Background(), top, "", []int{3}, 0, 8, 4, &out)
	if gate == nil || scheduling.Width != 1 {
		t.Fatalf("one target planned as %+v", scheduling)
	}
	if out.Len() != 0 {
		t.Fatalf("one target produced scheduling chatter:\n%s", out.String())
	}
	release, err := gate.Acquire(context.Background(), 3)
	if err != nil {
		t.Fatalf("the single target was not admitted: %v", err)
	}
	release()
}

// An operator who names --parallel gets it, and gets it on the record. A width
// above what the cluster advertises is the operator's decision to make, and
// the marks it produces have to be auditable as having been produced that way.
func TestExplicitParallelOverridesAndIsAudited(t *testing.T) {
	top := canonicalLab(t)
	targets := studentASes(top)

	var out bytes.Buffer
	gate, scheduling := planGradeRun(context.Background(), top, "", targets, 8, 8, 4, &out)
	if scheduling.Width != 8 {
		t.Fatalf("--parallel 8 was silently narrowed to %d", scheduling.Width)
	}
	if gate == nil {
		t.Fatal("no admission gate was returned")
	}
	text := out.String()
	if !strings.Contains(text, "AUDIT:") {
		t.Fatalf("an explicitly unsafe width was not recorded:\n%s", text)
	}
	if !strings.Contains(text, "--parallel 8") || !strings.Contains(text, "quarantined") {
		t.Fatalf("the audit line does not say what was overridden or what still holds:\n%s", text)
	}
	// The reports have to carry it too: an operator reading summary.json
	// months later cannot see the terminal this was run in.
	if scheduling.Requested != 8 || scheduling.Safe >= 8 {
		t.Fatalf("the summary would not record the override: %+v", scheduling)
	}
	if !strings.Contains(scheduling.Reason, "capacity-safe width") {
		t.Fatalf("the recorded reason does not name the safe width: %q", scheduling.Reason)
	}
}

// With no --parallel, the derived width and the reason for it are printed
// before anything is read, so an operator can see why a run is narrow without
// reading the source.
func TestDerivedWidthAndReasonAreAnnounced(t *testing.T) {
	top := canonicalLab(t)
	targets := studentASes(top)

	var out bytes.Buffer
	gate, scheduling := planGradeRun(context.Background(), top, "", targets, 0, 8, 4, &out)
	if gate == nil {
		t.Fatal("no admission gate was returned")
	}
	if scheduling.Width < 1 || scheduling.Width >= len(targets) {
		t.Fatalf("derived width %d for %d targets:\n%s", scheduling.Width, len(targets), out.String())
	}
	if scheduling.Requested != 0 || scheduling.Reason == "" {
		t.Fatalf("a derived width was not recorded as derived: %+v", scheduling)
	}
	text := out.String()
	if !strings.Contains(text, "at most") {
		t.Fatalf("the chosen width was not announced:\n%s", text)
	}
	// The cluster cannot be reached from a test, so the honest answer is that
	// capacity is unknown -- and saying so is part of the contract.
	if !strings.Contains(text, "--parallel") {
		t.Fatalf("the announcement does not say how to override it:\n%s", text)
	}
}

// --parallel must remain documented as an override rather than as the number
// of submissions, and the default must be "derive it".
func TestParallelFlagDocumentsTheAdaptiveDefault(t *testing.T) {
	run := findCommand(t, Root(), "grade", "run")
	flag := run.Flags().Lookup("parallel")
	if flag == nil {
		t.Fatal("grade run has no --parallel")
	}
	if flag.DefValue != "0" {
		t.Fatalf("--parallel still ships a fixed default of %q", flag.DefValue)
	}
	if !strings.Contains(flag.Usage, "derived") {
		t.Fatalf("--parallel does not document the adaptive default: %q", flag.Usage)
	}
	for _, want := range []string{"--parallel", "node agents", "independent nodes"} {
		if !strings.Contains(run.Long, want) {
			t.Fatalf("grade run --help does not explain adaptive scheduling (%q missing):\n%s",
				want, run.Long)
		}
	}
}
