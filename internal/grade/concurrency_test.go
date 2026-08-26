package grade

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

// cable joins two devices with a point-to-point link, the way the expander
// does, so a footprint walk finds the same neighbours it would in a real lab.
func cable(a, b *model.Device) {
	ia := &model.Iface{Name: "to_" + b.Name, Device: a}
	ib := &model.Iface{Name: "to_" + a.Name, Device: b}
	ia.Peer, ib.Peer = ib, ia
	link := &model.Link{ID: a.ID + "--" + b.ID, A: ia, B: ib, InterAS: a.ASN != b.ASN}
	ia.Link, ib.Link = link, link
	a.Ifaces = append(a.Ifaces, ia)
	b.Ifaces = append(b.Ifaces, ib)
}

func device(top *model.Topology, id, name string, asn int, kind model.DeviceKind, node string) *model.Device {
	d := &model.Device{ID: id, Name: name, ASN: asn, Kind: kind, Node: node}
	top.Devices[d.ID] = d
	as := top.ASes[asn]
	if as == nil {
		role := model.RoleStudent
		switch asn {
		case 1:
			role = model.RoleStaff
		case 99:
			role = model.RoleIXP
		}
		as = &model.AS{ASN: asn, Role: role}
		top.ASes[asn] = as
	}
	as.Devices = append(as.Devices, d)
	if kind == model.KindRouter {
		as.Routers = append(as.Routers, d)
	}
	return d
}

// classTopology is the shape the canonical lab has: several student systems,
// one staff transit AS, and one exchange route server every student peers
// with. Every student system is cabled to both, which is what makes the staff
// router and the route server shared between every grade.
func classTopology(students int, nodes ...string) *model.Topology {
	top := &model.Topology{
		Name: "contention", Devices: map[string]*model.Device{}, ASes: map[int]*model.AS{},
	}
	nodeFor := func(i int) string {
		if len(nodes) == 0 {
			return "node-0"
		}
		return nodes[i%len(nodes)]
	}
	transit := device(top, "as1/TRANSIT", "TRANSIT", 1, model.KindRouter, nodeFor(0))
	server := device(top, "as99/RS", "RS", 99, model.KindRouter, nodeFor(0))
	for i := 0; i < students; i++ {
		asn := 3 + i
		node := nodeFor(i)
		router := device(top, fmt.Sprintf("as%d/R", asn), "R", asn, model.KindRouter, node)
		host := device(top, fmt.Sprintf("as%d/H", asn), "H", asn, model.KindHost, node)
		cable(router, host)
		cable(router, transit)
		cable(router, server)
	}
	return top
}

// isolatedTopology is the opposite shape: every target is a system of its own
// on a node of its own, sharing nothing with any other target.
func isolatedTopology(students int) *model.Topology {
	top := &model.Topology{
		Name: "isolated", Devices: map[string]*model.Device{}, ASes: map[int]*model.AS{},
	}
	for i := 0; i < students; i++ {
		asn := 3 + i
		node := fmt.Sprintf("node-%d", i)
		router := device(top, fmt.Sprintf("as%d/R", asn), "R", asn, model.KindRouter, node)
		host := device(top, fmt.Sprintf("as%d/H", asn), "H", asn, model.KindHost, node)
		cable(router, host)
	}
	return top
}

func studentTargets(top *model.Topology) []int {
	var out []int
	for _, asn := range top.SortedASNs() {
		if top.ASes[asn].Role == model.RoleStudent {
			out = append(out, asn)
		}
	}
	return out
}

func footprintsFor(top *model.Topology) []RunFootprint {
	var out []RunFootprint
	for _, asn := range studentTargets(top) {
		out = append(out, Footprint(top, asn))
	}
	return out
}

// The defect this exists to prevent: `twinet grade run` with no --as against
// the canonical lab, whose placement puts all 212 containers on one agent. The
// shipped default read all eight systems at once, every check timed out after
// two minutes against that single agent, and all eight reports were
// quarantined -- while the same lab graded 10.00/10.00 one system at a time.
func TestEightSystemsOnOneAgentAreNotGradedEightWide(t *testing.T) {
	top := classTopology(8)
	plan := PlanConcurrency(ConcurrencyRequest{
		Footprints: footprintsFor(top),
		// What a live node advertised for exec_probe on this cluster.
		Budgets:       []NodeExecBudget{{Node: "node-0", Limit: 56, Known: true, Source: "node node-0"}},
		CheckParallel: 8,
	})

	if plan.Width >= 8 {
		t.Fatalf("all eight systems were admitted against one agent again: width %d (%s)",
			plan.Width, plan.Reason)
	}
	if plan.Width < 1 {
		t.Fatalf("width %d would grade nothing", plan.Width)
	}
	// Every grade must still be admissible on its own: a plan that cannot
	// start one system has replaced a timeout with a deadlock.
	for as, demand := range plan.Demand {
		for node, need := range demand {
			if need > plan.Budget[node] {
				t.Fatalf("as%d needs %d exec slot(s) on %s, which admits %d",
					as, need, node, plan.Budget[node])
			}
		}
	}
	if !strings.Contains(plan.Reason, "node-0") && !strings.Contains(plan.Reason, "as1/TRANSIT") &&
		!strings.Contains(plan.Reason, "as99/RS") {
		t.Fatalf("the width is not explained by the node or the shared devices: %q", plan.Reason)
	}
}

// The same command must not become slow everywhere to fix one packed lab.
// Systems that share no device and sit on nodes of their own cost each other
// nothing, and all of them run at once.
func TestIndependentSystemsOnSeparateNodesKeepTheirParallelism(t *testing.T) {
	top := isolatedTopology(8)
	budgets := make([]NodeExecBudget, 0, 8)
	for i := 0; i < 8; i++ {
		budgets = append(budgets, NodeExecBudget{
			Node: fmt.Sprintf("node-%d", i), Limit: 56, Known: true,
		})
	}
	plan := PlanConcurrency(ConcurrencyRequest{
		Footprints: footprintsFor(top), Budgets: budgets, CheckParallel: 8,
	})
	if plan.Width != 8 {
		t.Fatalf("independent systems were serialized: width %d (%s)", plan.Width, plan.Reason)
	}
}

// A node that could not be asked is a machine of unknown capacity, not an idle
// one. Grading assumes room for a single system there and says so.
func TestUnknownNodeCapacityIsConservative(t *testing.T) {
	top := classTopology(8)
	plan := PlanConcurrency(ConcurrencyRequest{
		Footprints: footprintsFor(top), CheckParallel: 8,
	})
	if plan.Width != 1 {
		t.Fatalf("width %d against a node nobody could ask (%s)", plan.Width, plan.Reason)
	}
	if len(plan.Unknown) != 1 || plan.Unknown[0] != "node-0" {
		t.Fatalf("the unknown node is not named: %v", plan.Unknown)
	}
	if !strings.Contains(plan.Reason, "could not be asked") {
		t.Fatalf("the reason hides that capacity is unknown: %q", plan.Reason)
	}
}

// A busy node admits fewer grades than an idle one: what the agent is already
// serving is subtracted rather than assumed away.
func TestWorkAlreadyInFlightNarrowsTheWidth(t *testing.T) {
	top := classTopology(8, "node-0", "node-1", "node-2")
	footprints := footprintsFor(top)
	idle := []NodeExecBudget{
		{Node: "node-0", Limit: 56, Known: true},
		{Node: "node-1", Limit: 56, Known: true},
		{Node: "node-2", Limit: 56, Known: true},
	}
	busy := []NodeExecBudget{
		{Node: "node-0", Limit: 56, InFlight: 30, Queued: 8, Known: true},
		{Node: "node-1", Limit: 56, InFlight: 30, Queued: 8, Known: true},
		{Node: "node-2", Limit: 56, InFlight: 30, Queued: 8, Known: true},
	}
	wide := PlanConcurrency(ConcurrencyRequest{Footprints: footprints, Budgets: idle, CheckParallel: 8})
	narrow := PlanConcurrency(ConcurrencyRequest{Footprints: footprints, Budgets: busy, CheckParallel: 8})
	if narrow.Width >= wide.Width {
		t.Fatalf("a node with %d exec(s) in flight admitted as much as an idle one: %d vs %d",
			38, narrow.Width, wide.Width)
	}
	if narrow.Width < 1 {
		t.Fatalf("a busy cluster refused to grade at all: %s", narrow.Reason)
	}
}

// The gate is what actually holds during the run, so it -- not only the
// planned number -- must respect both budgets.
func TestAdmissionNeverExceedsNodeBudgetOrDeviceReaders(t *testing.T) {
	top := classTopology(8, "node-0", "node-1")
	footprints := footprintsFor(top)
	plan := PlanConcurrency(ConcurrencyRequest{
		Footprints: footprints,
		Budgets: []NodeExecBudget{
			{Node: "node-0", Limit: 24, Known: true},
			{Node: "node-1", Limit: 24, Known: true},
		},
		CheckParallel: 8,
	})
	gate := plan.Admission()

	var (
		mu       sync.Mutex
		onNode   = map[string]int{}
		onDevice = map[string]int{}
		peakNode = map[string]int{}
		peakDev  = map[string]int{}
		peakAll  int
		running  int
		wg       sync.WaitGroup
	)
	for _, footprint := range footprints {
		footprint := footprint
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := gate.Acquire(context.Background(), footprint.AS)
			if err != nil {
				t.Errorf("as%d was never admitted: %v", footprint.AS, err)
				return
			}
			mu.Lock()
			running++
			if running > peakAll {
				peakAll = running
			}
			for node, need := range plan.Demand[footprint.AS] {
				onNode[node] += need
				if onNode[node] > peakNode[node] {
					peakNode[node] = onNode[node]
				}
			}
			for _, id := range footprint.Devices {
				onDevice[id]++
				if onDevice[id] > peakDev[id] {
					peakDev[id] = onDevice[id]
				}
			}
			mu.Unlock()

			time.Sleep(5 * time.Millisecond)

			mu.Lock()
			running--
			for node, need := range plan.Demand[footprint.AS] {
				onNode[node] -= need
			}
			for _, id := range footprint.Devices {
				onDevice[id]--
			}
			mu.Unlock()
			release()
		}()
	}
	wg.Wait()

	for node, peak := range peakNode {
		if peak > plan.Budget[node] {
			t.Errorf("%s carried %d concurrent grading exec slot(s), budget %d",
				node, peak, plan.Budget[node])
		}
	}
	for id, peak := range peakDev {
		if peak > DefaultDeviceReaders {
			t.Errorf("%s was read by %d grades at once, limit %d", id, peak, DefaultDeviceReaders)
		}
	}
	if peakAll > plan.Width {
		t.Errorf("%d grades ran at once, plan announced %d", peakAll, plan.Width)
	}
	if peakAll < 1 {
		t.Error("nothing ran at all")
	}
}

// --parallel is the operator's override, and an override that quietly kept
// enforcing the derived limits would not be one. It is bounded by exactly the
// number given.
func TestFixedAdmissionHonoursAnExplicitWidth(t *testing.T) {
	gate := FixedAdmission(3)
	var (
		mu      sync.Mutex
		running int
		peak    int
		wg      sync.WaitGroup
	)
	for i := 0; i < 12; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := gate.Acquire(context.Background(), i)
			if err != nil {
				t.Errorf("waiter %d was never admitted: %v", i, err)
				return
			}
			mu.Lock()
			running++
			if running > peak {
				peak = running
			}
			mu.Unlock()
			time.Sleep(2 * time.Millisecond)
			mu.Lock()
			running--
			mu.Unlock()
			release()
		}()
	}
	wg.Wait()
	if peak > 3 {
		t.Fatalf("--parallel 3 ran %d grades at once", peak)
	}
}

// A narrower gate must not change which report is which. Report order is the
// target order, whatever order the grades happen to finish in.
func TestReportOrderFollowsTargetOrderNotCompletionOrder(t *testing.T) {
	targets := []int{3, 4, 5, 6}
	gate := FixedAdmission(4)
	reports := RunEach(context.Background(), targets, gate,
		func(_ context.Context, as int) *Report {
			// Later targets finish first.
			time.Sleep(time.Duration(10-as) * 3 * time.Millisecond)
			return &Report{AS: as, Submission: fmt.Sprintf("as%d", as)}
		}, nil)
	if len(reports) != len(targets) {
		t.Fatalf("got %d reports for %d targets", len(reports), len(targets))
	}
	for i, as := range targets {
		if reports[i] == nil || reports[i].AS != as {
			t.Fatalf("report %d is %v, want as%d", i, reports[i], as)
		}
	}
}

// Progress must still count every grade exactly once, so a run that is
// deliberately narrow still shows an operator that it is advancing.
func TestProgressCountsEveryGradeOnce(t *testing.T) {
	targets := []int{3, 4, 5, 6, 7}
	var (
		mu   sync.Mutex
		seen []int
	)
	RunEach(context.Background(), targets, FixedAdmission(2),
		func(_ context.Context, as int) *Report { return &Report{AS: as} },
		func(done, total int, _ *Report) {
			mu.Lock()
			defer mu.Unlock()
			if total != len(targets) {
				t.Errorf("progress reported %d targets, want %d", total, len(targets))
			}
			seen = append(seen, done)
		})
	if len(seen) != len(targets) {
		t.Fatalf("progress fired %d times for %d targets", len(seen), len(targets))
	}
	for i, done := range seen {
		if done != i+1 {
			t.Fatalf("progress counted %v, want 1..%d in order", seen, len(targets))
		}
	}
}

// A cancelled run must not leave a grade waiting at the gate forever.
func TestAdmissionReleasesWaitersWhenTheRunIsCancelled(t *testing.T) {
	top := classTopology(4)
	plan := PlanConcurrency(ConcurrencyRequest{
		Footprints: footprintsFor(top),
		Budgets:    []NodeExecBudget{{Node: "node-0", Limit: 16, Known: true}},
	})
	gate := plan.Admission()
	release, err := gate.Acquire(context.Background(), 3)
	if err != nil {
		t.Fatalf("first grade was not admitted: %v", err)
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	blocked := make(chan error, 1)
	go func() {
		_, err := gate.Acquire(ctx, 4)
		blocked <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-blocked:
		if err == nil {
			t.Fatal("a cancelled waiter reported that it was admitted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled waiter is still queued at the gate")
	}
}

// A node so small that one grade does not fit must serialize grading, never
// stall it: a plan that can admit nothing has replaced a slow answer with no
// answer at all.
func TestATinyNodeSerializesGradingRatherThanDeadlocking(t *testing.T) {
	top := classTopology(8)
	footprints := footprintsFor(top)
	plan := PlanConcurrency(ConcurrencyRequest{
		Footprints:    footprints,
		Budgets:       []NodeExecBudget{{Node: "node-0", Limit: 2, Known: true}},
		CheckParallel: 8,
	})
	if plan.Width != 1 {
		t.Fatalf("width %d against a node that admits %d exec(s)", plan.Width, plan.Budget["node-0"])
	}
	gate := plan.Admission()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, footprint := range footprints {
			release, err := gate.Acquire(context.Background(), footprint.AS)
			if err != nil {
				t.Errorf("as%d was never admitted: %v", footprint.AS, err)
				return
			}
			release()
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("grading stalled at the gate on a node that admits one grade at a time")
	}
}

// The footprint is the whole set of devices a grade reads, because that is
// what decides which grades contend. A footprint of only the target AS would
// report the eight systems of the canonical lab as sharing nothing.
func TestFootprintIncludesNeighboursAndExchangeRouteServers(t *testing.T) {
	top := classTopology(3)
	footprint := Footprint(top, 3)
	want := []string{"as1/TRANSIT", "as3/H", "as3/R", "as99/RS"}
	if len(footprint.Devices) != len(want) {
		t.Fatalf("footprint %v, want %v", footprint.Devices, want)
	}
	for i, id := range want {
		if footprint.Devices[i] != id {
			t.Fatalf("footprint %v, want %v", footprint.Devices, want)
		}
	}
	if footprint.ByNode["node-0"] != len(want) {
		t.Fatalf("placement was not counted: %v", footprint.ByNode)
	}
}
