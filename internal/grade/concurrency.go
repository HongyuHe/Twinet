package grade

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/HongyuHe/twinet/internal/model"
)

// Outer grading concurrency: how many systems of one lab may be read at once.
//
// A grade is not one command. Each one surveys its own devices and its
// neighbours' through a node agent, at its own internal read/active width, and
// every one of those commands is a container exec on whichever machine happens
// to hold the device. Choosing the outer width by counting submissions -- or
// by dividing this laptop's CPUs -- ignores both facts, and the failure it
// produces is the worst kind: `twinet grade run` with no --as on the canonical
// 12-AS lab put all eight student systems against one agent holding all 212
// containers, every check timed out after two minutes, and all eight reports
// were quarantined at a provisional 7.00/10 while the same lab graded 10.00/10
// one system at a time.
//
// Two facts bound the safe width, and both are properties of the deployment
// rather than of the request:
//
//  1. A node agent has a finite exec budget it advertises (its `exec_probe`
//     limiter). Every grade reading devices on that node occupies a share of
//     it: up to one batched survey fan-out plus its in-flight checks.
//  2. A router is one small container running one routing daemon. Several
//     grades converge on the same staff transit routers and the same exchange
//     route servers -- that is what an inter-domain rubric is about -- and
//     asking one route server for eight simultaneous full-table dumps makes
//     each of them take eight times as long, which is precisely how a
//     two-minute check budget is exhausted by a lab that is working perfectly.
//
// So the width is derived from placement, from what the agents advertise, and
// from how far the targets' footprints overlap. Independent systems on
// independent nodes still run wide; systems packed onto one agent do not.
const (
	// gradingExecShareNum/gradingExecShareDen is the share of a node's
	// advertised exec budget that grading may occupy. The rest is left for the
	// node's own work -- the per-minute reconciler, the semantic audit, the
	// control sidecars, and any other lab on the same machine -- and for the
	// fact that a grading exec is not a cheap one: each is preceded by a tool
	// integrity check and most of them are full control-plane dumps.
	//
	// Half, not three quarters. The only live measurement available is the
	// failure this exists to fix: eight grades at eight checks each offered 64
	// concurrent execs to an agent advertising 56, and every check exhausted
	// its two-minute budget rather than merely queueing. A budget that is
	// nearly exhausted by grading alone is not a budget, so grading takes half
	// of it and an operator who knows their cluster can widen it.
	gradingExecShareNum = 1
	gradingExecShareDen = 2

	// agentBatchWorkers mirrors the fan-out a node agent uses inside one
	// batched exec request. It is the number of exec slots one grade's passive
	// survey occupies on one node at a time.
	agentBatchWorkers = 8

	// unknownNodeExecBudget is what a node is assumed to admit when it cannot
	// be asked. It is deliberately one batch fan-out: enough for a single
	// grade to make progress, not enough for a second to be started against a
	// machine whose capacity nobody knows.
	unknownNodeExecBudget = agentBatchWorkers

	// DefaultDeviceReaders is how many grades may read one router's control
	// plane at the same time. Two is the largest overlap this platform has
	// evidence for: one reader is the measured-good configuration (`grade run
	// --as N`, and `grade class`, which marks one system at a time), and one
	// daemon in one container answers N simultaneous full-table dumps roughly
	// N times slower, so a larger number is paid for out of the check budget.
	DefaultDeviceReaders = 2

	// unplacedNode is the node key for a device the placer left unassigned,
	// which is the ordinary case for a lab running on this machine alone.
	unplacedNode = "local"
)

// NodeExecBudget is what one node advertises about its exec capacity.
//
// Known is not decoration. A node that did not answer, or that runs an agent
// too old to report backpressure, must be treated as a machine of unknown
// capacity rather than as an empty one: reporting zero here and dividing by it
// is how a scheduler talks itself into unbounded concurrency.
type NodeExecBudget struct {
	Node string
	// Limit is the agent's advertised concurrent exec budget.
	Limit int
	// InFlight and Queued are what that budget is already serving. They are
	// subtracted, so a node busy with another lab admits fewer grades.
	InFlight int
	Queued   int
	Known    bool
	// Source names where the numbers came from, for the operator line.
	Source string
}

// grading returns the exec slots this node will admit for grading, and whether
// the number came from the node itself.
func (b NodeExecBudget) grading() (int, bool) {
	if !b.Known || b.Limit <= 0 {
		return unknownNodeExecBudget, false
	}
	usable := b.Limit * gradingExecShareNum / gradingExecShareDen
	usable -= b.InFlight + b.Queued
	if usable < 1 {
		usable = 1
	}
	return usable, true
}

// RunFootprint is the set of devices grading one system reads, and where those
// devices are placed.
//
// It is deliberately the whole footprint and not the target AS: a grade reads
// its neighbours' tables, the exchange route servers it peers through, and the
// services it is cabled to. Those are the devices several grades share, and
// sharing is what has to be counted.
//
// Routers are kept separately because they are the expensive readers. A
// router's evidence is a full control-plane dump -- OSPF database, BGP table,
// advertised routes per neighbour -- served by one FRR process inside one
// container, so simultaneous readers of the same router each wait for all the
// others. A host or a service answers a handful of cheap commands and does not
// have that property.
type RunFootprint struct {
	AS      int
	Devices []string
	Routers []string
	ByNode  map[string]int
}

// Footprint computes what grading one AS of a topology will read.
func Footprint(top *model.Topology, asn int) RunFootprint {
	out := RunFootprint{AS: asn, ByNode: map[string]int{}}
	if top == nil {
		return out
	}
	as := top.ASes[asn]
	if as == nil {
		return out
	}
	seen := map[string]*model.Device{}
	add := func(d *model.Device) {
		if d != nil && d.ID != "" {
			seen[d.ID] = d
		}
	}
	adjacent := func(d *model.Device, visit func(*model.Device)) {
		if d == nil {
			return
		}
		for _, iface := range d.Ifaces {
			if iface == nil {
				continue
			}
			if iface.Peer != nil {
				visit(iface.Peer.Device)
			}
			if iface.Link != nil {
				if iface.Link.A != nil {
					visit(iface.Link.A.Device)
				}
				if iface.Link.B != nil {
					visit(iface.Link.B.Device)
				}
			}
		}
	}
	// One hop is the whole survey: a grade reads its own devices, its
	// neighbours' routing tables, the exchange route servers it peers with,
	// and the switches and services it is cabled to. Those are the devices
	// several grades converge on, and converging is what has to be counted.
	for _, device := range as.Devices {
		add(device)
		adjacent(device, add)
	}
	ids := make([]string, 0, len(seen))
	routers := make([]string, 0, len(seen))
	for id, device := range seen {
		ids = append(ids, id)
		if device.IsRouter() {
			routers = append(routers, id)
		}
		out.ByNode[nodeKey(device.Node)]++
	}
	sort.Strings(ids)
	sort.Strings(routers)
	out.Devices = ids
	out.Routers = routers
	return out
}

func nodeKey(node string) string {
	if strings.TrimSpace(node) == "" {
		return unplacedNode
	}
	return node
}

// ConcurrencyRequest describes one `grade run` invocation for planning.
type ConcurrencyRequest struct {
	// Footprints are the targets in the order they will be graded.
	Footprints []RunFootprint
	// Budgets is what each node advertises. A node named by a footprint and
	// missing here is treated as unknown, never as unlimited.
	Budgets []NodeExecBudget
	// CheckParallel and ObservationParallel are the internal widths one grade
	// will use, which is what makes one grade cost more than one exec slot.
	CheckParallel       int
	ObservationParallel int
	// ActiveParallel is the packet/capture/control-refresh sub-pool. It is
	// bounded by CheckParallel rather than added to it -- a check is admitted
	// only while fewer than CheckParallel are running -- so it raises the
	// reservation only if a caller sets it wider than the total.
	ActiveParallel int
	// DeviceReaders overrides how many grades may read one router at once.
	DeviceReaders int
}

// ConcurrencyPlan is the derived outer width plus everything needed to enforce
// it while the run proceeds.
type ConcurrencyPlan struct {
	// Width is the largest number of grades this plan expects to have running
	// at once. It is the operator-facing number and the one that is logged.
	Width int
	// Reason explains the width in one line, naming the binding constraint.
	Reason string
	// Demand is the exec slots each target occupies on each node.
	Demand map[int]map[string]int
	// Budget is the grading exec budget derived for each node.
	Budget map[string]int
	// Unknown names the nodes whose capacity could not be read.
	Unknown []string

	footprints  []RunFootprint
	deviceLimit int
}

// PlanConcurrency derives a capacity-safe outer width.
//
// It never returns zero: one grade at a time is the floor, because refusing to
// grade at all is a worse answer than grading slowly, and one at a time is the
// configuration the reference solution is known to pass in.
func PlanConcurrency(req ConcurrencyRequest) ConcurrencyPlan {
	checks := req.CheckParallel
	if checks <= 0 {
		checks = 8
	}
	observation := req.ObservationParallel
	if observation <= 0 {
		observation = checks
	}
	readers := req.DeviceReaders
	if readers <= 0 {
		readers = DefaultDeviceReaders
	}

	inFlight := maxInt(checks, req.ActiveParallel)
	plan := ConcurrencyPlan{
		Demand: map[int]map[string]int{}, Budget: map[string]int{},
		footprints:  append([]RunFootprint(nil), req.Footprints...),
		deviceLimit: readers,
	}
	advertised := map[string]NodeExecBudget{}
	for _, budget := range req.Budgets {
		advertised[nodeKey(budget.Node)] = budget
	}
	sources := map[string]string{}
	for _, footprint := range req.Footprints {
		for node := range footprint.ByNode {
			if _, done := plan.Budget[node]; done {
				continue
			}
			budget, known := advertised[node].grading()
			plan.Budget[node] = budget
			if !known {
				plan.Unknown = append(plan.Unknown, node)
			}
			sources[node] = advertised[node].Source
		}
	}
	sort.Strings(plan.Unknown)

	for _, footprint := range req.Footprints {
		demand := map[string]int{}
		for node, devices := range footprint.ByNode {
			demand[node] = footprint.demandOn(devices, inFlight, observation, plan.Budget[node])
		}
		plan.Demand[footprint.AS] = demand
	}

	plan.Width = plan.simulate(true, true)
	byNode := plan.simulate(true, false)
	byDevice := plan.simulate(false, true)
	plan.Reason = plan.explain(byNode, byDevice, sources, inFlight)
	return plan
}

// demandOn is the exec slots one grade occupies on one node at a time.
//
// A grade has two phases and they do not overlap with each other: it surveys
// passively, then it runs checks. The survey reaches a node through one
// batched request whose fan-out the agent fixes; the checks reach it as
// individual execs, at most the internal check width and in proportion to how
// much of the footprint lives there. The reservation is therefore the larger
// of the two, not their sum -- charging both would halve the width for
// concurrency that never exists.
func (f RunFootprint) demandOn(devices, checks, observation, budget int) int {
	if devices <= 0 {
		return 0
	}
	survey := minInt(agentBatchWorkers, minInt(observation, devices))
	share := checks
	if total := len(f.Devices); total > 0 && devices < total {
		share = (checks*devices + total - 1) / total
	}
	if share > checks {
		share = checks
	}
	need := maxInt(survey, share)
	if need < 1 {
		need = 1
	}
	// A single grade must always be admissible: a node that advertises less
	// than one grade's width serializes grading rather than deadlocking it.
	if budget > 0 && need > budget {
		need = budget
	}
	return need
}

// simulate counts how many targets fit at once under the selected
// constraints, considering them in target order. It is the same first-fit rule
// the admission gate applies while the run is in flight, so the number that is
// logged is the number that is enforced.
func (p ConcurrencyPlan) simulate(nodes, devices bool) int {
	free := map[string]int{}
	for node, budget := range p.Budget {
		free[node] = budget
	}
	readers := map[string]int{}
	admitted := 0
	for _, footprint := range p.footprints {
		if !p.fits(footprint, free, readers, nodes, devices) {
			continue
		}
		p.charge(footprint, free, readers)
		admitted++
	}
	if admitted < 1 {
		admitted = 1
	}
	return admitted
}

func (p ConcurrencyPlan) fits(f RunFootprint, free, readers map[string]int, nodes, devices bool) bool {
	if nodes {
		for node, need := range p.Demand[f.AS] {
			if free[node] < need {
				return false
			}
		}
	}
	if devices {
		for _, router := range f.Routers {
			if readers[router] >= p.deviceLimit {
				return false
			}
		}
	}
	return true
}

func (p ConcurrencyPlan) charge(f RunFootprint, free, readers map[string]int) {
	for node, need := range p.Demand[f.AS] {
		free[node] -= need
	}
	for _, router := range f.Routers {
		readers[router]++
	}
}

func (p ConcurrencyPlan) explain(byNode, byDevice int, sources map[string]string, checks int) string {
	targets := len(p.footprints)
	if targets <= 1 {
		return "one system was selected"
	}
	if p.Width >= targets {
		return fmt.Sprintf("all %d target(s) fit the advertised exec budget of %s",
			targets, describeNodes(p.Budget))
	}
	var causes []string
	if byNode <= p.Width {
		node, budget, need := p.tightestNode()
		source := sources[node]
		if source == "" {
			source = node
		}
		if p.isUnknown(node) {
			causes = append(causes, fmt.Sprintf(
				"%s could not be asked what it admits, so grading assumes %d exec slot(s) there and each grade needs up to %d",
				source, budget, need))
		} else {
			causes = append(causes, fmt.Sprintf(
				"%s admits %d concurrent grading exec(s) and each grade needs up to %d there",
				source, budget, need))
		}
	}
	if byDevice <= p.Width {
		shared, count := p.mostSharedDevice()
		if shared != "" {
			causes = append(causes, fmt.Sprintf(
				"%d of the %d target(s) read router %s, and one router's control plane serves at most %d grade(s) at a time",
				count, targets, shared, p.deviceLimit))
		}
	}
	if len(causes) == 0 {
		causes = append(causes, fmt.Sprintf("each grade runs up to %d check(s) at once", checks))
	}
	return strings.Join(causes, "; ")
}

func (p ConcurrencyPlan) isUnknown(node string) bool {
	for _, name := range p.Unknown {
		if name == node {
			return true
		}
	}
	return false
}

// tightestNode is the node that admits the fewest grades, and is therefore the
// one an operator has to change something about.
func (p ConcurrencyPlan) tightestNode() (string, int, int) {
	nodes := make([]string, 0, len(p.Budget))
	for node := range p.Budget {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	best, bestBudget, bestNeed, bestFit := "", 0, 0, 0
	for _, node := range nodes {
		need := 0
		for _, demand := range p.Demand {
			need = maxInt(need, demand[node])
		}
		if need <= 0 {
			continue
		}
		fit := p.Budget[node] / need
		if best == "" || fit < bestFit {
			best, bestBudget, bestNeed, bestFit = node, p.Budget[node], need, fit
		}
	}
	return best, bestBudget, bestNeed
}

// mostSharedDevice is the device the largest number of targets read, which is
// the one whose contention explains the width.
func (p ConcurrencyPlan) mostSharedDevice() (string, int) {
	counts := map[string]int{}
	for _, footprint := range p.footprints {
		for _, router := range footprint.Routers {
			counts[router]++
		}
	}
	devices := make([]string, 0, len(counts))
	for device := range counts {
		devices = append(devices, device)
	}
	sort.Strings(devices)
	best, most := "", 0
	for _, device := range devices {
		if counts[device] > most {
			best, most = device, counts[device]
		}
	}
	return best, most
}

func describeNodes(budgets map[string]int) string {
	nodes := make([]string, 0, len(budgets))
	for node := range budgets {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	parts := make([]string, 0, len(nodes))
	for _, node := range nodes {
		parts = append(parts, fmt.Sprintf("%s (%d)", node, budgets[node]))
	}
	return strings.Join(parts, ", ")
}

// Admission admits grades under the plan's node and router constraints.
//
// It is a gate rather than a counting semaphore because the constraints are
// per node and per router: eight targets whose devices sit on independent
// nodes must all start, and eight targets sharing one agent must not, and no
// single number expresses both. Waiters are considered in target order and a
// waiter that fits is admitted even if an earlier one does not, so targets on
// an idle node are never held behind a target queued for a busy one.
type Admission struct {
	mu      sync.Mutex
	free    map[string]int
	readers map[string]int
	limit   int
	demand  map[int]map[string]int
	routers map[int][]string
	waiters []*admissionWaiter
	// fixed is set when an operator named an explicit width. The gate then
	// enforces exactly that number and nothing else, because an override that
	// silently kept enforcing the derived limits would not be an override.
	fixed int
	slots int
}

type admissionWaiter struct {
	as       int
	admitted bool
	ready    chan struct{}
}

// Admission builds the gate that enforces this plan.
func (p ConcurrencyPlan) Admission() *Admission {
	gate := &Admission{
		free: map[string]int{}, readers: map[string]int{}, limit: p.deviceLimit,
		demand: map[int]map[string]int{}, routers: map[int][]string{},
	}
	for node, budget := range p.Budget {
		gate.free[node] = budget
	}
	for as, demand := range p.Demand {
		copied := map[string]int{}
		for node, need := range demand {
			copied[node] = need
		}
		gate.demand[as] = copied
	}
	for _, footprint := range p.footprints {
		gate.routers[footprint.AS] = append([]string(nil), footprint.Routers...)
	}
	return gate
}

// FixedAdmission is the gate for an explicit --parallel: a plain width, with
// the derived node and device limits deliberately not applied.
func FixedAdmission(width int) *Admission {
	if width < 1 {
		width = 1
	}
	return &Admission{fixed: width}
}

// Acquire blocks until grading the named AS is admissible.
func (a *Admission) Acquire(ctx context.Context, as int) (func(), error) {
	if a == nil {
		return func() {}, nil
	}
	waiter := &admissionWaiter{as: as, ready: make(chan struct{})}
	a.mu.Lock()
	a.waiters = append(a.waiters, waiter)
	a.dispatchLocked()
	a.mu.Unlock()

	select {
	case <-waiter.ready:
		var once sync.Once
		return func() { once.Do(func() { a.release(as) }) }, nil
	case <-ctx.Done():
		a.mu.Lock()
		if waiter.admitted {
			// It was admitted while this goroutine was giving up. Hand the
			// slots straight back rather than leaking them out of the gate.
			a.mu.Unlock()
			a.release(as)
			return nil, ctx.Err()
		}
		for i, queued := range a.waiters {
			if queued == waiter {
				a.waiters = append(a.waiters[:i], a.waiters[i+1:]...)
				break
			}
		}
		a.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (a *Admission) release(as int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fixed > 0 {
		a.slots--
	} else {
		for node, need := range a.demand[as] {
			a.free[node] += need
		}
		for _, router := range a.routers[as] {
			a.readers[router]--
		}
	}
	a.dispatchLocked()
}

func (a *Admission) dispatchLocked() {
	kept := a.waiters[:0]
	for _, waiter := range a.waiters {
		if !a.fitsLocked(waiter.as) {
			kept = append(kept, waiter)
			continue
		}
		a.chargeLocked(waiter.as)
		waiter.admitted = true
		close(waiter.ready)
	}
	a.waiters = kept
}

func (a *Admission) fitsLocked(as int) bool {
	if a.fixed > 0 {
		return a.slots < a.fixed
	}
	for node, need := range a.demand[as] {
		if a.free[node] < need {
			return false
		}
	}
	for _, router := range a.routers[as] {
		if a.readers[router] >= a.limit {
			return false
		}
	}
	return true
}

func (a *Admission) chargeLocked(as int) {
	if a.fixed > 0 {
		a.slots++
		return
	}
	for node, need := range a.demand[as] {
		a.free[node] -= need
	}
	for _, router := range a.routers[as] {
		a.readers[router]++
	}
}

// RunEach grades every target under a gate, in target order, and returns the
// reports in that same order.
//
// Report order is the target order and never the completion order: a wider or
// narrower gate must not be able to change which report is which, or the order
// marks appear in. progress is called once per completed grade, with the
// number finished so far, so an operator watching a narrow run still sees it
// advance.
func RunEach(ctx context.Context, targets []int, gate *Admission,
	one func(context.Context, int) *Report,
	progress func(done, total int, report *Report),
) []*Report {
	reports := make([]*Report, len(targets))
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		done int
	)
	for index, as := range targets {
		wg.Add(1)
		go func(index, as int) {
			defer wg.Done()
			release, err := gate.Acquire(ctx, as)
			if err == nil {
				defer release()
			}
			// A gate that could not admit this system means the run is being
			// cancelled. The grade is still attempted with that context so the
			// report comes back through the ordinary machinery -- needing
			// review, carrying no total -- rather than as a silent absence.
			report := one(ctx, as)
			reports[index] = report

			mu.Lock()
			done++
			if progress != nil {
				progress(done, len(targets), report)
			}
			mu.Unlock()
		}(index, as)
	}
	wg.Wait()
	return reports
}
