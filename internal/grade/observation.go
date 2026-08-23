package grade

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// ObservationSnapshot is the immutable record of the passive facts a grade
// used. Entries are collected once, shared by every passive check, and frozen
// before the report is returned. Active probes deliberately do not use it:
// their counters, captures, and random flow tags are evidence only at the time
// they run.
type ObservationSnapshot struct {
	TakenAt     time.Time            `json:"taken_at"`
	CompletedAt time.Time            `json:"completed_at,omitempty"`
	States      []StateObservation   `json:"states,omitempty"`
	Commands    []CommandObservation `json:"commands,omitempty"`
	Errors      []ObservationError   `json:"errors,omitempty"`
	Stats       ObservationStats     `json:"stats"`
	Frozen      bool                 `json:"frozen"`

	exec rtExecFunc

	mu       sync.Mutex
	states   map[observationStateKey]observationState
	commands map[string]observationCommand
	stateRun map[observationStateKey]*observationStateFlight
	cmdRun   map[string]*observationCommandFlight
}

// StateObservation is a vendor-neutral state read captured for a device.
// Query is textual so reports are portable across netstate query bit layouts.
type StateObservation struct {
	Device   string         `json:"device"`
	Source   string         `json:"source"`
	Query    string         `json:"query"`
	TakenAt  time.Time      `json:"taken_at"`
	Duration string         `json:"duration"`
	State    netstate.State `json:"state,omitempty"`
	Error    string         `json:"error,omitempty"`
}

// CommandObservation records a passive command that supplied an observation.
// Its result is retained so evidence can be reproduced without repeating a
// query against a submission after its grade has completed.
type CommandObservation struct {
	Device   string        `json:"device"`
	Source   string        `json:"source"`
	Command  []string      `json:"command"`
	TakenAt  time.Time     `json:"taken_at"`
	Duration string        `json:"duration"`
	Result   rt.ExecResult `json:"result"`
	Error    string        `json:"error,omitempty"`
}

// ObservationError makes an unreadable state source explicit. It is never
// converted to an empty table or a failed student check.
type ObservationError struct {
	Device  string    `json:"device"`
	Source  string    `json:"source"`
	Query   string    `json:"query,omitempty"`
	Command []string  `json:"command,omitempty"`
	TakenAt time.Time `json:"taken_at"`
	Error   string    `json:"error"`
}

type rtExecFunc func(context.Context, string, []string) (rt.ExecResult, error)

type observationStateKey struct {
	device string
	query  netstate.Query
}

type observationState struct {
	at       time.Time
	duration time.Duration
	source   string
	state    netstate.State
	err      error
}

type observationCommand struct {
	at       time.Time
	duration time.Duration
	source   string
	device   string
	command  []string
	result   rt.ExecResult
	err      error
}

type observationStateFlight struct {
	done chan struct{}
}

type observationCommandFlight struct {
	done chan struct{}
}

// newObservationSnapshot starts one per-grade observation set. The executor is
// captured before Env is copied for checks, so snapshot reads cannot recurse
// through a later wrapper.
func newObservationSnapshot(exec rtExecFunc) *ObservationSnapshot {
	return &ObservationSnapshot{
		TakenAt:  time.Now().UTC(),
		exec:     exec,
		states:   map[observationStateKey]observationState{},
		commands: map[string]observationCommand{},
		stateRun: map[observationStateKey]*observationStateFlight{},
		cmdRun:   map[string]*observationCommandFlight{},
	}
}

// state returns a copy of a cached state read, loading it exactly once if the
// snapshot does not already cover the requested query. A wider collected query
// covers a narrower request, which lets the survey ask one provider call for
// interfaces, kernel state, and BGP instead of one call per check.
func (s *ObservationSnapshot) state(ctx context.Context, device string, query netstate.Query,
	load func(context.Context) (netstate.State, error),
) (netstate.State, error) {
	if s == nil {
		return load(ctx)
	}
	key := observationStateKey{device: device, query: query}

	for {
		s.mu.Lock()
		if value, ok := s.coveringStateLocked(key); ok {
			s.recordCacheLocked(ctx, true, false)
			s.mu.Unlock()
			return cloneNetstate(value.state), value.err
		}
		if s.Frozen {
			s.mu.Unlock()
			return netstate.State{}, fmt.Errorf(
				"immutable observation snapshot has no %s state for %s", query.String(), device)
		}
		if flight := s.stateRun[key]; flight != nil {
			s.recordCacheLocked(ctx, true, true)
			done := flight.done
			s.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return netstate.State{}, ctx.Err()
			}
		}
		flight := &observationStateFlight{done: make(chan struct{})}
		s.recordCacheLocked(ctx, false, false)
		s.stateRun[key] = flight
		s.mu.Unlock()

		start := time.Now()
		value, err := load(ctx)
		value.Sort()
		entry := observationState{
			at:       start.UTC(),
			duration: time.Since(start),
			source:   "netstate",
			state:    cloneNetstate(value),
			err:      err,
		}

		s.mu.Lock()
		delete(s.stateRun, key)
		// A caller whose context was cancelled must not poison a healthy
		// shared observation for another check. Real provider errors remain
		// cached and are reported as infrastructure errors to every consumer.
		if !isObservationCancellation(err) {
			s.states[key] = entry
		}
		close(flight.done)
		s.mu.Unlock()
		return cloneNetstate(value), err
	}
}

func (s *ObservationSnapshot) coveringStateLocked(want observationStateKey) (observationState, bool) {
	var (
		best    observationState
		bestSet bool
		bestN   int
	)
	for key, value := range s.states {
		if key.device != want.device || !key.query.Has(want.query) {
			continue
		}
		n := queryParts(key.query)
		if !bestSet || n < bestN {
			best, bestSet, bestN = value, true, n
		}
	}
	return best, bestSet
}

// command executes a passive command once. The caller must have classified it
// as an observation; active deliveries intentionally bypass this cache.
func (s *ObservationSnapshot) command(ctx context.Context, source, device string,
	command []string,
) (rt.ExecResult, error) {
	if s == nil || s.exec == nil {
		return rt.ExecResult{}, fmt.Errorf("no device executor is available")
	}
	key := commandKey(device, command)
	for {
		s.mu.Lock()
		if value, ok := s.commands[key]; ok {
			s.recordCacheLocked(ctx, true, false)
			s.mu.Unlock()
			return value.result, value.err
		}
		if s.Frozen {
			s.mu.Unlock()
			return rt.ExecResult{}, fmt.Errorf(
				"immutable observation snapshot has no command %q on %s", strings.Join(command, " "), device)
		}
		if flight := s.cmdRun[key]; flight != nil {
			s.recordCacheLocked(ctx, true, true)
			done := flight.done
			s.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return rt.ExecResult{}, ctx.Err()
			}
		}
		flight := &observationCommandFlight{done: make(chan struct{})}
		s.recordCacheLocked(ctx, false, false)
		s.cmdRun[key] = flight
		s.mu.Unlock()

		start := time.Now()
		result, err := s.exec(ctx, device, append([]string(nil), command...))
		entry := observationCommand{
			at:       start.UTC(),
			duration: time.Since(start),
			source:   source,
			device:   device,
			command:  append([]string(nil), command...),
			result:   result,
			err:      err,
		}

		s.mu.Lock()
		s.Stats.ExecCalls++
		delete(s.cmdRun, key)
		if !isObservationCancellation(err) {
			s.commands[key] = entry
		}

		close(flight.done)
		s.mu.Unlock()
		return result, err
	}
}

func (s *ObservationSnapshot) recordCacheLocked(ctx context.Context, hit, coalesced bool) {
	if hit {
		s.Stats.Hits++
	} else {
		s.Stats.Misses++
	}
	if coalesced {
		s.Stats.Coalesced++
	}
	if trace := traceFromContext(ctx); trace != nil {
		trace.cache(hit, coalesced)
	}
}

func (s *ObservationSnapshot) recordExternalBatchExec() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.Stats.Misses++
	s.Stats.ExecCalls++
	s.mu.Unlock()
}

func isObservationCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func commandKey(device string, command []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d:%s", len(device), device)
	for _, part := range command {
		fmt.Fprintf(&b, "|%d:%s", len(part), part)
	}
	return b.String()
}

func queryParts(query netstate.Query) int {
	n := 0
	for bit := netstate.QueryInterfaces; bit <= netstate.QueryPolicy; bit <<= 1 {
		if query.Has(bit) {
			n++
		}
	}
	return n
}

// Freeze publishes stable, sorted copies for the report. It is called only
// after all checks have joined, so the report cannot contain a half-written
// observation or depend on goroutine completion order.
func (s *ObservationSnapshot) Freeze() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Frozen {
		return
	}
	s.CompletedAt = time.Now().UTC()
	for key, value := range s.states {
		s.States = append(s.States, StateObservation{
			Device: key.device, Source: value.source, Query: key.query.String(),
			TakenAt: value.at, Duration: value.duration.Round(time.Millisecond).String(),
			State: cloneNetstate(value.state), Error: observationError(value.err),
		})
		if value.err != nil {
			s.Errors = append(s.Errors, ObservationError{
				Device: key.device, Source: value.source, Query: key.query.String(),
				TakenAt: value.at, Error: value.err.Error(),
			})
		}
	}
	for _, value := range s.commands {
		s.Commands = append(s.Commands, CommandObservation{
			Device: value.device, Source: value.source, Command: append([]string(nil), value.command...),
			TakenAt: value.at, Duration: value.duration.Round(time.Millisecond).String(),
			Result: value.result, Error: observationError(value.err),
		})
		if value.err != nil {
			s.Errors = append(s.Errors, ObservationError{
				Device: value.device, Source: value.source, Command: append([]string(nil), value.command...),
				TakenAt: value.at, Error: value.err.Error(),
			})
		}
	}
	sort.Slice(s.States, func(i, j int) bool {
		if s.States[i].Device != s.States[j].Device {
			return s.States[i].Device < s.States[j].Device
		}
		return s.States[i].Query < s.States[j].Query
	})
	sort.Slice(s.Commands, func(i, j int) bool {
		if s.Commands[i].Device != s.Commands[j].Device {
			return s.Commands[i].Device < s.Commands[j].Device
		}
		return strings.Join(s.Commands[i].Command, "\x00") < strings.Join(s.Commands[j].Command, "\x00")
	})
	sort.Slice(s.Errors, func(i, j int) bool {
		if s.Errors[i].Device != s.Errors[j].Device {
			return s.Errors[i].Device < s.Errors[j].Device
		}
		if s.Errors[i].Query != s.Errors[j].Query {
			return s.Errors[i].Query < s.Errors[j].Query
		}
		return strings.Join(s.Errors[i].Command, "\x00") < strings.Join(s.Errors[j].Command, "\x00")
	})
	s.Frozen = true
}

func observationError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// cloneNetstate keeps check code from mutating a shared snapshot through a
// returned slice. The state structs contain only values and slices, so a
// targeted deep copy is both cheaper and clearer than JSON round-tripping.
func cloneNetstate(in netstate.State) netstate.State {
	out := in
	out.Interfaces = make([]netstate.Interface, len(in.Interfaces))
	for i, iface := range in.Interfaces {
		out.Interfaces[i] = iface
		out.Interfaces[i].Addresses = append([]netstate.Address(nil), iface.Addresses...)
	}
	out.Kernel.Routes = make([]netstate.Route, len(in.Kernel.Routes))
	for i, route := range in.Kernel.Routes {
		out.Kernel.Routes[i] = route
		out.Kernel.Routes[i].NextHops = append([]netstate.NextHop(nil), route.NextHops...)
	}
	out.BGP.Sessions = append([]netstate.BGPSession(nil), in.BGP.Sessions...)
	out.BGP.Paths = make([]netstate.BGPPath, len(in.BGP.Paths))
	for i, path := range in.BGP.Paths {
		out.BGP.Paths[i] = path
		out.BGP.Paths[i].ASNs = append([]uint32(nil), path.ASNs...)
		out.BGP.Paths[i].NextHops = append([]netstate.NextHop(nil), path.NextHops...)
		out.BGP.Paths[i].Communities = append([]string(nil), path.Communities...)
	}
	out.OSPF = append([]netstate.OSPFPeer(nil), in.OSPF...)
	out.Policy = make([]netstate.PolicyFact, len(in.Policy))
	for i, policy := range in.Policy {
		out.Policy[i] = policy
		out.Policy[i].Communities = append([]string(nil), policy.Communities...)
	}
	return out
}

// observationPlan is intentionally derived only from topology and rubric
// declarations. It never runs student code while deciding what to inspect.
type observationPlan struct {
	state map[string]netstate.Query
	raw   map[string][][]string
	ovs   []*model.Device
	svc   []*model.Device
}

func buildObservationPlan(r *Rubric, env *Env) observationPlan {
	out := observationPlan{state: map[string]netstate.Query{}, raw: map[string][][]string{}}
	if r == nil || env == nil || env.Topology == nil {
		return out
	}
	var needRPKI, needOSPFRoutes bool
	for _, q := range r.Questions {
		for _, spec := range q.Checks {
			check, ok := Lookup(spec.Check)
			if !ok {
				continue
			}
			deps := check.Observations
			if len(deps) == 0 {
				deps = inferredObservations(check.Name)
			}
			for _, dep := range deps {
				for _, device := range observationDevices(env, dep.Scope) {
					if device == nil || !device.IsRouter() {
						continue
					}
					// A kernel route/forwarding read is common evidence,
					// // and piggybacks on every router netstate request.
					out.state[device.ID] |= dep.Query | netstate.QueryKernel
				}
			}
			if checkNeedsOVS(check.Name) {
				for _, device := range targetDevices(env) {
					if device.Kind == model.KindSwitch {
						out.ovs = append(out.ovs, device)
					}
					switch check.Name {
					case "rpki.invalid_rejected", "rpki.notfound_preserved":
						needRPKI = true
					case "ospf.subnets_advertised", "config.no_forbidden_ospf":
						needOSPFRoutes = true
					}
				}
			}
		}
	}
	for _, device := range targetDevices(env) {
		if device.IsRouter() {
			out.state[device.ID] |= netstate.QueryInterfaces | netstate.QueryKernel
		}
		if device.Kind == model.KindService {
			out.svc = append(out.svc, device)
		}
	}
	out.svc = append(out.svc, targetAttachedServices(env)...)
	for _, router := range env.Routers() {
		if needRPKI {
			out.raw[router.ID] = append(out.raw[router.ID],
				[]string{"vtysh", "-c", "show rpki cache-connection"},
				[]string{"vtysh", "-c", "show rpki prefix-table"},
				[]string{"vtysh", "-c", "show bgp ipv4 unicast rpki invalid"},
				[]string{"vtysh", "-c", "show bgp ipv4 unicast rpki valid"},
			)
		}
		if needOSPFRoutes {
			out.raw[router.ID] = append(out.raw[router.ID],
				[]string{"vtysh", "-c", "show ip ospf route json"},
				[]string{"vtysh", "-c", "show ip ospf interface json"},
				[]string{"vtysh", "-c", "show ip route vrf all ospf json"},
			)
		}
	}
	out.ovs = uniqueDevices(out.ovs)
	out.svc = uniqueDevices(out.svc)
	return out
}

// ObservationScope says which topology devices a check's passive facts need.
type ObservationScope string

const (
	ObservationTargetRouters   ObservationScope = "target_routers"
	ObservationNeighborRouters ObservationScope = "neighbor_routers"
	ObservationTargetDevices   ObservationScope = "target_devices"
)

// ObservationDependency is a declarative passive state requirement. Checks
// whose requirements cannot be inferred should set Check.Observations rather
// than issuing an ad-hoc duplicate query.
type ObservationDependency struct {
	Scope ObservationScope
	Query netstate.Query
}

func inferredObservations(name string) []ObservationDependency {
	target := func(query netstate.Query) []ObservationDependency {
		return []ObservationDependency{{Scope: ObservationTargetRouters, Query: query}}
	}
	switch name {
	case "l3.addressing_matches_plan":
		return target(netstate.QueryInterfaces)
	case "ospf.full_adjacency", "ospf.subnets_advertised", "ospf.ecmp_paths",
		"config.no_forbidden_ospf":
		return target(netstate.QueryOSPF | netstate.QueryInterfaces)
	case "bgp.ebgp_established":
		return []ObservationDependency{
			{Scope: ObservationTargetRouters, Query: netstate.QueryBGPSessions},
			{Scope: ObservationNeighborRouters, Query: netstate.QueryBGPSessions | netstate.QueryInterfaces},
		}
	case "bgp.own_prefix_only", "policy.gao_rexford", "policy.no_transit_for_peers",
		"policy.transit_for_customers", "policy.ixp_communities",
		"rpki.invalid_rejected", "rpki.notfound_preserved", "bgp.next_hop_self":
		return target(netstate.QueryBGP | netstate.QueryPolicy)
	case "bgp.ibgp_full_mesh":
		// This check actively refreshes sessions and compares counters before
		// and after. It must be live rather than read from a passive snapshot.
		return nil
	default:
		return target(netstate.QueryInterfaces)
	}
}

func observationDevices(env *Env, scope ObservationScope) []*model.Device {
	switch scope {
	case ObservationNeighborRouters:
		return neighborRouters(env)
	case ObservationTargetDevices:
		return targetDevices(env)
	default:
		return env.Routers()
	}
}

func targetDevices(env *Env) []*model.Device {
	if env == nil || env.Topology == nil || env.Topology.ASes[env.AS] == nil {
		return nil
	}
	return append([]*model.Device(nil), env.Topology.ASes[env.AS].Devices...)
}

func neighborRouters(env *Env) []*model.Device {
	if env == nil || env.Topology == nil {
		return nil
	}
	seen := map[string]*model.Device{}
	for _, router := range env.Routers() {
		for _, iface := range router.Ifaces {
			if iface == nil || iface.Peer == nil || iface.Peer.Device == nil || iface.Peer.Device.ASN == env.AS {
				continue
			}
			peer := iface.Peer.Device
			if peer.IsRouter() {
				seen[peer.ID] = peer
			}
		}
	}
	out := make([]*model.Device, 0, len(seen))
	for _, device := range seen {
		out = append(out, device)
	}
	return uniqueDevices(out)
}

func targetAttachedServices(env *Env) []*model.Device {
	if env == nil || env.Topology == nil {
		return nil
	}
	seen := map[string]*model.Device{}
	for _, device := range targetDevices(env) {
		for _, iface := range device.Ifaces {
			if iface == nil || iface.Peer == nil || iface.Peer.Device == nil {
				continue
			}
			if iface.Peer.Device.Kind == model.KindService {
				seen[iface.Peer.Device.ID] = iface.Peer.Device
			}
		}
	}
	out := make([]*model.Device, 0, len(seen))
	for _, device := range seen {
		out = append(out, device)
	}
	return uniqueDevices(out)
}

func uniqueDevices(in []*model.Device) []*model.Device {
	seen := map[string]*model.Device{}
	for _, device := range in {
		if device != nil && device.ID != "" {
			seen[device.ID] = device
		}
	}
	out := make([]*model.Device, 0, len(seen))
	for _, device := range seen {
		out = append(out, device)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func checkNeedsOVS(name string) bool {
	switch name {
	case "l2.vlan_isolation":
		return true
	default:
		return false
	}
}

// collectObservationSnapshot batches passive state at a bounded width. The
// node agent separately applies its own ExecProbe limiter, so this bound limits
// controller pressure without bypassing node-wide admission.
func collectObservationSnapshot(ctx context.Context, r *Rubric, env *Env, parallel int) *ObservationSnapshot {
	if env == nil {
		return newObservationSnapshot(nil)
	}
	snapshot := newObservationSnapshot(env.Exec)
	if env.Exec == nil {
		return snapshot
	}
	if parallel <= 0 {
		parallel = 16
	}
	observed := *env
	observed.snapshot = snapshot
	batcher := newObservationBatcher(ctx, snapshot, observed.BatchExec)
	observed.observationBatcher = batcher
	plan := buildObservationPlan(r, &observed)
	observed.observationExtras = plan.raw

	type task struct {
		name string
		run  func()
	}
	var tasks []task
	for deviceID, query := range plan.state {
		deviceID, query := deviceID, query
		tasks = append(tasks, task{name: "netstate/" + deviceID, run: func() {
			_, _ = observed.DeviceState(ctx, deviceID, query)
		}})
	}
	for deviceID, commands := range plan.raw {
		if _, covered := plan.state[deviceID]; covered {
			continue // folded into the device's state batch above
		}
		deviceID, commands := deviceID, commands
		tasks = append(tasks, task{name: "rubric/" + deviceID, run: func() {
			_, _ = runObservationBatch(ctx, snapshot, batcher, "rubric-batch", deviceID, commands)
		}})
	}
	for _, device := range plan.ovs {
		device := device
		tasks = append(tasks, task{name: "ovs/" + device.ID, run: func() {
			collectOVSState(ctx, snapshot, batcher, device.ID)
		}})
	}
	for _, device := range plan.svc {
		device := device
		tasks = append(tasks, task{name: "service/" + device.ID, run: func() {
			collectServiceState(ctx, snapshot, batcher, device.ID)
		}})
	}
	sort.Slice(tasks, func(i, j int) bool {
		// Task ordering does not decide report ordering, but a deterministic
		// launch order makes traces and capacity debugging reproducible.
		return tasks[i].name < tasks[j].name
	})
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for _, task := range tasks {
		task := task
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			task.run()
		}()
	}
	wg.Wait()
	batcher.close()
	return snapshot
}

func collectOVSState(ctx context.Context, snapshot *ObservationSnapshot, batcher *observationBatcher, device string) {
	if snapshot == nil {
		return
	}
	first := [][]string{
		{"ovs-vsctl", "--columns=name,tag", "--format=csv", "list", "port"},
		{"ovs-vsctl", "--columns=name,type,options", "--format=csv", "list", "interface"},
		{"ovs-vsctl", "list-br"},
	}
	results, err := runObservationBatch(ctx, snapshot, batcher, "ovs-batch", device, first)
	if err != nil || len(results) != len(first) || results[2].ExitCode != 0 {
		return
	}
	var second [][]string
	for _, bridge := range strings.Fields(results[2].Stdout) {
		second = append(second,
			[]string{"ovs-ofctl", "show", bridge},
			[]string{"ovs-ofctl", "dump-flows", bridge},
			[]string{"ovs-ofctl", "dump-groups", bridge},
			[]string{"ovs-vsctl", "get-controller", bridge},
		)
	}
	if len(second) > 0 {
		_, _ = runObservationBatch(ctx, snapshot, batcher, "ovs-batch", device, second)
	}
}

func collectServiceState(ctx context.Context, snapshot *ObservationSnapshot, batcher *observationBatcher, device string) {
	if snapshot == nil {
		return
	}
	_, _ = runObservationBatch(ctx, snapshot, batcher, "service-batch", device, [][]string{
		{"ip", "-j", "address", "show"},
		{"ip", "-j", "route", "show"},
		{"sysctl", "-n", "net.ipv4.ip_forward"},
		{"ps", "-eo", "args"},
	})
}

func runObservationBatch(ctx context.Context, snapshot *ObservationSnapshot, batcher *observationBatcher,
	source, device string, commands [][]string,
) ([]rt.ExecResult, error) {
	if batcher != nil {
		return batcher.run(ctx, source, device, commands)
	}
	return snapshot.observationBatch(ctx, source, device, commands)
}

// snapshotReadOnlyCommand intentionally has a small allow-list. In
// particular, counters, captures, shell scripts, route changes, and active
// delivery probes never enter the snapshot cache.
func snapshotReadOnlyCommand(command []string) bool {
	if len(command) == 0 {
		return false
	}
	switch command[0] {
	case "vtysh":
		for i := 0; i+1 < len(command); i++ {
			if command[i] == "-c" && strings.HasPrefix(strings.TrimSpace(command[i+1]), "show ") {
				return true
			}
		}
	case "birdc":
		for _, word := range command {
			if word == "show" {
				return true
			}
		}
	case "ovs-vsctl", "ovs-ofctl":
		return true
	case "ip":
		// Route lookups and neighbour tables are commonly read immediately
		// after a check changes a route or emits ARP. Only immutable address
		// and link inventory is safe to share automatically; other ip(8)
		// reads enter the snapshot only when collection explicitly asks them.
		joined := " " + strings.Join(command[1:], " ") + " "
		return strings.Contains(joined, " address show ") ||
			strings.Contains(joined, " addr show ") ||
			strings.Contains(joined, " link show ")
	}
	return false
}
