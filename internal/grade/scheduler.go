package grade

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

// ProbeResourceKind names a fact whose attribution is invalid when two active
// checks touch it at the same time.
type ProbeResourceKind string

const (
	ProbeSource      ProbeResourceKind = "source"
	ProbeDestination ProbeResourceKind = "destination"
	ProbeInterface   ProbeResourceKind = "interface"
	ProbeCounter     ProbeResourceKind = "counter"
	ProbeCapture     ProbeResourceKind = "capture"
	ProbePort        ProbeResourceKind = "port"
)

// ProbeResource is an exclusive active-probe resource. IDs are topology
// identities (device IDs, interface IDs, or flow tags), never human names, so
// two similar student routers cannot accidentally share a lock.
type ProbeResource struct {
	Kind ProbeResourceKind
	ID   string
}

func (r ProbeResource) key() string {
	return string(r.Kind) + "\x00" + r.ID
}

// ProbeResourceResolver turns a rubric's concrete arguments into the active
// resources a check will use. It must be pure: scheduler decisions are made
// before a check runs and must not observe or mutate student state.
type ProbeResourceResolver func(env *Env, args map[string]any) []ProbeResource

func inferredCheckClass(name string) CheckClass {
	switch name {
	case "bgp.ibgp_full_mesh", "bgp.ebgp_established",
		"dataplane.internal_reachability", "l2.vlan_isolation", "ospf.ecmp_paths",
		"tunnel.sixin4", "policy.transit_for_customers", "policy.traffic_engineering",
		"vpn.site_reachability", "vpn.label_switched", "vpn.isolation",
		"multicast.delivery", "multicast.no_flooding":
		return CheckActive
	default:
		return CheckReadOnly
	}
}

type scheduledCheck struct {
	order    int
	check    *Check
	spec     CheckSpec
	env      *Env
	instance string
	queuedAt time.Time
	key      string
	trace    *checkTrace
}

type scheduledCheckResult struct {
	order      int
	result     Result
	startedAt  time.Time
	finishedAt time.Time
	stats      ObservationStats
}

// scheduleChecks executes a fixed check set at a bounded width. It always
// considers jobs in rubric order, starts every non-conflicting job it can, and
// writes results back in that same order. Completion timing can therefore
// never change report ordering or which evidence is attached to a check.
func scheduleChecks(ctx context.Context, jobs []scheduledCheck, opts RunOptions) []Result {
	results := make([]Result, len(jobs))
	if len(jobs) == 0 {
		return results
	}
	if opts.Parallel <= 0 {
		opts.Parallel = 8
	}
	if opts.ReadParallel <= 0 {
		opts.ReadParallel = opts.Parallel
	}
	if opts.ActiveParallel <= 0 {
		opts.ActiveParallel = minInt(4, opts.Parallel)
	}
	if opts.CheckTimeout <= 0 {
		opts.CheckTimeout = 120 * time.Second
	}

	pending := append([]scheduledCheck(nil), jobs...)
	sort.SliceStable(pending, func(i, j int) bool { return pending[i].order < pending[j].order })
	byOrder := map[int]scheduledCheck{}
	now := time.Now().UTC()
	for i := range pending {
		if pending[i].queuedAt.IsZero() {
			pending[i].queuedAt = now
		}
		if pending[i].key == "" {
			pending[i].key = schedulerKey(pending[i])
		}
		if pending[i].trace == nil {
			pending[i].trace = &checkTrace{}
		}
		byOrder[pending[i].order] = pending[i]
	}
	running := map[int][]ProbeResource{}
	type startMeta struct {
		resources []ProbeResource
		blockedBy []int
		reasons   map[string]bool
	}
	metas := map[int]startMeta{}
	blockedBy := map[int]map[int]bool{}
	waitReasons := map[int]map[string]bool{}
	done := make(chan scheduledCheckResult, len(pending))
	finished := 0

	start := func(job scheduledCheck, resources []ProbeResource) {
		running[job.order] = resources
		meta := startMeta{resources: resources, reasons: waitReasons[job.order]}
		for parent := range blockedBy[job.order] {
			meta.blockedBy = append(meta.blockedBy, parent)
		}
		sort.Ints(meta.blockedBy)
		metas[job.order] = meta
		go func() {
			result, startedAt, finishedAt, stats := executeScheduledCheck(ctx, job, opts)
			done <- scheduledCheckResult{order: job.order, result: result,
				startedAt: startedAt, finishedAt: finishedAt, stats: stats}
		}()
	}

	for finished < len(jobs) {
		for _, job := range pending {
			owners, conflicts := blockingResources(resourcesFor(job), running)
			if len(owners) == 0 {
				continue
			}
			if blockedBy[job.order] == nil {
				blockedBy[job.order] = map[int]bool{}
			}
			for _, owner := range owners {
				blockedBy[job.order][owner] = true
			}
			if waitReasons[job.order] == nil {
				waitReasons[job.order] = map[string]bool{}
			}
			for _, conflict := range conflicts {
				waitReasons[job.order]["resource lock: "+conflict] = true
			}
		}
		for len(running) < opts.Parallel {
			index, resources, owners, _ := firstRunnable(pending, running, byOrder, opts)
			if index < 0 {
				for _, blockedJob := range pending {
					blockedOwners, conflicts := blockingResources(resourcesFor(blockedJob), running)
					if len(blockedOwners) == 0 {
						continue
					}
					if blockedBy[blockedJob.order] == nil {
						blockedBy[blockedJob.order] = map[int]bool{}
					}
					for _, owner := range blockedOwners {
						blockedBy[blockedJob.order][owner] = true
					}
					if waitReasons[blockedJob.order] == nil {
						waitReasons[blockedJob.order] = map[string]bool{}
					}
					for _, conflict := range conflicts {
						waitReasons[blockedJob.order]["resource lock: "+conflict] = true
					}
				}
				break
			}
			job := pending[index]
			_ = owners
			pending = append(pending[:index], pending[index+1:]...)
			start(job, resources)
		}
		recordPoolWaits(pending, running, byOrder, opts, blockedBy, waitReasons)
		if len(running) == 0 {
			// Resources are normalized before scheduling, so this can only
			// happen if a malformed job escaped normalization. Turn it into
			// a grader error rather than spin forever.
			for _, job := range pending {
				name := job.spec.Check
				if job.check != nil {
					name = job.check.Name
				}
				results[job.order] = Errored(name,
					fmt.Errorf("check scheduler could not admit its probe resources"))
			}
			break
		}
		select {
		case completed := <-done:
			results[completed.order] = completed.result
			delete(running, completed.order)
			job := byOrder[completed.order]
			meta := metas[completed.order]
			name := job.spec.Check
			if job.check != nil {
				name = job.check.Name
			}
			reasons := sortedReasonKeys(meta.reasons)
			parents := make([]string, 0, len(meta.blockedBy))
			for _, parent := range meta.blockedBy {
				parents = append(parents, byOrder[parent].key)
			}
			if opts.scheduler != nil {
				opts.scheduler.record(schedulerEvent{
					key: job.key, check: checkInstance(job), queuedAt: job.queuedAt,
					startedAt: completed.startedAt, finishedAt: completed.finishedAt,
					resources: resourceKeys(meta.resources), waitReason: strings.Join(reasons, "; "),
					blockedBy: parents, stats: completed.stats,
				})
			}
			if opts.phases != nil {
				if completed.startedAt.After(job.queuedAt) {
					opts.phases.appendDetail(PhaseTiming{
						Name: "check_wait", Check: name, StartedAt: job.queuedAt,
						Instance:   checkInstance(job),
						FinishedAt: completed.startedAt,
						Duration:   completed.startedAt.Sub(job.queuedAt).Round(time.Millisecond).String(),
						WaitReason: strings.Join(reasons, "; "), Resources: resourceKeys(meta.resources),
					})
				}
				opts.phases.appendDetail(PhaseTiming{
					Name: "check", Check: name, StartedAt: completed.startedAt,
					Instance:   checkInstance(job),
					FinishedAt: completed.finishedAt,
					Duration:   completed.finishedAt.Sub(completed.startedAt).Round(time.Millisecond).String(),
					WaitReason: strings.Join(reasons, "; "), Resources: resourceKeys(meta.resources),
					Cache: completed.stats,
				})
			}
			finished++
		case <-ctx.Done():
			for _, job := range pending {
				name := job.spec.Check
				if job.check != nil {
					name = job.check.Name
				}
				results[job.order] = Errored(name, ctxErr(ctx))
			}
			for order := range running {
				if results[order].Check == "" {
					name := jobs[order].spec.Check
					if jobs[order].check != nil {
						name = jobs[order].check.Name
					}
					results[order] = Errored(name, ctxErr(ctx))
				}
			}
			return results
		}
	}
	return results
}

func firstRunnable(pending []scheduledCheck, running map[int][]ProbeResource,
	byOrder map[int]scheduledCheck, opts RunOptions,
) (int, []ProbeResource, []int, []string) {
	for i, job := range pending {
		resources := resourcesFor(job)
		owners, _ := blockingResources(resources, running)
		if len(owners) == 0 && poolAvailable(job, running, byOrder, opts) {
			return i, resources, nil, nil
		}
	}
	return -1, nil, nil, nil
}

func poolAvailable(job scheduledCheck, running map[int][]ProbeResource,
	byOrder map[int]scheduledCheck, opts RunOptions,
) bool {
	if len(running) >= opts.Parallel {
		return false
	}
	read, active := runningClassCounts(running, byOrder)
	switch checkClass(job) {
	case CheckActive:
		return active < opts.ActiveParallel
	default:
		return read < opts.ReadParallel
	}
}

func runningClassCounts(running map[int][]ProbeResource,
	byOrder map[int]scheduledCheck,
) (read, active int) {
	for order := range running {
		if checkClass(byOrder[order]) == CheckActive {
			active++
		} else {
			read++
		}
	}
	return read, active
}

func checkClass(job scheduledCheck) CheckClass {
	if job.check != nil && job.check.Class != "" {
		return job.check.Class
	}
	return inferredCheckClass(job.spec.Check)
}

func recordPoolWaits(pending []scheduledCheck, running map[int][]ProbeResource,
	byOrder map[int]scheduledCheck, opts RunOptions,
	blockedBy map[int]map[int]bool, waitReasons map[int]map[string]bool,
) {
	read, active := runningClassCounts(running, byOrder)
	for _, job := range pending {
		if owners, _ := blockingResources(resourcesFor(job), running); len(owners) > 0 {
			continue
		}
		reason := ""
		var parents []int
		switch checkClass(job) {
		case CheckActive:
			if active >= opts.ActiveParallel {
				reason = "active pool limit"
				for order := range running {
					if checkClass(byOrder[order]) == CheckActive {
						parents = append(parents, order)
					}
				}
			}
		default:
			if read >= opts.ReadParallel {
				reason = "read-only pool limit"
				for order := range running {
					if checkClass(byOrder[order]) != CheckActive {
						parents = append(parents, order)
					}
				}
			}
		}
		if reason == "" && len(running) >= opts.Parallel {
			reason = "total check limit"
			for order := range running {
				parents = append(parents, order)
			}
		}
		if reason == "" {
			continue
		}
		if waitReasons[job.order] == nil {
			waitReasons[job.order] = map[string]bool{}
		}
		waitReasons[job.order][reason] = true
		if blockedBy[job.order] == nil {
			blockedBy[job.order] = map[int]bool{}
		}
		for _, parent := range parents {
			blockedBy[job.order][parent] = true
		}
	}
}

func blockingResources(want []ProbeResource, running map[int][]ProbeResource) ([]int, []string) {
	if len(want) == 0 {
		return nil, nil
	}
	owners := map[int]bool{}
	conflicts := map[string]bool{}
	for order, held := range running {
		for _, candidate := range want {
			for _, resource := range held {
				if candidate.key() == resource.key() {
					owners[order] = true
					conflicts[strings.ReplaceAll(candidate.key(), "\x00", "/")] = true
				}
			}
		}
	}
	outOwners := make([]int, 0, len(owners))
	for owner := range owners {
		outOwners = append(outOwners, owner)
	}
	sort.Ints(outOwners)
	outConflicts := make([]string, 0, len(conflicts))
	for conflict := range conflicts {
		outConflicts = append(outConflicts, conflict)
	}
	sort.Strings(outConflicts)
	return outOwners, outConflicts
}

func resourcesFor(job scheduledCheck) []ProbeResource {
	var resources []ProbeResource
	if job.check != nil && job.check.Resources != nil {
		resources = job.check.Resources(job.env, job.spec.Args)
	} else if job.check != nil {
		resources = inferredProbeResources(job.check.Name, job.env)
	}
	seen := map[string]bool{}
	out := make([]ProbeResource, 0, len(resources))
	for _, resource := range resources {
		if resource.Kind == "" || strings.TrimSpace(resource.ID) == "" {
			continue
		}
		key := resource.key()
		if !seen[key] {
			seen[key] = true
			out = append(out, resource)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// inferredProbeResources protects shipped active checks while keeping
// control-plane reads fully concurrent. They share target hosts and their
// destination counters/captures, so concurrent attribution would be invalid;
// independent AS grades have different device IDs and do not serialize.
func inferredProbeResources(name string, env *Env) []ProbeResource {
	switch name {
	case "bgp.ibgp_full_mesh", "bgp.ebgp_established":
		return bgpRefreshResources(name, env)
	case "dataplane.internal_reachability":
		return internalReachabilityResources(env)
	case "l2.vlan_isolation", "ospf.ecmp_paths":
		// VLAN uses ARP/neighbour-table evidence and ECMP uses ordinary
		// ping/table lookups; neither attributes a shared counter/capture.
		return nil
	case "tunnel.sixin4":
		return sixIn4Resources(env)
	case "policy.transit_for_customers":
		return transitResources(env)
	case "vpn.site_reachability", "vpn.label_switched", "vpn.isolation":
		return vpnResources(env)
	case "multicast.delivery", "multicast.no_flooding":
		return multicastResources(env)
	default:
		return nil
	}
}

func bgpRefreshResources(name string, env *Env) []ProbeResource {
	if env == nil {
		return nil
	}
	var out []ProbeResource
	for _, router := range env.Routers() {
		switch name {
		case "bgp.ibgp_full_mesh":
			for _, other := range env.Routers() {
				if other == router {
					continue
				}
				if loopback, ok := other.IfaceByName("lo"); ok && loopback.Addr4 != "" {
					out = append(out, ProbeResource{
						Kind: ProbeCounter, ID: router.ID + "/bgp-session/" + addrOf(loopback.Addr4),
					})
				}
			}
		case "bgp.ebgp_established":
			for _, iface := range router.Ifaces {
				if iface.Role != model.RoleInterAS && iface.Role != model.RoleIXPLink {
					continue
				}
				out = append(out, ProbeResource{
					Kind: ProbeCounter, ID: router.ID + "/bgp-interface/" + iface.Name,
				})
			}
		}
	}
	return out
}

func internalReachabilityResources(env *Env) []ProbeResource {
	if env == nil || env.Topology == nil {
		return nil
	}
	var devices []*model.Device
	for _, device := range targetDevices(env) {
		if device.Kind == model.KindHost && device.L2Domain == "" {
			devices = append(devices, device)
		}
	}
	return ipv4TransportResources(devices)
}

func sixIn4Resources(env *Env) []ProbeResource {
	if env == nil || env.Topology == nil {
		return nil
	}
	var hosts, gateways []*model.Device
	for _, device := range targetDevices(env) {
		if device.Kind == model.KindHost && device.L2Domain != "" {
			hosts = append(hosts, device)
		}
		if device.Kind == model.KindRouter && device.L2Gateway != "" {
			gateways = append(gateways, device)
		}
	}
	out := counterResources(hosts, "tcp", "udp6")
	for _, gateway := range gateways {
		out = append(out, ProbeResource{Kind: ProbeInterface, ID: gateway.ID + "/tunnel"})
	}
	return out
}

func transitResources(env *Env) []ProbeResource {
	if env == nil || env.Topology == nil {
		return nil
	}
	var out []ProbeResource
	for _, link := range env.Topology.Links {
		if link == nil || !link.InterAS || link.A == nil || link.B == nil ||
			link.A.Device == nil || link.B.Device == nil {
			continue
		}
		for _, side := range []*model.Iface{link.A, link.B} {
			if side.Device.ASN != env.AS || side.Peer == nil || side.Peer.Device == nil {
				continue
			}
			if link.PeerRelationship(side) == model.RelCustomer {
				out = append(out,
					ProbeResource{Kind: ProbeSource, ID: side.Peer.Device.ID},
					ProbeResource{Kind: ProbeInterface, ID: side.Peer.Device.ID + "/" + side.Peer.Name},
				)
			}
		}
	}
	for _, device := range env.Topology.SortedDevices() {
		if device.Kind == model.KindHost && device.ASN != env.AS && device.L2Domain == "" {
			out = append(out, ProbeResource{Kind: ProbeCounter, ID: device.ID + "/tcp"})
		}
	}
	return out
}

func vpnResources(env *Env) []ProbeResource {
	if env == nil || env.Topology == nil {
		return nil
	}
	var devices []*model.Device
	for _, device := range targetDevices(env) {
		if device.Kind == model.KindHost {
			devices = append(devices, device)
		}
	}
	return counterResources(devices, "tcp", "udp4")
}

func multicastResources(env *Env) []ProbeResource {
	if env == nil || env.Topology == nil {
		return nil
	}
	var devices []*model.Device
	for _, device := range targetDevices(env) {
		if device.Kind == model.KindHost {
			devices = append(devices, device)
		}
	}
	return counterResources(devices, "udp4")
}

func ipv4TransportResources(devices []*model.Device) []ProbeResource {
	return counterResources(devices, "tcp", "udp4")
}

func counterResources(devices []*model.Device, counters ...string) []ProbeResource {
	seen := map[string]bool{}
	for _, device := range devices {
		if device != nil && device.ID != "" {
			seen[device.ID] = true
		}
	}
	var out []ProbeResource
	for device := range seen {
		for _, counter := range counters {
			out = append(out, ProbeResource{Kind: ProbeCounter, ID: device + "/" + counter})
		}
	}
	return out
}

func executeScheduledCheck(ctx context.Context, job scheduledCheck, opts RunOptions) (
	Result, time.Time, time.Time, ObservationStats,
) {
	startedAt := time.Now().UTC()
	if job.check == nil {
		finishedAt := time.Now().UTC()
		return Errored(job.spec.Check, fmt.Errorf("no such check")), startedAt, finishedAt, ObservationStats{}
	}
	cctx, cancel := context.WithTimeout(ctx, opts.CheckTimeout)
	defer cancel()
	cctx = withCheckTrace(cctx, job.trace)

	// Each check owns mutable arguments and its infrastructure tracker, while
	// the snapshot and peer cache remain shared by pointer.
	env := *job.env
	if env.peers == nil {
		env.peers = &peerCache{addr: map[string]string{}}
	}
	env.Args = job.spec.Args
	env.infraSeen = &infraTracker{}
	env.liveState = job.check.LiveObservations
	env.trace = job.trace
	res := runCheck(cctx, job.check, &env)

	if fail := env.infraSeen.failure(); fail != nil && res.Status != StatusError {
		res = Errored(job.spec.Check, fail)
	}
	if cctx.Err() != nil && res.Status != StatusError {
		res = Errored(job.spec.Check, fmt.Errorf(
			"this check ran out of time after %s, so what it found is what it had managed "+
				"to look at rather than a judgement about the submission: %w",
			opts.CheckTimeout, cctx.Err()))
	}
	return res, startedAt, time.Now().UTC(), job.trace.snapshot()
}

func schedulerKey(job scheduledCheck) string {
	return fmt.Sprintf("%04d:%s", job.order, checkInstance(job))
}

func checkInstance(job scheduledCheck) string {
	if job.instance != "" {
		return job.instance
	}
	return checkInstanceFor("", job.spec.Check, job.order)
}

func checkInstanceFor(questionID, check string, index int) string {
	if questionID == "" {
		return fmt.Sprintf("%s[%d]", check, index)
	}
	return fmt.Sprintf("%s/%s[%d]", questionID, check, index)
}

func sortedReasonKeys(reasons map[string]bool) []string {
	out := make([]string, 0, len(reasons))
	for reason := range reasons {
		out = append(out, reason)
	}
	sort.Strings(out)
	return out
}

// runChecksAcrossQuestions schedules a dependency-ready question wave as one
// job list. Results are split back into question order after all active probe
// conflicts have been resolved.
func runChecksAcrossQuestions(ctx context.Context, questions []QuestionSpec, indices []int,
	env *Env, opts RunOptions,
) map[int][]Result {
	type location struct {
		question int
		check    int
	}
	var (
		jobs      []scheduledCheck
		locations []location
	)
	for _, questionIndex := range indices {
		q := questions[questionIndex]
		for checkIndex, spec := range q.Checks {
			check, _ := Lookup(spec.Check)
			jobs = append(jobs, scheduledCheck{
				order: len(jobs), check: check, spec: spec, env: env,
				instance: checkInstanceFor(q.ID, spec.Check, checkIndex),
			})
			locations = append(locations, location{question: questionIndex, check: checkIndex})
		}
	}
	flat := scheduleChecks(ctx, jobs, opts)
	out := map[int][]Result{}
	for _, questionIndex := range indices {
		out[questionIndex] = make([]Result, len(questions[questionIndex].Checks))
	}
	for index, result := range flat {
		where := locations[index]
		out[where.question][where.check] = result
	}
	return out
}
