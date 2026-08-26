package deploy

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// A device's network state is not in its container.
//
// Addresses, routes, tunnels and bridge ports live in a network namespace, and
// the namespace belongs to the running task rather than to the container. Kill
// a containerd router's pid 1 and it comes back with the same name, the same
// image, the same specification hash, the same filesystem -- and an empty
// namespace. Every comparison a deployment makes says the device is current,
// because every one of them is a comparison of things that did not change.
//
// What is lost is the student's work, and on a teaching deployment the state
// store is the only place it exists. The platform renders no `ip address` for
// an interface the student owns: the address is in the model so the grader and
// `--solve` agree on it, but the running lab has it only because somebody
// configured it, and it was captured from the kernel into a snapshot. The
// routing configuration is a file and survives; the addressing it depends on
// does not. So the router came back with its OSPF stanza intact, no address on
// any interface, and no neighbour -- while the deployment reported success.
//
// The namespace a device was last configured in is therefore recorded beside
// the hashes that decide whether it is current, and a device found in a
// different one is not current. It needs its links, its configuration, and
// then its saved state replayed on top, in that order: an address cannot be
// put on an interface that does not exist yet.

// namespaceProofAttempts bounds the retries when recording a namespace after a
// configure. A backend may publish a restarted task's pid a moment late; an
// identity that stays unreadable is a failure and is reported as one.
const namespaceProofAttempts = 5

// namespaceProofBackoff is the pause between those attempts.
const namespaceProofBackoff = 100 * time.Millisecond

// markNamespaceStateLost records that what lived in this device's network
// namespace is gone: the namespace was replaced, or the interfaces that held
// it were rebuilt end to end because a neighbour's was.
func (e *Engine) markNamespaceStateLost(id string) { e.lostNamespaceState.Store(id, true) }

func (e *Engine) namespaceStateLost(id string) bool {
	outstanding, ok := e.lostNamespaceState.Load(id)
	return ok && outstanding == true
}

// clearNamespaceStateLost records that the loss has been made good: the device
// has been rewired, reconfigured, and its saved state replayed. Until that
// happens what is in its namespace is not its student's work, and nothing may
// store it as though it were.
//
// The device stays in the map with the loss settled, so the caller can still
// be told which devices this deployment put back together.
func (e *Engine) clearNamespaceStateLost(id string) { e.lostNamespaceState.Store(id, false) }

// DirtyNamespaceStateDevices names the devices this deployment found with their
// namespace-backed state gone.
//
// The caller needs them because they are exactly the devices whose cached
// health verdict is now wrong. A device found in this state has its semantic
// probe skipped -- there is no point auditing addressing that is about to be
// replayed -- and skipping the probe is what leaves the verdict from before
// the repair standing. A deployment that fixed a router and then reported it
// as degraded is not wrong for long, but it is wrong at the only moment an
// operator is looking.
func (e *Engine) DirtyNamespaceStateDevices() []string {
	var out []string
	e.lostNamespaceState.Range(func(key, _ any) bool {
		if id, ok := key.(string); ok {
			out = append(out, id)
		}
		return true
	})
	sort.Strings(out)
	return out
}

func (e *Engine) resetLostNamespaceState() {
	e.lostNamespaceState.Range(func(key, _ any) bool {
		e.lostNamespaceState.Delete(key)
		return true
	})
	e.unprovenNamespace.Range(func(key, _ any) bool {
		e.unprovenNamespace.Delete(key)
		return true
	})
}

// markNamespaceUnproven records that a device has no recorded namespace and
// that this pass could not establish what is in the one it is using.
//
// This is the upgrade window. Everything above compares a device's namespace
// against the one it was last configured in, and before this code existed
// nothing recorded that -- so on the first pass after an upgrade every device
// is unbaselined. A device that can be proven continuous is baselined below
// and the window closes for it. A device that is already broken is the
// dangerous one: it may have restarted weeks ago, in which case its namespace
// is empty and its student's addressing exists only in the state store.
// Recording that namespace would bless the emptiness as the device's own, and
// capturing from it would then overwrite the only copy of the work.
//
// So it is left unbaselined, and its namespace-backed state is withheld from
// the store until continuity can be shown again. The device is still repaired
// -- a failing semantic probe already schedules its configuration -- and the
// snapshot is still there for an operator who wants it replayed.
func (e *Engine) markNamespaceUnproven(id, reason string) {
	e.unprovenNamespace.Store(id, reason)
}

// namespaceUnproven reports whether this pass failed to establish what is in a
// device's network namespace.
//
// A container this pass created from its image is no longer in doubt whatever
// the doubt was about: the namespace is new, and the create path replays the
// store into it before anything reads it back. Without that exemption a first
// deployment -- where every container is absent and so nothing can be proven
// about any of them -- would refuse to baseline every device it built, and a
// lab that is deployed once and left alone would never be protected at all.
func (e *Engine) namespaceUnproven(id string) bool {
	if _, ok := e.unprovenNamespace.Load(id); !ok {
		return false
	}
	return !e.containerCreatedThisPass(id)
}

// UnprovenNamespaceDevices names the devices this pass could neither baseline
// nor vouch for, with the reason for each.
//
// Refusing is not the same as reporting. A device here is one whose saved
// state is being withheld from the store and whose namespace is not being
// recorded, which is a state an operator has to be able to see rather than
// infer from a lab that quietly stops being backed up.
func (e *Engine) UnprovenNamespaceDevices() map[string]string {
	out := map[string]string{}
	e.unprovenNamespace.Range(func(key, value any) bool {
		id, idOK := key.(string)
		reason, reasonOK := value.(string)
		if idOK && reasonOK {
			out[id] = reason
		}
		return true
	})
	return out
}

// namespaceContinuityProbe reads what is actually in a device's network
// namespace: the netdevs, then the addressing, routes and link objects a
// capture would read back out of it.
//
// It is deliberately the same reading a capture makes, because the question it
// answers is whether a capture taken now would be the student's work or an
// empty room with their name on it.
const namespaceContinuityProbe = "ip -o link show || exit $?\necho ---\n" + addrCapture

// namespaceContents is one reading of a namespace: which netdevs are in it and
// which typed address facts are on them.
type namespaceContents struct {
	links map[string]bool
	addrs map[string]bool
}

func parseNamespaceContents(raw string) namespaceContents {
	out := namespaceContents{links: map[string]bool{}, addrs: map[string]bool{}}
	linkLines, addrBody := splitNamespaceProbe(raw)
	for _, line := range strings.Split(linkLines, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		name, _, _ = strings.Cut(name, "@")
		if name != "" {
			out.links[name] = true
		}
	}
	for _, fact := range canonicalAddressFacts(addrBody) {
		out.addrs[fact] = true
	}
	return out
}

func splitNamespaceProbe(raw string) (links, addrs string) {
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "---" {
			return strings.Join(lines[:i], "\n"), strings.Join(lines[i+1:], "\n")
		}
	}
	return raw, ""
}

// canonicalAddressFacts reduces one addrCapture reading to its typed address
// lines. Routes are deliberately left out: a routing daemon installs and
// withdraws them constantly, and comparing them would make every busy router
// look discontinuous.
func canonicalAddressFacts(raw string) []string {
	var out []string
	for _, line := range strings.Split(CanonicalDynamicSnapshot(state.KindAddrs, raw), "\n") {
		if strings.HasPrefix(line, "addr ") {
			out = append(out, line)
		}
	}
	return out
}

// modelledNamespaceInterfaces names the netdevs the platform's own wiring puts
// in a device's namespace. They are the part of a namespace's contents that
// does not depend on whether a student has done any work yet.
func modelledNamespaceInterfaces(d *model.Device) []string {
	var out []string
	for _, i := range d.Ifaces {
		if i == nil || i.Link == nil || i.Name == "" {
			continue
		}
		out = append(out, i.Name)
	}
	sort.Strings(out)
	return out
}

// modelledPlatformAddresses names the addresses the platform itself renders
// onto a device's wired interfaces.
//
// A student's addresses are not here, and must not be: in teaching mode the
// model carries them so that grading and `--solve` agree about what the answer
// is, while the running lab has them only because somebody configured them.
// Requiring them would call every unstarted exercise broken.
func modelledPlatformAddresses(d *model.Device) []string {
	var out []string
	for _, i := range d.Ifaces {
		if i == nil || i.Link == nil || i.Name == "" || i.Owner != model.OwnerPlatform {
			continue
		}
		for _, address := range []string{i.Addr4, i.Addr6} {
			if address == "" || dynamicKernelAddress(address) {
				continue
			}
			family := "inet"
			if strings.Contains(address, ":") {
				family = "inet6"
			}
			out = append(out, "addr "+family+" "+i.Name+" "+address)
		}
	}
	sort.Strings(out)
	return out
}

// savedNamespaceAddresses names the addresses the state store says this device
// had the last time anything read it.
//
// This is the evidence the model cannot supply. On a teaching deployment the
// student's addressing is captured out of the kernel and kept here, and it is
// the only description of what their namespace is supposed to contain.
func (e *Engine) savedNamespaceAddresses(top *model.Topology, d *model.Device) []string {
	if e.State == nil || top == nil || !studentOwned(top, d) {
		return nil
	}
	snapshot, err := e.State.Current(top.Name, d.ID, state.KindAddrs)
	if err != nil {
		return nil
	}
	return canonicalAddressFacts(string(snapshot.Content))
}

// provenNamespaceContinuity reports whether a device's current namespace can
// be shown to hold the network state it is supposed to hold.
//
// This is the contract a baseline needs, and passing a semantic probe is not
// it. In platform mode the probe deliberately skips every interface a student
// owns, a router is not asked for a default route, and a device the audit
// already believes healthy is not re-read at all -- so a student's router that
// restarted into an empty namespace last week passes every one of those checks
// and would have its emptiness recorded as the namespace its work was done in.
func (e *Engine) provenNamespaceContinuity(ctx context.Context, top *model.Topology,
	d *model.Device,
) (bool, string) {
	result, err := e.Runtime.Exec(ctx, d.Container, runtime.ExecCmd{
		Cmd: []string{"sh", "-c", namespaceContinuityProbe}})
	if err != nil {
		return false, fmt.Sprintf("its network namespace could not be read: %v", err)
	}
	if result.ExitCode != 0 {
		return false, fmt.Sprintf("reading its network namespace exited %d", result.ExitCode)
	}
	have := parseNamespaceContents(result.Stdout)
	for _, name := range modelledNamespaceInterfaces(d) {
		if !have.links[name] {
			return false, "the modelled interface " + name + " is not in it"
		}
	}
	for _, want := range modelledPlatformAddresses(d) {
		if !have.addrs[want] {
			return false, "the platform address it should carry is not in it (" + want + ")"
		}
	}
	// The interfaces can be back without the work on them: a reconcile that
	// rewired a restarted device rebuilds bare veths, and a namespace with
	// every cable in it and none of the student's addresses is exactly what
	// this must not bless.
	for _, want := range e.savedNamespaceAddresses(top, d) {
		if !have.addrs[want] {
			return false, "the saved address it was last seen with is not in it (" + want + ")"
		}
	}
	return true, ""
}

// settleNamespaceBaselines gives a recorded namespace to every device whose
// current one can be proven continuous with the state it is supposed to hold,
// and refuses one -- and the right to overwrite that state -- to every device
// where it cannot.
//
// A device is otherwise only baselined by the configure step, so a node full of
// healthy devices that never need configuring would never be protected: the
// first restart of any of them would be invisible for ever, because there would
// be nothing to compare against. That is the upgrade window, and closing it is
// what this is for.
//
// It runs over every device with no baseline, not only the ones a semantic
// probe was run on. A device that also needs a new image or a changed file is
// excluded from the probe entirely, and it is the one about to be captured and
// replaced -- so leaving it out was leaving out the case where being wrong
// costs the student their work rather than a wasted pass.
func (e *Engine) settleNamespaceBaselines(ctx context.Context, top *model.Topology,
	devices []*model.Device, diff BuildDiff, lost map[string]bool,
	byName map[string]runtime.Container, tracker *observationTracker,
) {
	if e.Runtime == nil || tracker == nil || !runtime.SupportsNetnsIdentity(e.Runtime) {
		return
	}
	if e.ObservationReadOnly {
		// A plan reports; it does not decide what the next deployment will
		// trust, and it captures nothing that could go wrong. Reading every
		// unbaselined namespace here would cost a round trip per device and
		// persist nothing.
		return
	}
	type candidate struct {
		device   *model.Device
		baseline bool
	}
	var candidates []candidate
	for _, d := range devices {
		if recorded, known := tracker.namespace(d.ID); known && recorded.Known() {
			continue
		}
		if lost[d.ID] {
			// The repair path owns this device. Its state is already withheld
			// and the configure step records the namespace it puts it back in.
			continue
		}
		// A device that is clean can be baselined. A device that is dirty
		// cannot -- the configure step records a better baseline once the work
		// is done -- but if this pass is going to capture it, what is in its
		// namespace still has to be established before that capture is allowed
		// to become the stored copy.
		baseline := !diff.Create[d.ID] && !diff.Recreate[d.ID] &&
			!diff.Configure[d.ID] && !diff.Ready[d.ID]
		if !baseline && !diff.Capture[d.ID] {
			continue
		}
		if diff.Semantic[d.ID] {
			e.markNamespaceUnproven(d.ID, "its modelled network state is missing")
			continue
		}
		container, ok := byName[d.Container]
		if !ok || !container.State.Joinable() {
			// Nothing can be read from a container that is not running, and a
			// stopped task has already lost its namespace: starting it makes a
			// new empty one. Capturing from that is the destructive mistake.
			e.markNamespaceUnproven(d.ID, "its container is not running, so its "+
				"network namespace cannot be read")
			continue
		}
		candidates = append(candidates, candidate{device: d, baseline: baseline})
	}
	if len(candidates) == 0 {
		return
	}
	proven := make([]runtime.NetnsIdentity, len(candidates))
	reasons := make([]string, len(candidates))
	_, _, ctxErr := e.runBounded(ctx, len(candidates), func(i int) error {
		proven[i], reasons[i] = e.proveNamespaceBaseline(ctx, top, candidates[i].device)
		return nil
	})
	if ctxErr != nil {
		return
	}
	for i, c := range candidates {
		if !proven[i].Known() {
			e.markNamespaceUnproven(c.device.ID, reasons[i])
			continue
		}
		if c.baseline {
			tracker.bootstrapNamespace(c.device.ID, proven[i])
		}
	}
}

// proveNamespaceBaseline brackets the continuity proof with the identity of
// the namespace it was read from.
//
// The proof takes several round trips, and a device is perfectly capable of
// restarting during them: the container record the observation is holding
// names a pid that has already gone, and reading the namespace through it
// would attribute one namespace's contents to another's identity. So the
// identity is resolved from the backend before and after, and both readings
// have to agree before anything is recorded.
func (e *Engine) proveNamespaceBaseline(ctx context.Context, top *model.Topology,
	d *model.Device,
) (runtime.NetnsIdentity, string) {
	before, err := runtime.NetnsIdentityOf(ctx, e.Runtime, d.Container)
	if err != nil || !before.Known() {
		return runtime.NetnsIdentity{}, "its network namespace identity could not be read"
	}
	proven, reason := e.provenNamespaceContinuity(ctx, top, d)
	if !proven {
		return runtime.NetnsIdentity{}, reason
	}
	after, err := runtime.NetnsIdentityOf(ctx, e.Runtime, d.Container)
	if err != nil || !after.Known() || !after.SameAs(before) {
		return runtime.NetnsIdentity{}, "it restarted while its network namespace was being read"
	}
	return after, ""
}

// observedNamespaceReplacements names devices whose network namespace is not
// the one their state was last configured in.
//
// It is a screen over an observation the caller already holds, so it costs no
// engine round trip on a node with two hundred devices, and the configure step
// proves the identity again when it records the new one. A device with no
// recorded namespace is not reported: nothing was ever proven about it, and
// inventing a replacement would replay a snapshot over a device that is
// working. That is the one blind spot, and it closes after the first configure
// of each device.
//
// A backend that cannot prove namespace identity at all is left alone. Split
// namespaces of this kind are a property of the host backends; a backend
// without the capability replaces the whole container when its task dies,
// which the create path already restores through.
func (e *Engine) observedNamespaceReplacements(ctx context.Context, devices []*model.Device,
	byName map[string]runtime.Container, tracker *observationTracker,
) map[string]bool {
	out := map[string]bool{}
	if e.Runtime == nil || tracker == nil || !runtime.SupportsNetnsIdentity(e.Runtime) {
		return out
	}
	for _, d := range devices {
		recorded, known := tracker.namespace(d.ID)
		if !known || !recorded.Known() {
			continue
		}
		container, ok := byName[d.Container]
		if !ok || !container.State.Joinable() {
			// A container that is absent or not running is the create step's
			// to repair, and that path restores through its own marker.
			continue
		}
		now, err := runtime.ObservedNetnsIdentityOf(ctx, e.Runtime, container)
		if err != nil || !now.SameAs(recorded) {
			// Fail closed. An identity that could not be read is not evidence
			// that the namespace survived, and being wrong costs one replay of
			// state the store already holds.
			out[d.ID] = true
		}
	}
	return out
}

// recordDeviceNamespace stores the namespace a device has just been configured
// and replayed in, which is what the next deployment compares against.
func (e *Engine) recordDeviceNamespace(ctx context.Context, tracker *observationTracker,
	d *model.Device,
) error {
	if e.Runtime == nil || tracker == nil || d == nil || !runtime.SupportsNetnsIdentity(e.Runtime) {
		return nil
	}
	if e.namespaceUnproven(d.ID) {
		// This device has never had a namespace recorded and arrived at this
		// pass with what should be in its namespace unaccounted for.
		// Configuring it does not settle which of the two things happened --
		// an ordinary drift, or a restart that emptied the namespace weeks ago
		// -- and recording the namespace now would settle it the wrong way for
		// ever. It stays unbaselined until continuity can be proven, or until
		// a pass rebuilds the container and replays the store into it, which
		// makes the question moot.
		return nil
	}
	var last error
	for attempt := 0; attempt < namespaceProofAttempts; attempt++ {
		identity, err := runtime.NetnsIdentityOf(ctx, e.Runtime, d.Container)
		if err == nil {
			return tracker.markNamespace(d.ID, identity)
		}
		last = err
		timer := time.NewTimer(namespaceProofBackoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("record the network namespace %s was configured in: %w", d.ID, last)
}

// namespaceBackedKind reports whether a snapshot records what is in a network
// namespace rather than what is on a filesystem.
//
// The distinction decides what may be captured from a device whose namespace
// was replaced. Its routing configuration is a file and is still the student's
// work; its addresses, routes, tunnels and bridge ports are gone, and writing
// that emptiness to the store as the current snapshot destroys the only copy
// of the work that is meant to be replayed back on top.
func namespaceBackedKind(kind state.Kind) bool {
	switch kind {
	case state.KindAddrs, state.KindTunnels, state.KindOVS:
		return true
	default:
		return false
	}
}

// storableSnapshots drops the namespace-backed snapshots of a device whose
// namespace was replaced and whose saved state has not been replayed back into
// it yet.
//
// A deployment captures at every destructive boundary, and the boundary a
// restarted router arrives at is exactly the moment its namespace is empty.
// Without this, the pass that noticed the restart is the pass that overwrites
// the snapshot it was about to restore -- and then reports success.
//
// Both the finding of this pass and the marker a previous one left are
// consulted. The marker is what makes the guard hold across the process
// boundary: capture is also run by an engine that did no observing, and by a
// later agent entirely, and neither of those knows what the pass that found
// the restart knew.
//
// A device with no baseline whose namespace could not be shown to hold what it
// is supposed to hold is withheld too. There the doubt is the point: nothing
// can say whether its namespace is the one its student worked in or an empty
// one it restarted into before any of this was recorded, and the emptiness is
// exactly what a capture would file over the work.
func (e *Engine) storableSnapshots(ctx context.Context, d *model.Device,
	snaps []state.Snapshot,
) []state.Snapshot {
	if d == nil {
		return snaps
	}
	namespaceBacked := false
	for _, s := range snaps {
		if namespaceBackedKind(s.Kind) {
			namespaceBacked = true
			break
		}
	}
	if !namespaceBacked {
		return snaps
	}
	if !e.namespaceStateLost(d.ID) && !e.namespaceUnproven(d.ID) && !e.restoreIsPending(ctx, d) {
		return snaps
	}
	out := snaps[:0:0]
	for _, s := range snaps {
		if namespaceBackedKind(s.Kind) {
			continue
		}
		out = append(out, s)
	}
	return out
}
