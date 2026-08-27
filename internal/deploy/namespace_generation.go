package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	_, unproven := e.unprovenNamespaceReason(id)
	return unproven
}

// unprovenNamespaceReason is that question and its answer together, so that
// the exemption above is written once. A caller acting on the doubt rather
// than only recording it -- a destructive replacement refusing to go ahead, a
// report to an operator -- has to be able to say what the doubt was.
func (e *Engine) unprovenNamespaceReason(id string) (string, bool) {
	value, ok := e.unprovenNamespace.Load(id)
	if !ok || e.containerCreatedThisPass(id) {
		return "", false
	}
	reason, _ := value.(string)
	return reason, true
}

// UnprovenNamespaceDevices names the devices this pass could neither baseline
// nor vouch for, with the reason for each.
//
// Refusing is not the same as reporting. A device here is one whose saved
// state is being withheld from the store and whose namespace is not being
// recorded, which is a state an operator has to be able to see rather than
// infer from a lab that quietly stops being backed up.
//
// A device this pass rebuilt from its image is not here even if something
// earlier in the pass was in doubt about it, for the same reason it is not
// withheld: the create path replays the store into the new namespace, so the
// doubt was settled by the deployment rather than left for somebody to chase.
func (e *Engine) UnprovenNamespaceDevices() map[string]string {
	out := map[string]string{}
	e.unprovenNamespace.Range(func(key, _ any) bool {
		id, ok := key.(string)
		if !ok {
			return true
		}
		if reason, unproven := e.unprovenNamespaceReason(id); unproven {
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
// which typed facts -- addresses, VLAN and VRF interfaces, tunnels, bridge
// ports -- are on them.
type namespaceContents struct {
	links map[string]bool
	facts map[string]bool
}

// namespaceReading names one exec a continuity proof makes: the kind of saved
// state it is evidence about, and the shell that reads it.
type namespaceReading struct {
	kind state.Kind
	cmd  string
}

// namespaceReadingName describes a reading in the words an operator would use
// for the thing it failed to read.
func namespaceReadingName(kind state.Kind) string {
	switch kind {
	case state.KindTunnels:
		return "tunnels"
	case state.KindOVS:
		return "switch ports"
	default:
		return "network namespace"
	}
}

func addNamespaceLinks(links map[string]bool, raw string) {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		name, _, _ = strings.Cut(name, "@")
		if name != "" {
			links[name] = true
		}
	}
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

// stableNamespaceFacts reduces one reading of a namespace-backed artefact to
// the objects in it that are supposed to stay where they were put.
//
// Both sides of the comparison go through here, and through the same
// canonicalisation a capture writes into the store, so a saved snapshot and a
// live reading are compared as the same strings rather than as two spellings
// of the same fact.
//
// What a namespace holds is more than addresses. A VLAN sub-interface and a
// VRF master are objects in their own right -- they are captured in the
// addresses snapshot precisely because the addressing depends on them -- and a
// tunnel and a bridge port are the whole of what the other two snapshots are.
// Comparing only the addresses meant a switch whose ports had lost every VLAN,
// or a router that came back without its 6in4 tunnel, read as continuous and
// had that emptiness recorded as the namespace its student had worked in.
//
// Routes are left out of every kind. A routing daemon installs and withdraws
// them constantly, and requiring them would make every busy router look
// discontinuous; the objects they are configured on are what this proves, and
// a route cannot be present without the interface, address, or tunnel it runs
// over.
func stableNamespaceFacts(kind state.Kind, raw string) []string {
	var out []string
	for _, line := range strings.Split(CanonicalDynamicSnapshot(kind, raw), "\n") {
		switch kind {
		case state.KindAddrs:
			if strings.HasPrefix(line, "addr ") || strings.HasPrefix(line, "link ") {
				out = append(out, line)
			}
		case state.KindTunnels:
			if strings.HasPrefix(line, "tunnel ") {
				out = append(out, line)
			}
		case state.KindOVS:
			if strings.HasPrefix(line, "port ") {
				out = append(out, line)
			}
		}
	}
	return out
}

// namespaceObjectName describes a saved fact as the kind of object it is, so a
// refusal names what is missing rather than printing a typed line at somebody.
func namespaceObjectName(kind state.Kind, fact string) string {
	switch {
	case strings.HasPrefix(fact, "addr "):
		return "address"
	case strings.HasPrefix(fact, "link vlan "):
		return "VLAN interface"
	case strings.HasPrefix(fact, "link vrf "):
		return "VRF interface"
	case strings.HasPrefix(fact, "tunnel "):
		return "tunnel"
	case strings.HasPrefix(fact, "port "):
		return "switch port"
	default:
		return string(kind) + " object"
	}
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

// savedNamespaceObjects names every stable object the state store says this
// device's namespace held the last time anything read it.
//
// This is the evidence the model cannot supply. On a teaching deployment the
// student's addressing, VLANs, VRFs, tunnels and bridge ports are captured out
// of the kernel and kept here, and this is the only description of what their
// namespace is supposed to contain.
//
// Every namespace-backed kind is read, not the ones this device's kind is
// captured for. What is in the store is what a restore would replay and what a
// capture would overwrite, whatever the device is called now.
//
// The store is a parameter rather than the engine's own, because the caller
// that needs this most is a capture, and the store a capture must be judged
// against is the one it is about to write. An engine assembled only to capture
// need not have been given the same one.
//
// Ownership is allowed to rule a device out only while the manifest still
// describes it. A prune's candidates are exactly the devices it no longer
// does: one removed from the manifest has no autonomous system left to hold a
// role, so asking whether a student owns it answers no for every orphan --
// including the orphan whose only copy of a term's work is the snapshot this
// exists to protect. For those the store is the evidence, and it is read.
func savedNamespaceObjects(store *state.Store, top *model.Topology, d *model.Device,
) (map[state.Kind][]string, error) {
	out := map[state.Kind][]string{}
	if store == nil || top == nil || d == nil {
		return out, nil
	}
	if _, modelled := top.Device(d.ID); modelled && !studentOwned(top, d) {
		return out, nil
	}
	for _, kind := range namespaceBackedKinds {
		facts, err := savedNamespaceFacts(store, top.Name, d.ID, kind)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", kind, err)
		}
		if len(facts) > 0 {
			out[kind] = facts
		}
	}
	return out, nil
}

// savedNamespaceFacts reads one saved snapshot, and distinguishes a device
// that has never had one from a snapshot that could not be read.
//
// The two used to be the same answer. Every failure -- a body whose digest
// does not match what was written beside it, a half-written file, a disk that
// is refusing reads -- returned "nothing is saved", and nothing saved is
// exactly the condition under which a namespace with nothing in it proves
// continuous. So the one circumstance where the stored copy of a student's
// work is already in question was the circumstance that let an empty namespace
// be recorded as theirs and then captured over the top of it.
//
// A missing snapshot is a legitimate none: the device is new, or nobody has
// configured anything on it yet. Anything else fails closed.
func savedNamespaceFacts(store *state.Store, lab, device string, kind state.Kind) ([]string, error) {
	snapshot, err := store.Current(lab, device, kind)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !store.Has(lab, device, kind) {
			return nil, nil
		}
		return nil, err
	}
	return stableNamespaceFacts(kind, string(snapshot.Content)), nil
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
func (e *Engine) provenNamespaceContinuity(ctx context.Context, store *state.Store,
	top *model.Topology, d *model.Device,
) (bool, string) {
	saved, err := savedNamespaceObjects(store, top, d)
	if err != nil {
		return false, fmt.Sprintf("its saved network state could not be read, so there is "+
			"nothing trustworthy to compare its namespace against: %v", err)
	}
	have, reason := e.readNamespaceContents(ctx, d, saved)
	if reason != "" {
		return false, reason
	}
	for _, name := range modelledNamespaceInterfaces(d) {
		if !have.links[name] {
			return false, "the modelled interface " + name + " is not in it"
		}
	}
	for _, want := range modelledPlatformAddresses(d) {
		if !have.facts[want] {
			return false, "the platform address it should carry is not in it (" + want + ")"
		}
	}
	// The student's own state, from the store rather than from the model. A
	// namespace that has the platform's wiring in it but not this has been
	// rewired since the work was done, which is exactly what a restart
	// followed by a reconcile looks like: bare veths back, and nothing on
	// them.
	for _, kind := range namespaceBackedKinds {
		for _, want := range saved[kind] {
			if !have.facts[want] {
				return false, "the saved " + namespaceObjectName(kind, want) +
					" it was last seen with is not in it (" + want + ")"
			}
		}
	}
	return true, ""
}

// readNamespaceContents reads a device's namespace once for its netdevs and
// addressing, and again for each further kind of state there is something
// saved to compare against.
//
// Reading only what there is evidence about keeps the common device at one
// round trip, and keeps the proof from depending on commands an image need not
// have: a router with no tunnels is never asked for them, and nothing but a
// switch is ever asked for bridge ports. A device holding saved state its own
// kind is never read for is not quietly excused it -- the command is still not
// run, and the mismatch is reported as what it is.
func (e *Engine) readNamespaceContents(ctx context.Context, d *model.Device,
	saved map[state.Kind][]string,
) (namespaceContents, string) {
	have := namespaceContents{links: map[string]bool{}, facts: map[string]bool{}}
	readings := []namespaceReading{{kind: state.KindAddrs, cmd: namespaceContinuityProbe}}
	if len(saved[state.KindTunnels]) > 0 {
		if d.Kind != model.KindRouter {
			return have, "it has saved tunnels, which only a router's namespace is read for"
		}
		readings = append(readings, namespaceReading{kind: state.KindTunnels, cmd: tunnelCapture})
	}
	if len(saved[state.KindOVS]) > 0 {
		if d.Kind != model.KindSwitch {
			return have, "it has saved switch ports, which only a switch's namespace is read for"
		}
		readings = append(readings, namespaceReading{kind: state.KindOVS, cmd: switchCapture})
	}
	for _, reading := range readings {
		result, err := e.Runtime.Exec(ctx, d.Container, runtime.ExecCmd{
			Cmd: []string{"sh", "-c", reading.cmd}})
		if err != nil {
			return have, fmt.Sprintf("its %s could not be read: %v",
				namespaceReadingName(reading.kind), err)
		}
		if result.ExitCode != 0 {
			return have, fmt.Sprintf("reading its %s exited %d",
				namespaceReadingName(reading.kind), result.ExitCode)
		}
		body := result.Stdout
		if reading.kind == state.KindAddrs {
			var links string
			links, body = splitNamespaceProbe(body)
			addNamespaceLinks(have.links, links)
		}
		for _, fact := range stableNamespaceFacts(reading.kind, body) {
			have.facts[fact] = true
		}
	}
	return have, ""
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
		proven[i], reasons[i] = e.proveNamespaceBaseline(ctx, e.State, top, candidates[i].device)
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
func (e *Engine) proveNamespaceBaseline(ctx context.Context, store *state.Store,
	top *model.Topology, d *model.Device,
) (runtime.NetnsIdentity, string) {
	before, err := runtime.NetnsIdentityOf(ctx, e.Runtime, d.Container)
	if err != nil || !before.Known() {
		return runtime.NetnsIdentity{}, "its network namespace identity could not be read"
	}
	proven, reason := e.provenNamespaceContinuity(ctx, store, top, d)
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

// namespaceBackedKinds are the snapshots that record what is in a network
// namespace rather than what is on a filesystem.
//
// One list, used by both halves of the rule: these are the snapshots withheld
// from the store when a device's namespace is in doubt, and these are the
// snapshots a namespace has to be shown to still hold before it is trusted.
var namespaceBackedKinds = []state.Kind{state.KindAddrs, state.KindTunnels, state.KindOVS}

// ensureCaptureSafety decides, for devices that are about to be captured,
// whether the namespace each of them is using is the one its saved state came
// out of.
//
// Everything above establishes this during a deployment, and a deployment is
// not the only thing that captures. Periodic durability captures on a timer;
// a destructive boundary captures before it replaces anything; a destroy
// captures before it removes the containers; recovery captures after a
// rollback. Every one of those builds an Engine for the purpose and calls
// straight into the capture API, so none of them has observed anything, none
// of them holds a build's findings, and the guard those findings feed was
// simply not armed. The check that decides whether a student's work is about
// to be overwritten was running only on the path that had already done the
// work of finding out.
//
// So it is established here instead, from the two things a capture always has:
// the namespace recorded on disk by whichever pass last configured the device,
// and the identity of the one it is in now. A device whose namespace has been
// replaced has its namespace-backed snapshots withheld; a device that never
// had a baseline has to prove continuity against what is saved before it may
// take one. Its configuration files are captured either way -- they are on a
// filesystem, they survived, and they are still the student's work.
//
// A pass that already knows is not asked again: a device this engine found
// with its state lost, or could not vouch for, keeps that finding. A device
// this engine repaired and replayed keeps the baseline the configure step
// recorded, and is re-proved against it here, which is what makes it
// capturable again in the same pass.
//
// It is arranged so that losing the record is not a way through. A device with
// no baseline -- because none was ever taken, or because the file holding them
// could not be read -- has to prove continuity against what is saved before it
// may overwrite it, which is the same answer by a longer route.
//
// recordBaselines says whether a baseline this proves may be written back.
// A capture taken inside a running deployment must not: the configure steps
// executing beside it are writing the same file through the build's own
// tracker, and this one was loaded from disk before they started. The proof
// still decides what this capture may store -- that is held on the engine --
// and the next pass proves it again.
func (e *Engine) ensureCaptureSafety(ctx context.Context, top *model.Topology,
	store *state.Store, devices []*model.Device, recordBaselines bool,
) []string {
	if e.Runtime == nil || top == nil || store == nil || len(devices) == 0 {
		return nil
	}
	if !runtime.SupportsNetnsIdentity(e.Runtime) {
		// A backend that cannot prove namespace identity does not hand a
		// device a new namespace behind the deployment's back: it replaces the
		// whole container, which the create path already restores through.
		return nil
	}
	tracker, err := e.loadObservation(top.Name)
	var problems []string
	if err != nil {
		// An observation that cannot be read is not the dangerous case it
		// looks like. Every device becomes one with no baseline, so every one
		// of them has to prove continuity against what is saved before it may
		// overwrite it -- which is more work, and the same answer, for a
		// device that really did restart.
		//
		// Reported unless it is the default root refusing an unprivileged
		// process, which is the same exemption a destroy makes when it cannot
		// remove that file: the record belongs to the agent, and a lab run
		// without one has never had it.
		tracker = e.newObservationTracker(top.Name)
		if e.ObservationRoot != "" || !errors.Is(err, os.ErrPermission) {
			problems = append(problems,
				fmt.Sprintf("read the recorded network namespaces: %v", err))
		}
	}
	baselines := make([]runtime.NetnsIdentity, len(devices))
	settled := make([]bool, len(devices))
	_, _, ctxErr := e.runBounded(ctx, len(devices), func(i int) error {
		baselines[i] = e.settleCaptureSafety(ctx, top, store, devices[i], tracker)
		settled[i] = true
		return nil
	})
	for i, d := range devices {
		if !settled[i] {
			e.markNamespaceUnproven(d.ID, fmt.Sprintf("this capture was interrupted before it "+
				"could establish what is in its network namespace: %v", ctxErr))
			continue
		}
		if baselines[i].Known() {
			tracker.bootstrapNamespace(d.ID, baselines[i])
		}
	}
	if e.ObservationReadOnly || !recordBaselines {
		return problems
	}
	if err := tracker.save(); err != nil &&
		(e.ObservationRoot != "" || !errors.Is(err, os.ErrPermission)) {
		// The capture itself is still safe -- every decision above was taken
		// before this -- but a baseline that was proved and then not written is
		// work the next capture has to do again, and a disk that will not take
		// it is worth saying out loud.
		problems = append(problems, fmt.Sprintf("record proven network namespaces: %v", err))
	}
	return problems
}

// settleCaptureSafety establishes one device's capture safety, and returns the
// namespace identity to baseline it at if it earned one.
func (e *Engine) settleCaptureSafety(ctx context.Context, top *model.Topology,
	store *state.Store, d *model.Device, tracker *observationTracker,
) runtime.NetnsIdentity {
	if e.namespaceStateLost(d.ID) || e.namespaceUnproven(d.ID) {
		// Already decided, by a build this engine ran or by a loss it is on
		// its way to repair. Asking again could only weaken it.
		return runtime.NetnsIdentity{}
	}
	recorded, known := tracker.namespace(d.ID)
	if !known || !recorded.Known() {
		identity, reason := e.proveNamespaceBaseline(ctx, store, top, d)
		if !identity.Known() {
			e.markNamespaceUnproven(d.ID, reason)
			return runtime.NetnsIdentity{}
		}
		return identity
	}
	now, err := runtime.NetnsIdentityOf(ctx, e.Runtime, d.Container)
	if err != nil || !now.Known() || !now.SameAs(recorded) {
		// Fail closed on all three. A namespace that is demonstrably not the
		// recorded one has lost what was in it; an identity that could not be
		// read is not evidence that it survived; and a container that is not
		// running lost its namespace when its task did. Being wrong here costs
		// one deferred snapshot of state the store already holds. Being wrong
		// the other way costs the only copy of it.
		e.markNamespaceStateLost(d.ID)
	}
	return runtime.NetnsIdentity{}
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
	for _, backed := range namespaceBackedKinds {
		if kind == backed {
			return true
		}
	}
	return false
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
