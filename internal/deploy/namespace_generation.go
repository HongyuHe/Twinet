package deploy

import (
	"context"
	"fmt"
	"sort"
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
	if !e.namespaceStateLost(d.ID) && !e.restoreIsPending(ctx, d) {
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
