package agent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// controlNamespaceSplit prefixes the reason a router is broken when its
// private FRR control sidecar is alive, healthy in itself, and attached to a
// network namespace that is no longer the router's.
//
// It is deliberately its own reason, distinct from daemonsDown. The daemons in
// an orphaned sidecar are running, their vty socket answers, and every count is
// exactly one -- the sidecar is a perfectly healthy router of an empty network.
// Restarting those daemons repairs nothing, so the repair for this must be to
// rebuild the sidecar in the namespace the router is in now.
const controlNamespaceSplit = "its FRR control sidecar is attached to a different network namespace:"

// controlNamespaceUnknown prefixes the reason a router's control namespace
// could not be proven either way. It is never treated as evidence of health.
const controlNamespaceUnknown = "the FRR control namespace identity could not be established:"

const (
	// controlRebindTimeout bounds one sidecar rebuild: remove, recreate in the
	// router's current namespace, restart the daemon set from the shared
	// configuration, and prove the result. It is longer than a daemon repair
	// because it includes a container create.
	controlRebindTimeout = 45 * time.Second
)

// controlNamespaceProof is the outcome of comparing a router's own network
// namespace with the one its private FRR control sidecar is attached to.
//
// The three outcomes are kept apart on purpose. "Not supported" is a backend
// that cannot answer at all and must not be turned into a fault; "not proven"
// is an attempted proof that failed and must never be read as agreement; only
// Proven && Match is evidence that the control plane is where the router is.
type controlNamespaceProof struct {
	// Supported reports whether the backend can prove namespace identity.
	Supported bool
	// Proven reports whether both identities were established.
	Proven bool
	// Match reports whether the two identities name one namespace.
	Match bool
	// Interfaces reports whether the sidecar can see the router's own wired
	// interfaces. It is an independent, exec-only proof that holds even on a
	// backend with no identity capability.
	Interfaces bool
	Primary    rt.NetnsIdentity
	Control    rt.NetnsIdentity
	Reason     string
}

// OK reports whether the sidecar is provably in the router's namespace.
func (p controlNamespaceProof) OK() bool { return p.Reason == "" }

// ControlNamespace is the wire form of a namespace proof. It is reported by
// the sidecar audit so an operator can see the two namespaces rather than
// having to infer a split from a control plane that answers every question
// correctly about a network it is not attached to.
type ControlNamespace struct {
	Supported  bool   `json:"supported"`
	Proven     bool   `json:"proven"`
	Match      bool   `json:"match"`
	Interfaces bool   `json:"interfaces"`
	Primary    string `json:"primary,omitempty"`
	Control    string `json:"control,omitempty"`
}

func (p controlNamespaceProof) wire() *ControlNamespace {
	out := &ControlNamespace{
		Supported: p.Supported, Proven: p.Proven, Match: p.Match, Interfaces: p.Interfaces,
	}
	if p.Primary.Known() {
		out.Primary = p.Primary.String()
	}
	if p.Control.Known() {
		out.Control = p.Control.String()
	}
	return out
}

// hostNetnsIdentity returns the identity of the agent's own network namespace,
// resolved once. A Twinet device is always created with a private namespace, so
// an identity equal to this one proves that the namespace path resolved to some
// process other than the container's task -- the shape a recycled PID takes.
func (s *Server) hostNetnsIdentity() (rt.NetnsIdentity, error) {
	s.hostNetnsOnce.Do(func() {
		s.hostNetns, s.hostNetnsErr = rt.SelfNetnsIdentity()
	})
	return s.hostNetns, s.hostNetnsErr
}

// proveControlNamespace establishes whether a router's private FRR control
// sidecar is attached to the router's current network namespace.
//
// A container that is SIGKILLed and restarted by its runtime comes back in a
// *new* network namespace. Its sidecar was created against the previous task
// and keeps running in the old one, which still holds a loopback and nothing
// else. Every question that can be asked inside the sidecar -- how many daemons
// are running, whether the vty socket answers, what the running configuration
// says -- is answered correctly and means nothing, because the answers describe
// a router with no cables. Only the namespace identity tells them apart.
func (s *Server) proveControlNamespace(ctx context.Context, d *model.Device) controlNamespaceProof {
	var proof controlNamespaceProof
	if d == nil || s.rt == nil || !s.requiresFRRControl(d) {
		return proof
	}
	control := deploy.FRRControlContainer(d)

	primary, primaryErr := rt.NetnsIdentityOf(ctx, s.rt, d.Container)
	if errors.Is(primaryErr, rt.ErrNamespaceIdentityUnsupported) {
		// Capability-gated: a backend that cannot prove identity still gets
		// the interface proof below, which needs nothing but exec.
		return s.proveControlInterfaces(ctx, d, proof)
	}
	proof.Supported = true
	if primaryErr != nil {
		proof.Reason = controlNamespaceUnknown + " " + d.Container + ": " + primaryErr.Error()
		return proof
	}
	sidecar, controlErr := rt.NetnsIdentityOf(ctx, s.rt, control)
	if errors.Is(controlErr, rt.ErrNamespaceIdentityUnsupported) {
		proof.Supported = false
		proof.Primary = rt.NetnsIdentity{}
		return s.proveControlInterfaces(ctx, d, proof)
	}
	if controlErr != nil {
		proof.Reason = controlNamespaceUnknown + " " + control + ": " + controlErr.Error()
		return proof
	}
	proof.Primary, proof.Control = primary, sidecar

	if host, err := s.hostNetnsIdentity(); err == nil &&
		(host.SameAs(primary) || host.SameAs(sidecar)) {
		// A device never shares the agent's namespace. Reaching it means the
		// pid that was read is not this container's task any more, so the
		// identity describes whatever process inherited that number.
		proof.Reason = controlNamespaceUnknown + fmt.Sprintf(
			" %s resolved to the agent's own namespace %s, so the reported task is not this container's",
			d.ID, host)
		return proof
	}

	proof.Proven = true
	proof.Match = primary.SameAs(sidecar)
	if !proof.Match {
		proof.Reason = fmt.Sprintf("%s the sidecar %s is in %s while %s is in %s",
			controlNamespaceSplit, control, sidecar, d.Container, primary)
		return proof
	}
	// Two containers in one namespace see one set of interfaces, so once the
	// identities agree the exec-based proof below can add nothing: the router's
	// own interface set is what the device audit already checks. Running it per
	// device per pass on a node with two hundred routers is not free.
	proof.Interfaces = true
	return proof
}

// proveControlInterfaces checks that the sidecar can see the interfaces the
// router is wired with. It is the same evidence an operator reads from `ip -br
// addr` inside both containers, and it needs only exec, so it is the fallback
// for a backend that cannot prove inode identity: an orphaned namespace holds a
// loopback and the kernel's default tunnels, and none of the router's cables.
func (s *Server) proveControlInterfaces(ctx context.Context, d *model.Device,
	proof controlNamespaceProof,
) controlNamespaceProof {
	want := make([]string, 0, len(d.Ifaces))
	for _, iface := range d.Ifaces {
		if iface.Link != nil || iface.VLAN > 0 {
			want = append(want, iface.Name)
		}
	}
	if len(want) == 0 {
		// Nothing is wired, so there is nothing an orphaned namespace could
		// fail to show, and this backend has no identity to fall back on.
		return proof
	}
	sort.Strings(want)
	control := deploy.FRRControlContainer(d)
	result, err := s.probeExec(ctx, control, rt.ExecCmd{
		Cmd: []string{"sh", "-c", `ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1`},
	})
	if err != nil {
		proof.Reason = controlNamespaceUnknown + " " + control +
			" interface probe unreadable: " + err.Error()
		return proof
	}
	if result.ExitCode != 0 {
		proof.Reason = fmt.Sprintf("%s %s interface probe exited %d",
			controlNamespaceUnknown, control, result.ExitCode)
		return proof
	}
	have := map[string]bool{}
	for _, name := range strings.Fields(result.Stdout) {
		have[name] = true
	}
	missing := make([]string, 0, len(want))
	for _, name := range want {
		if !have[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		proof.Reason = fmt.Sprintf("%s %s cannot see %s of %s",
			controlNamespaceSplit, control, strings.Join(missing, ", "), d.Container)
		return proof
	}
	proof.Interfaces = true
	return proof
}

// controlNamespaceObservation turns a proof into a device observation, or
// returns false when there is nothing to report.
//
// Fail-closed is the whole point: an unreadable namespace is reported as
// unknown, never as healthy, so no caller can read "we could not tell" as "it
// is fine". Unknown is deliberately not broken either, because rebuilding a
// sidecar on evidence that could not be obtained would turn a transient
// runtime error into a restart loop against a working control plane.
func controlNamespaceObservation(proof controlNamespaceProof, c rt.Container,
	specMatches bool,
) (deviceObservation, bool) {
	if proof.OK() {
		return deviceObservation{}, false
	}
	health := healthUnknown
	if strings.HasPrefix(proof.Reason, controlNamespaceSplit) {
		health = healthBroken
	}
	return deviceObservation{
		Health: health, State: c.State, SpecMatches: specMatches, Reason: proof.Reason,
	}, true
}

// rebindControlSidecar rebuilds a router's private FRR control sidecar in the
// network namespace the router is in now.
//
// The router itself is never touched. It keeps its unprivileged shell, its
// filesystem, and everything a student wrote into it; the sidecar is the only
// container replaced, and the configuration it starts from is the shared
// /etc/frr bind mount, so the exact configuration that was rendered or saved is
// what comes back.
//
// The router's namespace is recorded before the rebuild and re-proven after it.
// A router that restarts again while its sidecar is being replaced would
// otherwise leave a sidecar bound to a namespace that had already gone, and the
// repair would report success for the fault it just recreated.
func (s *Server) rebindControlSidecar(ctx context.Context, eng *deploy.Engine,
	top *model.Topology, d *model.Device,
) error {
	if err := s.rebindControlSidecarOnly(ctx, eng, top, d); err != nil {
		return err
	}
	return s.confirmDaemonRepair(ctx, top, d)
}

// rebindControlSidecarOnly performs the rebuild without re-observing the whole
// device. The rewire path calls it mid-repair, when the device is deliberately
// not yet in its final state.
func (s *Server) rebindControlSidecarOnly(ctx context.Context, eng *deploy.Engine,
	top *model.Topology, d *model.Device,
) error {
	if eng == nil {
		return errors.New("no repair engine is available to rebuild the FRR control sidecar")
	}
	return s.rebindControlSidecarWith(ctx, top, d, func(ctx context.Context) error {
		return eng.RecreateRuntimeSupport(ctx, top, d)
	})
}

// rebindControlSidecarWith is the namespace contract of a sidecar rebuild,
// independent of who performs the rebuild itself.
func (s *Server) rebindControlSidecarWith(ctx context.Context, top *model.Topology,
	d *model.Device, rebuild func(context.Context) error,
) error {
	rebindCtx, cancel := context.WithTimeout(ctx, controlRebindTimeout)
	defer cancel()

	control := deploy.FRRControlContainer(d)
	before, err := rt.NetnsIdentityOf(rebindCtx, s.rt, d.Container)
	if err != nil && !errors.Is(err, rt.ErrNamespaceIdentityUnsupported) {
		return fmt.Errorf("read the router's network namespace before rebinding %s: %w", control, err)
	}

	if err := rebuild(rebindCtx); err != nil {
		return fmt.Errorf("rebuild %s in the router's namespace: %w", control, err)
	}
	if err := s.waitForJoinable(rebindCtx, control); err != nil {
		return err
	}

	// Proven before the daemons are started, so a rebuild that landed in the
	// wrong namespace is reported as such instead of as a daemon failure.
	if proof := s.proveControlNamespace(rebindCtx, d); !proof.OK() {
		if raced := racedPrimary(before, proof.Primary, control); raced != nil {
			return raced
		}
		return errors.New(proof.Reason)
	}

	if err := s.startDaemons(rebindCtx, top.Name, d); err != nil {
		return fmt.Errorf("restart the FRR control daemons after rebinding %s: %w", control, err)
	}

	// Re-proven after the daemons are up. Between the check above and this one
	// the router could have been restarted again, and a sidecar full of running
	// daemons is precisely the state that looks healthy while being orphaned.
	after := s.proveControlNamespace(rebindCtx, d)
	if !after.OK() {
		if raced := racedPrimary(before, after.Primary, control); raced != nil {
			return raced
		}
		return errors.New(after.Reason)
	}
	if raced := racedPrimary(before, after.Primary, control); raced != nil {
		return raced
	}
	return s.verifyControlDaemonSet(rebindCtx, d, s.asOf(top.Name, d))
}

// racedPrimary reports a router that was restarted again while its sidecar was
// being rebuilt. The rebuild is abandoned rather than retried in place: the
// namespace it was built for has already gone, and the next observation sees
// the current one.
func racedPrimary(before, now rt.NetnsIdentity, control string) error {
	if !before.Known() || !now.Known() || before.SameAs(now) {
		return nil
	}
	return fmt.Errorf("the router moved from %s to %s while %s was being rebuilt; leaving it to the next pass",
		before, now, control)
}

// repairControlNamespaceAfterRewire rebinds a sidecar that a just-rewired
// router has left behind, so a restarted container recovers its control plane
// within the same repair rather than one bounded retry later.
func (s *Server) repairControlNamespaceAfterRewire(ctx context.Context, eng *deploy.Engine,
	top *model.Topology, d *model.Device,
) error {
	if !s.requiresFRRControl(d) {
		return nil
	}
	proof := s.proveControlNamespace(ctx, d)
	if proof.OK() || !strings.HasPrefix(proof.Reason, controlNamespaceSplit) {
		return nil
	}
	return s.rebindControlSidecarOnly(ctx, eng, top, d)
}
