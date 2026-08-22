// Package deploy turns an expanded topology into a plan and executes it.
//
// This is where the model meets the machine: containers are created from
// devices, links are realised as veths or VXLAN tunnels, configuration is
// rendered and pushed, and readiness is verified. Every step is idempotent, so
// deploying twice converges rather than duplicating or failing.
package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"sync"

	"github.com/HongyuHe/twinet/internal/alloc"
	"github.com/HongyuHe/twinet/internal/images"
	"github.com/HongyuHe/twinet/internal/limiter"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
	"github.com/HongyuHe/twinet/internal/nos"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// Label keys stamped onto every container. These are the observed state: there
// is no database, so "what is deployed" is answered by querying labels.
const (
	LabelLab    = "twinet.lab"
	LabelAS     = "twinet.as"
	LabelDevice = "twinet.device"
	LabelKind   = "twinet.kind"
	LabelRole   = "twinet.role"
	LabelOwner  = "twinet.owner"
	LabelNode   = "twinet.node"
	LabelHash   = "twinet.topology-hash"
	// LabelSpec is a hash of everything about *this* container that would
	// require it to be recreated. The topology hash alone is far too coarse:
	// changing one link's delay changes it, which would otherwise recreate
	// every container in the class.
	LabelSpec = "twinet.spec-hash"
	// LabelRuntimeContract names the version folded into LabelSpec. It makes
	// a policy migration auditable while the hash remains the authority.
	LabelRuntimeContract = "twinet.runtime-spec-contract"
	// LabelGen is the deployment generation, used to find objects that the
	// current topology no longer wants.
	LabelGen      = "twinet.generation"
	LabelRegion   = "twinet.region"
	LabelManaged  = "twinet.managed"
	LabelDeviceID = "twinet.device-id"
	// LabelImageLock records the exact checked image-lock document that
	// produced this container. It ties runtime observation back to reports
	// without trusting a mutable tag.
	LabelImageLock = "twinet.image-lock"
	// LabelFRRControl marks the privileged control-plane sidecar for an FRR
	// router. It shares the router network namespace and FRR config/vty
	// directories, but is a separate container that a student shell cannot
	// exec into.
	LabelFRRControl = "twinet.frr-control"
	// LabelInternal marks a runtime implementation container that is not a
	// topology device. Every user-facing API filters this label rather than
	// relying on a naming convention for privileged sidecars.
	LabelInternal = "twinet.internal"
	// LabelNOS records an explicitly selected router NOS. Legacy routers omit
	// it so their historic container/spec identity remains unchanged.
	LabelNOS = "twinet.nos"
	// Request labels let agents reconstruct reservations for every lab after
	// restart, including a lab whose controller is no longer connected.
	LabelRequestCPU     = "twinet.request.cpu"
	LabelRequestMemory  = "twinet.request.memory"
	LabelRequestPids    = "twinet.request.pids"
	LabelRequestDisk    = "twinet.request.ephemeral-storage"
	LabelRequestFDs     = "twinet.request.file-descriptors"
	LabelRequestNetDevs = "twinet.request.netdevs"
)

// DefaultStopTimeout bounds how long a container is given to exit cleanly.
const DefaultStopTimeout = 10 * time.Second

// Engine deploys a topology onto one node.
//
// A multi-node deployment runs one Engine per node, inside that node's agent;
// the control plane fans out and merges the reports. Keeping the engine
// node-local means the same code path serves single-machine and cluster
// deployments, so the common case is never a special case.
type Engine struct {
	Runtime runtime.Runtime
	Node    string
	// Limiter is shared by every Engine on an agent, so simultaneous labs do
	// not turn their individually bounded worker pools into an unbounded
	// node-wide burst.
	Limiter *limiter.Limiter
	// Workers bounds capture, pruning, and teardown fan-out. Zero uses a
	// conservative default so a large lab cannot turn cleanup into an
	// unbounded burst of runtime or netlink requests.
	Workers int
	// PullPolicy controls image fetching.
	PullPolicy runtime.PullPolicy
	// Renderer produces per-device configuration. Optional.
	Renderer Renderer
	// WritesReference says this deployment installs the reference solution, so
	// what ends up on a student-owned device is the answer rather than their
	// work, and must never be captured as theirs.
	WritesReference bool
	// UnderlayIP is this node's VTEP source address.
	UnderlayIP string
	// UnderlayDev optionally pins the tunnel source interface.
	UnderlayDev string
	// PeerUnderlay maps node name to VTEP address, for cross-node links.
	PeerUnderlay map[string]string
	// Authoritative makes the rendered configuration win over whatever is in
	// the container already.
	//
	// It is deliberately not the default: an ordinary redeploy converges the
	// platform's own state and must leave a student's file alone, because
	// overwriting it is silent -- FRR is not restarted, so the router keeps
	// running correctly and the loss only appears when the container next
	// restarts. Solve mode is the exception, since installing the reference
	// solution over whatever is there is its entire purpose; preserving in that
	// mode would leave the grading oracle quietly wrong.
	Authoritative bool
	// State persists student-owned configuration. When set, a container is
	// never replaced without its contents being captured first and replayed
	// afterwards, so a deployment cannot destroy a student's work.
	State *state.Store
	// Prune removes containers this node hosts that the topology no longer
	// wants. Off by default: a partial topology (say, `--only as=12`) must not
	// be read as "delete everything else".
	Prune bool
	// Generation stamps this deployment, so pruning can identify leftovers.
	Generation string
	// ModeKey identifies the desired renderer mode and ungraded harness AS.
	// It is persisted alongside observed hashes so a restarted agent cannot
	// bootstrap a platform container as if a requested solve had already run.
	ModeKey string
	// ForceStudentReset is set only for a committed solve->platform
	// transition. Reference configuration must not survive merely because the
	// primary container spec did not change; student snapshots are replayed
	// afterwards when RestoreStudentState is set.
	ForceStudentReset   bool
	RestoreStudentState bool
	PreviousMode        string
	PreviousUngraded    int
	// SemanticProbe is an agent-supplied, cheap runtime fingerprint check.
	// It lets no-change deploys detect address/route/session drift that labels
	// and rendered-file hashes cannot observe, without coupling deploy to the
	// agent's mode and durability policy.
	SemanticProbe func(context.Context, *model.Device) error
	// FRRControlRoot holds the host directories shared only between an
	// unprivileged router shell and its privileged FRR control sidecar. Empty
	// selects the node-local runtime path.
	FRRControlRoot string
	// WritableRoot holds per-device bind mounts for platform-rendered files.
	// Docker's archive copy API refuses a read-only rootfs even when a tmpfs
	// target is mounted, while bind targets remain writable and survive a
	// container recreation. Empty selects the node-local runtime path.
	WritableRoot string
	// RequireImmutableImages rejects a post-pull image that cannot be proven
	// to match a registry manifest digest. It is set for release and grading
	// image policies; development remains explicitly tag-capable.
	RequireImmutableImages bool
	// RetainLegacyOverlays keeps a live legacy per-link tunnel during a
	// fenced forward apply. The transaction commits cleanup only after the
	// replacement multiplex trunk and service inventory are verified.
	RetainLegacyOverlays bool
	// ForceOverlayReconcile permits a targeted repair to replace an active
	// multiplex trunk whose UDP receive port no longer matches its peer. It is
	// deliberately off for ordinary deploy/recovery, where preserving a live
	// trunk avoids unnecessary packet loss.
	ForceOverlayReconcile bool
	// RecoveryCompatibility reconstructs a previously committed lab under a
	// fenced rollback. It strips only legacy SYS_ADMIN requests from student
	// containers; the internal FRR control sidecar retains that capability.
	// This permits service recovery without reintroducing the old privilege.
	RecoveryCompatibility bool
	// ObservationRoot persists the node-local desired/observed hash snapshot.
	// Empty uses /run/twinet/observed. It contains hashes only, never student
	// configuration bytes.
	ObservationRoot string

	// pendingRestore records devices whose captured configuration must be
	// replayed once their interfaces exist.
	pendingRestore       sync.Map
	observationMu        sync.Mutex
	observation          *observationTracker
	lastDiff             BuildDiff
	mutationMu           sync.Mutex
	mutations            map[string]int
	removeEmptyMultiplex func(string) ([]string, error)
}

func (e *Engine) limited(ctx context.Context, kinds []limiter.Kind, fn func() error) error {
	if e.Limiter == nil {
		return fn()
	}
	return e.Limiter.Run(ctx, kinds, fn)
}

// Renderer produces the files and commands that configure a device.
type Renderer interface {
	// Files returns the files to write into the container, keyed by absolute
	// in-container path.
	Files(d *model.Device) (map[string]FileSpec, error)
	// Commands returns commands to run after the device is wired.
	Commands(d *model.Device) ([]Command, error)
	// Ready returns a readiness predicate for the device, or nil.
	Ready(d *model.Device, rt runtime.Runtime) *plan.Waiter
}

// deviceAuthorityRenderer is an optional extension implemented by renderers
// that can distinguish a solved grading harness from its one ungraded AS.
// Engine.Authoritative is lab-wide for backwards compatibility, but using it
// for every endpoint would put reference addresses back on the submission AS
// during a targeted repair.
type deviceAuthorityRenderer interface {
	AuthoritativeDevice(*model.Device) bool
}

func (e *Engine) authoritativeDevice(d *model.Device) bool {
	if renderer, ok := e.Renderer.(deviceAuthorityRenderer); ok {
		return renderer.AuthoritativeDevice(d)
	}

	return e.Authoritative
}

func (e *Engine) shouldForceStudentReset(d *model.Device) bool {
	if !e.ForceStudentReset || d == nil {
		return false
	}
	previousSolve := e.PreviousMode == "solve" &&
		(e.PreviousUngraded == 0 || d.ASN != e.PreviousUngraded)
	return previousSolve && !e.authoritativeDevice(d)
}

// FileSpec is a file to place inside a container.
type FileSpec struct {
	Content []byte
	Mode    int64
}

// Command is a command to run inside a container.
type Command struct {
	Args []string
	// IgnoreError marks a command whose failure is tolerable.
	IgnoreError bool
	// Describe is used in error messages.
	Describe string
	// FRRControl executes the command in the private privileged FRR sidecar
	// for an FRR router. It is used only for daemon lifecycle/probes; ordinary
	// router configuration and every student shell command remain in the
	// unprivileged router container.
	FRRControl bool
}

// Build constructs the deployment plan using a node-local desired/observed
// snapshot. Callers that have a request context should prefer BuildContext.
func (e *Engine) Build(top *model.Topology) (*plan.Plan, error) {
	return e.BuildContext(context.Background(), top)
}

// BuildContext constructs the minimal executable deployment DAG for this node.
func (e *Engine) BuildContext(ctx context.Context, top *model.Topology) (*plan.Plan, error) {
	p := plan.New()
	e.resetMutationCounts()
	devices := top.DevicesOnNode(e.Node)
	if len(devices) == 0 {
		e.setBuildObservation(nil, BuildDiff{})
		return p, nil
	}
	tracker, desired, diff, err := e.observeNode(ctx, top, devices)
	if err != nil {
		return nil, err
	}
	e.setBuildObservation(tracker, diff)

	// One image pull per distinct image, shared by every device that needs it.
	images := map[string][]*model.Device{}
	for _, d := range devices {
		if !diff.Create[d.ID] {
			continue
		}
		if d.Image == "" {
			return nil, fmt.Errorf("device %s has no image; set it under kinds.%s.image", d.ID, d.Kind)
		}
		images[d.Image] = append(images[d.Image], d)
	}
	imageStep := map[string]string{}
	for _, img := range sortedKeys(images) {
		id := "image:" + img
		image := img
		p.Add(&plan.Step{
			ID: id, Stage: plan.StageImage, Describe: "pull " + image,
			Run: func(ctx context.Context) error {
				return e.limited(ctx, []limiter.Kind{limiter.Apply, limiter.ImagePull}, func() error {
					if err := e.Runtime.PullImage(ctx, image, e.pullPolicy()); err != nil {
						return err
					}
					e.recordMutation("image", 1)
					return nil
				})
			},
		})
		verifyID := "verify-image:" + img
		p.Add(&plan.Step{
			ID: verifyID, Stage: plan.StageImage, Describe: "verify " + image,
			Needs: []string{id},
			Run: func(ctx context.Context) error {
				return e.limited(ctx, []limiter.Kind{limiter.Apply, limiter.ImagePull}, func() error {
					return e.verifyPulledImage(ctx, image)
				})
			},
		})
		imageStep[img] = verifyID
	}

	// Create and start each container.
	for _, d := range devices {
		if !diff.Create[d.ID] {
			continue
		}
		dev := d
		p.Add(&plan.Step{
			ID:       "create:" + dev.ID,
			Stage:    plan.StageCreate,
			Scope:    scopeOf(dev),
			Describe: "create " + dev.ID,
			Needs:    []string{imageStep[dev.Image]},
			Run: func(ctx context.Context) error {
				return e.limited(ctx, []limiter.Kind{limiter.Apply, limiter.Lifecycle}, func() error {
					state := desired[dev.ID]
					if err := e.ensureContainer(ctx, top, dev, state.runtime); err != nil {
						return err
					}
					e.recordMutation("create", 1)
					return tracker.markDevice(dev.ID, observedDeviceState{SpecHash: state.runtime.spec.Labels[LabelSpec]})
				})
			},
		})
	}

	// Wire each link with at least one endpoint on this node.
	for _, l := range top.Links {
		link := l
		if !diff.Wire[link.ID] {
			continue
		}
		aHere := link.A.Device.Node == e.Node
		bHere := link.B.Device.Node == e.Node
		if !aHere && !bHere {
			continue
		}
		var needs []string
		if aHere && diff.Create[link.A.Device.ID] {
			needs = append(needs, "create:"+link.A.Device.ID)
		}
		if bHere && diff.Create[link.B.Device.ID] {
			needs = append(needs, "create:"+link.B.Device.ID)
		}
		p.Add(&plan.Step{
			ID:       "wire:" + link.ID,
			Stage:    plan.StageWire,
			Scope:    linkScope(link),
			Describe: "wire " + link.ID,
			Needs:    needs,
			Run: func(ctx context.Context) error {
				return e.limited(ctx, []limiter.Kind{limiter.Apply, limiter.Netlink}, func() error {
					if err := e.wire(ctx, top, link); err != nil {
						return err
					}
					e.recordMutation("wire", 1)
					if !link.Props.Empty() {
						e.recordMutation("qdisc", qdiscEndpointsOnNode(link, e.Node))
					}
					hash, err := e.desiredWireHash(top, link)
					if err != nil {
						return err
					}
					return tracker.markLink(link.ID, hash)
				})
			},
		})
	}

	// Configure devices once every link they own is up, so a daemon never sees
	// a half-wired interface list.
	for _, d := range devices {
		dev := d
		if !diff.Configure[dev.ID] {
			continue
		}
		var needs []string
		if diff.Create[dev.ID] {
			needs = append(needs, "create:"+dev.ID)
		}
		for _, i := range dev.Ifaces {
			if i.Link != nil && diff.Wire[i.Link.ID] {
				needs = append(needs, "wire:"+i.Link.ID)
			}
		}
		p.Add(&plan.Step{
			ID:       "configure:" + dev.ID,
			Stage:    plan.StageConfigure,
			Scope:    scopeOf(dev),
			Describe: "configure " + dev.ID,
			Needs:    dedup(needs),
			Run: func(ctx context.Context) error {
				return e.limited(ctx, []limiter.Kind{limiter.Apply, limiter.ExecProbe}, func() error {
					state := desired[dev.ID]
					if err := e.configureDesired(ctx, dev, state); err != nil {
						return err
					}
					// Whatever the student had is replayed *after* the platform's
					// own configuration and after the interfaces exist, so it wins
					// over the defaults and lands on devices that are present.
					if e.RestoreStudentState && e.shouldForceStudentReset(dev) && studentOwned(top, dev) {
						if _, err := Restore(ctx, e.Runtime, dev, top.Name, e.State); err != nil {
							return fmt.Errorf("restore student state after solve->platform transition for %s: %w", dev.ID, err)
						}
						e.pendingRestore.Delete(dev.ID)
						e.clearRestorePending(ctx, dev)
					} else if err := e.replayPending(ctx, top, dev); err != nil {
						return err
					}
					return tracker.markDevice(dev.ID, observedDeviceState{
						SpecHash: state.runtime.spec.Labels[LabelSpec], ConfigHash: state.configHash,
						FileHash: state.fileHash, CommandHash: state.commandHash, ReadyHash: "",
					})
				})
			},
		})
	}

	// Readiness.
	if e.Renderer != nil {
		for _, d := range devices {
			dev := d
			if !diff.Ready[dev.ID] {
				continue
			}
			w := e.Renderer.Ready(dev, e.Runtime)
			if w == nil {
				continue
			}
			waiter := *w
			p.Add(&plan.Step{
				ID:       "ready:" + dev.ID,
				Stage:    plan.StageReady,
				Scope:    scopeOf(dev),
				Describe: "wait for " + dev.ID,
				Needs: func() []string {
					if diff.Configure[dev.ID] {
						return []string{"configure:" + dev.ID}
					}
					return nil
				}(),
				Run: func(ctx context.Context) error {
					return e.limited(ctx, []limiter.Kind{limiter.Apply, limiter.ExecProbe}, func() error {
						if err := plan.Wait(ctx, waiter); err != nil {
							return err
						}
						state := desired[dev.ID]
						return tracker.markDevice(dev.ID, observedDeviceState{
							SpecHash: state.runtime.spec.Labels[LabelSpec], ConfigHash: state.configHash,
							FileHash: state.fileHash, CommandHash: state.commandHash, ReadyHash: state.readyHash,
						})
					})
				},
			})
		}
	}

	// A renderer mode is a semantic contract, not a per-container hash. Do
	// not publish it while a partially failed transition still has untouched
	// hosts or links: the next retry must keep all of them dirty. The final
	// marker is deliberately a plan step so dependency failure prevents it
	// from being written, and scoped applies omit it with the rest of the
	// whole-lab mode transition.
	if e.ModeKey != "" && tracker.state.Mode != e.ModeKey {
		needs := make([]string, 0, p.Len())
		for _, step := range p.Steps() {
			needs = append(needs, step.ID)
		}
		p.Add(&plan.Step{
			ID:       "record-mode",
			Stage:    plan.StageReady,
			Scope:    "mode",
			Describe: "record renderer mode",
			Needs:    needs,
			Run: func(context.Context) error {
				return tracker.markMode()
			},
		})
	}

	return p, p.Validate()
}

func qdiscEndpointsOnNode(link *model.Link, node string) int {
	ends := 0
	if link.A.Device.Node == node {
		ends++
	}
	if link.B.Device.Node == node {
		ends++
	}
	return ends
}

// verifyPulledImage runs after the pull and before any container is created.
// Pre-pull agreement alone is insufficient: a moving tag can change between a
// controller's survey and a node's pull.
func (e *Engine) verifyPulledImage(ctx context.Context, ref string) error {
	actual, err := e.Runtime.ImageDigest(ctx, ref)
	if err != nil || strings.TrimSpace(actual) == "" {
		if err == nil {
			err = errors.New("runtime returned an empty image identity")
		}
		return fmt.Errorf("verify pulled image %s: %w", ref, err)
	}
	expected := images.Digest(ref)
	if expected == "" {
		if e.RequireImmutableImages {
			return fmt.Errorf("verify pulled image %s: release/grading mode requires an immutable registry digest", ref)
		}
		return nil
	}
	if !images.SameDigest(ref, actual) {
		return fmt.Errorf("verify pulled image %s: runtime reports %s, want %s",
			ref, actual, expected)
	}
	return nil
}

func (e *Engine) pullPolicy() runtime.PullPolicy {
	if e.PullPolicy == "" {
		return runtime.PullIfMissing
	}
	return e.PullPolicy
}

// ensureContainer creates and starts a device's container if needed.
//
// A container built from a different topology is replaced rather than reused:
// silently running a stale container is worse than recreating one, because the
// difference is invisible to a student.
func (e *Engine) ensureContainer(ctx context.Context, top *model.Topology, d *model.Device,
	final finalDeviceSpec,
) error {
	cur, err := e.Runtime.Inspect(ctx, d.Container)
	if err != nil {
		return err
	}

	want := final.spec.Labels[LabelSpec]

	if cur.State != runtime.StateAbsent {
		forceRecoveryRecreate := e.RecoveryCompatibility && d.Kind == model.KindService
		// Only a change to *this* container's own specification justifies
		// replacing it. Anything else -- a neighbour's address, another AS's
		// link delay -- must leave it alone, because replacing it would throw
		// away whatever the student had configured inside.
		if cur.Labels[LabelSpec] == want && !forceRecoveryRecreate {
			if cur.State.Joinable() {
				if err := e.ensureFRRControl(ctx, top, final); err != nil {
					return err
				}
				return nil
			}
			// The container exists but is stopped: start it and put back
			// whatever was captured before it went down.
			if err := e.Runtime.Start(ctx, d.Container); err != nil {
				return err
			}
			if err := e.restoreIfNeeded(ctx, top, d); err != nil {
				return err
			}
			return e.ensureFRRControl(ctx, top, final)
		}

		// It genuinely must be replaced. Capture first; if capture fails we
		// refuse rather than proceed, because the alternative is silent
		// destruction of a student's work.
		if err := e.captureBeforeReplace(ctx, top, d); err != nil {
			return err
		}
		if err := e.removeFRRControl(ctx, d); err != nil {
			return err
		}
		if err := e.Runtime.Remove(ctx, d.Container, true); err != nil {
			return fmt.Errorf("replace container %s: %w", d.Container, err)
		}
	}

	if err := e.prepareFinalRuntimeSpecs(top, final); err != nil {
		return err
	}
	if _, err := e.Runtime.Create(ctx, final.spec); err != nil {
		return err
	}
	if err := e.Runtime.Start(ctx, d.Container); err != nil {
		return err
	}
	if err := e.restoreIfNeeded(ctx, top, d); err != nil {
		return err
	}
	return e.ensureFRRControl(ctx, top, final)
}

// FRRControlContainer returns the private control-plane container associated
// with an FRR router. It is deterministic so lifecycle, repair, and cleanup
// can operate on it without adding a student-visible topology device.
func FRRControlContainer(d *model.Device) string {
	if d == nil {
		return ""
	}
	return d.Container + "-frr"
}

// UsesFRRControl reports whether d needs the split-privilege FRR runtime.
//
// Alpine FRR 10 retains CAP_SYS_ADMIN in its daemon capability vector. Giving
// that capability to a student router shell violates O12, so every FRR router
// gets a private sibling with the capability instead. BIRD and non-router
// devices retain their own native runtime contracts.
func UsesFRRControl(d *model.Device) bool {
	return d != nil && d.Kind == model.KindRouter && d.EffectiveNOS() == model.DefaultNOS
}

func (e *Engine) usesFRRControl(d *model.Device) bool {
	if !UsesFRRControl(d) || e.Runtime == nil {
		return false
	}
	// The split runtime needs Docker/Podman namespace sharing. Unit runtimes
	// deliberately stay single-container fakes; they test planning without
	// creating host directories or a second process namespace.
	switch runtimeName(e.Runtime) {
	case "docker", "podman":
		return true
	default:
		return false
	}
}

func runtimeName(r runtime.Runtime) (name string) {
	defer func() {
		if recover() != nil {
			name = ""
		}
	}()
	return r.Name()
}

const frrControlContractVersion = "frr-control-v2"

func (e *Engine) frrControlBinds(top *model.Topology, d *model.Device) ([]runtime.Bind, error) {
	if !e.usesFRRControl(d) {
		return nil, nil
	}
	etc, run, _, err := e.frrControlPaths(top, d)
	if err != nil {
		return nil, err
	}
	return []runtime.Bind{
		{Source: etc, Target: "/etc/frr"},
		{Source: run, Target: "/run/frr"},
	}, nil
}

// frrControlLogBind is intentionally sidecar-only. Router shells receive the
// configuration directory and vty sockets they need to configure and observe
// their own routing daemon, but not the sidecar's log filesystem.
func (e *Engine) frrControlLogBind(top *model.Topology, d *model.Device) (runtime.Bind, error) {
	_, _, log, err := e.frrControlPaths(top, d)
	if err != nil {
		return runtime.Bind{}, err
	}
	return runtime.Bind{Source: log, Target: "/var/log/frr"}, nil
}

func (e *Engine) frrControlPaths(top *model.Topology, d *model.Device) (etc, run, log string, err error) {
	if top == nil || d == nil {
		return "", "", "", fmt.Errorf("FRR control paths need a topology and device")
	}
	sum := sha256.Sum256([]byte(top.Name + "\x00" + d.ID))
	dir := filepath.Join(e.frrControlRoot(), top.Name, hex.EncodeToString(sum[:8]))
	return filepath.Join(dir, "etc"), filepath.Join(dir, "run"), filepath.Join(dir, "log"), nil
}

func (e *Engine) prepareFRRControlPaths(top *model.Topology, d *model.Device) error {
	if !e.usesFRRControl(d) {
		return nil
	}
	etc, run, log, err := e.frrControlPaths(top, d)
	if err != nil {
		return err
	}
	for _, path := range []string{etc, run, log} {
		if err := os.MkdirAll(path, 0o775); err != nil {
			return fmt.Errorf("create FRR control directory for %s: %w", d.ID, err)
		}
	}
	for _, path := range []string{etc, run} {
		if err := os.Chown(path, 100, 102); err != nil {
			return fmt.Errorf("set FRR vty ownership for %s: %w", d.ID, err)
		}
	}
	if err := os.Chown(log, 100, 101); err != nil {
		return fmt.Errorf("set FRR log ownership for %s: %w", d.ID, err)
	}
	vtysh := filepath.Join(etc, "vtysh.conf")
	if _, err := os.Stat(vtysh); os.IsNotExist(err) {
		if err := os.WriteFile(vtysh, []byte("service integrated-vtysh-config\n"), 0o640); err != nil {
			return fmt.Errorf("write FRR vty configuration for %s: %w", d.ID, err)
		}
		if err := os.Chown(vtysh, 100, 102); err != nil {
			return fmt.Errorf("set FRR vty configuration ownership for %s: %w", d.ID, err)
		}
	} else if err != nil {
		return fmt.Errorf("inspect FRR vty configuration for %s: %w", d.ID, err)
	}
	return nil
}

func (e *Engine) frrControlRoot() string {
	if e.FRRControlRoot != "" {
		return e.FRRControlRoot
	}
	return filepath.Join("/run", "twinet", "frr-control")
}

// writableBinds gives platform-rendered files a host-backed writable target.
// A Docker tmpfs is appropriate for daemon scratch state, but Docker's
// CopyToContainer API rejects it when ReadonlyRootfs is true. These mounts are
// therefore a deliberate control-plane volume contract, not an attempt to
// make the root filesystem writable.
func (e *Engine) writableBinds(top *model.Topology, d *model.Device,
	existing []runtime.Bind,
) ([]runtime.Bind, error) {
	if top == nil || d == nil {
		return nil, fmt.Errorf("platform writable mounts need a topology and device")
	}
	hardening := effectiveHardening(d)
	targets := platformWritableBindTargets(hardening.WritablePaths)
	if len(targets) == 0 {
		return nil, nil
	}
	sum := sha256.Sum256([]byte(top.Name + "\x00" + d.ID))
	root := filepath.Join(e.writableRoot(), top.Name, hex.EncodeToString(sum[:8]))
	var out []runtime.Bind
	for _, target := range targets {
		allBinds := make([]runtime.Bind, 0, len(existing)+len(out))
		allBinds = append(allBinds, existing...)
		allBinds = append(allBinds, out...)
		if bindCovers(target, allBinds) {
			continue
		}
		name := strings.TrimPrefix(target, "/")
		name = strings.ReplaceAll(name, "/", "-")
		source := filepath.Join(root, name)
		out = append(out, runtime.Bind{Source: source, Target: target})
	}
	return out, nil
}

func (e *Engine) writableRoot() string {
	if e.WritableRoot != "" {
		return e.WritableRoot
	}
	if e.ObservationRoot != "" {
		// Test/offline engines often redirect observed state to a writable
		// workspace. Keep their derived platform volumes beside that state
		// rather than assuming the privileged agent's /run root.
		return filepath.Join(e.ObservationRoot, "writable")
	}
	return filepath.Join("/run", "twinet", "writable")
}

// prepareFinalRuntimeSpecs performs the only filesystem side effects needed
// for a derived runtime contract. It is called immediately before a primary
// or sidecar create/recreate, never by RuntimeSpec, FinalSpecHash, or observed
// planning.
func (e *Engine) prepareFinalRuntimeSpecs(top *model.Topology, final finalDeviceSpec) error {
	if err := e.preparePlatformBinds(final.device, final.platformBinds); err != nil {
		return err
	}
	return e.prepareFRRControlPaths(top, final.device)
}

func (e *Engine) preparePlatformBinds(d *model.Device, binds []runtime.Bind) error {
	if d == nil {
		return fmt.Errorf("prepare platform binds for nil device")
	}
	for _, bind := range binds {
		if err := os.MkdirAll(bind.Source, 0o755); err != nil {
			return fmt.Errorf("create writable platform mount for %s at %s: %w", d.ID, bind.Target, err)
		}
	}
	hardening := effectiveHardening(d)
	for _, target := range hardening.WritablePaths {
		target = filepath.Clean(target)
		for _, bind := range binds {
			if target != bind.Target && !strings.HasPrefix(target, bind.Target+"/") {
				continue
			}
			relative, err := filepath.Rel(bind.Target, target)
			if err != nil || relative == "." {
				break
			}
			if err := os.MkdirAll(filepath.Join(bind.Source, relative), 0o755); err != nil {
				return fmt.Errorf("create writable child mount for %s at %s: %w", d.ID, target, err)
			}
			break
		}
	}
	return nil
}

func platformWritableBindTargets(paths []string) []string {
	ephemeral := map[string]bool{
		"/run": true, "/var/run": true, "/var/log": true, "/var/tmp": true,
		"/tmp": true, "/etc/openvswitch": true,
	}
	seen := map[string]bool{}
	var candidates []string
	for _, target := range paths {
		target = filepath.Clean(target)
		if ephemeral[target] || seen[target] {
			continue
		}
		seen[target] = true
		candidates = append(candidates, target)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if len(candidates[i]) != len(candidates[j]) {
			return len(candidates[i]) < len(candidates[j])
		}
		return candidates[i] < candidates[j]
	})
	var out []string
	for _, target := range candidates {
		covered := false
		for _, parent := range out {
			if target == parent || strings.HasPrefix(target, parent+"/") {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, target)
		}
	}
	return out
}

func (e *Engine) ensureFRRControl(ctx context.Context, top *model.Topology, final finalDeviceSpec) error {
	spec := final.controlSpec
	if spec == nil {
		return nil
	}
	name := spec.Name
	current, err := e.Runtime.Inspect(ctx, name)
	if err != nil {
		return err
	}
	want := spec.Labels[LabelSpec]
	if current.State != runtime.StateAbsent {
		if current.Labels[LabelSpec] == want && current.State.Joinable() {
			return e.stopPrimaryFRRDaemons(ctx, final.device)
		}
		if err := e.Runtime.Remove(ctx, name, true); err != nil {
			return fmt.Errorf("replace FRR control %s: %w", name, err)
		}
	}
	if err := e.prepareFinalRuntimeSpecs(top, final); err != nil {
		return err
	}
	if _, err := e.Runtime.Create(ctx, spec); err != nil {
		return fmt.Errorf("create FRR control %s: %w", name, err)
	}
	if err := e.Runtime.Start(ctx, name); err != nil {
		return fmt.Errorf("start FRR control %s: %w", name, err)
	}
	return e.stopPrimaryFRRDaemons(ctx, final.device)
}

// stopPrimaryFRRDaemons migrates legacy routers to the split control-plane
// contract. The primary container remains the student shell, but it must never
// retain a second zebra/bgpd set after the sidecar owns /etc/frr and /run/frr:
// duplicate daemons compete for vty/netlink state and leave routes apparently
// configured but absent from the kernel.
func (e *Engine) stopPrimaryFRRDaemons(ctx context.Context, d *model.Device) error {
	if !e.usesFRRControl(d) {
		return nil
	}
	const processes = `watchfrr|zebra|bgpd|ospfd|ospf6d|isisd|ldpd|pimd|staticd|bfdd|ripd|ripngd|pathd|sharpd|mgmtd`
	script := strings.Join([]string{
		`find_frr() { ps -eo pid=,args= | awk '$0 ~ /\/usr\/lib\/frr\/(` + processes + `)( |$)/ || $0 ~ /(^|[[:space:]])watchfrr( |$)/ {print $1}'; }`,
		`pids="$(find_frr)"`,
		`if [ -n "$pids" ]; then kill $pids 2>/dev/null || true; sleep 1; fi`,
		`pids="$(find_frr)"`,
		`if [ -n "$pids" ]; then kill -9 $pids 2>/dev/null || true; sleep 1; fi`,
		`test -z "$(find_frr)"`,
	}, "\n")
	result, err := e.Runtime.Exec(ctx, d.Container, runtime.ExecCmd{Cmd: []string{"sh", "-c", script}})
	if err != nil {
		return fmt.Errorf("stop legacy primary FRR daemons for %s: %w", d.ID, err)
	}
	if err := result.Err(); err != nil {
		return fmt.Errorf("legacy primary FRR daemons remain for %s: %w", d.ID, err)
	}
	return nil
}

func (e *Engine) removeFRRControl(ctx context.Context, d *model.Device) error {
	if !e.usesFRRControl(d) {
		return nil
	}
	name := FRRControlContainer(d)
	current, err := e.Runtime.Inspect(ctx, name)
	if err != nil {
		return err
	}
	if current.State == runtime.StateAbsent {
		return nil
	}
	return e.Runtime.Remove(ctx, name, true)
}

func frrControlSpecHash(d *model.Device) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n", frrControlContractVersion, d.ID, d.Image)
	fmt.Fprintf(h, "imageid=%s\nrestart=%s\n", d.ImageID, d.Restart)
	fmt.Fprintf(h, "device=%s\n", SpecHash(d))
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// captureBeforeReplace snapshots a student-owned device before it is destroyed.
func (e *Engine) captureBeforeReplace(ctx context.Context, top *model.Topology, d *model.Device) error {
	if e.State == nil || !studentOwned(top, d) {
		return nil
	}
	// Not while the reference solution is what is on the device.
	//
	// Capturing then files the answer as the student's own saved
	// configuration, to be replayed onto their router the next time a
	// container is recreated. A grading run solves the lab constantly, so this
	// would happen to every student on every class run.
	if e.WritesReference {
		return nil
	}
	var (
		snaps []state.Snapshot
		err   error
	)
	err = e.limited(ctx, []limiter.Kind{limiter.Capture}, func() error {
		var captureErr error
		snaps, captureErr = Capture(ctx, e.Runtime, d, top.Name, top.Hash)
		return captureErr
	})
	if errors.Is(err, ErrNotRunning) {
		// A stopped container still holds the student's work on its
		// filesystem. Start it, read it, and only then allow the replacement.
		// Refusing outright would strand the device instead, and going ahead
		// would delete the work of whoever's router happened to be down.
		if serr := e.Runtime.Start(ctx, d.Container); serr != nil {
			return fmt.Errorf("refusing to replace %s: it is not running and could not be "+
				"started to read its configuration: %w", d.ID, serr)
		}
		err = e.limited(ctx, []limiter.Kind{limiter.Capture}, func() error {
			var captureErr error
			snaps, captureErr = Capture(ctx, e.Runtime, d, top.Name, top.Hash)
			return captureErr
		})
	}
	if err != nil {
		return fmt.Errorf("refusing to replace %s: its configuration could not be captured: %w", d.ID, err)
	}
	for _, s := range snaps {
		if _, err := e.State.Put(s); err != nil {
			return fmt.Errorf("refusing to replace %s: its configuration could not be saved: %w", d.ID, err)
		}
	}
	return nil
}

// restoreIfNeeded replays captured configuration into a device that has just
// been created or restarted.
func (e *Engine) restoreIfNeeded(ctx context.Context, top *model.Topology, d *model.Device) error {
	if e.State == nil || !studentOwned(top, d) {
		return nil
	}
	// Not when this deployment is writing the reference solution.
	//
	// Restoration exists so that a container recreated during teaching comes
	// back with the student's work. A deployment that installs the reference
	// wants the opposite: replaying the snapshot afterwards puts the student's
	// old configuration back on top of the answer, and a grading run then
	// measures every other submission against a lab that is not the reference
	// -- while every check on that system passes, because it is somebody's
	// converged network. The snapshot stays in the store for the platform-mode
	// deployment that wants it.
	if e.WritesReference {
		return nil
	}
	// Restoration must happen after the interfaces exist, or addresses land on
	// devices that are not there yet. It is therefore deferred to the configure
	// stage; this records that it is pending.
	e.pendingRestore.Store(d.ID, true)
	e.markRestorePending(ctx, d)
	return nil
}

// restoreMarker is written inside a device that has been recreated and not yet
// had its saved configuration replayed.
//
// Pendingness used to live only in a map on the engine, which exists for the
// length of one request. If the node's agent was restarted, killed by the OOM
// killer, or simply upgraded between creating a container and configuring it,
// the fact that a student's configuration was still waiting to be replayed went
// with it. The next deploy saw a container that existed and nothing marking it,
// so it converged happily on an empty router. The work was still in the state
// store, and nothing would ever look for it again.
//
// The marker lives where the consequence lives. A container that comes back
// without its configuration carries the note saying so, so any later deploy
// finds it, whatever happened to the process that created it.
const restoreMarker = "/etc/twinet/restore-pending"

func (e *Engine) markRestorePending(ctx context.Context, d *model.Device) {
	// Best effort: the in-memory marker covers this request, and failing to
	// write the file must not fail a deployment. What it costs is the ability
	// to recover from a crash, which is exactly what the in-memory marker
	// cannot do either.
	_, _ = e.Runtime.Exec(ctx, d.Container, runtime.ExecCmd{Cmd: []string{"sh", "-c",
		"mkdir -p /etc/twinet && echo 'this device was recreated and its saved " +
			"configuration has not been replayed yet' > " + restoreMarker}})
}

func (e *Engine) clearRestorePending(ctx context.Context, d *model.Device) {
	_, _ = e.Runtime.Exec(ctx, d.Container, runtime.ExecCmd{
		Cmd: []string{"rm", "-f", restoreMarker}})
}

// restoreIsPending reports whether this device still owes a restore, from
// either the marker this request left or one a previous run left behind.
func (e *Engine) restoreIsPending(ctx context.Context, d *model.Device) bool {
	if _, ok := e.pendingRestore.Load(d.ID); ok {
		return true
	}
	res, err := e.Runtime.Exec(ctx, d.Container, runtime.ExecCmd{
		Cmd: []string{"test", "-f", restoreMarker}})
	return err == nil && res.ExitCode == 0
}

// replayPending restores a device's captured configuration if one was pending.
func (e *Engine) replayPending(ctx context.Context, top *model.Topology, d *model.Device) error {
	if e.State == nil || !studentOwned(top, d) {
		return nil
	}
	// See restoreIfNeeded: the reference is not something to restore over.
	if e.WritesReference {
		return nil
	}
	if !e.restoreIsPending(ctx, d) {
		return nil
	}
	ok, err := Restore(ctx, e.Runtime, d, top.Name, e.State)
	if err != nil {
		// The marker stays. It used to be taken with LoadAndDelete, before the
		// restore was attempted, so a restore that failed for any transient
		// reason -- the container not yet accepting commands, a busy node --
		// left nothing to say the device still needed one. The next deploy saw
		// a device that existed, no pending work, and converged happily on a
		// router with none of its student's configuration. The failure was
		// reported once and then became invisible.
		//
		// A failed restore is loud: the snapshot is still on disk, and an
		// operator must know that this device came back empty.
		return fmt.Errorf("%s was recreated but its saved configuration could not be replayed "+
			"(the snapshot is safe in the state store, and the device is still marked "+
			"as needing one): %w", d.ID, err)
	}
	e.pendingRestore.Delete(d.ID)
	e.clearRestorePending(ctx, d)
	_ = ok
	return nil
}

// PruneOrphans removes containers on this node that belong to the lab but are
// not in the topology any more.
//
// Deployment alone only ensures the desired objects exist; without this, an AS
// removed from the manifest keeps running, and an AS moved to another node runs
// twice, announcing the same prefix from two places.
func (e *Engine) PruneOrphans(ctx context.Context, top *model.Topology) ([]string, error) {
	want := map[string]bool{}
	for _, d := range top.DevicesOnNode(e.Node) {
		want[d.Container] = true
		if e.usesFRRControl(d) {
			want[FRRControlContainer(d)] = true
		}
	}
	// A device that has moved to another node must also be removed from here.
	elsewhere := map[string]bool{}
	for _, d := range top.SortedDevices() {
		if d.Node != e.Node {
			elsewhere[d.Container] = true
		}
	}

	cs, err := e.Runtime.List(ctx, runtime.Filter{All: true,
		Labels: map[string]string{LabelLab: top.Name}})
	if err != nil {
		return nil, err
	}
	var candidates []runtime.Container
	for _, c := range cs {
		if want[c.Name] {
			continue
		}
		// Only remove what this node is responsible for, and only what the
		// topology genuinely no longer places here.
		if c.Labels[LabelNode] != "" && c.Labels[LabelNode] != e.Node && !elsewhere[c.Name] {
			continue
		}
		candidates = append(candidates, c)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })

	// Capture every candidate before removing any one of them. A parallel
	// prune must not turn a capture failure into a race where another worker
	// has already destroyed an unrelated student's only copy.
	captures := make([][]state.Snapshot, len(candidates))
	_, captureErrs, ctxErr := e.runBounded(ctx, len(candidates), func(i int) error {
		return e.limited(ctx, []limiter.Kind{limiter.Capture}, func() error {
			snaps, err := e.orphanSnapshots(ctx, top, candidates[i])
			captures[i] = snaps
			return err
		})
	})
	var problems []string
	for i, c := range candidates {
		// Capture before removing. An orphan is usually a device that moved to
		// another node or left the manifest, and in both cases it may hold a
		// student's work -- the only copy of it. Removing first and asking
		// later is not recoverable, and the loss is silent: the deployment
		// reports success, the container is gone, and nobody discovers what
		// was in it until someone asks for a mark.
		//
		// Refusing is the right failure. A lab with one stale container is a
		// nuisance; a lab that has quietly eaten a group's configuration is
		// not something an apology fixes.
		if err := captureErrs[i]; err != nil {
			problems = append(problems, fmt.Sprintf(
				"refusing to remove %s: its configuration could not be captured (%v). "+
					"Destroy the lab explicitly if it is genuinely disposable", c.Name, err))
		}
		for _, snap := range captures[i] {
			if _, err := e.State.Put(snap); err != nil {
				problems = append(problems, fmt.Sprintf(
					"refusing to remove %s: its configuration could not be saved (%v). "+
						"Destroy the lab explicitly if it is genuinely disposable", c.Name, err))
			}
		}
	}
	if err := deterministicError(ctxErr, problems); err != nil {
		return nil, err
	}

	started, removeErrs, ctxErr := e.runBounded(ctx, len(candidates), func(i int) error {
		return e.limited(ctx, []limiter.Kind{limiter.Lifecycle}, func() error {
			return e.Runtime.Remove(ctx, candidates[i].Name, true)
		})
	})
	var removed []string
	for i, c := range candidates {
		if !started[i] {
			continue
		}
		if err := removeErrs[i]; err != nil {
			problems = append(problems, fmt.Sprintf("remove orphan %s: %v", c.Name, err))
			continue
		}
		removed = append(removed, c.Name)
	}
	return removed, deterministicError(ctxErr, problems)
}

// captureOrphan snapshots a container that is about to be removed.
//
// A container with no state store configured is removed without capture,
// because there is nowhere to put the snapshot and blocking every prune on a
// store nobody configured would make the platform unusable. That is a
// deliberate trade and it is recorded here rather than left implicit.
func (e *Engine) captureOrphan(ctx context.Context, top *model.Topology, c runtime.Container) error {
	snaps, err := e.orphanSnapshots(ctx, top, c)
	if err != nil {
		return err
	}
	for _, snap := range snaps {
		if _, err := e.State.Put(snap); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) orphanSnapshots(ctx context.Context, top *model.Topology, c runtime.Container) ([]state.Snapshot, error) {
	if c.Labels[LabelFRRControl] == "true" {
		// The sidecar has only the router's shared config/vty mounts. The
		// student-owned snapshot belongs to the shell container, and capturing
		// the sidecar would duplicate or race that state.
		return nil, nil
	}
	if e.State == nil {
		return nil, nil
	}
	// Nothing is captured while the reference solution is what is on the
	// device: the snapshot would be the answer filed as the student's work.
	if e.WritesReference {
		return nil, nil
	}
	// The device is gone from the topology, so its identity comes from the
	// labels the deployment stamped on it.
	//
	// The *canonical* identifier, not the short name. Every autonomous system
	// in these labs has a router called ATL, so keying on the name filed
	// as3/ATL's configuration and as4/ATL's under the same "ATL" -- one
	// overwriting the other, and neither findable by the identifier a restore
	// looks up.
	id := c.Labels[LabelDeviceID]
	if id == "" {
		id = c.Labels[LabelDevice]
	}
	if id == "" {
		return nil, nil
	}
	d, ok := top.Device(id)
	if !ok {
		// Not in the manifest any more, which is exactly why it is an orphan.
		// A minimal stand-in is enough for the capture, which reads the
		// container rather than the model.
		d = &model.Device{ID: id, Container: c.Name, Kind: model.DeviceKind(c.Labels[LabelKind])}
	}
	if d.Kind == "" {
		d.Kind = model.KindRouter
	}
	snaps, err := Capture(ctx, e.Runtime, d, top.Name, top.Hash)
	if err != nil {
		return snaps, err
	}
	return snaps, nil
}

// PruneOverlays removes stale VNI bindings and any now-empty shared
// bridge/VXLAN pair this node no longer needs.
func (e *Engine) PruneOverlays(top *model.Topology) ([]string, error) {
	return e.PruneOverlaysContext(context.Background(), top)
}

// PruneOverlaysContext is PruneOverlays with cancellation for callers that
// already have a deployment request context.
func (e *Engine) PruneOverlaysContext(ctx context.Context, top *model.Topology) ([]string, error) {
	want := map[uint32]bool{}
	for _, l := range top.LinksTouchingNode(e.Node) {
		if l.CrossNode() {
			want[l.VNI] = true
		}
	}
	// Only this lab's own overlays are considered. A sweep of every twvx
	// device on the host would delete the fabric of every other lab sharing
	// the node, which is exactly the situation batch grading creates.
	live, err := netx.ListOverlaysOfLab(top.Name)
	if err != nil {
		return nil, err
	}
	var stale []uint32
	for _, vni := range live {
		if want[vni] {
			continue
		}
		stale = append(stale, vni)
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i] < stale[j] })
	started, errs, ctxErr := e.runBounded(ctx, len(stale), func(i int) error {
		vni := stale[i]
		return e.limited(ctx, []limiter.Kind{limiter.Netlink}, func() error {
			if err := netx.DeleteHostLink(hostSideName(vni)); err != nil {
				return err
			}
			return netx.RemoveOverlay(vni)
		})
	})
	var removed []string
	var problems []string
	for i, vni := range stale {
		if !started[i] {
			continue
		}
		if err := errs[i]; err != nil {
			problems = append(problems, fmt.Sprintf("remove overlay %d: %v", vni, err))
			continue
		}
		removed = append(removed, netx.VxlanName(vni))
	}
	if ctxErr == nil {
		var empty []string
		err = e.limited(ctx, []limiter.Kind{limiter.Netlink}, func() error {
			var removeErr error
			empty, removeErr = netx.RemoveEmptyMultiplexOverlays(top.Name)
			return removeErr
		})
		if err != nil {
			problems = append(problems, fmt.Sprintf("remove empty multiplex overlays: %v", err))
		} else {
			removed = append(removed, empty...)
		}
	}
	sort.Strings(removed)
	return removed, deterministicError(ctxErr, problems)
}

// SpecHash is a digest of everything about a container that would require it to
// be recreated if it changed.
//
// Deliberately excluded: anything that can be changed in place, such as link
// shaping or an address on an interface. Deliberately included: image, command,
// resource limits, capabilities, sysctls, binds, environment and placement,
// because none of those can be altered on a running container.
//
// The image *identity* is included, not only its reference. A tag rebuilt in
// place is different software under an unchanged name, and hashing the name
// alone means the new image is never deployed: the lab keeps running the old
// one while every report says it is up to date. That was not hypothetical --
// it cost a debugging session here, where a fixed image sat on the host and the
// containers kept the broken one.
func SpecHash(d *model.Device) string {
	h := sha256.New()
	fmt.Fprintf(h, "id=%s\nkind=%s\nimage=%s\nimageid=%s\nhost=%s\nnode=%s\n",
		d.ID, d.Kind, d.Image, d.ImageID, d.Hostname, d.Node)
	if d.NOS != "" {
		fmt.Fprintf(h, "nos=%s\n", d.NOS)
	}
	if UsesFRRControl(d) {
		fmt.Fprintf(h, "frr-control=%s\n", frrControlContractVersion)
	}
	cpus, memory, pids := effectiveRuntimeLimits(d)
	fmt.Fprintf(h, "cpus=%v\nmem=%s\npids=%d\nrestart=%s\npriv=%v\n",
		cpus, memory, pids, d.Restart, d.Privileged)
	fmt.Fprintf(h, "cmd=%s\ncaps=%s\nbinds=%s\n",
		strings.Join(d.Command, ","),
		strings.Join(effectiveCapabilities(d), ","),
		strings.Join(sortedCopy(d.Binds), ","))
	for _, k := range sortedKeys(d.Env) {
		fmt.Fprintf(h, "env:%s=%s\n", k, d.Env[k])
	}
	for _, k := range sortedKeys(d.Sysctls) {
		fmt.Fprintf(h, "sysctl:%s=%s\n", k, d.Sysctls[k])
	}
	hardening := model.EffectiveRuntimeHardening(d.Kind, d.Hardening)
	fmt.Fprintf(h, "hardening=nnp:%t,seccomp:%s,apparmor:%s,rootfs:%t,runtime:%s,userns:%s,pid:%s\n",
		hardening.NoNewPrivileges != nil && *hardening.NoNewPrivileges,
		hardening.SeccompProfile, hardening.AppArmorProfile,
		hardening.ReadOnlyRootfs != nil && *hardening.ReadOnlyRootfs,
		hardening.RuntimeClass, hardening.UsernsMode, hardening.PIDMode)
	fmt.Fprintf(h, "hardening-writable=%s\nhardening-masked=%s\nhardening-readonly=%s\n",
		strings.Join(sortedCopy(hardening.WritablePaths), ","),
		strings.Join(sortedCopy(hardening.MaskedPaths), ","),
		strings.Join(sortedCopy(hardening.ReadonlyPaths), ","))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func (e *Engine) labels(top *model.Topology, d *model.Device, specHash string) map[string]string {
	request := d.Requests
	if request.Empty() {
		request = model.DefaultResourceRequest(d.Kind)
	}
	out := map[string]string{
		LabelManaged:  "true",
		LabelLab:      top.Name,
		LabelDevice:   d.Name,
		LabelDeviceID: d.ID,
		LabelKind:     string(d.Kind),
		LabelNode:     e.Node,
		LabelHash:     top.Hash,
	}
	if specHash != "" {
		out[LabelSpec] = specHash
	}
	if top.Lab != nil && top.Lab.Images.LockDigest != "" {
		out[LabelImageLock] = top.Lab.Images.LockDigest
	}
	setRequestLabels(out, request)
	if e.Generation != "" {
		out[LabelGen] = e.Generation
	}
	if d.ASN > 0 {
		out[LabelAS] = strconv.Itoa(d.ASN)
	}
	if d.NOS != "" {
		out[LabelNOS] = d.NOS
	}
	if d.Owner != "" {
		out[LabelOwner] = d.Owner
	}
	for k, v := range d.Labels {
		if _, reserved := out[k]; !reserved {
			out[k] = v
		}
	}
	return out
}

func setRequestLabels(labels map[string]string, request model.ResourceRequest) {
	labels[LabelRequestCPU] = strconv.FormatFloat(request.CPUs, 'f', -1, 64)
	labels[LabelRequestMemory] = request.Memory
	labels[LabelRequestPids] = strconv.FormatInt(request.Pids, 10)
	labels[LabelRequestDisk] = request.Storage()
	labels[LabelRequestFDs] = strconv.FormatInt(request.FileDescriptors, 10)
	labels[LabelRequestNetDevs] = strconv.FormatInt(request.NetDevices, 10)
}

// wire realises one link.
func (e *Engine) wire(ctx context.Context, top *model.Topology, l *model.Link) error {
	if l.CrossNode() {
		return e.wireCrossNode(ctx, top, l)
	}
	aNS, err := e.Runtime.NSPath(ctx, l.A.Device.Container)
	if err != nil {
		return fmt.Errorf("link %s: side a: %w", l.ID, err)
	}
	bNS, err := e.Runtime.NSPath(ctx, l.B.Device.Container)
	if err != nil {
		return fmt.Errorf("link %s: side b: %w", l.ID, err)
	}
	spec := netx.VethSpec{
		TempA: alloc.TempIfName(top.Name, l.ID, 'a'),
		TempB: alloc.TempIfName(top.Name, l.ID, 'b'),
		MTU:   linkMTU(l),
		A:     e.endpoint(top, l.A, aNS, l),
		B:     e.endpoint(top, l.B, bNS, l),
	}
	if err := netx.CreateVeth(spec); err != nil {
		return fmt.Errorf("link %s: %w", l.ID, err)
	}
	return nil
}

// wireCrossNode attaches this node's half of the link to a shared external
// VXLAN for the lab/node pair. Each link retains its own VNI on the wire; a
// deterministic bridge VLAN maps that VNI through the shared tunnel.
func (e *Engine) wireCrossNode(ctx context.Context, top *model.Topology, l *model.Link) error {
	var local, remote *model.Iface
	switch e.Node {
	case l.A.Device.Node:
		local, remote = l.A, l.B
	case l.B.Device.Node:
		local, remote = l.B, l.A
	default:
		return nil
	}

	remoteIP := e.PeerUnderlay[remote.Device.Node]
	if remoteIP == "" {
		return fmt.Errorf("link %s: no underlay address known for node %s", l.ID, remote.Device.Node)
	}
	vlan, mtu, port, err := multiplexParameters(top, e.Node, remote.Device.Node, l.VNI)
	if err != nil {
		return fmt.Errorf("link %s: %w", l.ID, err)
	}
	bridge, err := netx.EnsureMultiplexOverlay(netx.MultiplexOverlaySpec{
		Lab:            top.Name,
		LocalNode:      e.Node,
		RemoteNode:     remote.Device.Node,
		LocalIP:        e.UnderlayIP,
		RemoteIP:       remoteIP,
		UnderlayDev:    e.UnderlayDev,
		MTU:            mtu,
		Port:           port,
		VNI:            l.VNI,
		VLAN:           vlan,
		PreserveActive: e.RecoveryCompatibility,
		ForcePort:      e.ForceOverlayReconcile,
	})
	if err != nil {
		return fmt.Errorf("link %s: %w", l.ID, err)
	}

	ns, err := e.Runtime.NSPath(ctx, local.Device.Container)
	if err != nil {
		return fmt.Errorf("link %s: %w", l.ID, err)
	}
	hostSide := hostSideName(l.VNI)
	spec := netx.VethSpec{
		TempA: alloc.TempIfName(top.Name+e.Node, l.ID, 'a'),
		TempB: alloc.TempIfName(top.Name+e.Node, l.ID, 'b'),
		MTU:   mtu,
		A:     e.endpoint(top, local, ns, l),
		B: netx.EndpointSpec{
			Name:    hostSide, // stays in the root namespace, enslaved to the bridge
			Altname: alloc.LinkAltname(top.Name, l.ID+"/host"),
			MTU:     mtu,
			Up:      true,
		},
	}
	if err := netx.CreateVeth(spec); err != nil {
		return fmt.Errorf("link %s: %w", l.ID, err)
	}
	if err := netx.AttachToMultiplexOverlay(hostSide, bridge, vlan); err != nil {
		return fmt.Errorf("link %s: attach multiplex port: %w", l.ID, err)
	}
	// A successful attach has moved the only host-side veth away from the old
	// bridge, so the legacy per-link pair is now safe to remove. If this step
	// failed, the old path remains intact for a retry instead of cutting a
	// running lab over half way through migration.
	if !e.RetainLegacyOverlays {
		if err := netx.RemoveLegacyOverlayForLab(l.VNI, top.Name); err != nil {
			return fmt.Errorf("link %s: remove legacy overlay: %w", l.ID, err)
		}
	}
	return nil
}

// hostSideName derives the root-namespace veth name for a cross-node link.
// It must fit IFNAMSIZ-1 and be unique per VNI, which it is because the VNI is.
func hostSideName(vni uint32) string { return fmt.Sprintf("twp%d", vni) }

// multiplexParameters computes the one bridge VLAN, outer MTU, and UDP port
// for a link's node pair. Both endpoint agents run this against the same full
// topology, so VLAN and port collision resolution stays symmetric.
func multiplexParameters(top *model.Topology, first, second string, target uint32) (uint16, int, int, error) {
	var vnis []uint32
	mtu := 0
	found := false
	pairs := map[string][2]string{}
	for _, link := range top.Links {
		if link == nil || !link.CrossNode() || link.A == nil || link.B == nil ||
			link.A.Device == nil || link.B.Device == nil {
			continue
		}
		a, b := link.A.Device.Node, link.B.Device.Node
		pairID, err := netx.MultiplexPairID(a, b)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("cross-node link %s: %w", link.ID, err)
		}
		pairs[pairID] = [2]string{a, b}
		if !sameNodePair(a, b, first, second) {
			continue
		}
		if link.VNI == 0 {
			return 0, 0, 0, fmt.Errorf("cross-node link %s has no VNI", link.ID)
		}
		vnis = append(vnis, link.VNI)
		if linkMTU(link) > mtu {
			mtu = linkMTU(link)
		}
		if link.VNI == target {
			found = true
		}
	}
	if !found {
		return 0, 0, 0, fmt.Errorf("VNI %d is not a cross-node link between %s and %s",
			target, first, second)
	}
	if mtu == 0 {
		mtu = 1500
	}
	vlans, err := netx.AssignOverlayVLANs(vnis)
	if err != nil {
		return 0, 0, 0, err
	}
	vlan := vlans[target]
	if vlan == 0 {
		return 0, 0, 0, fmt.Errorf("no VLAN assigned to VNI %d", target)
	}
	allPairs := make([][2]string, 0, len(pairs))
	for _, pair := range pairs {
		allPairs = append(allPairs, pair)
	}
	ports, err := netx.AssignMultiplexPorts(top.Name, allPairs)
	if err != nil {
		return 0, 0, 0, err
	}
	pairID, err := netx.MultiplexPairID(first, second)
	if err != nil {
		return 0, 0, 0, err
	}
	port := ports[pairID]
	if port == 0 {
		return 0, 0, 0, fmt.Errorf("no UDP port assigned to node pair %s/%s", first, second)
	}
	return vlan, mtu, port, nil
}

func sameNodePair(a, b, first, second string) bool {
	return (a == first && b == second) || (a == second && b == first)
}

// endpoint builds the netx specification for one side of a link.
func (e *Engine) endpoint(top *model.Topology, i *model.Iface, nsPath string, l *model.Link) netx.EndpointSpec {
	ep := netx.EndpointSpec{
		NSPath:  nsPath,
		Name:    i.Name,
		MAC:     i.MAC,
		MTU:     linkMTU(l),
		Altname: alloc.LinkAltname(top.Name, l.ID),
		Up:      true,
	}
	// Label switching is enabled on every interface of a router in an
	// MPLS-enabled AS, including the ones facing customers: LDP is not offered
	// there, but a labelled packet that does arrive must be forwarded rather
	// than dropped, and deciding per interface here would mean two places that
	// have to agree about which interfaces are interior.
	if as := top.ASes[i.Device.ASN]; as != nil && as.MPLS.Enabled {
		ep.MPLS = true
		// Room is left for the label stack.
		//
		// A label is four bytes on the wire, and a VPN packet carries two: the
		// transport label and the VPN label. The interface MTU is what TCP
		// derives its segment size from, so without this a router negotiates
		// segments that are exactly the link MTU and every one of them becomes
		// oversized the moment a label is pushed.
		//
		// The failure that produces is remarkably quiet. Small messages get
		// through, so BGP sessions to label-switched peers open, exchange
		// keepalives and sit there reporting Established while not one UPDATE
		// crosses -- and only for peers more than one hop away, because the
		// last hop uses implicit null and pushes no label at all. The result
		// is a VPN whose sessions are all up and which carries no routes,
		// which looks like a policy mistake and is not one.
		if ep.MTU > mplsLabelHeadroom {
			ep.MTU -= mplsLabelHeadroom
		}
	}

	// A customer-facing interface belongs to that customer's routing table.
	// This is a kernel device, not only an FRR setting: without it the
	// addresses land in the main table, and two customers using the same
	// private prefix silently overwrite each other's routes.
	if i.VRF != "" {
		if as, ok := top.ASes[i.Device.ASN]; ok {
			if v := as.VRFs[i.VRF]; v != nil {
				ep.VRF, ep.VRFTable = i.VRF, v.Table
			}
		}
	}
	// Addresses are applied only for interfaces the platform owns. Those the
	// student owns are left bare on purpose: configuring them is the exercise.
	//
	// Where the platform does own them, it owns them exactly: an address left
	// behind by an earlier revision of the manifest is removed. Converging by
	// adding alone is not converging -- the router answers on both the old and
	// the new address, and the session comes up on neither, because each end
	// uses what its own copy of the model says and those no longer agree.
	if i.Owner == model.OwnerPlatform {
		ep.OwnAddrs = true
		if i.Addr4 != "" {
			ep.Addrs = append(ep.Addrs, i.Addr4)
		}
		if i.Addr6 != "" {
			ep.Addrs = append(ep.Addrs, i.Addr6)
		}
	} else if e.authoritativeDevice(i.Device) {
		// Solve mode installs the reference answer, which includes the
		// addresses a student would have chosen, so it owns them too.
		ep.OwnAddrs = true
		if i.Addr4 != "" {
			ep.Addrs = append(ep.Addrs, i.Addr4)
		}
		if i.Addr6 != "" {
			ep.Addrs = append(ep.Addrs, i.Addr6)
		}
	}
	// Every managed link owns its qdisc state, including the empty state. That
	// lets a redeploy remove a delay that was deleted from the manifest while
	// netx's observation avoids touching qdiscs whose declaration is unchanged.
	ep.Shaping = &netx.Shaping{
		Bandwidth: l.Props.Bandwidth,
		Delay:     l.Props.Delay,
		Queue:     l.Props.Queue,
		Loss:      l.Props.Loss,
	}
	return ep
}

// configure writes the device's files and runs its post-wiring commands.
func (e *Engine) configure(ctx context.Context, d *model.Device) error {
	if e.Renderer == nil {
		return nil
	}
	state, err := e.renderDesired(d)
	if err != nil {
		return err
	}
	if !e.RecoveryCompatibility && e.configurationCurrent(ctx, d, state.files, state.configHash) {
		return nil
	}
	return e.configureDesired(ctx, d, state)
}

// configureDesired applies a pre-rendered dirty configuration. Build renders
// once during observation, so the executable plan does not render again or
// perform an extra marker/file survey for every untouched device.
func (e *Engine) configureDesired(ctx context.Context, d *model.Device, state desiredDeviceState) error {
	if e.Renderer == nil {
		return nil
	}
	if e.shouldForceStudentReset(d) && hasStudentConfig(d) {
		if err := e.resetStudentNetworkState(ctx, d); err != nil {
			return err
		}
	}
	for _, path := range sortedKeys(state.files) {
		f := state.files[path]
		keep, err := e.holdsStudentWork(ctx, d, path)
		if err != nil {
			return err
		}
		if keep {
			// The file on disk is the student's, and overwriting it would be
			// silent: FRR is not restarted here, so the router keeps running
			// correctly and the loss only appears later, when the container is
			// restarted and comes up on a configuration nobody chose.
			//
			// A deployment converges the platform's own state. It has no
			// business rewriting the part it deliberately left to someone else.
			continue
		}
		if e.fileContentMatches(ctx, d, path, f.Content) {
			continue
		}
		if err := e.Runtime.CopyTo(ctx, d.Container, path, f.Mode, f.Content); err != nil {
			return fmt.Errorf("write %s to %s: %w", path, d.ID, err)
		}
		e.recordMutation("copy", 1)
	}
	for _, c := range state.commands {
		container := d.Container
		if c.FRRControl && e.usesFRRControl(d) {
			container = FRRControlContainer(d)
		}
		res, err := e.Runtime.Exec(ctx, container, runtime.ExecCmd{Cmd: c.Args})
		if err != nil {
			return fmt.Errorf("%s: %s: %w", d.ID, c.Describe, err)
		}
		if err := res.Err(); err != nil && !c.IgnoreError {
			return fmt.Errorf("%s: %s: %w", d.ID, c.Describe, err)
		}
		e.recordMutation("command", 1)
	}
	if e.shouldForceStudentReset(d) && d.Kind == model.KindRouter {
		if err := e.restartPlatformRouting(ctx, d); err != nil {
			return err
		}
	}
	if err := e.writeConfigurationMarker(ctx, d, state.configHash); err != nil {
		return err
	}

	e.recordMutation("configure", 1)
	return nil
}

func (e *Engine) resetStudentNetworkState(ctx context.Context, d *model.Device) error {
	for _, command := range referenceNetworkResetCommands(d) {
		result, err := e.Runtime.Exec(ctx, d.Container, runtime.ExecCmd{Cmd: []string{"sh", "-c", command}})
		if err != nil {
			return fmt.Errorf("reset reference address state on %s: %w", d.ID, err)
		}
		if err := result.Err(); err != nil {
			return fmt.Errorf("reset reference address state on %s: %w", d.ID, err)
		}
	}
	return nil
}

// referenceNetworkResetCommands removes only facts that solve mode installed
// on student-owned interfaces. Alpine iproute2 rejects `addr flush ... scope
// global` for several link kinds, and blanket flushing can remove platform
// addresses that teaching mode must retain. Exact deletes are idempotent and
// leave link-local/kernel addresses untouched.
func referenceNetworkResetCommands(d *model.Device) []string {
	if d == nil {
		return nil
	}
	var commands []string
	for _, iface := range d.Ifaces {
		if iface.Owner != model.OwnerStudent {
			continue
		}
		lines := []string{
			"ip link show dev " + iface.Name + " >/dev/null 2>&1 || exit $?",
		}
		if iface.Addr4 != "" {
			lines = append(lines,
				"if ip -o -4 addr show dev "+iface.Name+
					" | awk '$3 == \"inet\" && $4 == \""+iface.Addr4+"\" { found=1 } END { exit !found }'; then",
				"  ip addr del "+iface.Addr4+" dev "+iface.Name+" || exit $?",
				"fi")
		}
		if iface.Addr6 != "" {
			lines = append(lines,
				"if ip -o -6 addr show dev "+iface.Name+
					" | awk '$3 == \"inet6\" && $4 == \""+iface.Addr6+"\" { found=1 } END { exit !found }'; then",
				"  ip -6 addr del "+iface.Addr6+" dev "+iface.Name+" || exit $?",
				"fi")
		}
		// Routes on a student-owned non-loopback interface are part of the
		// reference answer in solve mode. Deleting the exact loopback address
		// already removes its connected route; flushing lo risks kernel local
		// defaults that platform mode never owned.
		if iface.Name != "lo" {
			lines = append(lines,
				"ip route flush dev "+iface.Name+" || exit $?",
				"ip -6 route flush dev "+iface.Name+" || exit $?")
		}
		commands = append(commands, strings.Join(lines, "\n"))
	}
	// `tun6` is the renderer's reference-only 6in4 tunnel. A student's
	// captured tunnel is restored after platform mode is configured; an
	// untouched teaching start remains blank.
	if d.Kind == model.KindRouter && d.L2Gateway != "" {
		commands = append(commands, strings.Join([]string{
			"if ip link show tun6 >/dev/null 2>&1; then",
			"  ip -6 route flush dev tun6 || exit $?",
			"  ip tunnel del tun6 || exit $?",
			"fi",
		}, "\n"))
	}
	return commands
}

func (e *Engine) restartPlatformRouting(ctx context.Context, d *model.Device) error {
	provider, err := nos.Resolve(d)
	if err != nil {
		return fmt.Errorf("resolve routing provider for %s: %w", d.ID, err)
	}
	// BIRD's renderer invokes birdProvider.Apply, which replaces/reloads BIRD
	// with the platform file. It has no FRR init script and must never be sent
	// an FRR lifecycle command during a mode transition.
	if provider.Name() != model.DefaultNOS {
		return nil
	}
	container := d.Container
	if e.usesFRRControl(d) {
		container = FRRControlContainer(d)
	}
	result, err := e.Runtime.Exec(ctx, container, runtime.ExecCmd{Cmd: []string{
		"sh", "-c", "/usr/lib/frr/frrinit.sh restart",
	}})
	if err != nil {
		return fmt.Errorf("restart platform routing on %s: %w", d.ID, err)
	}
	if err := result.Err(); err != nil {
		return fmt.Errorf("restart platform routing on %s: %w", d.ID, err)
	}
	return nil
}

// configurationMarker records the content hash of the platform files and
// commands that have been applied to a container. It contains no configuration
// itself, so it cannot expose a reference solution to a student shell.
const configurationMarker = "/etc/twinet/config-hash"

// ConfigHash is a deterministic digest of rendered platform files and
// daemon-affecting commands. It intentionally excludes student-owned state:
// a student's edit must not be turned into a platform mutation on redeploy.
func ConfigHash(files map[string]FileSpec, cmds []Command) string {
	h := sha256.New()
	write := func(s string) {
		fmt.Fprintf(h, "%d:", len(s))
		_, _ = h.Write([]byte(s))
	}
	for _, path := range sortedKeys(files) {
		f := files[path]
		write("file")
		write(path)
		write(strconv.FormatInt(f.Mode, 10))
		fmt.Fprintf(h, "%d:", len(f.Content))
		_, _ = h.Write(f.Content)
	}
	for _, c := range cmds {
		write("command")
		if c.IgnoreError {
			write("ignore-error")
		} else {
			write("required")
		}
		if c.FRRControl {
			write("frr-control")
		} else {
			write("device")
		}
		for _, arg := range c.Args {
			write(arg)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (e *Engine) configurationCurrent(ctx context.Context, d *model.Device,
	files map[string]FileSpec, want string) bool {

	res, err := e.Runtime.Exec(ctx, d.Container, runtime.ExecCmd{
		Cmd: []string{"sh", "-c", "cat " + configurationMarker + " 2>/dev/null"},
	})
	if err != nil || res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != want {
		return false
	}
	if e.usesFRRControl(d) {
		sidecar, err := e.Runtime.Exec(ctx, FRRControlContainer(d), runtime.ExecCmd{
			Cmd: []string{"sh", "-c", "pidof zebra >/dev/null 2>&1"},
		})
		if err != nil || sidecar.ExitCode != 0 {
			return false
		}
	}
	for _, path := range sortedKeys(files) {
		// This path is controlled by the student once it has content. Do not
		// turn a comparison into an excuse to load or overwrite it.
		if studentOwnedPaths[path] && hasStudentConfig(d) && !e.authoritativeDevice(d) && !e.shouldForceStudentReset(d) {
			continue
		}
		if !e.fileContentMatches(ctx, d, path, files[path].Content) {
			return false
		}
	}
	return true
}

func (e *Engine) fileContentMatches(ctx context.Context, d *model.Device, path string, want []byte) bool {
	got, err := e.Runtime.CopyFrom(ctx, d.Container, path)
	if err != nil {
		// A missing or unreadable platform file is observed as drift. CopyTo
		// will provide the authoritative error if it cannot repair it.
		return false
	}
	return bytes.Equal(got, want)
}

func (e *Engine) writeConfigurationMarker(ctx context.Context, d *model.Device, hash string) error {
	res, err := e.Runtime.Exec(ctx, d.Container, runtime.ExecCmd{Cmd: []string{
		"sh", "-c", "umask 077; mkdir -p /etc/twinet && printf '%s\\n' " + hash +
			" > " + configurationMarker,
	}})
	if err != nil {
		return fmt.Errorf("record applied configuration for %s: %w", d.ID, err)
	}
	if err := res.Err(); err != nil {
		return fmt.Errorf("record applied configuration for %s: %w", d.ID, err)
	}
	return nil
}

// studentOwnedPaths are the files a student's own work can end up in. Only
// these are protected: everything else is the platform's and must converge.
var studentOwnedPaths = map[string]bool{
	"/etc/frr/frr.conf": true,
}

// holdsStudentWork reports whether a file already in the container is work the
// platform did not write and must not overwrite.
func (e *Engine) holdsStudentWork(ctx context.Context, d *model.Device, path string) (bool, error) {
	if !studentOwnedPaths[path] || !hasStudentConfig(d) {
		return false, nil
	}
	// Solve mode exists precisely to install the reference solution over
	// whatever is there. Preserving in that mode would make the golden answer
	// silently not apply, which is worse than the loss this guard prevents:
	// the grading oracle would be wrong and nothing would say so.
	if e.authoritativeDevice(d) || e.shouldForceStudentReset(d) {
		return false, nil
	}
	res, err := e.Runtime.Exec(ctx, d.Container, runtime.ExecCmd{
		Cmd: []string{"sh", "-c", "test -s " + path + " && echo yes || echo no"}})
	if err != nil {
		// A container that cannot be asked is assumed to hold work. Refusing
		// to overwrite is recoverable; overwriting is not, and the loss would
		// not surface until the container was next restarted.
		//
		// The error is deliberately not propagated: failing the deployment
		// here would turn a transient probe failure into an outage, when the
		// safe interpretation is available and costs nothing.
		return true, nil //nolint:nilerr // the safe answer, explained above
	}
	return strings.TrimSpace(res.Stdout) == "yes", nil
}

// hasStudentConfig reports whether any part of a device is the student's to
// configure.
func hasStudentConfig(d *model.Device) bool {
	for _, i := range d.Ifaces {
		if i.Owner == model.OwnerStudent {
			return true
		}
	}
	return false
}

// Destroy removes every container belonging to a lab on this node. It works
// from labels alone, so it can clean up a deployment whose manifest is gone.
func (e *Engine) Destroy(ctx context.Context, lab string) error {
	cs, err := e.Runtime.List(ctx, runtime.Filter{
		All:    true,
		Labels: map[string]string{LabelLab: lab},
	})
	if err != nil {
		return err
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
	var problems []string
	var ctxErr error
	// Podman (correctly) refuses to remove a network-namespace parent while
	// the private FRR control sidecar still joins it. Docker happened to
	// remove dependent containers under force, which hid the ordering bug.
	// Remove all internal dependants first, then retain bounded parallelism
	// among independent topology containers.
	for _, group := range removalGroups(cs) {
		started, errs, groupCtxErr := e.runBounded(ctx, len(group), func(i int) error {
			return e.limited(ctx, []limiter.Kind{limiter.Lifecycle}, func() error {
				return e.Runtime.Remove(ctx, group[i].Name, true)
			})
		})
		if ctxErr == nil {
			ctxErr = groupCtxErr
		}
		for i, c := range group {
			if !started[i] {
				continue
			}
			if err := errs[i]; err != nil {
				problems = append(problems, fmt.Sprintf("remove %s: %v", c.Name, err))
			}
		}
		if groupCtxErr != nil {
			break
		}
	}
	if ctxErr == nil {
		if err := e.limited(ctx, []limiter.Kind{limiter.Netlink}, func() error {
			_, removeErr := e.removeEmptyMultiplexOverlays(lab)
			return removeErr
		}); err != nil {
			problems = append(problems, fmt.Sprintf("remove empty multiplex overlays: %v", err))
		}
	}
	if len(problems) == 0 && ctxErr == nil {
		if err := os.RemoveAll(filepath.Join(e.frrControlRoot(), lab)); err != nil {
			problems = append(problems, fmt.Sprintf("remove FRR control state: %v", err))
		}
		if err := os.RemoveAll(filepath.Join(e.writableRoot(), lab)); err != nil {
			problems = append(problems, fmt.Sprintf("remove writable platform state: %v", err))
		}
	}
	return deterministicError(ctxErr, problems)
}

func (e *Engine) removeEmptyMultiplexOverlays(lab string) ([]string, error) {
	if e.removeEmptyMultiplex != nil {
		return e.removeEmptyMultiplex(lab)
	}
	return netx.RemoveEmptyMultiplexOverlays(lab)
}

func removalGroups(containers []runtime.Container) [][]runtime.Container {
	internal := make([]runtime.Container, 0, len(containers))
	ordinary := make([]runtime.Container, 0, len(containers))
	for _, container := range containers {
		if container.Labels[LabelInternal] == "true" || container.Labels[LabelFRRControl] == "true" {
			internal = append(internal, container)
		} else {
			ordinary = append(ordinary, container)
		}
	}
	var groups [][]runtime.Container
	if len(internal) > 0 {
		groups = append(groups, internal)
	}
	if len(ordinary) > 0 {
		groups = append(groups, ordinary)
	}
	return groups
}

// DestroyOverlays removes host-side veths and VNI bindings for the given
// links, deleting a shared bridge/VXLAN pair only after its final VNI is gone.
func (e *Engine) DestroyOverlays(vnis []uint32) error {
	return e.DestroyOverlaysContext(context.Background(), vnis)
}

// DestroyOverlaysContext removes overlays in bounded parallel while retaining
// deterministic errors. A VNI is deduplicated before fan-out so two workers
// never race to remove the same multiplex binding.
func (e *Engine) DestroyOverlaysContext(ctx context.Context, vnis []uint32) error {
	seen := map[uint32]bool{}
	unique := make([]uint32, 0, len(vnis))
	for _, vni := range vnis {
		if !seen[vni] {
			seen[vni] = true
			unique = append(unique, vni)
		}
	}
	sort.Slice(unique, func(i, j int) bool { return unique[i] < unique[j] })
	started, errs, ctxErr := e.runBounded(ctx, len(unique), func(i int) error {
		vni := unique[i]
		return e.limited(ctx, []limiter.Kind{limiter.Netlink}, func() error {
			var problems []string
			if err := netx.DeleteHostLink(hostSideName(vni)); err != nil {
				problems = append(problems, err.Error())
			}
			if err := netx.RemoveOverlay(vni); err != nil {
				problems = append(problems, err.Error())
			}
			return deterministicError(nil, problems)
		})
	})
	var problems []string
	for i, vni := range unique {
		if !started[i] || errs[i] == nil {
			continue
		}
		problems = append(problems, fmt.Sprintf("remove overlay %d: %v", vni, errs[i]))
	}
	return deterministicError(ctxErr, problems)
}

// mplsLabelHeadroom is the number of bytes reserved on a label-switching
// interface. Four bytes per label, and three labels is enough for a transport
// label, a VPN label and one more for a future fast-reroute or entropy label
// without having to revisit this.
const mplsLabelHeadroom = 12

func linkMTU(l *model.Link) int {
	if l.Props.MTU != nil {
		return *l.Props.MTU
	}
	return 1500
}

func scopeOf(d *model.Device) string {
	if d.ASN > 0 {
		return "as" + strconv.Itoa(d.ASN)
	}
	return "services"
}

func linkScope(l *model.Link) string {
	// An inter-AS link belongs to no single AS: attributing it to one would
	// mark an innocent group degraded when its neighbour is broken.
	if l.InterAS {
		return "peering"
	}
	return scopeOf(l.A.Device)
}

func shortHostname(d *model.Device) string {
	h := d.Hostname
	if h == "" {
		h = strings.ToLower(d.Name)
	}
	// DNS labels disallow underscores, and some Docker versions reject them.
	return strings.ReplaceAll(h, "_", "-")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// RewireDevice rebuilds every link that terminates on one device.
//
// A container whose network namespace was emptied -- by a restart, an
// out-of-memory kill, a host reboot -- is running and reachable and connected
// to nothing. The wiring itself is idempotent, so the repair is to run it
// again for that device's links alone, rather than redeploying the lab and
// disturbing everyone else's work to fix one node.
func (e *Engine) RewireDevice(ctx context.Context, top *model.Topology, d *model.Device) error {
	var failed []string
	for _, l := range top.Links {
		if l.A == nil || l.B == nil || l.A.Device == nil || l.B.Device == nil {
			continue
		}
		if l.A.Device.ID != d.ID && l.B.Device.ID != d.ID {
			continue
		}
		if l.A.Device.Node != e.Node && l.B.Device.Node != e.Node {
			continue
		}
		if err := e.limited(ctx, []limiter.Kind{limiter.Netlink}, func() error {
			return e.wire(ctx, top, l)
		}); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", l.ID, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("rewiring %s: %s", d.ID, strings.Join(failed, "; "))
	}
	final, err := e.finalRuntimeSpecs(top, d)
	if err != nil {
		return err
	}
	if err := e.ensureFRRControl(ctx, top, final); err != nil {
		return err
	}
	// Interfaces are only half the device. The daemons were started against a
	// namespace that no longer exists, so they are pointed at the new one.
	//
	// Rewire is an explicit repair boundary, not an ordinary no-change
	// deploy. The observed configuration marker can still match after a host
	// lost its address/default route, so configure() would incorrectly skip
	// the idempotent `ip addr replace` and `ip route replace` commands. Apply
	// the pre-rendered desired commands directly while retaining the
	// student-owned-file protection in configureDesired.
	return e.limited(ctx, []limiter.Kind{limiter.ExecProbe}, func() error {
		state, err := e.renderDesired(d)
		if err != nil {
			return err
		}
		return e.configureDesired(ctx, d, state)
	})
}
