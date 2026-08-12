// Package deploy turns an expanded topology into a plan and executes it.
//
// This is where the model meets the machine: containers are created from
// devices, links are realised as veths or VXLAN tunnels, configuration is
// rendered and pushed, and readiness is verified. Every step is idempotent, so
// deploying twice converges rather than duplicating or failing.
package deploy

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/HongyuHe/twinet/internal/alloc"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
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
	// LabelGen is the deployment generation, used to find objects that the
	// current topology no longer wants.
	LabelGen      = "twinet.generation"
	LabelRegion   = "twinet.region"
	LabelManaged  = "twinet.managed"
	LabelDeviceID = "twinet.device-id"
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

	// pendingRestore records devices whose captured configuration must be
	// replayed once their interfaces exist.
	pendingRestore sync.Map
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
}

// Build constructs the deployment plan for the devices placed on this node.
func (e *Engine) Build(top *model.Topology) (*plan.Plan, error) {
	p := plan.New()
	devices := top.DevicesOnNode(e.Node)
	if len(devices) == 0 {
		return p, nil
	}

	// One image pull per distinct image, shared by every device that needs it.
	images := map[string][]*model.Device{}
	for _, d := range devices {
		if d.Image == "" {
			return nil, fmt.Errorf("device %s has no image; set it under kinds.%s.image", d.ID, d.Kind)
		}
		images[d.Image] = append(images[d.Image], d)
	}
	imageStep := map[string]string{}
	for _, img := range sortedKeys(images) {
		id := "image:" + img
		imageStep[img] = id
		image := img
		p.Add(&plan.Step{
			ID: id, Stage: plan.StageImage, Describe: "pull " + image,
			Run: func(ctx context.Context) error {
				return e.Runtime.PullImage(ctx, image, e.pullPolicy())
			},
		})
	}

	// Create and start each container.
	for _, d := range devices {
		dev := d
		p.Add(&plan.Step{
			ID:       "create:" + dev.ID,
			Stage:    plan.StageCreate,
			Scope:    scopeOf(dev),
			Describe: "create " + dev.ID,
			Needs:    []string{imageStep[dev.Image]},
			Run: func(ctx context.Context) error {
				return e.ensureContainer(ctx, top, dev)
			},
		})
	}

	// Wire each link with at least one endpoint on this node.
	for _, l := range top.Links {
		link := l
		aHere := link.A.Device.Node == e.Node
		bHere := link.B.Device.Node == e.Node
		if !aHere && !bHere {
			continue
		}
		var needs []string
		if aHere {
			needs = append(needs, "create:"+link.A.Device.ID)
		}
		if bHere {
			needs = append(needs, "create:"+link.B.Device.ID)
		}
		p.Add(&plan.Step{
			ID:       "wire:" + link.ID,
			Stage:    plan.StageWire,
			Scope:    linkScope(link),
			Describe: "wire " + link.ID,
			Needs:    needs,
			Run: func(ctx context.Context) error {
				return e.wire(ctx, top, link)
			},
		})
	}

	// Configure devices once every link they own is up, so a daemon never sees
	// a half-wired interface list.
	for _, d := range devices {
		dev := d
		needs := []string{"create:" + dev.ID}
		for _, i := range dev.Ifaces {
			if i.Link != nil {
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
				if err := e.configure(ctx, dev); err != nil {
					return err
				}
				// Whatever the student had is replayed *after* the platform's
				// own configuration and after the interfaces exist, so it wins
				// over the defaults and lands on devices that are present.
				return e.replayPending(ctx, top, dev)
			},
		})
	}

	// Readiness.
	if e.Renderer != nil {
		for _, d := range devices {
			dev := d
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
				Needs:    []string{"configure:" + dev.ID},
				Run: func(ctx context.Context) error {
					return plan.Wait(ctx, waiter)
				},
			})
		}
	}

	return p, p.Validate()
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
func (e *Engine) ensureContainer(ctx context.Context, top *model.Topology, d *model.Device) error {
	cur, err := e.Runtime.Inspect(ctx, d.Container)
	if err != nil {
		return err
	}
	want := SpecHash(d)

	if cur.State != runtime.StateAbsent {
		// Only a change to *this* container's own specification justifies
		// replacing it. Anything else -- a neighbour's address, another AS's
		// link delay -- must leave it alone, because replacing it would throw
		// away whatever the student had configured inside.
		if cur.Labels[LabelSpec] == want {
			if cur.State.Joinable() {
				return nil
			}
			// The container exists but is stopped: start it and put back
			// whatever was captured before it went down.
			if err := e.Runtime.Start(ctx, d.Container); err != nil {
				return err
			}
			return e.restoreIfNeeded(ctx, top, d)
		}

		// It genuinely must be replaced. Capture first; if capture fails we
		// refuse rather than proceed, because the alternative is silent
		// destruction of a student's work.
		if err := e.captureBeforeReplace(ctx, top, d); err != nil {
			return err
		}
		if err := e.Runtime.Remove(ctx, d.Container, true); err != nil {
			return fmt.Errorf("replace container %s: %w", d.Container, err)
		}
	}

	spec := &runtime.Spec{
		Name:         d.Container,
		Image:        d.Image,
		Hostname:     shortHostname(d),
		Command:      d.Command,
		Env:          d.Env,
		Labels:       e.labels(top, d),
		Sysctls:      d.Sysctls,
		Capabilities: d.Capabilities,
		Privileged:   d.Privileged,
		CPUs:         d.CPUs,
		Memory:       d.Memory,
		PidsLimit:    d.Pids,
		Restart:      d.Restart,
		NetworkMode:  "none",
		Init:         true,
	}
	for _, b := range d.Binds {
		parts := strings.Split(b, ":")
		bind := runtime.Bind{Source: parts[0]}
		if len(parts) > 1 {
			bind.Target = parts[1]
		}
		if len(parts) > 2 && parts[2] == "ro" {
			bind.ReadOnly = true
		}
		spec.Binds = append(spec.Binds, bind)
	}

	if _, err := e.Runtime.Create(ctx, spec); err != nil {
		return err
	}
	if err := e.Runtime.Start(ctx, d.Container); err != nil {
		return err
	}
	return e.restoreIfNeeded(ctx, top, d)
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
	snaps, err := Capture(ctx, e.Runtime, d, top.Name, top.Hash)
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
	var removed []string
	for _, c := range cs {
		if want[c.Name] {
			continue
		}
		// Only remove what this node is responsible for, and only what the
		// topology genuinely no longer places here.
		if c.Labels[LabelNode] != "" && c.Labels[LabelNode] != e.Node && !elsewhere[c.Name] {
			continue
		}
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
		if err := e.captureOrphan(ctx, top, c); err != nil {
			return removed, fmt.Errorf(
				"refusing to remove %s: its configuration could not be captured (%w). "+
					"Destroy the lab explicitly if it is genuinely disposable", c.Name, err)
		}
		if err := e.Runtime.Remove(ctx, c.Name, true); err != nil {
			return removed, fmt.Errorf("remove orphan %s: %w", c.Name, err)
		}
		removed = append(removed, c.Name)
	}
	sort.Strings(removed)
	return removed, nil
}

// captureOrphan snapshots a container that is about to be removed.
//
// A container with no state store configured is removed without capture,
// because there is nowhere to put the snapshot and blocking every prune on a
// store nobody configured would make the platform unusable. That is a
// deliberate trade and it is recorded here rather than left implicit.
func (e *Engine) captureOrphan(ctx context.Context, top *model.Topology, c runtime.Container) error {
	if e.State == nil {
		return nil
	}
	// The device is gone from the topology, so its identity comes from the
	// labels the deployment stamped on it.
	id := c.Labels[LabelDevice]
	if id == "" {
		return nil
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
		return err
	}
	for _, snap := range snaps {
		if _, err := e.State.Put(snap); err != nil {
			return err
		}
	}
	return nil
}

// PruneOverlays removes VXLAN bridges and tunnels this node no longer needs.
func (e *Engine) PruneOverlays(top *model.Topology) ([]string, error) {
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
	var removed []string
	for _, vni := range live {
		if want[vni] {
			continue
		}
		if err := netx.DeleteHostLink(hostSideName(vni)); err != nil {
			return removed, err
		}
		if err := netx.RemoveOverlay(vni); err != nil {
			return removed, err
		}
		removed = append(removed, netx.VxlanName(vni))
	}
	sort.Strings(removed)
	return removed, nil
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
	fmt.Fprintf(h, "cpus=%v\nmem=%s\npids=%d\nrestart=%s\npriv=%v\n",
		d.CPUs, d.Memory, d.Pids, d.Restart, d.Privileged)
	fmt.Fprintf(h, "cmd=%s\ncaps=%s\nbinds=%s\n",
		strings.Join(d.Command, ","),
		strings.Join(sortedCopy(d.Capabilities), ","),
		strings.Join(sortedCopy(d.Binds), ","))
	for _, k := range sortedKeys(d.Env) {
		fmt.Fprintf(h, "env:%s=%s\n", k, d.Env[k])
	}
	for _, k := range sortedKeys(d.Sysctls) {
		fmt.Fprintf(h, "sysctl:%s=%s\n", k, d.Sysctls[k])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func (e *Engine) labels(top *model.Topology, d *model.Device) map[string]string {
	out := map[string]string{
		LabelManaged:  "true",
		LabelLab:      top.Name,
		LabelDevice:   d.Name,
		LabelDeviceID: d.ID,
		LabelKind:     string(d.Kind),
		LabelNode:     e.Node,
		LabelHash:     top.Hash,
		LabelSpec:     SpecHash(d),
	}
	if e.Generation != "" {
		out[LabelGen] = e.Generation
	}
	if d.ASN > 0 {
		out[LabelAS] = strconv.Itoa(d.ASN)
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

// wireCrossNode attaches this node's half of the link to a VXLAN tunnel.
//
// Each node runs this independently for its own side. Because the VNI is
// derived from the link identity, the two sides agree without coordination,
// which is what makes cluster deployment need no distributed allocation.
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
	mtu := linkMTU(l)
	bridge, err := netx.EnsureOverlay(netx.OverlaySpec{
		VNI:         l.VNI,
		LocalIP:     e.UnderlayIP,
		RemoteIP:    remoteIP,
		UnderlayDev: e.UnderlayDev,
		MTU:         mtu,
		Lab:         top.Name,
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
	return netx.AttachToBridgeByName(hostSide, bridge)
}

// hostSideName derives the root-namespace veth name for a cross-node link.
// It must fit IFNAMSIZ-1 and be unique per VNI, which it is because the VNI is.
func hostSideName(vni uint32) string { return fmt.Sprintf("twp%d", vni) }

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
	} else if e.Authoritative {
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
	if !l.Props.Empty() {
		ep.Shaping = &netx.Shaping{
			Bandwidth: l.Props.Bandwidth,
			Delay:     l.Props.Delay,
			Queue:     l.Props.Queue,
			Loss:      l.Props.Loss,
		}
	}
	return ep
}

// configure writes the device's files and runs its post-wiring commands.
func (e *Engine) configure(ctx context.Context, d *model.Device) error {
	if e.Renderer == nil {
		return nil
	}
	files, err := e.Renderer.Files(d)
	if err != nil {
		return fmt.Errorf("render files for %s: %w", d.ID, err)
	}
	for _, path := range sortedKeys(files) {
		f := files[path]
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
		if err := e.Runtime.CopyTo(ctx, d.Container, path, f.Mode, f.Content); err != nil {
			return fmt.Errorf("write %s to %s: %w", path, d.ID, err)
		}
	}
	cmds, err := e.Renderer.Commands(d)
	if err != nil {
		return fmt.Errorf("render commands for %s: %w", d.ID, err)
	}
	for _, c := range cmds {
		res, err := e.Runtime.Exec(ctx, d.Container, runtime.ExecCmd{Cmd: c.Args})
		if err != nil {
			return fmt.Errorf("%s: %s: %w", d.ID, c.Describe, err)
		}
		if err := res.Err(); err != nil && !c.IgnoreError {
			return fmt.Errorf("%s: %s: %w", d.ID, c.Describe, err)
		}
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
	if e.Authoritative {
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
	var errs []string
	for _, c := range cs {
		if err := e.Runtime.Remove(ctx, c.Name, true); err != nil {
			errs = append(errs, fmt.Sprintf("remove %s: %v", c.Name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// DestroyOverlays removes the bridges, tunnels and host-side veths for the
// given VNIs.
func (e *Engine) DestroyOverlays(vnis []uint32) error {
	var errs []string
	for _, v := range vnis {
		if err := netx.DeleteHostLink(hostSideName(v)); err != nil {
			errs = append(errs, err.Error())
		}
		if err := netx.RemoveOverlay(v); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
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
		if err := e.wire(ctx, top, l); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", l.ID, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("rewiring %s: %s", d.ID, strings.Join(failed, "; "))
	}
	// Interfaces are only half the device. The daemons were started against a
	// namespace that no longer exists, so they are pointed at the new one.
	return e.configure(ctx, d)
}
