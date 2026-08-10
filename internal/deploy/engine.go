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

	"github.com/HongyuHe/twinet/internal/alloc"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/runtime"
)

// Label keys stamped onto every container. These are the observed state: there
// is no database, so "what is deployed" is answered by querying labels.
const (
	LabelLab      = "twinet.lab"
	LabelAS       = "twinet.as"
	LabelDevice   = "twinet.device"
	LabelKind     = "twinet.kind"
	LabelRole     = "twinet.role"
	LabelOwner    = "twinet.owner"
	LabelNode     = "twinet.node"
	LabelHash     = "twinet.topology-hash"
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
	// UnderlayIP is this node's VTEP source address.
	UnderlayIP string
	// UnderlayDev optionally pins the tunnel source interface.
	UnderlayDev string
	// PeerUnderlay maps node name to VTEP address, for cross-node links.
	PeerUnderlay map[string]string
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
				return e.configure(ctx, dev)
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
	if cur.State != runtime.StateAbsent {
		if cur.Labels[LabelHash] == top.Hash {
			if cur.State.Joinable() {
				return nil
			}
			return e.Runtime.Start(ctx, d.Container)
		}
		if err := e.Runtime.Remove(ctx, d.Container, true); err != nil {
			return fmt.Errorf("replace stale container %s: %w", d.Container, err)
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
	return e.Runtime.Start(ctx, d.Container)
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
	// Addresses are applied only for interfaces the platform owns. Those the
	// student owns are left bare on purpose: configuring them is the exercise.
	if i.Owner == model.OwnerPlatform {
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
