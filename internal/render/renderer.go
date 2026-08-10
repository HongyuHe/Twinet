package render

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/runtime"
)

// Mode selects how much configuration is applied.
type Mode string

const (
	// ModePlatform applies only what Twinet owns, leaving the student's work
	// undone. This is the normal deployment mode.
	ModePlatform Mode = "platform"
	// ModeSolve additionally applies the reference solution, used to smoke-test
	// the platform end to end and to build grading baselines.
	ModeSolve Mode = "solve"
)

// Renderer implements deploy.Renderer for the built-in device kinds.
type Renderer struct {
	Top  *model.Topology
	Mode Mode
}

// New creates a renderer.
func New(top *model.Topology, mode Mode) *Renderer {
	if mode == "" {
		mode = ModePlatform
	}
	return &Renderer{Top: top, Mode: mode}
}

// Files returns the files to write into a device before configuring it.
func (r *Renderer) Files(d *model.Device) (map[string]deploy.FileSpec, error) {
	out := map[string]deploy.FileSpec{}
	switch d.Kind {
	case model.KindRouter:
		cfg, err := Router(r.Top, d)
		if err != nil {
			return nil, err
		}
		body := cfg.Platform
		if r.Mode == ModeSolve {
			body = cfg.Platform + cfg.Expected
		}
		out["/etc/frr/daemons"] = deploy.FileSpec{Content: []byte(FRRDaemons), Mode: 0o640}
		out["/etc/frr/frr.conf"] = deploy.FileSpec{Content: []byte(body), Mode: 0o640}
		// The reference solution always ships alongside, so a TA can diff a
		// student's configuration against it without re-deriving anything.
		out["/etc/twinet/reference.conf"] = deploy.FileSpec{
			Content: []byte(cfg.Platform + cfg.Expected), Mode: 0o600}
	case model.KindSwitch:
		out["/etc/twinet/vlans"] = deploy.FileSpec{Content: []byte(vlanList(d)), Mode: 0o644}
	}
	out["/etc/twinet/device.json"] = deploy.FileSpec{Content: deviceFacts(r.Top, d), Mode: 0o644}
	return out, nil
}

// Commands returns the commands that bring a device into service.
func (r *Renderer) Commands(d *model.Device) ([]deploy.Command, error) {
	switch d.Kind {
	case model.KindRouter:
		return r.routerCommands(d), nil
	case model.KindSwitch:
		return r.switchCommands(d), nil
	case model.KindHost, model.KindService:
		return r.hostCommands(d), nil
	}
	return nil, nil
}

func (r *Renderer) routerCommands(d *model.Device) []deploy.Command {
	var cmds []deploy.Command

	// VLAN sub-interfaces on an L2 gateway must exist before the student can
	// configure them: the assignment tells students they will see ATL-L2.10
	// and ATL-L2.20 in `show interface brief`, so the platform creates the
	// interfaces and the student supplies the addresses.
	for _, i := range d.Ifaces {
		if i.Role != model.RoleL2SubIface || i.Parent == "" {
			continue
		}
		cmds = append(cmds, deploy.Command{
			Args: []string{"sh", "-c", fmt.Sprintf(
				"ip link show %s >/dev/null 2>&1 || ip link add link %s name %s type vlan id %d; ip link set %s up",
				i.Name, i.Parent, i.Name, i.VLAN, i.Name)},
			Describe: "create VLAN sub-interface " + i.Name,
		})
	}

	cmds = append(cmds, []deploy.Command{
		{Args: []string{"sh", "-c", "chown -R frr:frr /etc/frr 2>/dev/null || true"},
			Describe: "fix FRR file ownership", IgnoreError: true},
		{Args: []string{"sh", "-c", "/usr/lib/frr/frrinit.sh start || /etc/init.d/frr start"},
			Describe: "start FRR"},
	}...)
	// Loopback addresses are configured on the interface rather than through
	// FRR when the platform owns them, so the address exists even if FRR is
	// still starting.
	if lo, ok := d.IfaceByName("lo"); ok && lo.Owner == model.OwnerPlatform && lo.Addr4 != "" {
		cmds = append([]deploy.Command{{
			Args:     []string{"sh", "-c", fmt.Sprintf("ip addr replace %s dev lo && ip link set lo up", lo.Addr4)},
			Describe: "configure loopback",
		}}, cmds...)
	}
	return cmds
}

// switchCommands builds the OVS bridge and its ports.
//
// The bridge and its ports are platform-owned: they must exist before a student
// can do anything. VLAN tags are *not* set here, because assigning ports to
// VLANs and configuring trunks is the exercise. That split is exactly what the
// provisioning contract in the model expresses.
func (r *Renderer) switchCommands(d *model.Device) []deploy.Command {
	br := "br0"
	cmds := []deploy.Command{
		{Args: []string{"sh", "-c", "ovs-vsctl --may-exist add-br " + br},
			Describe: "create the OVS bridge"},
		{Args: []string{"sh", "-c", "ip link set " + br + " up"},
			Describe: "bring the bridge up"},
	}
	for _, i := range d.Ifaces {
		if i.Link == nil {
			continue
		}
		cmds = append(cmds, deploy.Command{
			Args:     []string{"sh", "-c", fmt.Sprintf("ovs-vsctl --may-exist add-port %s %s", br, i.Name)},
			Describe: "attach port " + i.Name,
		})
	}
	if r.Mode == ModeSolve {
		cmds = append(cmds, r.switchSolution(d, br)...)
	}
	return cmds
}

// switchSolution applies the VLAN assignment a correct student would make.
func (r *Renderer) switchSolution(d *model.Device, br string) []deploy.Command {
	var cmds []deploy.Command
	for _, i := range d.Ifaces {
		if i.Link == nil {
			continue
		}
		switch {
		case i.Trunk:
			trunks := make([]string, 0, len(d.VLANs))
			for _, v := range d.VLANs {
				trunks = append(trunks, fmt.Sprint(v))
			}
			cmds = append(cmds, deploy.Command{
				Args: []string{"sh", "-c", fmt.Sprintf("ovs-vsctl set port %s vlan_mode=trunk trunks=%s",
					i.Name, strings.Join(trunks, ","))},
				Describe: "configure trunk " + i.Name,
			})
		case i.VLAN > 0:
			cmds = append(cmds, deploy.Command{
				Args:     []string{"sh", "-c", fmt.Sprintf("ovs-vsctl set port %s tag=%d", i.Name, i.VLAN)},
				Describe: fmt.Sprintf("put %s in VLAN %d", i.Name, i.VLAN),
			})
		}
	}
	return cmds
}

// hostCommands configures a host's addresses and default route, but only for
// the parts the platform owns.
func (r *Renderer) hostCommands(d *model.Device) []deploy.Command {
	var cmds []deploy.Command
	apply := func(i *model.Iface) {
		if i.Addr4 != "" {
			cmds = append(cmds, deploy.Command{
				Args:     []string{"sh", "-c", fmt.Sprintf("ip addr replace %s dev %s", i.Addr4, i.Name)},
				Describe: "address " + i.Name,
			})
		}
		if i.Addr6 != "" {
			cmds = append(cmds, deploy.Command{
				Args:     []string{"sh", "-c", fmt.Sprintf("ip -6 addr replace %s dev %s", i.Addr6, i.Name)},
				Describe: "address " + i.Name + " (v6)",
			})
		}
	}
	for _, i := range d.Ifaces {
		if i.Owner == model.OwnerPlatform || r.Mode == ModeSolve {
			apply(i)
		}
	}
	// A host's default route points at its attached router.
	if r.Mode == ModeSolve || d.Kind == model.KindService {
		for _, i := range d.Ifaces {
			if i.Peer == nil || i.Peer.Addr4 == "" {
				continue
			}
			if i.Role != model.RoleHostLink && i.Role != model.RoleService {
				continue
			}
			cmds = append(cmds, deploy.Command{
				Args: []string{"sh", "-c", fmt.Sprintf("ip route replace default via %s dev %s || true",
					addrOf(i.Peer.Addr4), i.Name)},
				Describe:    "default route via " + i.Peer.Device.Name,
				IgnoreError: true,
			})
			break
		}
	}
	return cmds
}

// Ready returns a readiness predicate for a device.
//
// This is what replaces the legacy platform's two hardcoded sixty-second
// sleeps. A router is ready when its routing daemons answer, not when a clock
// says so, and the difference at class scale is minutes per deployment.
func (r *Renderer) Ready(d *model.Device, rt runtime.Runtime) *plan.Waiter {
	switch d.Kind {
	case model.KindRouter:
		container := d.Container
		return &plan.Waiter{
			Describe:  "FRR on " + d.ID + " to answer",
			Interval:  200 * time.Millisecond,
			Timeout:   90 * time.Second,
			StableFor: 2,
			Check: func(ctx context.Context) (bool, error) {
				res, err := rt.Exec(ctx, container, runtime.ExecCmd{
					Cmd: []string{"vtysh", "-c", "show version"}})
				if err != nil {
					return false, err
				}
				if res.ExitCode != 0 {
					return false, fmt.Errorf("vtysh exited %d: %s", res.ExitCode, firstLine(res.Stderr))
				}
				return true, nil
			},
		}
	case model.KindSwitch:
		container := d.Container
		return &plan.Waiter{
			Describe:  "Open vSwitch on " + d.ID + " to answer",
			Interval:  200 * time.Millisecond,
			Timeout:   90 * time.Second,
			StableFor: 2,
			Check: func(ctx context.Context) (bool, error) {
				res, err := rt.Exec(ctx, container, runtime.ExecCmd{
					Cmd: []string{"ovs-vsctl", "show"}})
				if err != nil {
					return false, err
				}
				if res.ExitCode != 0 {
					return false, fmt.Errorf("ovs-vsctl exited %d: %s", res.ExitCode, firstLine(res.Stderr))
				}
				return true, nil
			},
		}
	}
	return nil
}

func vlanList(d *model.Device) string {
	parts := make([]string, 0, len(d.VLANs))
	for _, v := range d.VLANs {
		parts = append(parts, fmt.Sprint(v))
	}
	return strings.Join(parts, "\n") + "\n"
}

// deviceFacts writes a machine-readable description of the device into the
// container, so tooling inside it (the student shell, save/restore, the
// grader's probes) never has to guess or re-derive the topology.
func deviceFacts(top *model.Topology, d *model.Device) []byte {
	var b strings.Builder
	b.WriteString("{\n")
	fmt.Fprintf(&b, "  \"lab\": %q,\n", top.Name)
	fmt.Fprintf(&b, "  \"id\": %q,\n", d.ID)
	fmt.Fprintf(&b, "  \"name\": %q,\n", d.Name)
	fmt.Fprintf(&b, "  \"kind\": %q,\n", d.Kind)
	fmt.Fprintf(&b, "  \"as\": %d,\n", d.ASN)
	fmt.Fprintf(&b, "  \"router_id\": %d,\n", d.RouterID)
	fmt.Fprintf(&b, "  \"owner\": %q,\n", d.Owner)
	b.WriteString("  \"interfaces\": [\n")
	for i, ifc := range d.Ifaces {
		peer := ""
		if ifc.Peer != nil {
			peer = ifc.Peer.Device.ID + ":" + ifc.Peer.Name
		}
		fmt.Fprintf(&b, "    {\"name\": %q, \"role\": %q, \"owner\": %q, \"addr4\": %q, \"addr6\": %q, \"vlan\": %d, \"peer\": %q}",
			ifc.Name, ifc.Role, ifc.Owner, ifc.Addr4, ifc.Addr6, ifc.VLAN, peer)
		if i < len(d.Ifaces)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  ]\n}\n")
	return []byte(b.String())
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// SortedDeviceNames is a small helper used by tests and tooling.
func SortedDeviceNames(ds []*model.Device) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.Name)
	}
	sort.Strings(out)
	return out
}
