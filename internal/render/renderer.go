package render

import (
	"context"
	"fmt"
	"net/netip"
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
	// Ungraded, when non-zero, is the one AS that keeps the platform's own
	// mode while every other AS is rendered with the reference solution.
	//
	// This is what a grading harness needs. The surrounding internet must be
	// correct, or the submission is marked against neighbours that never
	// brought a session up; the AS under test must be left exactly as the
	// student submitted it, or the reference solution would be marked instead
	// of their work.
	Ungraded int
}

// New creates a renderer.
// NewHarness renders the reference solution everywhere except one AS, which is
// left to the configuration its owner submitted.
func NewHarness(top *model.Topology, ungraded int) *Renderer {
	return &Renderer{Top: top, Mode: ModeSolve, Ungraded: ungraded}
}

// modeFor returns the rendering mode that applies to one device.
func (r *Renderer) modeFor(d *model.Device) Mode {
	if r.Ungraded != 0 && d != nil && d.ASN == r.Ungraded {
		return ModePlatform
	}
	return r.Mode
}

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
		if r.modeFor(d) == ModeSolve {
			body = cfg.Platform + cfg.Expected
		}
		out["/etc/frr/daemons"] = deploy.FileSpec{Content: []byte(FRRDaemons), Mode: 0o640}
		out["/etc/frr/frr.conf"] = deploy.FileSpec{Content: []byte(body), Mode: 0o640}
		// The reference solution is deliberately NOT written here.
		//
		// It used to be, as /etc/twinet/reference.conf mode 0600, so that a TA
		// could diff against it in place. But a student has a root shell in
		// their own router -- that is the whole point of the exercise -- so
		// 0600 protects nothing. The complete expected OSPF, iBGP, eBGP, RPKI
		// and route-map configuration was sitting inside the container of the
		// person being asked to derive it, on every ordinary deployment, not
		// just under --solve. `cp /etc/twinet/reference.conf /etc/frr/frr.conf`
		// was full marks.
		//
		// Nothing read the file; it was pure liability. A TA who wants the
		// reference gets it from the controller with `twinet inspect --config`,
		// which renders it on demand from the same code path.
	case model.KindSwitch:
		out["/etc/twinet/vlans"] = deploy.FileSpec{Content: []byte(vlanList(d)), Mode: 0o644}
	case model.KindService:
		for path, spec := range r.serviceFiles(d) {
			out[path] = spec
		}
	}
	out["/etc/twinet/device.json"] = deploy.FileSpec{Content: deviceFacts(r.Top, d), Mode: 0o644}
	return out, nil
}

// Commands returns the commands that bring a device into service.
func (r *Renderer) Commands(d *model.Device) ([]deploy.Command, error) {
	switch d.Kind {
	case model.KindRouter:
		return append(r.routerCommands(d), r.rpkiReadyCommands(d)...), nil
	case model.KindSwitch:
		return r.switchCommands(d), nil
	case model.KindHost:
		return append(r.hostCommands(d), r.resolverCommands(d)...), nil
	case model.KindService:
		cmds := append(r.hostCommands(d), r.serviceRoutes(d)...)
		return append(cmds, r.serviceCommands(d)...), nil
	}
	return nil, nil
}

func (r *Renderer) routerCommands(d *model.Device) []deploy.Command {
	cmds := r.resolverCommands(d)

	// Earlier versions wrote the reference solution into every router. Deploy
	// converges rather than recreating, so simply not writing the file leaves
	// it in place on every lab already running -- the classes that are exposed
	// are exactly the ones that have been up longest. Remove it explicitly.
	cmds = append(cmds, deploy.Command{
		Describe: "remove any reference solution left by an earlier version",
		Args:     []string{"sh", "-c", "rm -f /etc/twinet/reference.conf"},
	})

	// Solve mode installs the reference answer, so the running daemon must end
	// up matching the file. Writing frr.conf does not do that: FRR keeps
	// whatever it already had, so a neighbour removed from the manifest lives
	// on in the running configuration, pointed at an address that no longer
	// exists. The session sits Active forever on a lab whose manifest and
	// configuration files are both correct -- which is exactly how it was
	// found, in a grading run that could not be explained.
	//
	// Only solve mode does this. Restarting FRR under a student would discard
	// whatever they were part-way through configuring.
	if r.modeFor(d) == ModeSolve {
		cmds = append(cmds, deploy.Command{
			Describe: "restart frr onto the reference configuration",
			Args: []string{"sh", "-c", strings.Join([]string{
				// watchfrr outlives a plain stop and holds the pid lock, after
				// which the daemons can never start again.
				"for p in $(ps -ef | awk '/watchfrr/ && !/awk/ {print $1}'); do kill $p 2>/dev/null || true; done",
				"/usr/lib/frr/frrinit.sh stop >/dev/null 2>&1 || true",
				"rm -f /var/run/frr/*.pid /var/run/frr/*.vty 2>/dev/null || true",
				"/usr/lib/frr/frrinit.sh start",
			}, "\n")},
		})
	}

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

	if r.modeFor(d) == ModeSolve {
		cmds = append(cmds, r.tunnelSolution(d)...)
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
// rpkiReadyCommands makes a router's validator session self-healing.
//
// FRR opens the RTR session when the cache is configured and does not reliably
// retry one that was unreachable at that moment. The validator lives behind
// routing the deployment is still installing, so whether a router ends up
// validating depends on which scope finished first -- and a router that lost
// the race stays silently disconnected, with every route becoming not-found
// and origin validation quietly doing nothing. Only the router the validator
// is cabled to would work, which is exactly the arrangement that survives a
// spot check.
//
// Resetting is cheap and idempotent, so it is done unconditionally rather than
// only when the session is down: a conditional would make the outcome depend on
// when the check happened to run.
func (r *Renderer) rpkiReadyCommands(d *model.Device) []deploy.Command {
	if d.Kind != model.KindRouter || d.ASN == 0 {
		return nil
	}
	// Only routers that actually carry the cache. A router with no external
	// sessions has nothing to validate and is given no cache, so waiting for a
	// session on it means every deployment pays a fixed delay per interior
	// router and then warns about a validator that was never configured.
	if !hasRPKICache(r.Top, d) {
		return nil
	}
	return []deploy.Command{{
		Describe: "connect to the origin validator",
		Args: []string{"sh", "-c", strings.Join([]string{
			"for i in 1 2 3 4 5 6 7 8; do",
			"  vtysh -c 'show rpki cache-connection' 2>/dev/null | grep -q Connected && exit 0",
			"  vtysh -c 'rpki reset' >/dev/null 2>&1 || true",
			"  sleep 4",
			"done",
			// Not a hard failure: a lab without a working validator is still a
			// usable lab, and refusing to deploy over it would turn a degraded
			// service into an outage. The grading check for origin validation
			// is what makes the degradation visible where it matters.
			"echo 'the origin validator did not answer; routes will be treated as not-found' >&2",
		}, "\n")},
		IgnoreError: true,
	}}
}

func (r *Renderer) switchCommands(d *model.Device) []deploy.Command {
	br := "br0"
	cmds := []deploy.Command{
		// Wait for the database before touching it. ovs-vsctl against an
		// ovsdb that has not finished starting fails, and the deployment
		// carries on: the container is up, its ports exist as interfaces, and
		// there is no bridge -- so an entire exchange fabric forwards nothing
		// while every router attached to it reports its session merely Active.
		// That is a very expensive silence to debug from the router's end.
		{Args: []string{"sh", "-c",
			"for i in $(seq 1 30); do ovs-vsctl --timeout=2 show >/dev/null 2>&1 && exit 0; sleep 1; done; " +
				"echo 'the switch database did not start' >&2; exit 1"},
			Describe: "wait for the switch database"},
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
	if r.modeFor(d) == ModeSolve {
		cmds = append(cmds, r.switchSolution(d, br)...)
	}
	// Prove the bridge exists and carries every port it was given. Without
	// this the deployment reports success on a switch that silently forwards
	// nothing, which presents at the routers as sessions that never establish.
	var want []string
	for _, i := range d.Ifaces {
		if i.Link != nil {
			want = append(want, i.Name)
		}
	}
	if len(want) > 0 {
		cmds = append(cmds, deploy.Command{
			Describe: "check the bridge carries every port",
			Args: []string{"sh", "-c", fmt.Sprintf(
				"have=$(ovs-vsctl list-ports %s 2>/dev/null | wc -l); "+
					"[ \"$have\" -ge %d ] || { echo \"bridge %s has $have of %d ports\" >&2; exit 1; }",
				br, len(want), br, len(want))},
		})
	}
	return cmds
}

// tunnelSolution builds the 6in4 tunnel between the two L2 gateways.
//
// The assignment requires it because FRR cannot configure a tunnel: students
// have to drop to a shell inside the router. The reference solution does the
// same thing, through the same interface, so `twinet solve` exercises the same
// path a student does rather than a privileged shortcut.
func (r *Renderer) tunnelSolution(d *model.Device) []deploy.Command {
	if d.L2Gateway == "" {
		return nil
	}
	as, ok := r.Top.ASes[d.ASN]
	if !ok {
		return nil
	}
	// The far end is the other L2 gateway in this AS.
	var peer *model.Device
	for _, o := range as.Routers {
		if o != d && o.L2Gateway != "" {
			peer = o
		}
	}
	if peer == nil {
		return nil
	}
	local, lok := d.IfaceByName("lo")
	remote, rok := peer.IfaceByName("lo")
	if !lok || !rok || local.Addr4 == "" || remote.Addr4 == "" {
		return nil
	}

	name := "tun6"
	// The tunnel carries the *other* datacentre's IPv6 prefix, so each gateway
	// routes its peer's subnets across it.
	var routes []string
	for _, i := range peer.Ifaces {
		if i.Role == model.RoleL2SubIface && i.Addr6 != "" {
			routes = append(routes, network6(i.Addr6))
		}
	}
	sort.Strings(routes)

	script := fmt.Sprintf(
		"ip link show %s >/dev/null 2>&1 || ip tunnel add %s mode sit remote %s local %s ttl 64; ip link set %s up",
		name, name, addrOf(remote.Addr4), addrOf(local.Addr4), name)
	cmds := []deploy.Command{{
		Args: []string{"sh", "-c", script}, Describe: "create the 6in4 tunnel",
	}}
	for _, n := range routes {
		if n == "" {
			continue
		}
		cmds = append(cmds, deploy.Command{
			Args:        []string{"sh", "-c", fmt.Sprintf("ip -6 route replace %s dev %s", n, name)},
			Describe:    "route " + n + " over the tunnel",
			IgnoreError: true,
		})
	}
	return cmds
}

// network6 masks an IPv6 address to its prefix.
func network6(cidr string) string {
	i := strings.IndexByte(cidr, '/')
	if i < 0 {
		return ""
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return ""
	}
	return p.Masked().String()
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
		if i.Owner == model.OwnerPlatform || r.modeFor(d) == ModeSolve {
			apply(i)
		}
	}
	// An L2 host's default gateway is its datacentre's router.
	if r.modeFor(d) == ModeSolve && d.L2Domain != "" {
		if gw4, gw6 := r.l2Gateway(d); gw4 != "" {
			cmds = append(cmds, deploy.Command{
				Args:        []string{"sh", "-c", fmt.Sprintf("ip route replace default via %s || true", gw4)},
				Describe:    "default route via the datacentre gateway",
				IgnoreError: true,
			})
			if gw6 != "" {
				cmds = append(cmds, deploy.Command{
					Args:        []string{"sh", "-c", fmt.Sprintf("ip -6 route replace default via %s || true", gw6)},
					Describe:    "IPv6 default route via the datacentre gateway",
					IgnoreError: true,
				})
			}
		}
		return cmds
	}

	// A host's default route points at its attached router.
	if r.modeFor(d) == ModeSolve || d.Kind == model.KindService {
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

// l2Gateway finds the addresses of the gateway serving a host's VLAN.
func (r *Renderer) l2Gateway(host *model.Device) (string, string) {
	as, ok := r.Top.ASes[host.ASN]
	if !ok {
		return "", ""
	}
	vlan := 0
	for _, i := range host.Ifaces {
		if i.VLAN > 0 {
			vlan = i.VLAN
		}
	}
	for _, rt := range as.Routers {
		if rt.L2Gateway != host.L2Domain {
			continue
		}
		for _, i := range rt.Ifaces {
			if i.Role == model.RoleL2SubIface && i.VLAN == vlan {
				return addrOf(i.Addr4), addrOf6(i.Addr6)
			}
		}
	}
	return "", ""
}

func addrOf6(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i > 0 {
		return cidr[:i]
	}
	return cidr
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
