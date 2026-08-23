package render

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/nos"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/svc"
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

// AuthoritativeDevice reports whether Twinet owns every configured fact for
// one device. Deploy uses this optional renderer capability while wiring so a
// solved harness restores reference addresses on surrounding hosts without
// overwriting the ungraded submission AS.
func (r *Renderer) AuthoritativeDevice(d *model.Device) bool {
	return r.modeFor(d) == ModeSolve
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
		provider, err := nos.Resolve(d)
		if err != nil {
			return nil, err
		}
		var cfg RouterConfig
		switch provider.Name() {
		case model.DefaultNOS:
			cfg, err = Router(r.Top, d)
		case "bird":
			cfg, err = BirdRouter(r.Top, d)
		default:
			return nil, fmt.Errorf("router %s selects NOS %q with no renderer", d.ID, provider.Name())
		}
		if err != nil {
			return nil, err
		}
		mode := nos.ModePlatform
		if r.modeFor(d) == ModeSolve {
			mode = nos.ModeSolve
		}
		rendered, err := provider.Render(nos.RenderRequest{
			Topology: r.Top, Device: d, Mode: mode,
			Platform: cfg.Platform, Expected: cfg.Expected, Daemons: DaemonsFor(r.Top.ASes[d.ASN]),
		})
		if err != nil {
			return nil, err
		}
		for path, spec := range rendered.Files {
			out[path] = deploy.FileSpec{Content: spec.Content, Mode: spec.Mode}
		}
		// A router that has hosts on a segment of its own serves them DHCP.
		//
		// On the gateway rather than in a service container of its own,
		// because a client's first packet is a broadcast and a server one hop
		// away never hears it -- which would give every fault about DHCP the
		// same symptom, "no address", whatever was actually wrong.
		if cfg := svc.BuildDHCP(r.Top, d); len(cfg.Subnets) > 0 {
			out[svc.DHCPConfigPath] = deploy.FileSpec{Content: cfg.JSON(), Mode: 0o644}
		}
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
	case model.KindP4:
		p4Files, err := r.p4Files(d)
		if err != nil {
			return nil, err
		}
		for path, spec := range p4Files {
			out[path] = spec
		}
	case model.KindController:
		if d.OpenFlow == nil {
			return nil, fmt.Errorf("controller %s has no OpenFlow contract", d.ID)
		}
		out["/etc/twinet/openflow.json"] = deploy.FileSpec{
			Content: []byte(fmt.Sprintf("{\"version\":%q,\"listen\":%q,\"port\":%d,\"fail_mode\":%q}\n",
				d.OpenFlow.Version, d.OpenFlow.Listen, d.OpenFlow.Port, d.OpenFlow.FailMode)),
			Mode: 0o644,
		}
	case model.KindService:
		serviceFiles, err := r.serviceFiles(d)
		if err != nil {
			return nil, err
		}
		for path, spec := range serviceFiles {
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
		provider, err := nos.Resolve(d)
		if err != nil {
			return nil, err
		}
		if provider.Name() == "bird" {
			return r.birdRouterCommands(d, provider)
		}
		cmds := append(r.routerCommands(d), r.dhcpCommands(d)...)
		return append(cmds, r.rpkiReadyCommands(d)...), nil
	case model.KindSwitch:
		return r.switchCommands(d), nil
	case model.KindP4:
		return r.p4Commands(d), nil
	case model.KindController:
		return append(r.hostCommands(d), r.controllerCommands(d)...), nil
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
		Describe: "remove any configuration left in the device by an earlier version",
		// restore.conf is the same problem found later: the snapshot loader
		// copied a complete routing configuration in and left it there. On a
		// lab deployed at the reference that is the answer, readable by any
		// root shell -- which is what a student has, and what an agent being
		// evaluated on root-cause analysis has.
		Args: []string{"sh", "-c", "rm -f /etc/twinet/reference.conf /etc/twinet/restore.conf"},
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
			Describe:   "restart frr onto the reference configuration",
			FRRControl: true,
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

	// And then check that it is actually running.
	//
	// frrinit.sh reports success whether or not the daemons come up, so a
	// router can be deployed with no routing process at all while every
	// device reports healthy and the lab reports zero failures. It is not a
	// theoretical concern: it was found on two routers out of 212 in a
	// class-scale lab, and the only symptom was a grading run timing out four
	// hops away with "1 of 62 sessions not established" -- a message that
	// points at the AS being graded rather than at the neighbour that had no
	// bgpd.
	//
	// Checked on every router, not only the ones this platform restarts,
	// because a student's daemon can die just as easily as a reference one and
	// the consequence is the same: a network that is wrong for a reason no
	// amount of looking at the configuration will reveal.
	if d.Kind == model.KindRouter {
		cmds = append(cmds, deploy.Command{
			Describe:   "check the routing daemons are running",
			FRRControl: true,
			Args: []string{"sh", "-c", strings.Join([]string{
				// The set comes from the daemons file, so a router is checked
				// for every process it was told to run. Checking only zebra
				// and bgpd let a router pass its deployment with ospfd dead,
				// which is the same silence in a different daemon: OSPF never
				// converges, and the report says the router is fine.
				"daemons='" + strings.Join(EnabledDaemonsFor(r.Top.ASes[d.ASN]), " ") + "'",
				"missing() { m=''; for d in $daemons; do",
				"  pidof \"$d\" >/dev/null 2>&1 || m=\"$m $d\"",
				"done; echo \"$m\"; }",
				// A short wait first: the daemons may be being started a few
				// commands earlier and take a moment to write their pid files.
				"for i in 1 2 3 4 5 6 7 8 9 10; do",
				"  [ -z \"$(missing)\" ] && exit 0",
				"  sleep 1",
				"done",
				// Then try to start them, because a daemon that has died is
				// the common case and re-running the deploy is what an
				// operator does about it. A router that only reports the
				// problem leaves them with nothing to do but destroy the
				// container, which loses the student's work.
				//
				// This is safe on a student's router: FRR reads its
				// configuration from the file it was given, so starting a
				// dead daemon restores what the student had rather than
				// replacing it.
				"echo \"not running:$(missing) -- starting the routing daemons\" >&2",
				"for p in $(ps -ef | awk '/watchfrr/ && !/awk/ {print $1}'); do kill $p 2>/dev/null || true; done",
				"/usr/lib/frr/frrinit.sh start >/dev/null 2>&1 || true",
				"for i in 1 2 3 4 5 6 7 8 9 10; do",
				"  [ -z \"$(missing)\" ] && exit 0",
				"  sleep 1",
				"done",
				`echo "these routing daemons are not running and could not be ` +
					`started:$(missing). A router missing a routing process will ` +
					`never converge, and the failure appears on its neighbours ` +
					`rather than here." >&2`,
				"exit 1",
			}, "\n")},
		})
	}

	// Label switching has to be enabled per interface, not once per router.
	//
	// A router with `mpls ldp` configured will happily distribute labels and
	// install label-switched routes while the kernel drops every labelled
	// packet that arrives, because net.mpls.conf.<iface>.input defaults to 0
	// and only lo was ever set. Everything reports success: LDP sessions are
	// operational, `show mpls table` is populated, the route is there with a
	// label on it -- and nothing gets through. That is precisely the failure
	// this platform is meant not to have.
	//
	// It is done here rather than in the manifest's sysctl list because the
	// interfaces do not exist when the container starts: they are created by
	// the link stage, and a sysctl for an interface that is not there yet
	// silently does nothing.
	if as, ok := r.Top.ASes[d.ASN]; ok && as.MPLS.Enabled {
		cmds = append(cmds, deploy.Command{
			Describe: "accept labelled packets on every interface",
			Args: []string{"sh", "-c",
				"for i in $(ls /sys/class/net); do " +
					"sysctl -qw net.mpls.conf.$i.input=1 2>/dev/null || true; done"},
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
	}...)
	provider, err := nos.Resolve(d)
	if err != nil {
		// Renderer.Commands cannot change its established signature, so the
		// deployment receives the concrete provider failure rather than an
		// implicit FRR fallback.
		cmds = append(cmds, deploy.Command{
			Describe: "reject an unknown routing NOS",
			Args:     []string{"sh", "-c", "echo " + shellQuote(err.Error()) + " >&2; exit 1"},
		})
	} else {
		apply, applyErr := provider.Apply(nos.RenderRequest{Topology: r.Top, Device: d})
		if applyErr != nil {
			cmds = append(cmds, deploy.Command{
				Describe: "apply " + provider.Name(),
				Args:     []string{"sh", "-c", "echo " + shellQuote(applyErr.Error()) + " >&2; exit 1"},
			})
		} else {
			applied := deployCommands(apply)
			if provider.Name() == model.DefaultNOS {
				for i := range applied {
					applied[i].FRRControl = true
				}
			}
			cmds = append(cmds, applied...)
		}
	}
	// Loopback addresses are configured on the interface rather than through
	// FRR when the platform owns them, so the address exists even if FRR is
	// still starting.
	if lo, ok := d.IfaceByName("lo"); ok && lo.Owner == model.OwnerPlatform && lo.Addr4 != "" {
		cmds = append([]deploy.Command{{
			Args:     []string{"sh", "-c", fmt.Sprintf("ip addr replace %s brd + dev lo && ip link set lo up", lo.Addr4)},
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
	cmds := []deploy.Command{{
		Describe:    "connect to the origin validator",
		Args:        []string{"sh", "-c", RPKIRefreshScript},
		IgnoreError: true,
	}}
	cmds = append(cmds, r.roaPublishCommands(d)...)
	return cmds
}

// dhcpCommands starts the address server on a router that serves a segment.
func (r *Renderer) dhcpCommands(d *model.Device) []deploy.Command {
	if d.Kind != model.KindRouter {
		return nil
	}
	if cfg := svc.BuildDHCP(r.Top, d); len(cfg.Subnets) == 0 {
		return nil
	}
	return []deploy.Command{{
		Describe: "serve DHCP on this router's own segments",
		Args: []string{"sh", "-c", strings.Join([]string{
			svc.DHCPStartCommand,
			// A server that is not listening hands out nothing, and a client
			// with no address then looks exactly like one whose server was
			// deliberately stopped -- which is one of the faults. The two must
			// not be confusable, so a deployment that cannot start it says so.
			"for i in 1 2 3 4 5; do",
			"  if ps -ef | grep -q '[t]winet-dhcpd'; then exit 0; fi",
			"  sleep 1",
			"done",
			"echo 'the address server did not start' >&2; exit 1",
		}, "\n")},
		IgnoreError: true,
	}}
}

// roaPublishCommands issues this system's own ROA, in solve mode only.
//
// Publishing is the student's action -- the platform authorises nothing for a
// student system -- so the reference solution has to perform it like anybody
// else, or the reference would fail the very question it defines the answer to.
//
// An autonomous system the manifest declares as having no ROA is skipped: that
// is the deliberate not-found case, and publishing for it would remove the one
// thing it exists to teach.
func (r *Renderer) roaPublishCommands(d *model.Device) []deploy.Command {
	if r.modeFor(d) != ModeSolve {
		return nil
	}
	as, ok := r.Top.ASes[d.ASN]
	if !ok || as.Role != model.RoleStudent || as.Block == "" {
		return nil
	}
	if r.Top.Lab != nil {
		for _, n := range r.Top.Lab.RPKI.NotFound {
			if n == d.ASN {
				return nil
			}
		}
	}
	addr := svc.RPKIAddrFor(r.Top, d.ASN)
	if addr == "" {
		return nil
	}
	body := fmt.Sprintf(`{"prefix":%q,"asn":%d}`, as.Block, d.ASN)
	return []deploy.Command{{
		Describe: "authorise this system's prefix with the lab's trust anchor",
		// Retried, because the validator and this router come up together and
		// the publication interface may not be listening yet. Failing softly:
		// a lab whose trust anchor is briefly unreachable is still a usable
		// lab, and the graded check is what makes a missing authorisation
		// visible where it matters.
		Args: []string{"sh", "-c", strings.Join([]string{
			"for i in 1 2 3 4 5 6 7 8 9 10; do",
			fmt.Sprintf("  curl -sf -m 5 -X POST http://%s%s/roas -d '%s' >/dev/null 2>&1 && exit 0",
				addr, svc.PublishListen, body),
			"  sleep 3",
			"done",
			"echo 'the trust anchor did not accept this authorisation' >&2",
		}, "\n")},
		IgnoreError: true,
	}}
}

// RPKIRefreshScript waits for the validator and then re-runs inbound policy.
//
// Exported because grading loads a submission by restarting FRR, which puts it
// in exactly the same race: the sessions come up while the validator is still
// connecting.
var RPKIRefreshScript = strings.Join([]string{
	// Origin validation only takes effect on a route when the inbound policy
	// runs, and FRR runs an inbound policy when the route arrives. ROAs that
	// turn up afterwards -- which is the normal order, because BGP converges
	// while the validator is still connecting -- record each route's
	// validation state and leave the route in place. The table then reads
	// "rpki validation-state: invalid" on a route the policy was written to
	// reject, still selected and still advertised onwards.
	//
	// That was the state of this cluster: the reference solution itself
	// carried the lab's hijack on 64 routers, with a correct deny clause on
	// every one of them, so the question could not be answered correctly by
	// anybody. A soft inbound refresh re-runs the policy against what the
	// neighbours already sent; it resets no session, and is what an operator
	// does when a validator comes up late.
	//
	// The refresh watches for the condition rather than trying to time it.
	// Timing it was tried five times and measured five times: the socket
	// reports connected before any record has arrived, the first record
	// arrives before the rest, a session the lab deliberately delays
	// delivers its routes after all of them, and a repair that restarts
	// FRR an hour later puts the router straight back into the same state
	// with no deployment running to notice. Every timed version refreshed
	// at the wrong moment, found nothing to do, and exited; 36 routers
	// stayed as they were through five of them.
	//
	// So it stays, cheaply: one look a minute, and a refresh only when
	// this router is holding an invalid route it learned itself.
	// The watcher already running is stopped first.
	//
	// A shell reads a `while` loop into memory before executing it, so a
	// watcher started an hour ago goes on running the script it was started
	// with no matter what is written to the file afterwards. The guard below
	// then refuses to start the new one, because a watcher is already
	// running. Every improvement to this script since it was written had
	// therefore been deployed to the file and to nothing else: the version
	// actually watching these routers was the first one.
	"for p in $(ps -ef | awk '/rpki_refresh/ && !/awk/ {print $1}'); do kill $p 2>/dev/null || true; done",
	"rm -f /run/twinet_rpki_refresh.pid",
	"cat > /etc/twinet/rpki_refresh.sh <<'TWINET_RPKI'",
	// One copy per container. A deployment runs this step every time, and
	// a repair runs it again; without the guard a router accumulates a
	// watcher per deployment for the life of the lab.
	"pid=/run/twinet_rpki_refresh.pid",
	"[ -f $pid ] && kill -0 \"$(cat $pid)\" 2>/dev/null && exit 0",
	"echo $$ > $pid",
	"while :; do",
	"  delay=60",
	// A session that is configured and not connected does not repair
	// itself, and nothing else was looking.
	//
	// FRR establishes the RTR connection when the cache line is
	// committed, not when the daemon reads it out of a file, so a bgpd
	// that restarts -- a repair, a container restart, an operator
	// reloading -- comes back with the configuration present and no
	// connection. Every route in the table is then not-found, which looks
	// exactly like a student who filtered too much, and the whole class
	// loses the origin-validation marks. Eight systems were found in that
	// state at once. `rpki reset` and `rpki start` do not bring it back;
	// re-entering the cache line does.
	"  if vtysh -c 'show rpki cache-connection' 2>/dev/null | grep -q 'No connection'; then",
	"    line=$(vtysh -c 'show running-config' 2>/dev/null | sed -n 's/^ *\\(rpki cache .*\\)$/\\1/p' | head -1)",
	"    if [ -n \"$line\" ]; then",
	"      vtysh -c 'configure terminal' -c 'rpki' -c \"no $line\" -c \"$line\" -c 'end' >/dev/null 2>&1",
	"    fi",
	"    delay=5",
	// Nothing to validate against yet.
	"  elif ! vtysh -c 'show rpki prefix-table' 2>/dev/null | grep -qE '^[0-9]+[.]'; then",
	"    delay=5",
	// Only a route this router learned for itself, and only while one is
	// there. A router cannot refresh away an invalid route it heard over
	// iBGP -- the border that accepted it is the only one that can -- and
	// FRR marks an iBGP path with an "i" directly after the status field:
	// "I*>i10.128.0.0/9" came from inside, "I*> 10.128.0.0/9" came from a
	// neighbour of this router.
	"  elif vtysh -c 'show bgp ipv4 unicast rpki invalid' 2>/dev/null |",
	"    grep -E '^[A-Za-z]*[*]' | grep -qv '>i'; then",
	// A route refresh, not a soft replay. Storing the received
	// announcements and replaying them was tried: FRR replays each stored
	// entry with the validation state it was given when it arrived, which
	// is precisely the stale answer being corrected. Asking the neighbour
	// to send its routes again re-validates them against the ROA table as
	// it stands now.
	"    vtysh -c 'clear bgp ipv4 unicast * in' >/dev/null 2>&1 || true",
	"  fi",
	"  sleep \"$delay\"",
	"done",
	"TWINET_RPKI",
	// Started before anything is waited for, and with every descriptor
	// detached under setsid.
	//
	// It used to be started only inside the loop below, once the validator
	// answered -- which it does not do within thirty seconds of an FRR
	// restart, which is exactly when this runs. So on a deployment the
	// watcher was never started at all, and the thing that was measured
	// five times as "the watcher ran and did nothing" was a watcher that
	// had never existed. A plain `&` does not survive either: the exec's
	// session ends with the command and the child is signalled before its
	// first sleep is over.
	// The watcher performs its first check immediately and retries a missing
	// validator every five seconds. Waiting here as well occupied every
	// convergence slot for 32 seconds per router at class scale, while adding
	// no correctness: this command is intentionally soft-failing and the
	// persistent watcher is the mechanism that establishes the session.
	"setsid sh /etc/twinet/rpki_refresh.sh </dev/null >/dev/null 2>&1 &",
}, "\n")

// p4Files copies the declared BMv2 pipeline under a fixed in-container name.
// The digest is checked again here, not only by manifest validation: a source
// tree can change between validation and deployment, and loading different
// bytes under the same incident record would make the result irreproducible.
func (r *Renderer) p4Files(d *model.Device) (map[string]deploy.FileSpec, error) {
	if d.P4 == nil || d.P4.ProgramPath == "" {
		return nil, fmt.Errorf("P4 device %s has no program contract", d.ID)
	}
	clean := filepath.Clean(d.P4.ProgramPath)
	if filepath.IsAbs(clean) || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("P4 device %s names program path outside the lab", d.ID)
	}
	raw, err := os.ReadFile(filepath.Join(r.Top.Lab.Dir, clean))
	if err != nil {
		return nil, fmt.Errorf("read P4 program for %s: %w", d.ID, err)
	}
	if d.P4.ProgramDigest != "" {
		sum := sha256.Sum256(raw)
		got := "sha256:" + hex.EncodeToString(sum[:])
		if got != d.P4.ProgramDigest {
			return nil, fmt.Errorf("P4 device %s program digest is %s, not pinned %s",
				d.ID, got, d.P4.ProgramDigest)
		}
	}
	ext := strings.ToLower(filepath.Ext(clean))
	switch ext {
	case ".p4", ".json":
	default:
		return nil, fmt.Errorf("P4 device %s program %q is neither .p4 nor .json", d.ID, clean)
	}
	return map[string]deploy.FileSpec{
		"/etc/twinet/p4/program" + ext: {Content: raw, Mode: 0o644},
	}, nil
}

// p4Commands compiles (when needed), starts and proves the BMv2 process after
// its veths exist. Starting it in the container entrypoint would race wiring
// and leave it with no ports; this configure-stage order is deterministic.
func (r *Renderer) p4Commands(d *model.Device) []deploy.Command {
	if d.P4 == nil {
		return nil
	}
	var ports []string
	port := 1
	for _, i := range d.Ifaces {
		if i.Link == nil || i.Role == model.RoleOpenFlowControl {
			continue
		}
		ports = append(ports, fmt.Sprintf("-i %d@%s", port, i.Name))
		port++
	}
	if len(ports) == 0 {
		return []deploy.Command{{
			Describe: "refuse an unwired P4 device",
			Args:     []string{"sh", "-c", "echo 'P4 device has no wired data-plane ports' >&2; exit 1"},
		}}
	}
	source := "/etc/twinet/p4/program" + strings.ToLower(filepath.Ext(d.P4.ProgramPath))
	jsonPath := "/etc/twinet/p4/program.json"
	compile := ""
	if strings.HasSuffix(source, ".p4") {
		// p4c-bm2-ss writes its BMv2 JSON to the explicit -o path; a
		// directory default depends on the source filename and is not stable.
		compile = fmt.Sprintf("p4c-bm2-ss --std p4-16 -o %s %s", jsonPath, source)
	} else {
		compile = fmt.Sprintf("cp %s %s", source, jsonPath)
	}
	commands := []string{
		"set -eu",
		"mkdir -p /etc/twinet/p4 /var/log/twinet",
		"for p in $(pidof simple_switch 2>/dev/null || true); do kill \"$p\" 2>/dev/null || true; done",
		compile,
		fmt.Sprintf("nohup simple_switch --log-console %s --thrift-port %d --device-id 0 %s >/var/log/twinet/bmv2.log 2>&1 &",
			strings.Join(ports, " "), d.P4.ThriftPort, jsonPath),
		fmt.Sprintf("for i in $(seq 1 30); do printf 'show_tables\\n' | simple_switch_CLI --thrift-port %d >/dev/null 2>&1 && exit 0; sleep 1; done",
			d.P4.ThriftPort),
		"echo 'BMv2 did not become ready' >&2; exit 1",
	}
	cmds := []deploy.Command{{
		Describe: "compile and start BMv2 program",
		Args:     []string{"sh", "-c", strings.Join(commands, "\n")},
	}}
	for _, entry := range d.P4.Entries {
		action := entry.Action
		if action == "" {
			action = d.P4.ForwardAction
		}
		line := fmt.Sprintf("table_add %s %s %s", d.P4.Table, action, entry.Match)
		if len(entry.Params) > 0 {
			line += " => " + strings.Join(entry.Params, " ")
		}
		// `table_add` is deliberately not ignored. A duplicate or malformed
		// entry means the declared forwarding contract is not in effect, and
		// an incident must not run against a switch merely assumed to work.
		cmds = append(cmds, deploy.Command{
			Describe: "install P4 table entry",
			Args: []string{"sh", "-c", fmt.Sprintf(
				"printf '%%s\\n' %s | simple_switch_CLI --thrift-port %d",
				shellQuoteP4(line), d.P4.ThriftPort)},
		})
	}
	if d.P4.ThresholdRegister != "" {
		indices := make([]int, 0, len(d.P4.RegisterValues))
		for index := range d.P4.RegisterValues {
			indices = append(indices, index)
		}
		sort.Ints(indices)
		for _, index := range indices {
			value := d.P4.RegisterValues[index]
			cmds = append(cmds, deploy.Command{
				Describe: "initialise P4 threshold register",
				Args: []string{"sh", "-c", fmt.Sprintf(
					"printf 'register_write %s %d %d\\n' | simple_switch_CLI --thrift-port %d",
					shellQuoteP4(d.P4.ThresholdRegister), index, value, d.P4.ThriftPort)},
			})
		}
	}
	return cmds
}

func shellQuoteP4(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func (r *Renderer) controllerCommands(d *model.Device) []deploy.Command {
	if d.OpenFlow == nil {
		return nil
	}
	port := d.OpenFlow.Port
	if port == 0 {
		port = 6653
	}
	return []deploy.Command{{
		Describe: "start OpenFlow controller",
		Args: []string{"sh", "-c", strings.Join([]string{
			"for p in $(pidof twinet-openflow-controller 2>/dev/null || true); do kill \"$p\" 2>/dev/null || true; done",
			fmt.Sprintf("nohup twinet-openflow-controller --listen :%d --state /run/twinet/openflow.json >/var/log/twinet-openflow.log 2>&1 &", port),
			fmt.Sprintf("for i in $(seq 1 30); do nc -z 127.0.0.1 %d >/dev/null 2>&1 && exit 0; sleep 1; done", port),
			"echo 'OpenFlow controller did not become ready' >&2; exit 1",
		}, "\n")},
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
	// An OpenFlow management cable is an IP-only control channel, not a
	// bridge port. Adding it to br0 leaks controller traffic into the student
	// fabric and makes a blocked southbound port look like a forwarding
	// failure instead of the control-plane failure it is meant to model.
	for _, i := range d.Ifaces {
		if i.Role != model.RoleOpenFlowControl || i.Addr4 == "" {
			continue
		}
		cmds = append(cmds, deploy.Command{
			Args: []string{"sh", "-c", fmt.Sprintf(
				"ip addr replace %s brd + dev %s && ip link set %s up", i.Addr4, i.Name, i.Name)},
			Describe: "configure OpenFlow control address " + i.Name,
		})
	}
	for _, i := range d.Ifaces {
		if i.Link == nil || i.Role == model.RoleOpenFlowControl {
			continue
		}
		cmds = append(cmds, deploy.Command{
			Args:     []string{"sh", "-c", fmt.Sprintf("ovs-vsctl --may-exist add-port %s %s", br, i.Name)},
			Describe: "attach port " + i.Name,
		})
	}
	if d.OpenFlowController != "" {
		if controller, ok := r.Top.Device(d.OpenFlowController); ok && controller.OpenFlow != nil {
			var endpoint string
			for _, i := range d.Ifaces {
				if i.Role == model.RoleOpenFlowControl && i.Peer != nil {
					endpoint = addrOf(i.Peer.Addr4)
					break
				}
			}
			if endpoint != "" {
				cmds = append(cmds, deploy.Command{
					Args: []string{"sh", "-c", fmt.Sprintf(
						"ovs-vsctl set-fail-mode %s %s && ovs-vsctl set-controller %s tcp:%s:%d",
						br, controller.OpenFlow.FailMode, br, endpoint, controller.OpenFlow.Port)},
					Describe: "connect OVS to controller " + controller.ID,
				})
			}
		}
	}
	if r.modeFor(d) == ModeSolve {
		cmds = append(cmds, r.switchSolution(d, br)...)
	}
	// Prove the bridge exists and carries every port it was given. Without
	// this the deployment reports success on a switch that silently forwards
	// nothing, which presents at the routers as sessions that never establish.
	var want []string
	for _, i := range d.Ifaces {
		if i.Link != nil && i.Role != model.RoleOpenFlowControl {
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
		if i.Link == nil || i.Role == model.RoleOpenFlowControl {
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
				Args: []string{"sh", "-c", // brd + , so the address carries its broadcast attribute.
					//
					// Without it the kernel records no broadcast address, and a
					// fault that removes and re-adds the address puts back
					// something that differs from what it found -- which the
					// baseline comparison then reports, correctly, as a lab that
					// was not restored. Measured on this cluster: every
					// address-changing fault left this residue behind.
					fmt.Sprintf("ip addr replace %s brd + dev %s", i.Addr4, i.Name)},
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
		provider, err := nos.Resolve(d)
		if err == nil {
			return provider.Ready(d, rt)
		}
		return &plan.Waiter{
			Describe: "known NOS for " + d.ID,
			Interval: 200 * time.Millisecond,
			Timeout:  time.Second,
			Check: func(context.Context) (bool, error) {
				return false, err
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
	case model.KindP4:
		if d.P4 == nil {
			return &plan.Waiter{
				Describe: "P4 contract for " + d.ID, Interval: 200 * time.Millisecond, Timeout: time.Second,
				Check: func(context.Context) (bool, error) {
					return false, fmt.Errorf("P4 device %s has no runtime contract", d.ID)
				},
			}
		}
		container, port := d.Container, d.P4.ThriftPort
		return &plan.Waiter{
			Describe: "BMv2 control plane on " + d.ID,
			Interval: 200 * time.Millisecond, Timeout: 60 * time.Second, StableFor: 2,
			Check: func(ctx context.Context) (bool, error) {
				res, err := rt.Exec(ctx, container, runtime.ExecCmd{Cmd: []string{"sh", "-c",
					fmt.Sprintf("printf 'show_tables\\n' | simple_switch_CLI --thrift-port %d", port)}})
				if err != nil {
					return false, err
				}
				if res.ExitCode != 0 {
					return false, fmt.Errorf("BMv2 CLI exited %d: %s", res.ExitCode, firstLine(res.Stderr))
				}
				return true, nil
			},
		}
	case model.KindController:
		if d.OpenFlow == nil {
			return nil
		}
		container, port := d.Container, d.OpenFlow.Port
		return &plan.Waiter{
			Describe: "OpenFlow controller " + d.ID + " to accept switches",
			Interval: 200 * time.Millisecond, Timeout: 60 * time.Second, StableFor: 2,
			Check: func(ctx context.Context) (bool, error) {
				res, err := rt.Exec(ctx, container, runtime.ExecCmd{Cmd: []string{"sh", "-c",
					fmt.Sprintf("nc -z 127.0.0.1 %d", port)}})
				if err != nil {
					return false, err
				}
				return res.ExitCode == 0, nil
			},
		}
	case model.KindService:
		var (
			describe string
			command  []string
		)
		switch {
		case isLoadBalancer(d):
			describe = "load balancer " + d.ID + " to publish metrics"
			command = []string{"sh", "-c", "curl -fsS http://127.0.0.1:8080/metrics >/dev/null"}
		case isTrafficGenerator(d):
			describe = "traffic generator " + d.ID + " profile to be readable"
			command = []string{"test", "-s", "/etc/twinet/traffic-profile.json"}
		case isDNS(d):
			describe = "DNS replica " + d.ID + " to answer"
			probe := "localhost"
			if plan := svc.BuildDNS(r.Top, dnsSerial(r.Top)); len(plan.Forward) > 0 {
				probe = strings.TrimSuffix(plan.Forward[0].Origin, ".")
			}
			command = []string{"sh", "-c", fmt.Sprintf(
				"dig +time=1 +tries=1 @127.0.0.1 %s SOA | grep -q 'status: NOERROR'", probe)}
		case isRPKI(d):
			describe = "RTR replica " + d.ID + " to accept connections"
			command = []string{"sh", "-c", "socat -u /dev/null TCP:127.0.0.1:3323"}
		default:
			return nil
		}
		container := d.Container
		return &plan.Waiter{
			Describe: describe, Interval: 200 * time.Millisecond, Timeout: 30 * time.Second,
			StableFor: 2,
			Check: func(ctx context.Context) (bool, error) {
				result, err := rt.Exec(ctx, container, runtime.ExecCmd{Cmd: command})
				if err != nil {
					return false, err
				}
				if result.ExitCode != 0 {
					return false, fmt.Errorf("%s exited %d", describe, result.ExitCode)
				}
				return true, nil
			},
		}
	}
	return nil
}

// birdRouterCommands configures kernel-owned interfaces, then lets the BIRD
// provider own its daemon lifecycle. BIRD intentionally does not use FRR's
// vtysh or daemon file paths.
func (r *Renderer) birdRouterCommands(d *model.Device, provider nos.Provider) ([]deploy.Command, error) {
	cmds := r.resolverCommands(d)
	for _, iface := range d.Ifaces {
		if iface.Owner != model.OwnerPlatform && r.modeFor(d) != ModeSolve {
			continue
		}
		if iface.Role == model.RoleL2SubIface && iface.Parent != "" {
			cmds = append(cmds, deploy.Command{
				Describe: "create VLAN sub-interface " + iface.Name,
				Args: []string{"sh", "-c", fmt.Sprintf(
					"ip link show %s >/dev/null 2>&1 || ip link add link %s name %s type vlan id %d; ip link set %s up",
					iface.Name, iface.Parent, iface.Name, iface.VLAN, iface.Name)},
			})
		}
		if iface.Addr4 != "" {
			cmds = append(cmds, deploy.Command{
				Describe: "address " + iface.Name,
				Args: []string{"sh", "-c", fmt.Sprintf(
					"ip addr replace %s brd + dev %s && ip link set %s up", iface.Addr4, iface.Name, iface.Name)},
			})
		}
		if iface.Addr6 != "" {
			cmds = append(cmds, deploy.Command{
				Describe: "address " + iface.Name + " (v6)",
				Args: []string{"sh", "-c", fmt.Sprintf(
					"ip -6 addr replace %s dev %s && ip link set %s up", iface.Addr6, iface.Name, iface.Name)},
			})
		}
	}
	apply, err := provider.Apply(nos.RenderRequest{Topology: r.Top, Device: d})
	if err != nil {
		return nil, err
	}
	return append(cmds, deployCommands(apply)...), nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func deployCommands(commands []nos.Command) []deploy.Command {
	out := make([]deploy.Command, 0, len(commands))
	for _, command := range commands {
		out = append(out, deploy.Command{
			Args: command.Args, IgnoreError: command.IgnoreError, Describe: command.Describe,
		})
	}
	return out
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
//
// It deliberately omits the addressing of interfaces the *student* owns.
//
// This file listed every prescribed address, including the ones a student is
// meant to configure themselves. For a teaching lab that is only mildly
// unhelpful. For the root-cause benchmark it is the answer: three of the
// end-host faults change an address, and an agent could find them by comparing
// this file with `ip addr` instead of diagnosing anything -- an oracle no other
// backend in the comparison has. What the platform configured is still
// described, because that is what the container's own tooling needs and it is
// not what anybody is being asked to work out.
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
		addr4, addr6 := ifc.Addr4, ifc.Addr6
		if ifc.Owner != model.OwnerPlatform {
			addr4, addr6 = "", ""
		}
		fmt.Fprintf(&b, "    {\"name\": %q, \"role\": %q, \"owner\": %q, \"addr4\": %q, \"addr6\": %q, \"vlan\": %d, \"peer\": %q}",
			ifc.Name, ifc.Role, ifc.Owner, addr4, addr6, ifc.VLAN, peer)
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
