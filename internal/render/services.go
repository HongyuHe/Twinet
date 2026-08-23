package render

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/svc"
)

// serviceFiles returns the files a service device needs to actually serve.
//
// Generating a zone and serving it are different things, and the gap between
// them is invisible from the control plane: the zone files are correct, the
// tests that check them pass, and inside the lab no name resolves. A service
// that is deployed, wired, addressed and running `sleep infinity` looks
// healthy from every angle except the only one that matters.
func (r *Renderer) serviceFiles(d *model.Device) (map[string]deploy.FileSpec, error) {
	out := map[string]deploy.FileSpec{}
	if d.ServiceReplica != "" {
		state, err := svc.BuildDeclaredReplicaState(r.Top, d)
		if err != nil {
			return nil, err
		}
		out["/etc/twinet/service-state.json"] = deploy.FileSpec{Content: state, Mode: 0o644}
	}
	if isLoadBalancer(d) {
		spec, err := r.measuredServiceSpec(d)
		if err != nil {
			return nil, err
		}
		if spec.LoadBalancer == nil {
			return nil, fmt.Errorf("load balancer %s has no typed specification", d.ID)
		}
		lb := *spec.LoadBalancer
		for i, backend := range lb.Backends {
			resolved, err := r.resolveTrafficTarget(backend)
			if err != nil {
				return nil, fmt.Errorf("load balancer %s backend %q: %w", d.ID, backend, err)
			}
			lb.Backends[i] = resolved
		}
		raw, err := json.MarshalIndent(lb, "", "  ")
		if err != nil {
			return nil, err
		}
		out["/etc/twinet/load-balancer.json"] = deploy.FileSpec{Content: append(raw, '\n'), Mode: 0o644}
		return out, nil
	}
	if isTrafficGenerator(d) {
		spec, err := r.measuredServiceSpec(d)
		if err != nil {
			return nil, err
		}
		if spec.TrafficGenerator == nil {
			return nil, fmt.Errorf("traffic generator %s has no typed profile", d.ID)
		}
		profile := spec.TrafficGenerator.Profile
		target, err := r.resolveTrafficTarget(profile.Target)
		if err != nil {
			return nil, fmt.Errorf("traffic generator %s target %q: %w", d.ID, profile.Target, err)
		}
		profile.Target = target
		raw, err := json.MarshalIndent(profile, "", "  ")
		if err != nil {
			return nil, err
		}
		out["/etc/twinet/traffic-profile.json"] = deploy.FileSpec{Content: append(raw, '\n'), Mode: 0o644}
		return out, nil
	}
	if isRPKI(d) {
		p := svc.BuildRPKI(r.Top, r.Top.Lab.RPKI.NotFound, r.Top.Lab.RPKI.Invalid)
		out["/etc/twinet/rpki.json"] = deploy.FileSpec{Content: p.JSON(), Mode: 0o644}
		// Who may authorise what. Derived from the topology so that a system
		// can publish for its own allocation and nothing else -- otherwise the
		// exercise's deliberate hijack could be published away by its victim,
		// and a group could authorise a neighbour's space.
		//
		// The published ROAs themselves are deliberately not written here: they
		// are a class's work, and a deployment that rewrote them would erase
		// it every time anything else about the lab changed.
		if raw, err := json.MarshalIndent(svc.AuthorityFor(r.Top), "", "  "); err == nil {
			out["/etc/twinet/rpki_authority.json"] = deploy.FileSpec{Content: append(raw, '\n'), Mode: 0o644}
		}
		return out, nil
	}
	if !isDNS(d) {
		return out, nil
	}
	plan := svc.BuildDNS(r.Top, dnsSerial(r.Top))
	for path, body := range plan.Files() {
		out[path] = deploy.FileSpec{Content: body, Mode: 0o644}
	}
	out["/etc/twinet/hosts"] = deploy.FileSpec{Content: []byte(plan.HostsFile()), Mode: 0o644}
	return out, nil
}

// serviceCommands starts the daemon a service device exists to run.
func (r *Renderer) serviceCommands(d *model.Device) []deploy.Command {
	if isLoadBalancer(d) {
		return []deploy.Command{{
			Describe: "start deterministic load balancer",
			Args: []string{"sh", "-c", strings.Join([]string{
				"cfg=/etc/twinet/load-balancer.json",
				"listen=$(jq -r '.listen // \":8080\"' \"$cfg\")",
				"backends=$(jq -r '.backends | join(\",\")' \"$cfg\")",
				"limit=$(jq -r '.max_inflight' \"$cfg\")",
				"delay=$(jq -r '.work_delay // \"30ms\"' \"$cfg\")",
				"for p in $(pidof twinet-traffic 2>/dev/null || true); do kill \"$p\" 2>/dev/null || true; done",
				"nohup twinet-traffic load-balancer --listen \"$listen\" --backends \"$backends\" --max-inflight \"$limit\" --work-delay \"$delay\" >/var/log/twinet-load-balancer.log 2>&1 &",
				"for i in $(seq 1 30); do curl -fsS http://127.0.0.1${listen}/metrics >/dev/null 2>&1 && exit 0; sleep 1; done",
				"echo 'load balancer did not become ready' >&2; exit 1",
			}, "\n")},
		}}
	}
	if isTrafficGenerator(d) {
		// The generator is deliberately idle on deployment. A declared
		// profile is a reusable substrate; starting it implicitly would make
		// every ordinary lab overloaded before an incident asked for it.
		return []deploy.Command{{
			Describe: "validate deterministic traffic profile",
			Args:     []string{"sh", "-c", "jq -e '.target and .requests > 0 and .concurrency > 0' /etc/twinet/traffic-profile.json >/dev/null"},
		}}
	}
	if isRPKI(d) {
		return []deploy.Command{{
			Describe: "start the RPKI validator",
			Args: []string{"sh", "-c", strings.Join([]string{
				"for p in $(ps -ef | awk '/twinet-rtr/ && !/awk/ {print $1}'); do kill $p 2>/dev/null || true; done",
				"nohup twinet-rtr -listen :3323 -payload /etc/twinet/rpki.json " +
					"-publish " + svc.PublishListen + " " +
					"-published /etc/twinet/rpki_published.json " +
					"-authority /etc/twinet/rpki_authority.json " +
					">/var/log/twinet-rtr.log 2>&1 &",
				// A validator that is listening but serving nothing is worse
				// than one that failed to start: every route becomes
				// not-found, and an exercise about filtering passes for a
				// reason that has nothing to do with the student.
				// socat, not bash's /dev/tcp: the service image runs busybox
				// sh, where /dev/tcp is an ordinary missing path, so the probe
				// would fail against a validator that was working perfectly.
				"for i in 1 2 3 4 5 6 7 8 9 10; do socat -u /dev/null TCP:127.0.0.1:3323 2>/dev/null && exit 0; sleep 1; done",
				"echo 'the validator is not accepting connections' >&2; exit 1",
			}, "\n")},
		}}
	}

	if !isDNS(d) {
		return nil
	}
	// The readiness probe asks for a zone the server is authoritative for.
	// Probing an outside name instead tests recursion to an internet the lab
	// does not have, so a perfectly working resolver times out and the
	// deployment fails for a reason that has nothing to do with the resolver.
	probe := "localhost"
	if plan := svc.BuildDNS(r.Top, dnsSerial(r.Top)); len(plan.Forward) > 0 {
		probe = strings.TrimSuffix(plan.Forward[0].Origin, ".")
	}
	return []deploy.Command{
		{
			Describe: "check the generated zones parse",
			// named-checkconf fails on a zone the server would refuse, which
			// is the difference between a resolver that is wrong and one that
			// never starts. Both are bad; only one is diagnosable later.
			Args: []string{"sh", "-c", "named-checkconf /etc/bind/named.conf"},
		},
		{
			Describe: "start the authoritative resolver",
			Args: []string{"sh", "-c", strings.Join([]string{
				"pkill -x named 2>/dev/null || true",
				"rm -f /var/run/named/named.pid 2>/dev/null || true",
				// Files arrive through the runtime API as root-owned. named
				// deliberately drops privilege, so make its generated config
				// and zones readable before asking it to become authoritative.
				"chown -R named:named /etc/bind /var/named",
				// Keep named in the foreground of its own redirected background
				// process. Daemon mode can retain an exec transport's pipes or
				// outlive an ambiguous fork boundary; explicit redirection is
				// reliable for Docker, Podman, and the containerd exec broker.
				"mkdir -p /var/log/named",
				"nohup named -g -c /etc/bind/named.conf -u named " +
					">/var/log/named/twinet.log 2>&1 &",
				// A resolver that started but answers nothing is worse than
				// one that failed to start, because nothing reports it.
				fmt.Sprintf("for i in 1 2 3 4 5 6 7 8 9 10; do "+
					"dig +time=1 +tries=1 @127.0.0.1 %s SOA 2>/dev/null | grep -q 'status: NOERROR' && exit 0; "+
					"sleep 1; done", probe),
				"tail -n 50 /var/log/named/twinet.log >&2 2>/dev/null || true",
				"echo 'named started but is not authoritative for its own zones' >&2; exit 1",
			}, "\n")},
		},
	}
}

func (r *Renderer) measuredServiceSpec(d *model.Device) (*model.ServiceSpec, error) {
	if d == nil || r.Top == nil || r.Top.Lab == nil {
		return nil, fmt.Errorf("no topology is available")
	}
	name := d.ServiceName
	if name == "" {
		name = d.Name
	}
	spec := r.Top.Lab.Services[name]
	if spec == nil {
		return nil, fmt.Errorf("service declaration %q was not found", name)
	}
	return spec, nil
}

// resolveTrafficTarget turns service://name into a concrete, topology-owned
// endpoint before it reaches a container. No container is given a controller
// credential or a host address, and an incident consequently cannot route
// traffic outside its lab by changing a profile file.
func (r *Renderer) resolveTrafficTarget(target string) (string, error) {
	if !strings.HasPrefix(target, "service://") {
		return target, nil
	}
	name := strings.TrimSuffix(strings.TrimPrefix(target, "service://"), "/")
	service := r.Top.Services[name]
	if service == nil || service.Device == nil {
		return "", fmt.Errorf("no expanded service %q", name)
	}
	var addr string
	for _, iface := range service.Device.Ifaces {
		if iface.Addr4 != "" {
			addr = addrOf(iface.Addr4)
			break
		}
	}
	if addr == "" {
		return "", fmt.Errorf("service %q has no reachable IPv4 attachment", name)
	}
	port := "8080"
	if spec := r.Top.Lab.Services[name]; spec != nil && spec.LoadBalancer != nil && spec.LoadBalancer.Listen != "" {
		if i := strings.LastIndex(spec.LoadBalancer.Listen, ":"); i >= 0 && i+1 < len(spec.LoadBalancer.Listen) {
			port = spec.LoadBalancer.Listen[i+1:]
		}
	}
	return "http://" + addr + ":" + port + "/", nil
}

// resolverCommands points a device at the lab's own resolver.
//
// Without this the zones are served and nothing uses them: every container
// keeps the resolver Docker gave it, so a student's traceroute still renders
// numbers and `dig msp.group3` still asks the internet.
func (r *Renderer) resolverCommands(d *model.Device) []deploy.Command {
	if d.Kind == model.KindService || d.ASN == 0 {
		return nil
	}
	if svc.ResolverFor(r.Top, d.ASN) == "" {
		return nil
	}
	addrs := svc.ServiceAddressesFor(r.Top, "builtin.dns", d.ASN)
	if len(addrs) == 0 {
		return nil
	}
	var nameservers strings.Builder
	for _, addr := range addrs {
		fmt.Fprintf(&nameservers, "nameserver %s\\n", addr)
	}
	// Docker bind-mounts /etc/resolv.conf, so it is truncated and rewritten in
	// place rather than replaced: removing it fails with "resource busy".
	return []deploy.Command{{
		Describe: "point the resolver at the lab's own DNS",
		Args: []string{"sh", "-c", fmt.Sprintf(
			": > /etc/resolv.conf; printf '%ssearch group%d\\noptions timeout:1 attempts:1\\n' > /etc/resolv.conf",
			nameservers.String(), d.ASN)},
		IgnoreError: true,
	}}
}

// serviceRoutes gives a service container a route to every AS it serves.
//
// Without them a service has only its directly-connected subnets and a default
// route out whichever AS happened to be last, so a reply to any device that is
// not on the service link leaves through the wrong AS. For DNS that was
// survivable and therefore invisible: the reply crossed the entire emulated
// internet and arrived anyway, with a path and a latency that were nonsense.
// For the RPKI validator, whose session is TCP, it simply failed -- and the
// failure presented as origin validation not working on any router except the
// one the validator happened to be cabled to.
func (r *Renderer) serviceRoutes(d *model.Device) []deploy.Command {
	if d.Kind != model.KindService {
		return nil
	}
	var cmds []deploy.Command
	byAS := map[int]*model.Iface{}
	for _, i := range d.Ifaces {
		var asn int
		if _, err := fmt.Sscanf(i.Name, "as%d", &asn); err != nil || asn == 0 {
			continue
		}
		byAS[asn] = i
	}
	// A replica normally has a direct cable only to the ASes placed on its
	// node. It still serves equivalent data for the whole lab, so traffic for
	// an AS it does not directly face goes through a deterministic attached
	// ingress AS instead of relying on whichever default route happened to be
	// installed last.
	var ingress *model.Iface
	var attached []int
	for asn := range byAS {
		attached = append(attached, asn)
	}
	sort.Ints(attached)
	if len(attached) > 0 {
		ingress = byAS[attached[0]]
	}
	for _, targetASN := range r.Top.SortedASNs() {
		as, ok := r.Top.ASes[targetASN]
		if !ok || as.Block == "" {
			continue
		}
		i := byAS[targetASN]
		if i == nil {
			i = ingress
		}
		if i == nil || i.Peer == nil || i.Peer.Addr4 == "" {
			continue
		}
		gw := addrOf(i.Peer.Addr4)
		cmds = append(cmds, deploy.Command{
			Describe: fmt.Sprintf("route to AS %d through service ingress", targetASN),
			Args: []string{"sh", "-c", fmt.Sprintf(
				"ip route replace %s via %s dev %s", as.Block, gw, i.Name)},
		})
	}
	sort.Slice(cmds, func(a, b int) bool { return cmds[a].Describe < cmds[b].Describe })
	return cmds
}

// isRPKI and isDNS ask what a service was declared to be.
//
// They used to ask what it was called: any service device whose name contained
// "rpki" got a validator started in it and any other did not, so a manifest
// that named its validator "roa" got a container running nothing at all, with
// no error anywhere -- and every route in the lab became not-found, which looks
// exactly like a student who filtered too much. The name is a label; the kind
// is the declaration.
//
// The name is still consulted as a fallback, because a service declared as a
// plain container may still be one of these, and because labs deployed before
// the kind was recorded must keep working.
func isRPKI(d *model.Device) bool {
	if d.Kind != model.KindService {
		return false
	}
	if d.ServiceKind != "" {
		return d.ServiceKind == "builtin.rpki"
	}
	return strings.Contains(strings.ToLower(d.Name), "rpki")
}

func isDNS(d *model.Device) bool {
	if d.Kind != model.KindService {
		return false
	}
	if d.ServiceKind != "" {
		return d.ServiceKind == "builtin.dns"
	}
	return strings.Contains(strings.ToLower(d.Name), "dns")
}

func isLoadBalancer(d *model.Device) bool {
	return d != nil && d.Kind == model.KindService && d.ServiceKind == "builtin.load-balancer"
}

func isTrafficGenerator(d *model.Device) bool {
	return d != nil && d.Kind == model.KindService && d.ServiceKind == "builtin.traffic-generator"
}

// dnsSerial derives a zone serial from the topology, so a redeployment of an
// unchanged lab does not renumber the zones and a changed one always does.
func dnsSerial(top *model.Topology) uint32 {
	var h uint32 = 2166136261
	for _, c := range top.Hash {
		h = (h ^ uint32(c)) * 16777619
	}
	if h == 0 {
		h = 1
	}
	return h
}
