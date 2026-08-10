package render

import (
	"fmt"
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
func (r *Renderer) serviceFiles(d *model.Device) map[string]deploy.FileSpec {
	out := map[string]deploy.FileSpec{}
	if !isDNS(d) {
		return out
	}
	plan := svc.BuildDNS(r.Top, dnsSerial(r.Top))
	for path, body := range plan.Files() {
		out[path] = deploy.FileSpec{Content: body, Mode: 0o644}
	}
	out["/etc/twinet/hosts"] = deploy.FileSpec{Content: []byte(plan.HostsFile()), Mode: 0o644}
	return out
}

// serviceCommands starts the daemon a service device exists to run.
func (r *Renderer) serviceCommands(d *model.Device) []deploy.Command {
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
				"named -c /etc/bind/named.conf -u named",
				// A resolver that started but answers nothing is worse than
				// one that failed to start, because nothing reports it.
				fmt.Sprintf("for i in 1 2 3 4 5 6 7 8 9 10; do "+
					"dig +time=1 +tries=1 @127.0.0.1 %s SOA 2>/dev/null | grep -q 'status: NOERROR' && exit 0; "+
					"sleep 1; done", probe),
				"echo 'named started but is not authoritative for its own zones' >&2; exit 1",
			}, "\n")},
		},
	}
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
	addr := svc.ResolverFor(r.Top, d.ASN)
	if addr == "" {
		return nil
	}
	// Docker bind-mounts /etc/resolv.conf, so it is truncated and rewritten in
	// place rather than replaced: removing it fails with "resource busy".
	return []deploy.Command{{
		Describe: "point the resolver at the lab's own DNS",
		Args: []string{"sh", "-c", fmt.Sprintf(
			": > /etc/resolv.conf; printf 'nameserver %s\\nsearch group%d\\noptions timeout:1 attempts:1\\n' > /etc/resolv.conf",
			addr, d.ASN)},
		IgnoreError: true,
	}}
}

func isDNS(d *model.Device) bool {
	return d.Kind == model.KindService && strings.Contains(strings.ToLower(d.Name), "dns")
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
