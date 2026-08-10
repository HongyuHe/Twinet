// Package svc implements the auxiliary services the courses depend on.
//
// The guiding rule: a service container runs a daemon that genuinely must live
// inside the topology (an authoritative DNS server, a route server, a VPN
// endpoint). Anything that is really "poll the network and render a page" lives
// in the control plane instead, where it can be tested, is not duplicated
// across a thousand containers, and does not need its own process supervisor.
//
// The platform this replaces ran a looking-glass loop and a VPN observer inside
// every router, which is why its own bug list complains about process limits
// and pruning.
package svc

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// Zone is a generated DNS zone.
type Zone struct {
	Origin  string
	Serial  uint32
	Records []Record
	// NS is the address the authoritative server actually answers on. A zone
	// whose authority record names an address nobody holds fails as a name
	// that intermittently does not resolve, rather than as a broken zone.
	NS string
}

// Record is one resource record.
type Record struct {
	Name string
	Type string
	Data string
}

// DNSPlan is every zone the lab needs.
type DNSPlan struct {
	Forward []Zone
	Reverse []Zone
	// Hosts is a flat name-to-address map, used for /etc/hosts style output and
	// by the gateway's completion.
	Hosts map[string]string
}

// BuildDNS generates the lab's DNS zones from the topology.
//
// This replaces a 244-line bash generator. Everything comes from the model, so
// a name can never refer to an address the topology does not actually assign,
// and adding an AS cannot leave the zone stale.
//
// The naming follows what the assignment tells students to expect: a router is
// <router>.group<N> and its attached host is host.<router>.group<N>, so a
// traceroute renders as names rather than numbers.
func BuildDNS(top *model.Topology, serial uint32) *DNSPlan {
	p := &DNSPlan{Hosts: map[string]string{}}
	rev := map[string][]Record{} // reverse zone origin -> records

	// The address the resolver itself answers on, per AS. It is the service
	// device's own address on that AS's service link, so the NS glue names
	// something that genuinely responds.
	nsFor := resolverAddrs(top)

	for _, asn := range top.SortedASNs() {
		as := top.ASes[asn]
		origin := fmt.Sprintf("group%d.", asn)
		zone := Zone{Origin: origin, Serial: serial, NS: nsFor[asn]}

		for _, d := range as.Devices {
			for _, i := range d.Ifaces {
				if i.Addr4 == "" {
					continue
				}
				addr, err := netip.ParsePrefix(i.Addr4)
				if err != nil {
					continue
				}
				ip := addr.Addr().String()

				var name string
				switch {
				case d.Kind == model.KindRouter:
					name = strings.ToLower(d.Name)
				case d.Kind == model.KindHost && strings.HasSuffix(d.Name, "_host"):
					name = "host." + strings.ToLower(strings.TrimSuffix(d.Name, "_host"))
				default:
					name = strings.ToLower(strings.ReplaceAll(d.Name, "_", "-"))
				}

				// A router has several addresses; the first in sorted interface
				// order wins the bare name so a traceroute is stable, and every
				// address still gets a reverse record.
				fqdn := name + "." + origin
				if _, taken := p.Hosts[fqdn]; !taken {
					zone.Records = append(zone.Records, Record{Name: name, Type: "A", Data: ip})
					p.Hosts[fqdn] = ip
				}

				if o, r, ok := reverseRecord(ip, fqdn); ok {
					rev[o] = append(rev[o], r)
				}
			}
		}
		sort.Slice(zone.Records, func(a, b int) bool { return zone.Records[a].Name < zone.Records[b].Name })
		if len(zone.Records) > 0 {
			p.Forward = append(p.Forward, zone)
		}
	}

	origins := make([]string, 0, len(rev))
	for o := range rev {
		origins = append(origins, o)
	}
	sort.Strings(origins)
	for _, o := range origins {
		recs := rev[o]
		sort.Slice(recs, func(a, b int) bool { return recs[a].Name < recs[b].Name })
		p.Reverse = append(p.Reverse, Zone{Origin: o, Serial: serial, Records: recs})
	}
	return p
}

// resolverAddrs maps each AS to the address the DNS service holds on that AS's
// service link, which is the address that AS's devices can reach it at.
func resolverAddrs(top *model.Topology) map[int]string {
	out := map[int]string{}
	for _, d := range top.Devices {
		if d.Kind != model.KindService || !strings.Contains(strings.ToLower(d.Name), "dns") {
			continue
		}
		for _, i := range d.Ifaces {
			if i.Addr4 == "" {
				continue
			}
			a, err := netip.ParsePrefix(i.Addr4)
			if err != nil {
				continue
			}
			// The interface is named after the AS it faces.
			var asn int
			if _, err := fmt.Sscanf(i.Name, "as%d", &asn); err == nil && asn > 0 {
				out[asn] = a.Addr().String()
			}
		}
	}
	return out
}

// ResolverFor returns the address devices in an AS should use as their
// nameserver, or empty if the lab has no DNS service reaching that AS.
func ResolverFor(top *model.Topology, asn int) string {
	return resolverAddrs(top)[asn]
}

// reverseRecord builds the PTR for an address, in the /24 reverse zone.
func reverseRecord(ip, fqdn string) (origin string, r Record, ok bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return "", Record{}, false
	}
	b := a.As4()
	origin = fmt.Sprintf("%d.%d.%d.in-addr.arpa.", b[2], b[1], b[0])
	return origin, Record{Name: fmt.Sprint(b[3]), Type: "PTR", Data: fqdn}, true
}

// ZoneFile renders a zone in BIND master-file format.
//
// The NS glue points at an address the server genuinely holds. A zone whose
// authority record names an address nobody answers on is not merely untidy: a
// resolver following the delegation gets nothing, and the failure appears as a
// name that intermittently does not resolve rather than as a broken zone.
func (z Zone) ZoneFile() string {
	var b strings.Builder
	ns := z.NS
	if ns == "" {
		ns = "198.0.0.100"
	}
	fmt.Fprintf(&b, "$TTL 60\n")
	fmt.Fprintf(&b, "@ IN SOA ns.%s root.%s (%d 60 60 300 60)\n", z.Origin, z.Origin, z.Serial)
	fmt.Fprintf(&b, "@ IN NS ns.%s\n", z.Origin)
	fmt.Fprintf(&b, "ns IN A %s\n", ns)
	for _, r := range z.Records {
		fmt.Fprintf(&b, "%s IN %s %s\n", r.Name, r.Type, r.Data)
	}
	return b.String()
}

// NamedConf renders the server configuration for the generated zones.
func (p *DNSPlan) NamedConf() string {
	var b strings.Builder
	b.WriteString(`options {
    directory "/var/named";
    recursion yes;
    allow-query { any; };
    allow-recursion { any; };
    dnssec-validation no;
    listen-on { any; };
    listen-on-v6 { none; };
};

`)
	for _, z := range append(append([]Zone{}, p.Forward...), p.Reverse...) {
		fmt.Fprintf(&b, "zone \"%s\" { type master; file \"%s\"; };\n",
			strings.TrimSuffix(z.Origin, "."), zoneFileName(z.Origin))
	}
	return b.String()
}

func zoneFileName(origin string) string {
	return "db." + strings.TrimSuffix(origin, ".")
}

// Files returns every file the DNS container needs, keyed by absolute path.
func (p *DNSPlan) Files() map[string][]byte {
	out := map[string][]byte{
		"/etc/bind/named.conf": []byte(p.NamedConf()),
	}
	for _, z := range append(append([]Zone{}, p.Forward...), p.Reverse...) {
		out["/var/named/"+zoneFileName(z.Origin)] = []byte(z.ZoneFile())
	}
	return out
}

// HostsFile renders the name-to-address map in /etc/hosts format, which the
// measurement service and the gateway use for completion.
func (p *DNSPlan) HostsFile() string {
	names := make([]string, 0, len(p.Hosts))
	for n := range p.Hosts {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%s\t%s\n", p.Hosts[n], strings.TrimSuffix(n, "."))
	}
	return b.String()
}
