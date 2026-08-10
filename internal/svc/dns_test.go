package svc

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

func loadLab(t *testing.T) *model.Topology {
	t.Helper()
	l, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Skipf("cos461 lab unavailable: %v", err)
	}
	res, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	return res.Topology
}

// The assignment promises that a traceroute renders "12.0.2.2" as "msp.group12".
// If the generated zone does not carry that name, every traceroute in the course
// prints numbers and the DNS section of the assignment is a lie.
func TestDNSNamesMatchTheAssignment(t *testing.T) {
	top := loadLab(t)
	p := BuildDNS(top, 1)

	want := []string{"msp.group3.", "atl.group3.", "host.msp.group3."}
	for _, n := range want {
		if _, ok := p.Hosts[n]; !ok {
			t.Errorf("no DNS record for %q", n)
		}
	}
	// A router's name must resolve to an address the topology actually assigns.
	addr := p.Hosts["msp.group3."]
	found := false
	d, _ := top.DeviceInAS(3, "MSP")
	for _, i := range d.Ifaces {
		if strings.HasPrefix(i.Addr4, addr+"/") {
			found = true
		}
	}
	if !found {
		t.Errorf("msp.group3 resolves to %s, which MSP does not own", addr)
	}
}

// Every address must have a reverse record, or traceroute shows numbers even
// though the forward zone is complete.
func TestDNSHasReverseRecords(t *testing.T) {
	top := loadLab(t)
	p := BuildDNS(top, 1)
	if len(p.Reverse) == 0 {
		t.Fatal("no reverse zones generated")
	}
	var ptrs int
	for _, z := range p.Reverse {
		if !strings.HasSuffix(z.Origin, ".in-addr.arpa.") {
			t.Errorf("reverse zone %q has the wrong origin form", z.Origin)
		}
		ptrs += len(z.Records)
	}
	if ptrs < len(p.Hosts) {
		t.Errorf("%d PTR records for %d names; some addresses have no reverse", ptrs, len(p.Hosts))
	}
}

func TestZoneFileIsWellFormed(t *testing.T) {
	top := loadLab(t)
	p := BuildDNS(top, 42)
	if len(p.Forward) == 0 {
		t.Fatal("no forward zones")
	}
	z := p.Forward[0].ZoneFile()
	for _, want := range []string{"$TTL", "IN SOA", "IN NS", "42"} {
		if !strings.Contains(z, want) {
			t.Errorf("zone file lacks %q:\n%s", want, z)
		}
	}
	conf := p.NamedConf()
	if !strings.Contains(conf, "zone \"group3\"") {
		t.Errorf("named.conf does not declare group3:\n%s", conf)
	}
}

// A name must never resolve to an address the topology does not assign: a stale
// zone is worse than no zone, because it sends debugging in a wrong direction.
func TestNoDNSRecordPointsAtAnUnassignedAddress(t *testing.T) {
	top := loadLab(t)
	p := BuildDNS(top, 1)
	assigned := map[string]bool{}
	for _, d := range top.Devices {
		for _, i := range d.Ifaces {
			if i.Addr4 != "" {
				assigned[strings.SplitN(i.Addr4, "/", 2)[0]] = true
			}
		}
	}
	for name, ip := range p.Hosts {
		if !assigned[ip] {
			t.Errorf("%s resolves to %s, which no interface owns", name, ip)
		}
	}
}
