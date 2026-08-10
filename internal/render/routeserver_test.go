package render

import (
	"strings"
	"testing"
)

// An exchange is a shared fabric, so its route server's peers are the members
// of that fabric, not the switch at the end of its cable. Discovering peers the
// way an ordinary router does finds nobody, and the exchange silently carries
// no routes at all -- which is exactly what a live deployment showed.
func TestRouteServerPeersWithEveryMember(t *testing.T) {
	top := loadCOS461(t)
	rs, ok := top.DeviceInAS(140, "RS")
	if !ok {
		t.Fatal("no route server in AS 140")
	}
	members := ExchangeMembers(top, 140)
	if len(members) < 2 {
		t.Fatalf("exchange 140 has %d members, expected several", len(members))
	}
	cfg, err := Router(top, rs)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if !strings.Contains(cfg.Platform, "neighbor "+m.Addr+" remote-as") {
			t.Errorf("the route server does not peer with member AS%d at %s", m.ASN, m.Addr)
		}
		if !strings.Contains(cfg.Platform, "neighbor "+m.Addr+" route-server-client") {
			t.Errorf("member AS%d is not configured as a route-server client", m.ASN)
		}
		// Question 2.4 turns entirely on this: relay only on a community match.
		want := "match community RELAY-" + itoa(m.ASN)
		if !strings.Contains(cfg.Platform, want) {
			t.Errorf("no community gate for member AS%d", m.ASN)
		}
	}
	// An exchange must not originate address space of its own.
	if strings.Contains(cfg.Platform, "network 140.0.0.0/8") {
		t.Error("the route server originates its own prefix, which an exchange must not do")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
