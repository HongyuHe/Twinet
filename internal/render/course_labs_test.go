package render

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
)

func TestMulticastReferenceRenders(t *testing.T) {
	l, err := manifest.Load("../../examples/multicast")
	if err != nil {
		t.Fatal(err)
	}
	res, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	top := res.Topology
	d, ok := top.DeviceInAS(1, "TOP")
	if !ok {
		t.Fatal("no TOP")
	}
	cfg, err := Router(top, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("PLATFORM:\n%s", cfg.Platform)
	t.Logf("EXPECTED:\n%s", cfg.Expected)
	if strings.Contains(cfg.Platform, "ip pim") {
		t.Error("multicast is the student's work here, but it is in the platform config")
	}
	if !strings.Contains(cfg.Expected, "ip pim") {
		t.Error("the reference solution has no PIM in it")
	}
	if !strings.Contains(cfg.Expected, "ip igmp") {
		t.Error("the reference solution has no IGMP in it")
	}
	if !strings.Contains(cfg.Expected, "ip pim rp 1.156.0.1 237.0.0.0/24") {
		t.Error("the reference solution has no rendezvous point")
	}
	if !strings.Contains(cfg.Platform, "router ospf") {
		t.Error("OSPF is given in this lab, but it is not in the platform config")
	}
	if got := DaemonsFor(top.ASes[1]); !strings.Contains(got, "pimd=yes") {
		t.Error("pimd is not enabled, so none of the above can be configured")
	}
	if got := DaemonsFor(top.ASes[1]); strings.Contains(got, "ldpd=yes") {
		t.Error("a non-MPLS lab starts LDP on every router")
	}
}

// The advanced VPN lab is an exercise only if the answer is not already in it.
//
// Every AS in it was staff-owned and provisioned in full, so the lab deployed
// with LDP, VPNv4 and the route targets already configured and there was
// nothing for a student to do -- while the status ledger claimed the course was
// supported. It is a student system now, with the interior given and the VPN
// left to be built.
func TestTheAdvancedLabLeavesTheExerciseToTheStudent(t *testing.T) {
	l, err := manifest.Load("../../examples/advnet")
	if err != nil {
		t.Fatal(err)
	}
	res, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	top := res.Topology
	if got := DaemonsFor(top.ASes[1]); !strings.Contains(got, "ldpd=yes") {
		t.Fatal("the MPLS exercise cannot start LDP")
	}
	for _, name := range []string{"R1", "R5"} {
		d, ok := top.DeviceInAS(1, name)
		if !ok {
			t.Fatalf("no %s", name)
		}
		cfg, err := Router(top, d)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(cfg.Platform, "mpls ldp") {
			t.Errorf("%s is deployed with LDP already configured, so the exercise is "+
				"already solved:\n%s", name, cfg.Platform)
		}
		if !strings.Contains(cfg.Platform, "router ospf") {
			t.Errorf("%s is not given OSPF, but the exercise says the unicast network "+
				"is built:\n%s", name, cfg.Platform)
		}
		if name == "R1" {
			if strings.Contains(cfg.Platform, "vrf VRF_UBS") {
				t.Errorf("%s is deployed with the customer's routing table already "+
					"attached:\n%s", name, cfg.Platform)
			}
			if !strings.Contains(cfg.Expected, "vrf VRF_UBS") {
				t.Errorf("the reference for %s has no customer VRF in it:\n%s",
					name, cfg.Expected)
			}
			if !strings.Contains(cfg.Expected, "mpls ldp") {
				t.Errorf("the reference for %s has no LDP in it:\n%s", name, cfg.Expected)
			}
		}
	}
	// And the branches are still given: they are ordinary customers and the
	// exercise is not about them.
	d, ok := top.DeviceInAS(20, "BR")
	if !ok {
		t.Fatal("no branch router")
	}
	cfg, err := Router(top, d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.Platform, "router bgp 20") {
		t.Errorf("a branch is not configured, but it is not part of the exercise:\n%s",
			cfg.Platform)
	}
}
