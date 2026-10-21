package msc

import (
	"strings"
	"testing"
)

func constructionSpec(t *testing.T, name string) *Spec {
	t.Helper()
	s, err := Load("../../examples/msc/construction/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConstructionFlowGuards(t *testing.T) {
	s := constructionSpec(t, "shared-four-levels")
	outer := s.Device("O_A1")
	text := filterRules(s, outer)
	for _, flow := range outer.Tunnel.Flows {
		for _, direction := range []string{"in", "out"} {
			if !strings.Contains(text, "--dir "+direction+" --pol ipsec --mode tunnel --reqid 201") {
				t.Fatal("missing policy guard", direction)
			}
		}
		if !strings.Contains(text, "-i "+flow.Inside+" -o black -s "+flow.Local+" -d "+flow.Remote) {
			t.Fatal("flow omitted", flow)
		}
	}
	gf := s.Device("GF_A")
	rules := filterRules(s, gf)
	for _, f := range gf.BoundaryFlows {
		if !strings.Contains(rules, "-i "+f.Ingress+" -o "+f.Egress+" -s "+f.Source+" -d "+f.Destination+" -p esp -j ACCEPT") {
			t.Fatal("boundary omitted", f)
		}
	}
	for _, a := range s.Role("inner") {
		for _, b := range s.Role("inner") {
			if a.Site == b.Site && a.Level != b.Level && !graySeparated(s, a.ID, b.ID) {
				t.Fatal("Gray bypass", a.ID, b.ID)
			}
		}
	}
	if strings.Count(swanConfig(outer), "auth = ecdsa-384-sha384") != 2 {
		t.Fatal("authentication constraints missing")
	}
}

func TestConstructionInvalidFlowInputs(t *testing.T) {
	cases := map[string]func(*Spec){
		"boundary-port":      func(s *Spec) { s.Device("GF_A").BoundaryFlows[0].Ingress = "absent" },
		"boundary-same-port": func(s *Spec) { s.Device("GF_A").BoundaryFlows[0].Egress = s.Device("GF_A").BoundaryFlows[0].Ingress },
		"boundary-selector":  func(s *Spec) { s.Device("GF_A").BoundaryFlows[0].Source = "10.0.0.0/99" },
		"protected-port":     func(s *Spec) { s.Device("O_A1").Tunnel.Flows[0].Inside = "black" },
		"protected-selector": func(s *Spec) { s.Device("O_A1").Tunnel.Flows[0].Local = "0.0.0.0/0" },
		"protected-ipv6":     func(s *Spec) { s.Device("O_A1").Tunnel.Flows[0].Remote = "::/0" },
		"negative-metric":    func(s *Spec) { s.Device("R_A1").Routes[0].Metric = -1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := constructionSpec(t, "shared-four-levels")
			mutate(s)
			if s.Validate() == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}

func TestConstructionRouteMetrics(t *testing.T) {
	r := Route{Prefix: "10.0.0.0/24", Via: "192.0.2.1", Metric: 100}
	if got := strings.Join(routeCommand(r), " "); !strings.HasSuffix(got, "proto static metric 100") {
		t.Fatal(got)
	}
	r.Metric = 0
	if strings.Contains(strings.Join(routeCommand(r), " "), "metric") {
		t.Fatal("unspecified metric emitted")
	}
}

func TestConstructionGrayProbeSelectsOnLinkFirewallWithoutTargetRoute(t *testing.T) {
	s := constructionSpec(t, "shared-four-levels")
	from := s.Device("I_A4")
	from.Routes = nil
	gateway, port, err := s.grayProbeGateway(from)
	if err != nil || gateway.ID != "GF_A" || port != "s4" {
		t.Fatalf("%v %s %v", gateway, port, err)
	}
	copy := *gateway
	copy.ID = "other"
	s.Devices = append(s.Devices, copy)
	if _, _, err = s.grayProbeGateway(from); err == nil {
		t.Fatal("ambiguous firewall accepted")
	}
}

func TestNativeGrayRouterKeepsStaticForwarding(t *testing.T) {
	s := constructionSpec(t, "native-redundant-four-levels")
	d := s.Device("NR_GR_A")
	if !s.IsFRR(d) || s.IsOSPF(d) {
		t.Fatal("Gray router must use FRR static forwarding")
	}
	if !strings.Contains(frrConfig(s, d), "ip route ") || strings.Contains(frrConfig(s, d), "router ospf") {
		t.Fatal("unexpected Gray routing daemon configuration")
	}
	if !s.IsOSPF(s.Device("NR_BLACK")) {
		t.Fatal("Black transport lost OSPF")
	}
	d.Routes[0].Metric = 20
	if s.Validate() == nil {
		t.Fatal("native FRR silently ignored Linux metric")
	}
}

func TestSameLevelIndependentNetworksRemainIsolated(t *testing.T) {
	a := &Device{Level: "SECRET-US-only", Network: "NETWORK-1"}
	b := &Device{Level: "SECRET-US-only", Network: "NETWORK-2"}
	if sameRedNetwork(a, b) {
		t.Fatal("level equality erased network identity")
	}
	b.Network = "NETWORK-1"
	if !sameRedNetwork(a, b) {
		t.Fatal("same-network useful traffic rejected")
	}
	b.Level = "SECRET-Coalition"
	if sameRedNetwork(a, b) {
		t.Fatal("network equality erased full level")
	}
}
