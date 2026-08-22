package agent

import "testing"

func TestRestoredAddressesIgnoreKernelNoiseButRequireSavedAddresses(t *testing.T) {
	want := []byte("2: eth0    inet 10.3.0.2/24 scope global eth0\n---\n")
	have := []byte("17: eth0@if18    inet 10.3.0.2/24 brd 10.3.0.255 scope global eth0\n" +
		"1: lo    inet 127.0.0.1/8 scope host lo\n---\n")
	if !restoredAddressesPresent(have, want) {
		t.Fatal("restored address was rejected because kernel output changed indices/flags")
	}
	missing := []byte("17: eth0@if18    inet 10.3.0.3/24 scope global eth0\n---\n")
	if restoredAddressesPresent(missing, want) {
		t.Fatal("different restored student address was accepted")
	}
	extra := []byte("17: eth0@if18    inet 10.3.0.2/24 scope global eth0\n" +
		"17: eth0@if18    inet 10.3.0.99/24 scope global eth0\n---\n")
	if restoredAddressesPresent(extra, want) {
		t.Fatal("extra restored student address was accepted")
	}
}

func TestRestoredTunnelsRequireSemanticTunnelAndRouteFacts(t *testing.T) {
	want := []byte("tun6: ipv6/ip remote 3.1.0.1 local 3.2.0.1 ttl 64\n" +
		"default via 2001:db8::1 dev tun6 metric 1024\n")
	have := []byte("tun6: ipv6/ip remote 3.1.0.1 local 3.2.0.1 ttl 255\n" +
		"default via 2001:db8::1 dev tun6 metric 1024 pref medium\n")
	if !restoredTunnelsPresent(have, want) {
		t.Fatal("equivalent restored tunnel was rejected for volatile details")
	}
	if restoredTunnelsPresent([]byte("tun6: ipv6/ip remote 3.9.0.1 local 3.2.0.1 ttl 64\n"), want) {
		t.Fatal("different tunnel endpoint was accepted")
	}
	if restoredTunnelsPresent([]byte("tun6: ipv6/ip remote 3.1.0.1 local 3.2.0.1 ttl 64\n"+
		"tun7: ipv6/ip remote 3.3.0.1 local 3.4.0.1 ttl 64\n"+
		"default via 2001:db8::1 dev tun6 metric 1024\n"), want) {
		t.Fatal("extra student tunnel was accepted")
	}
}

func TestRestoredConfigRetainsSavedStatementsDespiteOrdering(t *testing.T) {
	want := []byte("router bgp 3\n neighbor 10.0.0.1 remote-as 4\n")
	have := []byte("neighbor 10.0.0.1 remote-as 4\nrouter bgp 3\nservice integrated-vtysh-config\n")
	if !restoredConfigContains(have, want) {
		t.Fatal("reordered recovered configuration was rejected")
	}

	if restoredConfigContains([]byte("router bgp 3\n"), want) {
		t.Fatal("missing saved student neighbor statement was accepted")
	}
}

func TestRestoredConfigIgnoresRuntimeOwnedIPv6Forwarding(t *testing.T) {
	want := []byte("hostname PHY\nno ipv6 forwarding\nfrr version 10.0\nrouter bgp 8\nend\n")
	have := []byte("hostname chi.as8\nrouter bgp 8\n")
	if !restoredConfigContains(have, want) {
		t.Fatal("runtime-owned forwarding directive made an otherwise restored configuration fail")
	}
}
