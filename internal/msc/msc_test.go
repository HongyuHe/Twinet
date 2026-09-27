package msc

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleHasSeparateAppliancesAndManagement(t *testing.T) {
	s := Example()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(s.Devices) != 35 || len(s.Links) != 44 {
		t.Fatalf("devices=%d links=%d", len(s.Devices), len(s.Links))
	}
	counts := map[string]int{}
	for _, d := range s.Devices {
		counts[d.Role]++
		if d.Tunnel != nil {
			if d.Interface("mgmt") == nil {
				t.Fatalf("%s missing dedicated management", d.ID)
			}
			if d.Tunnel.Trust == s.Device("I_A1").Tunnel.Trust && d.Level != "S1" {
				t.Fatal("inner S1 trust shared across levels")
			}
		}
	}
	if counts["inner"] != 4 || counts["outer"] != 4 || counts["firewall"] != 4 || counts["gray-firewall"] != 2 || counts["admin"] != 6 {
		t.Fatal(counts)
	}
}
func TestRejectBrokenTopology(t *testing.T) {
	cases := map[string]func(*Spec){
		"missing-management-address": func(s *Spec) { s.Device("I_A1").Interface("mgmt").Address = "" },
		"missing-admin":              func(s *Spec) { s.Device("I_A1").Admin = "192.0.2.20" },
		"peer-label":                 func(s *Spec) { s.Device("I_B1").Level = "S2" },
		"missing-link":               func(s *Spec) { s.Links = s.Links[1:] },
		"duplicate-port":             func(s *Spec) { s.Links = append(s.Links, s.Links[0]) },
		"local-address":              func(s *Spec) { s.Device("I_A1").Tunnel.Local = "10.99.1.1" },
		"shell-device":               func(s *Spec) { s.Devices[0].ID = "bad;id" },
		"shell-route":                func(s *Spec) { s.Device("R_A1").Routes[0].Via = "1.2.3.4;id" },
		"wrong-layer":                func(s *Spec) { s.Device("I_A1").Tunnel.Peer = "O_B1" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := Example()
			mutate(s)
			if s.Validate() == nil {
				t.Fatal("invalid topology accepted")
			}
		})
	}
}
func TestRoundTripAndUnknownField(t *testing.T) {
	s := Example()
	b, _ := json.Marshal(s)
	path := filepath.Join(t.TempDir(), "spec.json")
	os.WriteFile(path, b, 0600)
	got, err := Load(path)
	if err != nil || got.Hash() != s.Hash() {
		t.Fatal(err)
	}
	b = append([]byte(`{"unexpected":true,`), b[1:]...)
	os.WriteFile(path, b, 0600)
	if _, err = Load(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}
func TestEncryptionFiltersNeverBypassPolicy(t *testing.T) {
	s := Example()
	for _, d := range s.Devices {
		if d.Tunnel == nil {
			continue
		}
		text := filterRules(s, &d)
		if !strings.Contains(text, ":FORWARD DROP") {
			t.Fatal("not fail closed")
		}
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "-A FORWARD") && (!strings.Contains(line, "--pol ipsec") || !strings.Contains(line, "--reqid ")) {
				t.Fatalf("unguarded forward rule: %s", line)
			}
			if strings.Contains(line, "-A FORWARD") && d.Role == "outer" && !strings.Contains(line, "-p esp") && !strings.Contains(line, "--dports 500,4500") {
				t.Fatalf("outer can carry arbitrary Gray plaintext: %s", line)
			}
		}
	}
}
func TestPersistentSeparatePKIAndRevocation(t *testing.T) {
	s := Example()
	e := &Engine{Spec: s, Dir: t.TempDir()}
	a, b, c := s.Device("I_A1"), s.Device("I_B1"), s.Device("I_A2")
	for _, d := range []*Device{a, b, c} {
		if err := e.prepare(d, false); err != nil {
			t.Fatal(err)
		}
	}
	cert, err := readCert(filepath.Join(e.tunnelDir(a), "x509", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ca, _, err := e.ca(a.Tunnel.Trust)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: a.ID + ".msc.test"}); err != nil {
		t.Fatal(err)
	}
	wrongCA, _, _ := e.ca(c.Tunnel.Trust)
	wrong := x509.NewCertPool()
	wrong.AddCert(wrongCA)
	if _, err = cert.Verify(x509.VerifyOptions{Roots: wrong}); err == nil {
		t.Fatal("certificate trusted across security levels")
	}
	if err = e.prepare(a, false); err != nil {
		t.Fatal(err)
	}
	again, _ := readCert(filepath.Join(e.tunnelDir(a), "x509", "cert.pem"))
	if again.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("ordinary up rotated credentials")
	}
	if err = e.crl(a.Tunnel.Trust, e.tunnelDir(b), []*x509.Certificate{cert}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(e.tunnelDir(b), "x509crl", "ca.crl.pem"))
	block, _ := pem.Decode(raw)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err = crl.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("incorrect revocation")
	}
	if err = e.crl(a.Tunnel.Trust, e.tunnelDir(b), nil); err != nil {
		t.Fatal(err)
	}
	freshBytes, _ := os.ReadFile(filepath.Join(e.tunnelDir(b), "x509crl", "ca.crl.pem"))
	freshBlock, _ := pem.Decode(freshBytes)
	fresh, _ := x509.ParseRevocationList(freshBlock.Bytes)
	if fresh.Number.Cmp(crl.Number) <= 0 {
		t.Fatal("CRL sequence did not increase")
	}
	key, err := os.Stat(filepath.Join(e.tunnelDir(a), "private", "key.pem"))
	if err != nil || key.Mode().Perm() != 0600 {
		t.Fatalf("key permissions: %v %v", key, err)
	}
}

func TestGrayBypassIsDetected(t *testing.T) {
	s := Example()
	if !graySeparated(s, "I_A1", "I_A2") {
		t.Fatal("reference cut failed")
	}
	for _, id := range []string{"G_A1", "G_A2"} {
		d := s.Device(id)
		d.Interfaces = append(d.Interfaces, Interface{Name: "bypass", Zone: "gray", Bridge: true})
	}
	s.Links = append(s.Links, Link{Endpoint{"G_A1", "bypass"}, Endpoint{"G_A2", "bypass"}})
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if graySeparated(s, "I_A1", "I_A2") {
		t.Fatal("cross-level bypass escaped the graph check")
	}
}

func TestPairedSAsRejectStalePeerState(t *testing.T) {
	a := "msc ESTABLISHED\n protected INSTALLED, TUNNEL\n in aaaa, 42 packets\n out bbbb, 42 packets"
	b := "msc ESTABLISHED\n protected INSTALLED, TUNNEL\n in bbbb, 42 packets\n out aaaa, 42 packets"
	if !pairedSAs(a, b) {
		t.Fatal("matching pair rejected")
	}
	for _, bad := range []string{"", a, strings.ReplaceAll(b, "bbbb", "cccc"), strings.ReplaceAll(b, "INSTALLED", "CONNECTING")} {
		if pairedSAs(a, bad) {
			t.Fatal("stale or missing peer accepted")
		}
	}
}

func TestPingObservationErrorsCannotPassIsolation(t *testing.T) {
	for _, code := range []int{0, 1, 2, 124, 137} {
		delivered, _, err := pingOutcome(rt.ExecResult{ExitCode: code}, nil)
		if code < 2 {
			if err != nil || delivered != (code == 0) {
				t.Fatalf("normal ping outcome %d: %v %v", code, delivered, err)
			}
		} else if err == nil {
			t.Fatalf("infrastructure status %d accepted as packet evidence", code)
		}
	}
	if _, _, err := pingOutcome(rt.ExecResult{}, errors.New("container absent")); err == nil {
		t.Fatal("runtime error accepted as packet evidence")
	}
}

func TestInterfaceMACsSurviveRecreation(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range Example().Devices {
		for _, iface := range d.Interfaces {
			mac := interfaceMAC("msc", d.ID, iface.Name)
			parsed, err := net.ParseMAC(mac)
			if err != nil || parsed[0]&3 != 2 || seen[mac] {
				t.Fatalf("invalid or duplicate MAC %s", mac)
			}
			if interfaceMAC("msc", d.ID, iface.Name) != mac || interfaceMAC("other", d.ID, iface.Name) == mac {
				t.Fatal("interface identity does not determine its MAC")
			}
			seen[mac] = true
		}
	}
}

func TestConfigurableLayouts(t *testing.T) {
	for levels := 1; levels <= 4; levels++ {
		for outer := 1; outer <= levels; outer++ {
			for gray := 1; gray <= levels; gray++ {
				for _, shared := range []bool{false, true} {
					s, err := Generate(Layout{Name: "variant", Levels: levels, OuterFirewalls: outer, GrayFirewalls: gray, SharedGray: shared})
					if err != nil {
						t.Fatal(err)
					}
					if len(s.Role("firewall")) != 2*outer || len(s.Role("gray-firewall")) != 2*gray {
						t.Fatal("wrong firewall count")
					}
					wantSwitches := 2 * levels
					if shared {
						wantSwitches = 2
					}
					got := 0
					for _, d := range s.Role("switch") {
						if d.Level != "management" {
							got++
						}
					}
					if got != wantSwitches {
						t.Fatal("wrong Gray switch count")
					}
					for _, a := range s.Role("inner") {
						for _, b := range s.Role("inner") {
							if a.Site == b.Site && a.Level != b.Level && !graySeparated(s, a.ID, b.ID) {
								t.Fatalf("Gray bypass %s/%s in %+v", a.ID, b.ID, s)
							}
						}
					}
					for _, of := range s.Role("firewall") {
						rules := filterRules(s, of)
						config := frrConfig(s, of)
						if strings.Contains(config, "ip route ") || !strings.Contains(config, "router ospf") {
							t.Fatal("Black underlay did not use OSPF exclusively")
						}
						for _, port := range of.Interfaces {
							peer, _ := s.Peer(of.ID, port.Name)
							if peer.Role == "outer" {
								expected := "-i " + port.Name + " -o outside -s " + peer.Tunnel.Local + " -d " + peer.Tunnel.Remote
								if !strings.Contains(rules, expected) {
									t.Fatalf("shared Outer Firewall omitted %s", peer.ID)
								}
							}
						}
					}
					for _, gf := range s.Role("gray-firewall") {
						if strings.Contains(frrConfig(s, gf), "router ospf") {
							t.Fatal("OSPF leaked into Gray")
						}
					}
				}
			}
		}
	}
	for _, bad := range []Layout{{Name: "msc", Levels: 2, OuterFirewalls: 0, GrayFirewalls: 1}, {Name: "msc", Levels: 2, OuterFirewalls: 1, GrayFirewalls: 0}, {Name: "msc", Levels: 2, OuterFirewalls: 3, GrayFirewalls: 1}, {Name: "msc", Levels: 9, OuterFirewalls: 1, GrayFirewalls: 1}} {
		if _, err := Generate(bad); err == nil {
			t.Fatal("invalid layout accepted")
		}
	}
}

func TestNativeContainerNamesAndLegacyCompatibility(t *testing.T) {
	s := Example()
	if s.Container("OF_A1") != "OF_A1" {
		t.Fatal("native name has a prefix")
	}
	legacy, err := Load("../../examples/msc/legacy.json")
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Container("OF_A1") != "twinet-msc-of_a1" || legacy.IsFRR(legacy.Device("OF_A1")) {
		t.Fatal("legacy runtime changed")
	}
}

func TestNativePolicyObservations(t *testing.T) {
	if fullNeighbors(`{"neighbors":{"172.21.11.1":[{"nbrState":"Full/DROther"}]}}`) != 1 || fullNeighbors(`{"neighbors":{"172.21.11.1":[{"nbrState":"Init/DROther"}]}}`) != 0 || fullNeighbors("bad") != -1 {
		t.Fatal("OSPF observation accepted an unconverged adjacency")
	}
}

func TestNativeRuntimeCapabilities(t *testing.T) {
	e := &Engine{Spec: Example(), Dir: t.TempDir()}
	top := e.nativeTopology()
	de := e.deployEngine()
	for _, id := range []string{"BLACK", "GF_A", "G_A1"} {
		spec, err := de.RuntimeSpec(context.Background(), top, top.Devices[id])
		if err != nil {
			t.Fatal(err)
		}
		caps := strings.Join(spec.Capabilities, ",")
		if !strings.Contains(caps, "NET_ADMIN") || !strings.Contains(caps, "NET_RAW") || strings.Contains(caps, "SYS_ADMIN") || !spec.ReadOnlyRootfs {
			t.Fatalf("incorrect native hardening on %s: %+v", id, spec)
		}
	}
}

type absentExportRuntime struct{ rt.Runtime }

func (absentExportRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return rt.Container{State: rt.StateAbsent}, nil
}

func TestExportAllowlistAndHashes(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	marker := "PRIVATE-MATERIAL-MUST-NOT-ESCAPE"
	if err := os.WriteFile(filepath.Join(private, "key.pem"), []byte(marker), 0600); err != nil {
		t.Fatal(err)
	}
	e := &Engine{Spec: Example(), Dir: private, Runtime: absentExportRuntime{}}
	destination := filepath.Join(root, "export")
	if err := e.Export(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	if err := e.Export(context.Background(), destination); err == nil {
		t.Fatal("overwrote an export")
	}
	raw, err := os.ReadFile(filepath.Join(destination, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Schema int               `json:"schema_version"`
		Hashes map[string]string `json:"sha256"`
	}
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Schema != 1 || len(manifest.Hashes) == 0 {
		t.Fatalf("bad manifest: %v", err)
	}
	for name, expected := range manifest.Hashes {
		b, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(b)
		if hex.EncodeToString(hash[:]) != expected {
			t.Fatalf("bad digest for %s", name)
		}
		if strings.Contains(string(b), marker) {
			t.Fatalf("export leaked private state through %s", name)
		}
	}
	if _, ok := manifest.Hashes["facts.json"]; !ok {
		t.Fatal("no machine-readable facts")
	}
	if _, ok := manifest.Hashes["devices/BLACK/intended.frr.conf"]; !ok {
		t.Fatal("no intended FRR config")
	}
	if _, ok := manifest.Hashes["devices/BLACK/observed.frr.conf"]; ok {
		t.Fatal("invented observations for an absent router")
	}
}

func TestOSPFReadinessRequiresKernelInstallation(t *testing.T) {
	prefix := "172.20.11.0/30"
	frr := `{"172.20.11.0/30":[{"protocol":"ospf","selected":true,"installed":true}]}`
	kernel := `[{"dst":"172.20.11.0/30"}]`
	if !installedOSPF(frr, kernel)[prefix] {
		t.Fatal("installed route rejected")
	}
	for _, candidate := range []string{`{}`, strings.ReplaceAll(frr, `"installed":true`, `"installed":false`), strings.ReplaceAll(frr, `"selected":true`, `"selected":false`), strings.ReplaceAll(frr, `"ospf"`, `"static"`)} {
		if installedOSPF(candidate, kernel)[prefix] {
			t.Fatal("uninstalled or non-OSPF route accepted")
		}
	}
	if installedOSPF(frr, `[]`)[prefix] || installedOSPF(frr, `invalid`)[prefix] {
		t.Fatal("missing kernel route accepted")
	}
}

func TestOVSObservationPreservesFlowTable(t *testing.T) {
	baseline := strings.Join(canonicalOVSFlows(" priority=0 actions=NORMAL\n"), "\n")
	moved := strings.Join(canonicalOVSFlows(" table=1, priority=0 actions=NORMAL\n"), "\n")
	if baseline == moved {
		t.Fatal("flow table change disappeared from observations")
	}
}

func TestLayoutChangesReissueManagementIdentity(t *testing.T) {
	e := &Engine{Spec: Example(), Dir: t.TempDir()}
	d := e.Spec.Device("O_A1")
	if err := e.prepare(d, false); err != nil {
		t.Fatal(err)
	}
	before, err := readCert(filepath.Join(e.tlsDir(d), "x509", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"172.30.109.42/24", "172.31.109.42/24"} {
		d.Interface("mgmt").Address = address
		if err := e.prepare(d, false); err != nil {
			t.Fatal(err)
		}
		after, err := readCert(filepath.Join(e.tlsDir(d), "x509", "cert.pem"))
		if err != nil {
			t.Fatal(err)
		}
		ca, err := readCert(filepath.Join(e.tlsDir(d), "x509ca", "ca.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if after.SerialNumber.Cmp(before.SerialNumber) == 0 || after.VerifyHostname(strings.Split(address, "/")[0]) != nil || after.CheckSignatureFrom(ca) != nil {
			t.Fatal("layout retained an obsolete identity or issuer")
		}
		before = after
	}
}

type staleSpecRuntime struct {
	rt.Runtime
	lab, dir string
}

func (r staleSpecRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return rt.Container{State: rt.StateRunning, Labels: map[string]string{"twinet.msc.lab": r.lab, "twinet.msc.state": r.dir, "twinet.msc.spec": "previous-deployment"}}, nil
}
func (staleSpecRuntime) Exec(context.Context, string, rt.ExecCmd) (rt.ExecResult, error) {
	return rt.ExecResult{Stdout: "{}"}, nil
}

func TestExportKeepsDeployedAndIntendedSpecsDistinct(t *testing.T) {
	e := &Engine{Spec: Example(), Dir: t.TempDir()}
	e.Runtime = staleSpecRuntime{lab: e.Spec.Name, dir: e.Dir}
	destination := filepath.Join(t.TempDir(), "export")
	if err := e.Export(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(destination, "facts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var facts struct {
		SpecHash string `json:"spec_sha256"`
		Devices  []struct {
			Deployed string `json:"deployed_spec_sha256"`
		} `json:"devices"`
	}
	if err = json.Unmarshal(raw, &facts); err != nil {
		t.Fatal(err)
	}
	if facts.SpecHash != e.Spec.Hash() || len(facts.Devices) != len(e.Spec.Devices) {
		t.Fatal("missing intended specification")
	}
	for _, d := range facts.Devices {
		if d.Deployed != "previous-deployment" {
			t.Fatal("relabelled old observations as the new specification")
		}
	}
}
