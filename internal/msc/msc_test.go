package msc

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
		"peer-label":     func(s *Spec) { s.Device("I_B1").Level = "S2" },
		"missing-link":   func(s *Spec) { s.Links = s.Links[1:] },
		"duplicate-port": func(s *Spec) { s.Links = append(s.Links, s.Links[0]) },
		"local-address":  func(s *Spec) { s.Device("I_A1").Tunnel.Local = "10.99.1.1" },
		"shell-device":   func(s *Spec) { s.Devices[0].ID = "bad;id" },
		"shell-route":    func(s *Spec) { s.Device("R_A1").Routes[0].Via = "1.2.3.4;id" },
		"wrong-layer":    func(s *Spec) { s.Device("I_A1").Tunnel.Peer = "O_B1" },
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
