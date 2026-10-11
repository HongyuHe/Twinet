package msc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func credentialFixture(t *testing.T) (*Engine, *time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	e := &Engine{Spec: Example(), Dir: t.TempDir(), Now: func() time.Time { return now }}
	return e, &now
}
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func cloneBundle(t *testing.T, b CredentialBundle) CredentialBundle {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var out CredentialBundle
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCRLRenewalPreservesRevocationsAndMigratesLegacy(t *testing.T) {
	e, now := credentialFixture(t)
	a, b := e.Spec.Device("I_A1"), e.Spec.Device("I_B1")
	for _, d := range []*Device{a, b} {
		if err := e.prepare(d, false); err != nil {
			t.Fatal(err)
		}
	}
	cert, err := readCert(filepath.Join(e.tunnelDir(a), "x509/cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err = e.crl(a.Tunnel.Trust, e.tunnelDir(b), []*x509.Certificate{cert}); err != nil {
		t.Fatal(err)
	}
	ca, _, err := e.ca(a.Tunnel.Trust)
	if err != nil {
		t.Fatal(err)
	}
	old, err := readCRL(filepath.Join(e.tunnelDir(b), "x509crl/ca.crl.pem"), ca)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(e.Dir, "ca", a.Tunnel.Trust, "crl.pem")); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(8 * 24 * time.Hour)
	fresh, err := e.canonicalCRL(a.Tunnel.Trust, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !revokedBy(fresh, cert) || fresh.Number.Cmp(old.Number) <= 0 || !fresh.NextUpdate.After(*now) {
		t.Fatal("stale revocation data was lost or not renewed")
	}
	again, err := e.canonicalCRL(a.Tunnel.Trust, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Raw, fresh.Raw) {
		t.Fatal("fresh CRL unnecessarily replaced")
	}
	if err = e.leaf(a, a.Tunnel.Trust, e.tunnelDir(a), "", false); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatal("automatic renewal restored revoked authorization", err)
	}
	if err = e.prepare(a, true); err != nil {
		t.Fatal(err)
	}
	replacement, err := readCert(filepath.Join(e.tunnelDir(a), "x509/cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if replacement.SerialNumber.Cmp(cert.SerialNumber) == 0 {
		t.Fatal("explicit fault recovery did not issue a replacement")
	}
	retained, err := e.canonicalCRL(a.Tunnel.Trust, nil, false)
	if err != nil || !revokedBy(retained, cert) {
		t.Fatal("fault recovery erased old revocation", err)
	}
}

func TestLeafRenewalRetainsCAAndPrivateKey(t *testing.T) {
	e, now := credentialFixture(t)
	d := e.Spec.Device("I_A1")
	if err := e.prepare(d, false); err != nil {
		t.Fatal(err)
	}
	dir := e.tunnelDir(d)
	key := mustRead(t, filepath.Join(dir, "private/key.pem"))
	ca := mustRead(t, filepath.Join(dir, "x509ca/ca.pem"))
	before := mustRead(t, filepath.Join(dir, "x509/cert.pem"))
	*now = now.Add(25 * 24 * time.Hour)
	if err := e.leaf(d, d.Tunnel.Trust, dir, "", false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, mustRead(t, filepath.Join(dir, "private/key.pem"))) || !bytes.Equal(ca, mustRead(t, filepath.Join(dir, "x509ca/ca.pem"))) || bytes.Equal(before, mustRead(t, filepath.Join(dir, "x509/cert.pem"))) {
		t.Fatal("renewal changed key/CA or failed to renew leaf")
	}
	*now = now.Add(320 * 24 * time.Hour)
	if err := e.leaf(d, d.Tunnel.Trust, dir, "", false); err == nil || !strings.Contains(err.Error(), "rollover") {
		t.Fatal("expiring CA did not require coordinated rollover", err)
	}
}

func TestCredentialWorkerPlacementAndIsolation(t *testing.T) {
	e, _ := credentialFixture(t)
	plan := e.LocalCredentialTargets()
	a := plan.Workers[0]
	a.Name = "site-a"
	a.Devices = nil
	b := CredentialWorker{Name: "site-b", SSH: "hy@worker-b", Binary: "/usr/local/bin/twinet", StateDir: "/var/lib/twinet/msc"}
	for _, id := range plan.Workers[0].Devices {
		if e.Spec.Device(id).Site == "A" {
			a.Devices = append(a.Devices, id)
		} else {
			b.Devices = append(b.Devices, id)
		}
	}
	plan.Workers = []CredentialWorker{a, b}
	if err := e.ValidateCredentialTargets(plan); err != nil {
		t.Fatal(err)
	}
	bundle, err := e.BuildCredentialBundle(b, true)
	if err != nil {
		t.Fatal(err)
	}
	worker := &Engine{Spec: e.Spec, Dir: t.TempDir(), Runtime: absentExportRuntime{}}
	if err = worker.ApplyCredentialBundle(context.Background(), bundle, true); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(worker.Dir, "ca")); !os.IsNotExist(err) {
		t.Fatal("CA private state reached worker")
	}
	if _, err = os.Stat(filepath.Join(worker.Dir, "devices", "I_A1")); !os.IsNotExist(err) {
		t.Fatal("another worker's private leaf reached worker")
	}
	if err = worker.prepare(e.Spec.Device("I_B1"), false); err == nil {
		t.Fatal("worker generated its own independent CA")
	}
	if _, _, err = worker.ca("inner-s1"); err == nil {
		t.Fatal("worker used the lower-level issuer to create a CA")
	}
	if _, err = os.Stat(filepath.Join(worker.Dir, "ca")); !os.IsNotExist(err) {
		t.Fatal("failed worker issuance still created CA private state")
	}
	plan.Workers[1].Devices = append(plan.Workers[1].Devices, a.Devices[0])
	if err = e.ValidateCredentialTargets(plan); err == nil {
		t.Fatal("duplicate device assignment accepted")
	}
}

func TestCredentialBundleRejectsTamperingRollbackAndTrustChange(t *testing.T) {
	e, now := credentialFixture(t)
	w := CredentialWorker{Name: "worker", Devices: []string{"I_A1"}}
	bundle, err := e.BuildCredentialBundle(w, true)
	if err != nil {
		t.Fatal(err)
	}
	worker := &Engine{Spec: e.Spec, Dir: t.TempDir(), Runtime: absentExportRuntime{}, Now: e.Now}
	if err = worker.ApplyCredentialBundle(context.Background(), bundle, true); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*CredentialBundle){
		"ca-key":       func(b *CredentialBundle) { b.Entries[0].Files["ca-key.pem"] = []byte("forbidden") },
		"missing-key":  func(b *CredentialBundle) { delete(b.Entries[0].Files, "private/key.pem") },
		"wrong-device": func(b *CredentialBundle) { b.Entries[0].Device = "I_B1" },
		"wrong-kind":   func(b *CredentialBundle) { b.Entries[0].Kind = "../../ca" },
		"changed-spec": func(b *CredentialBundle) { b.Spec.Name = "different" },
		"bad-signature": func(b *CredentialBundle) {
			block, _ := pem.Decode(b.Entries[0].Files["x509crl/ca.crl.pem"])
			block.Bytes[len(block.Bytes)-1] ^= 1
			b.Entries[0].Files["x509crl/ca.crl.pem"] = pem.EncodeToMemory(block)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := cloneBundle(t, bundle)
			mutate(&bad)
			if err := worker.ValidateCredentialBundle(bad); err == nil {
				t.Fatal("invalid bundle accepted")
			}
		})
	}
	other, _ := credentialFixture(t)
	foreign, err := other.BuildCredentialBundle(w, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = worker.ValidateCredentialBundle(foreign); err == nil {
		t.Fatal("uncoordinated CA replacement accepted")
	}
	*now = now.Add(8 * 24 * time.Hour)
	if err = worker.ValidateCredentialBundle(bundle); err == nil {
		t.Fatal("expired CRL accepted")
	}
	fresh, err := e.BuildCredentialBundle(w, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = worker.ApplyCredentialBundle(context.Background(), fresh, true); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(-8 * 24 * time.Hour)
	if err = worker.ValidateCredentialBundle(bundle); err == nil {
		t.Fatal("old signed CRL accepted after newer sequence")
	}
}

func TestSignedRevocationRemovalRejected(t *testing.T) {
	e, _ := credentialFixture(t)
	a, b := e.Spec.Device("I_A1"), e.Spec.Device("I_B1")
	for _, d := range []*Device{a, b} {
		if err := e.prepare(d, false); err != nil {
			t.Fatal(err)
		}
	}
	revoked, err := readCert(filepath.Join(e.tunnelDir(b), "x509/cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err = e.crl(a.Tunnel.Trust, e.tunnelDir(a), []*x509.Certificate{revoked}); err != nil {
		t.Fatal(err)
	}
	bundle, err := e.BuildCredentialBundle(CredentialWorker{Name: "worker", Devices: []string{a.ID}}, true)
	if err != nil {
		t.Fatal(err)
	}
	worker := &Engine{Spec: e.Spec, Dir: t.TempDir(), Runtime: absentExportRuntime{}}
	if err = worker.ApplyCredentialBundle(context.Background(), bundle, true); err != nil {
		t.Fatal(err)
	}
	ca, key, err := e.ca(a.Tunnel.Trust)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(bundle.Entries[0].Files["x509crl/ca.crl.pem"])
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	crl.Number.Add(crl.Number, serial())
	cleared := &x509.RevocationList{Number: crl.Number, ThisUpdate: crl.ThisUpdate, NextUpdate: crl.NextUpdate}
	der, err := x509.CreateRevocationList(rand.Reader, cleared, ca, key)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Entries[0].Files["x509crl/ca.crl.pem"] = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	if err = worker.ValidateCredentialBundle(bundle); err == nil {
		t.Fatal("validly signed removal of a revocation accepted")
	}
}

func TestRenewalRefusesActiveFaultAndReportsFailure(t *testing.T) {
	e, _ := credentialFixture(t)
	if err := os.WriteFile(filepath.Join(e.Dir, "fault.json"), []byte(`{"kind":"revoke"}`), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := e.RenewCredentials(context.Background(), e.LocalCredentialTargets(), false, false)
	if err == nil || report.Passed {
		t.Fatal("active fault was silently recovered")
	}
	var saved CredentialReport
	if err = json.Unmarshal(mustRead(t, filepath.Join(e.Dir, "credential-renewal.json")), &saved); err != nil || saved.Passed {
		t.Fatal("missing failure report", err)
	}
}
