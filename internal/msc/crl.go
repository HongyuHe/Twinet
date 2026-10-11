package msc

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type credentialBinding struct {
	Device          *Device
	Kind, Trust, IP string
}

func (e *Engine) credentialBindings() []credentialBinding {
	var out []credentialBinding
	for i := range e.Spec.Devices {
		d := &e.Spec.Devices[i]
		if d.Tunnel != nil {
			out = append(out, credentialBinding{Device: d, Kind: "swanctl", Trust: d.Tunnel.Trust})
		}
		if port := d.Interface("mgmt"); port != nil {
			ip := strings.Split(port.Address, "/")[0]
			domain := ip[:strings.LastIndex(ip, ".")]
			out = append(out, credentialBinding{Device: d, Kind: "tls", Trust: "management-" + strings.ReplaceAll(domain, ".", "-"), IP: ip})
		}
	}
	return out
}

func (e *Engine) bindingDir(b credentialBinding) string {
	return filepath.Join(e.Dir, "devices", b.Device.ID, b.Kind)
}

func readCRL(path string, ca *x509.Certificate) (*x509.RevocationList, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "X509 CRL" || strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("invalid CRL: %s", path)
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err = crl.CheckSignatureFrom(ca); err != nil {
		return nil, fmt.Errorf("CRL signature %s: %w", path, err)
	}
	if crl.Number == nil || !crl.NextUpdate.After(crl.ThisUpdate) {
		return nil, fmt.Errorf("invalid CRL sequence/validity: %s", path)
	}
	return crl, nil
}

func revokedBy(crl *x509.RevocationList, cert *x509.Certificate) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

// The authority keeps a canonical signed CRL per trust domain. On upgrade, all
// existing device CRLs are merged into it, including expired lists. A refresh
// never removes revocations or rolls the sequence backwards. The caller holds
// the authority state lock, so two renewal processes cannot fork its sequence.
func (e *Engine) canonicalCRL(trust string, revoked []*x509.Certificate, force bool) (*x509.RevocationList, error) {
	ca, key, err := e.ca(trust)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(e.Dir, "ca", trust, "crl.pem")
	paths := []string{path}
	for _, b := range e.credentialBindings() {
		if b.Trust == trust {
			paths = append(paths, filepath.Join(e.bindingDir(b), "x509crl", "ca.crl.pem"))
		}
	}
	entries := map[string]x509.RevocationListEntry{}
	maxNumber := big.NewInt(0)
	var canonical *x509.RevocationList
	for _, p := range paths {
		if p != path {
			anchor, readErr := readCert(filepath.Join(filepath.Dir(filepath.Dir(p)), "x509ca", "ca.pem"))
			if readErr == nil && publicFingerprint(anchor.Raw) != publicFingerprint(ca.Raw) {
				continue
			}
			if readErr != nil && !os.IsNotExist(readErr) {
				return nil, readErr
			}
		}
		crl, readErr := readCRL(p, ca)
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
		if p == path {
			canonical = crl
		}
		if crl.Number.Cmp(maxNumber) > 0 {
			maxNumber.Set(crl.Number)
		}
		for _, entry := range crl.RevokedCertificateEntries {
			serial := entry.SerialNumber.Text(16)
			if old, exists := entries[serial]; !exists || entry.RevocationTime.Before(old.RevocationTime) {
				entries[serial] = entry
			}
		}
	}
	numberPath := filepath.Join(e.Dir, "ca", trust, "crl-number")
	if raw, readErr := os.ReadFile(numberPath); readErr == nil {
		n, ok := new(big.Int).SetString(strings.TrimSpace(string(raw)), 10)
		if !ok || n.Sign() < 0 {
			return nil, fmt.Errorf("invalid CRL sequence for %s", trust)
		}
		if n.Cmp(maxNumber) > 0 {
			maxNumber.Set(n)
		}
	} else if !os.IsNotExist(readErr) {
		return nil, readErr
	}
	for _, cert := range revoked {
		if err := cert.CheckSignatureFrom(ca); err != nil {
			return nil, fmt.Errorf("cannot revoke certificate from another CA: %w", err)
		}
		serial := cert.SerialNumber.Text(16)
		if _, exists := entries[serial]; !exists {
			entries[serial] = x509.RevocationListEntry{SerialNumber: cert.SerialNumber, RevocationTime: e.now()}
		}
	}
	if !force && canonical != nil && canonical.Number.Cmp(maxNumber) == 0 && canonical.NextUpdate.After(e.now().Add(48*time.Hour)) && !canonical.ThisUpdate.After(e.now()) && len(canonical.RevokedCertificateEntries) == len(entries) {
		return canonical, nil
	}
	number := new(big.Int).Add(maxNumber, big.NewInt(1))
	next := e.now().Add(7 * 24 * time.Hour)
	if next.After(ca.NotAfter) {
		next = ca.NotAfter
	}
	template := &x509.RevocationList{Number: number, ThisUpdate: e.now().Add(-time.Minute), NextUpdate: next}
	for _, entry := range entries {
		template.RevokedCertificateEntries = append(template.RevokedCertificateEntries, entry)
	}
	sort.Slice(template.RevokedCertificateEntries, func(i, j int) bool {
		return template.RevokedCertificateEntries[i].SerialNumber.Cmp(template.RevokedCertificateEntries[j].SerialNumber) < 0
	})
	der, err := x509.CreateRevocationList(rand.Reader, template, ca, key)
	if err != nil {
		return nil, err
	}
	if err = writePrivate(numberPath, []byte(number.String()+"\n")); err != nil {
		return nil, err
	}
	if err = writePrivate(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})); err != nil {
		return nil, err
	}
	return x509.ParseRevocationList(der)
}

func (e *Engine) crl(trust, dir string, revoked []*x509.Certificate) error {
	crl, err := e.canonicalCRL(trust, revoked, true)
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(dir, "x509crl", "ca.crl.pem"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl.Raw}))
}
