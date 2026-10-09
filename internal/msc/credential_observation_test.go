package msc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestPublicCredentialAuditRetainsRetrievalLocations(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "control-uri-fixture"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: []string{"http://crl.example.test/current", "ldap://directory.example.test/crl"},
		OCSPServer:            []string{"http://ocsp.example.test/check"},
		IssuingCertificateURL: []string{"http://ca.example.test/issuer"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	audit, err := auditPublicCredentials(public, public, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(audit.Certificates) != 1 {
		t.Fatal("missing URI fixture certificate")
	}
	cert := audit.Certificates[0]
	if !reflect.DeepEqual(cert.CRLDistributionPoints, template.CRLDistributionPoints) ||
		!reflect.DeepEqual(cert.OCSPServers, template.OCSPServer) ||
		!reflect.DeepEqual(cert.IssuingCertificateURLs, template.IssuingCertificateURL) {
		t.Fatal("public retrieval locations changed or disappeared")
	}
}

func TestPublicCredentialAuditRetainsValidityRevocationAndTrust(t *testing.T) {
	spec := Example()
	engine := &Engine{Spec: spec, Dir: t.TempDir()}
	a, b, other := spec.Device("I_A1"), spec.Device("I_B1"), spec.Device("I_A2")
	for _, d := range []*Device{a, b, other} {
		if err := engine.prepare(d, false); err != nil {
			t.Fatal(err)
		}
	}
	read := func(device *Device, relative string) []byte {
		b, err := os.ReadFile(filepath.Join(engine.tunnelDir(device), relative))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	root := read(a, "x509ca/ca.pem")
	loaded := append(append(append([]byte{}, read(a, "x509/cert.pem")...), read(b, "x509/cert.pem")...), root...)
	loaded = append(loaded, read(a, "x509crl/ca.crl.pem")...)
	audit, err := auditPublicCredentials(loaded, root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(audit.Certificates) != 3 || len(audit.CRLs) != 1 || len(audit.Anchors) != 1 {
		t.Fatal("incomplete public inventory")
	}
	for _, cert := range audit.Certificates {
		if cert.PublicKeyBits != 384 || cert.Curve != "P-384" || !cert.Verifications[0].Valid || cert.NotAfter <= audit.AtEpoch {
			t.Fatalf("bad certificate audit: %+v", cert)
		}
	}
	if !audit.CRLs[0].Verifications[0].Valid || audit.CRLs[0].NextUpdate <= audit.AtEpoch {
		t.Fatal("bad CRL audit")
	}
	wrong, err := auditPublicCredentials(loaded, read(other, "x509ca/ca.pem"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range wrong.Certificates {
		if cert.Verifications[0].Valid {
			t.Fatal("wrong-domain anchor accepted")
		}
	}
	expired, err := auditPublicCredentials(loaded, root, time.Now().Add(2*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range expired.Certificates {
		if cert.Verifications[0].Valid {
			t.Fatal("expired certificate accepted")
		}
	}
	peer, err := readCert(filepath.Join(engine.tunnelDir(b), "x509/cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.crl(a.Tunnel.Trust, engine.tunnelDir(a), []*x509.Certificate{peer}); err != nil {
		t.Fatal(err)
	}
	revoked, err := auditPublicCredentials(read(a, "x509crl/ca.crl.pem"), root, time.Now())
	if err != nil || len(revoked.CRLs) != 1 || len(revoked.CRLs[0].RevokedSerials) != 1 || revoked.CRLs[0].RevokedSerials[0] != peer.SerialNumber.Text(16) {
		t.Fatal("revocation serial discarded", err)
	}
	block, _ := pem.Decode(read(b, "x509/cert.pem"))
	block.Bytes[len(block.Bytes)-1] ^= 1
	tampered, err := auditPublicCredentials(pem.EncodeToMemory(block), root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if tampered.Certificates[0].Verifications[0].Valid {
		t.Fatal("invalid public signature accepted")
	}
	for _, raw := range [][]byte{[]byte("unexpected"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})} {
		if _, err = auditPublicCredentials(raw, root, time.Now()); err == nil {
			t.Fatal("unsupported public observation accepted")
		}
	}
}
