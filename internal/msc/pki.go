package msc

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func writePrivate(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".msc-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if e != nil {
		panic(e)
	}
	return n.Add(n, big.NewInt(1))
}
func keyPair() (*ecdsa.PrivateKey, []byte, error) {
	k, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	b, e := x509.MarshalPKCS8PrivateKey(k)
	return k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), e
}
func readCert(path string) (*x509.Certificate, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, fmt.Errorf("invalid certificate %s", path)
	}
	return x509.ParseCertificate(p.Bytes)
}
func (e *Engine) ca(name string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if _, err := os.Stat(filepath.Join(e.Dir, "credential-worker.json")); err == nil {
		return nil, nil, fmt.Errorf("credential workers cannot create or use CA signing keys; issue credentials on the authority")
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	if !identifier.MatchString(name) && !strings.HasPrefix(name, "management-") {
		return nil, nil, fmt.Errorf("invalid CA name %q", name)
	}
	if strings.ContainsAny(name, "/\\") {
		return nil, nil, fmt.Errorf("invalid CA name")
	}
	dir := filepath.Join(e.Dir, "ca", name)
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	cert, err := readCert(certPath)
	if err == nil {
		b, er := os.ReadFile(keyPath)
		if er != nil {
			return nil, nil, er
		}
		p, _ := pem.Decode(b)
		if p == nil {
			return nil, nil, fmt.Errorf("invalid CA key")
		}
		k, er := x509.ParsePKCS8PrivateKey(p.Bytes)
		if er != nil {
			return nil, nil, er
		}
		key, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("unexpected CA key")
		}
		if !key.PublicKey.Equal(cert.PublicKey) || !cert.IsCA || e.now().Before(cert.NotBefore) || !e.now().Before(cert.NotAfter) {
			return nil, nil, fmt.Errorf("CA %s is invalid, expired, or has a mismatched key", name)
		}
		return cert, key, nil
	}
	if !os.IsNotExist(err) {
		return nil, nil, err
	}
	if _, err := os.Stat(keyPath); err == nil {
		return nil, nil, fmt.Errorf("CA certificate missing but signing key exists: %s", name)
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	key, kb, err := keyPair()
	if err != nil {
		return nil, nil, err
	}
	t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Twinet MSC " + name}, NotBefore: e.now().Add(-time.Hour), NotAfter: e.now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, t, t, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	if err = writePrivate(keyPath, kb); err != nil {
		return nil, nil, err
	}
	if err = writePrivate(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return nil, nil, err
	}
	cert, err = x509.ParseCertificate(der)
	return cert, key, err
}
func (e *Engine) leaf(d *Device, trust, dir, ip string, renew bool) error {
	ca, key, err := e.ca(trust)
	if err != nil {
		return err
	}
	if ca.NotAfter.Before(e.now().Add(31 * 24 * time.Hour)) {
		return fmt.Errorf("CA %s expires within 31 days; explicit coordinated CA rollover is required", trust)
	}
	crl, err := e.canonicalCRL(trust, nil, false)
	if err != nil {
		return err
	}
	certPath := filepath.Join(dir, "x509", "cert.pem")
	cert, err := readCert(certPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if cert != nil && revokedBy(crl, cert) && !renew {
		return fmt.Errorf("%s certificate is revoked; automatic renewal cannot restore authorization", d.ID)
	}
	// Layout edits can move a device to a new management address or trust
	// domain while retaining its private state directory. Reissue that leaf.
	identityMatches := cert != nil && cert.Subject.CommonName == d.ID+".msc.test" && cert.VerifyHostname(d.ID+".msc.test") == nil && cert.CheckSignatureFrom(ca) == nil
	if identityMatches {
		if ip != "" {
			identityMatches = len(cert.IPAddresses) == 1 && cert.IPAddresses[0].Equal(net.ParseIP(ip))
		} else {
			identityMatches = len(cert.IPAddresses) == 0
		}
	}
	if err != nil || renew || !identityMatches || cert.NotAfter.Before(e.now().Add(7*24*time.Hour)) {
		var priv crypto.Signer
		keyPath := filepath.Join(dir, "private", "key.pem")
		if raw, readErr := os.ReadFile(keyPath); readErr == nil && !renew && identityMatches {
			block, _ := pem.Decode(raw)
			if block == nil {
				return fmt.Errorf("invalid private key for %s", d.ID)
			}
			parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
			if parseErr != nil {
				return parseErr
			}
			var ok bool
			priv, ok = parsed.(crypto.Signer)
			if !ok {
				return fmt.Errorf("invalid signing key for %s", d.ID)
			}
		} else if readErr != nil && !os.IsNotExist(readErr) {
			return readErr
		}
		if priv == nil {
			key, kb, keyErr := keyPair()
			if keyErr != nil {
				return keyErr
			}
			priv = key
			if keyErr = writePrivate(keyPath, kb); keyErr != nil {
				return keyErr
			}
		}
		t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: d.ID + ".msc.test"}, DNSNames: []string{d.ID + ".msc.test"}, NotBefore: e.now().Add(-time.Hour), NotAfter: e.now().AddDate(0, 1, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
		if ip != "" {
			t.IPAddresses = []net.IP{net.ParseIP(ip)}
		}
		der, err := x509.CreateCertificate(rand.Reader, t, ca, priv.Public(), key)
		if err != nil {
			return err
		}
		if err = writePrivate(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			return err
		}
	}
	if err := validateKeyPair(certPath, filepath.Join(dir, "private", "key.pem")); err != nil {
		return err
	}
	if err = writePrivate(filepath.Join(dir, "x509ca", "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})); err != nil {
		return err
	}
	return writePrivate(filepath.Join(dir, "x509crl", "ca.crl.pem"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl.Raw}))
}

func validateKeyPair(certPath, keyPath string) error {
	cert, err := readCert(certPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return fmt.Errorf("invalid private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return fmt.Errorf("invalid signing key")
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(public, cert.RawSubjectPublicKeyInfo) {
		return fmt.Errorf("certificate/private-key mismatch: %s", certPath)
	}
	return nil
}
