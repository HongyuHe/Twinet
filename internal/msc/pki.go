package msc

import (
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
	defer os.Remove(f.Name())
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
		return cert, key, nil
	}
	if !os.IsNotExist(err) {
		return nil, nil, err
	}
	key, kb, err := keyPair()
	if err != nil {
		return nil, nil, err
	}
	t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Twinet MSC " + name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
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
	certPath := filepath.Join(dir, "x509", "cert.pem")
	cert, err := readCert(certPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err != nil || renew || cert.NotAfter.Before(time.Now().Add(24*time.Hour)) {
		priv, kb, err := keyPair()
		if err != nil {
			return err
		}
		t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: d.ID + ".msc.test"}, DNSNames: []string{d.ID + ".msc.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 1, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
		if ip != "" {
			t.IPAddresses = []net.IP{net.ParseIP(ip)}
		}
		der, err := x509.CreateCertificate(rand.Reader, t, ca, &priv.PublicKey, key)
		if err != nil {
			return err
		}
		if err = writePrivate(filepath.Join(dir, "private", "key.pem"), kb); err != nil {
			return err
		}
		if err = writePrivate(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			return err
		}
	}
	if err = writePrivate(filepath.Join(dir, "x509ca", "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})); err != nil {
		return err
	}
	return e.crl(trust, dir, nil)
}
func (e *Engine) crl(trust, dir string, revoked []*x509.Certificate) error {
	ca, key, err := e.ca(trust)
	if err != nil {
		return err
	}
	numberPath := filepath.Join(e.Dir, "ca", trust, "crl-number")
	number := big.NewInt(time.Now().UnixNano())
	if previous, readErr := os.ReadFile(numberPath); readErr == nil {
		old, ok := new(big.Int).SetString(strings.TrimSpace(string(previous)), 10)
		if !ok {
			return fmt.Errorf("invalid CRL sequence for %s", trust)
		}
		number.Add(old, big.NewInt(1))
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	if err = writePrivate(numberPath, []byte(number.String()+"\n")); err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.RevocationList{Number: number, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(7 * 24 * time.Hour)}
	for _, c := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: c.SerialNumber, RevocationTime: now})
	}
	b, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, key)
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(dir, "x509crl", "ca.crl.pem"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: b}))
}
