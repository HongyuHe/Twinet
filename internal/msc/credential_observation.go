package msc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"time"
)

// PublicVerification records a trusted library result against one explicit
// anchor. The Lean model checks its policy use; it does not reprove X.509 math.
type PublicVerification struct {
	Anchor string `json:"anchor"`
	Valid  bool   `json:"valid"`
	Error  string `json:"error"`
}

type PublicCertificateEvidence struct {
	Fingerprint                 string               `json:"fingerprint"`
	Subject                     string               `json:"subject"`
	Issuer                      string               `json:"issuer"`
	Serial                      string               `json:"serial"`
	NotBefore                   int64                `json:"not_before"`
	NotAfter                    int64                `json:"not_after"`
	PublicKeyAlgorithm          string               `json:"public_key_algorithm"`
	PublicKeyBits               int                  `json:"public_key_bits"`
	Curve                       string               `json:"curve"`
	SignatureAlgorithm          string               `json:"signature_algorithm"`
	IsCA                        bool                 `json:"is_ca"`
	BasicConstraintsValid       bool                 `json:"basic_constraints_valid"`
	KeyUsage                    int                  `json:"key_usage"`
	ExtendedKeyUsage            []int                `json:"extended_key_usage"`
	UnknownExtendedKeyUsage     []string             `json:"unknown_extended_key_usage"`
	UnhandledCriticalExtensions []string             `json:"unhandled_critical_extensions"`
	DNSNames                    []string             `json:"dns_names"`
	CRLDistributionPoints       []string             `json:"crl_distribution_points"`
	OCSPServers                 []string             `json:"ocsp_servers"`
	IssuingCertificateURLs      []string             `json:"issuing_certificate_urls"`
	SubjectKeyID                string               `json:"subject_key_id"`
	AuthorityKeyID              string               `json:"authority_key_id"`
	Verifications               []PublicVerification `json:"verifications"`
}

type PublicCRLEvidence struct {
	Fingerprint        string               `json:"fingerprint"`
	Issuer             string               `json:"issuer"`
	AuthorityKeyID     string               `json:"authority_key_id"`
	ThisUpdate         int64                `json:"this_update"`
	NextUpdate         int64                `json:"next_update"`
	Number             string               `json:"number"`
	SignatureAlgorithm string               `json:"signature_algorithm"`
	RevokedSerials     []string             `json:"revoked_serials"`
	Verifications      []PublicVerification `json:"verifications"`
}

type PublicCredentialAudit struct {
	AtEpoch      int64                       `json:"at_epoch"`
	PEMSHA256    string                      `json:"pem_sha256"`
	Anchors      []string                    `json:"anchors"`
	Certificates []PublicCertificateEvidence `json:"certificates"`
	CRLs         []PublicCRLEvidence         `json:"crls"`
}

func publicFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// decodePublicPEM accepts only certificate and CRL blocks. Extra bytes, PEM
// headers, private keys, and unsupported object kinds make observation fail.
func decodePublicPEM(raw []byte) ([]*x509.Certificate, []*x509.RevocationList, error) {
	certs := []*x509.Certificate{}
	crls := []*x509.RevocationList{}
	for len(bytes.TrimSpace(raw)) > 0 {
		raw = bytes.TrimSpace(raw)
		if !bytes.HasPrefix(raw, []byte("-----BEGIN ")) {
			return nil, nil, fmt.Errorf("unexpected public PEM preamble")
		}
		block, rest := pem.Decode(raw)
		if block == nil || len(block.Headers) != 0 {
			return nil, nil, fmt.Errorf("malformed public PEM block")
		}
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			certs = append(certs, cert)
		case "X509 CRL":
			crl, err := x509.ParseRevocationList(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			crls = append(crls, crl)
		default:
			return nil, nil, fmt.Errorf("unsupported public PEM object %q", block.Type)
		}
		raw = rest
	}
	return certs, crls, nil
}

func verification(anchor string, err error) PublicVerification {
	result := PublicVerification{Anchor: anchor, Valid: err == nil}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

// auditPublicCredentials checks the loaded public objects against the explicitly
// configured public trust file. It reads no private keys and changes no state.
// Certificate-path checks use Any EKU; the admission model separately requires
// the selected IKE certificate usages. Revocation membership and freshness are
// explicit facts, separate from certificate-path and CRL-signature verification.
func auditPublicCredentials(loaded, trusted []byte, now time.Time) (PublicCredentialAudit, error) {
	out := PublicCredentialAudit{AtEpoch: now.Unix(), PEMSHA256: publicFingerprint(loaded),
		Anchors: []string{}, Certificates: []PublicCertificateEvidence{}, CRLs: []PublicCRLEvidence{}}
	certs, crls, err := decodePublicPEM(loaded)
	if err != nil {
		return out, err
	}
	roots, rootCRLs, err := decodePublicPEM(trusted)
	if err != nil {
		return out, err
	}
	if len(roots) == 0 || len(rootCRLs) != 0 {
		return out, fmt.Errorf("missing/invalid public trust anchors")
	}
	for _, root := range roots {
		if !root.IsCA {
			return out, fmt.Errorf("configured anchor is not a CA")
		}
		out.Anchors = append(out.Anchors, publicFingerprint(root.Raw))
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs {
		if cert.IsCA {
			intermediates.AddCert(cert)
		}
	}
	for _, cert := range certs {
		c := PublicCertificateEvidence{Fingerprint: publicFingerprint(cert.Raw), Subject: cert.Subject.String(),
			Issuer: cert.Issuer.String(), Serial: cert.SerialNumber.Text(16), NotBefore: cert.NotBefore.Unix(),
			NotAfter: cert.NotAfter.Unix(), PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(), IsCA: cert.IsCA,
			BasicConstraintsValid: cert.BasicConstraintsValid, KeyUsage: int(cert.KeyUsage),
			ExtendedKeyUsage: []int{}, UnknownExtendedKeyUsage: []string{}, UnhandledCriticalExtensions: []string{},
			DNSNames: append([]string{}, cert.DNSNames...), SubjectKeyID: hex.EncodeToString(cert.SubjectKeyId),
			CRLDistributionPoints:  append([]string{}, cert.CRLDistributionPoints...),
			OCSPServers:            append([]string{}, cert.OCSPServer...),
			IssuingCertificateURLs: append([]string{}, cert.IssuingCertificateURL...),
			AuthorityKeyID:         hex.EncodeToString(cert.AuthorityKeyId), Verifications: []PublicVerification{}}
		switch key := cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			c.PublicKeyBits = key.Curve.Params().BitSize
			c.Curve = key.Curve.Params().Name
		case *rsa.PublicKey:
			c.PublicKeyBits = key.N.BitLen()
		case ed25519.PublicKey:
			c.PublicKeyBits = len(key) * 8
		}
		for _, usage := range cert.ExtKeyUsage {
			c.ExtendedKeyUsage = append(c.ExtendedKeyUsage, int(usage))
		}
		for _, oid := range cert.UnknownExtKeyUsage {
			c.UnknownExtendedKeyUsage = append(c.UnknownExtendedKeyUsage, oid.String())
		}
		for _, oid := range cert.UnhandledCriticalExtensions {
			c.UnhandledCriticalExtensions = append(c.UnhandledCriticalExtensions, oid.String())
		}
		for _, root := range roots {
			pool := x509.NewCertPool()
			pool.AddCert(root)
			_, verifyErr := cert.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates,
				CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
			c.Verifications = append(c.Verifications, verification(publicFingerprint(root.Raw), verifyErr))
		}
		out.Certificates = append(out.Certificates, c)
	}
	for _, crl := range crls {
		c := PublicCRLEvidence{Fingerprint: publicFingerprint(crl.Raw), Issuer: crl.Issuer.String(),
			AuthorityKeyID: hex.EncodeToString(crl.AuthorityKeyId), ThisUpdate: crl.ThisUpdate.Unix(),
			NextUpdate: crl.NextUpdate.Unix(), SignatureAlgorithm: crl.SignatureAlgorithm.String(),
			RevokedSerials: []string{}, Verifications: []PublicVerification{}}
		if crl.Number != nil {
			c.Number = crl.Number.Text(16)
		}
		for _, entry := range crl.RevokedCertificateEntries {
			c.RevokedSerials = append(c.RevokedSerials, entry.SerialNumber.Text(16))
		}
		sort.Strings(c.RevokedSerials)
		for _, root := range roots {
			verifyErr := crl.CheckSignatureFrom(root)
			if !bytes.Equal(crl.RawIssuer, root.RawSubject) {
				verifyErr = fmt.Errorf("CRL issuer differs from anchor subject")
			}
			c.Verifications = append(c.Verifications, verification(publicFingerprint(root.Raw), verifyErr))
		}
		out.CRLs = append(out.CRLs, c)
	}
	return out, nil
}
