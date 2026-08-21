// Package pki issues the certificates the cluster authenticates with.
//
// The agent API can create privileged containers and rewire hosts, so the
// question is not whether it needs strong authentication but why it shipped
// without it. A shared bearer token over plain HTTP has three problems that no
// amount of care makes acceptable: it is replayable by anyone who sees one
// request, it is identical on every node so a single leak compromises the
// cluster, and it authenticates the caller to the agent while leaving the agent
// unauthenticated to the caller -- so anything that can occupy the port can
// collect tokens.
//
// Mutual TLS answers all three, and the only reason it was not the default is
// that nothing generated the material. This does.
package pki

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
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/HongyuHe/twinet/internal/authz"
)

// Material is one issued identity on disk.
type Material struct {
	CertPath string
	KeyPath  string
	CAPath   string
}

// Bundle is everything a cluster needs.
type Bundle struct {
	Dir    string
	CA     Material
	Client Material
	Nodes  map[string]Material
}

const (
	// caValidity is long because rotating a teaching cluster's CA mid-term is
	// worse than the marginal risk of a longer-lived key kept offline.
	caValidity   = 5 * 365 * 24 * time.Hour
	leafValidity = 2 * 365 * 24 * time.Hour
)

// Generate issues a CA, one server certificate per node, and a client
// certificate for the controller.
//
// Each node gets its own key. One shared server certificate would be simpler
// and would recreate the property that makes the bearer token unacceptable: a
// single compromised machine able to impersonate every other.
func Generate(dir string, nodes map[string][]string) (*Bundle, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "twinet cluster CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	b := &Bundle{Dir: dir, Nodes: map[string]Material{}}
	b.CA = Material{
		CertPath: filepath.Join(dir, "ca_cert.pem"),
		KeyPath:  filepath.Join(dir, "ca_key.pem"),
	}
	if err := writePEM(b.CA.CertPath, "CERTIFICATE", caDER, 0o644); err != nil {
		return nil, err
	}
	if err := writeKey(b.CA.KeyPath, caKey); err != nil {
		return nil, err
	}

	for name, sans := range nodes {
		// A node uses its own certificate as a TLS client only on the
		// peer-replication API. The embedded peer role is deliberately
		// narrower than a controller identity, so possession of a node key
		// cannot mutate a lab or acquire a controller fence.
		claims, err := authz.URIs(authz.RolePeer, []string{"*"}, []string{authz.ActionPeerState})
		if err != nil {
			return nil, err
		}
		m, err := issueForClaimsSubject(dir, name+"_server", name, caCert, caKey, sans, claims,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, leafValidity)
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", name, err)
		}
		m.CAPath = b.CA.CertPath
		b.Nodes[name] = m
	}

	claims, err := authz.URIs(authz.RoleController, []string{"*"}, []string{"*"})
	if err != nil {
		return nil, err
	}
	client, err := issueForClaims(dir, "controller", caCert, caKey, nil,
		claims, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, leafValidity)
	if err != nil {
		return nil, err
	}
	client.CAPath = b.CA.CertPath
	b.Client = client
	return b, nil
}

func issue(dir, name string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey,
	sans []string, usage []x509.ExtKeyUsage) (Material, error) {
	return issueFor(dir, name, caCert, caKey, sans, usage, leafValidity)
}

// issueFor is issue with an explicit lifetime, so a credential handed to
// something under evaluation can be short-lived.
func issueFor(dir, name string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey,
	sans []string, usage []x509.ExtKeyUsage, valid time.Duration) (Material, error) {
	return issueForClaims(dir, name, caCert, caKey, sans, nil, usage, valid)
}

func issueForClaims(dir, name string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey,
	sans []string, uris []*url.URL, usage []x509.ExtKeyUsage, valid time.Duration) (Material, error) {
	return issueForClaimsSubject(dir, name, name, caCert, caKey, sans, uris, usage, valid)
}

// issueForClaimsSubject keeps the on-disk filename distinct from the
// authenticated common name. Node certificate files retain the historical
// "_server" suffix while the peer API binds requests to the manifest node name.
func issueForClaimsSubject(dir, name, subject string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey,
	sans []string, uris []*url.URL, usage []x509.ExtKeyUsage, valid time.Duration) (Material, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(valid),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  usage,
		URIs:         uris,
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return Material{}, err
	}
	m := Material{
		CertPath: filepath.Join(dir, name+"_cert.pem"),
		KeyPath:  filepath.Join(dir, name+"_key.pem"),
	}
	if err := writePEM(m.CertPath, "CERTIFICATE", der, 0o644); err != nil {
		return Material{}, err
	}
	if err := writeKey(m.KeyPath, key); err != nil {
		return Material{}, err
	}
	return m, nil
}

func writePEM(path, kind string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), mode)
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	// 0600: a private key readable by anyone on the machine is not private, and
	// this one authorises privileged container creation.
	return writePEM(path, "EC PRIVATE KEY", der, 0o600)
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		// A predictable serial is a genuine weakness, so failing here is the
		// right answer: the alternative is issuing a certificate that is weaker
		// than it claims to be, silently.
		panic("pki: no randomness available: " + err.Error())
	}
	return n
}

// IssueDiagnostic mints a short-lived client certificate for an evaluated RCA
// agent, in a directory of its own.
//
// The agent has to reach the node agents, and on a cluster with mutual TLS that
// takes a client certificate as well as a token. It had neither: the sandbox
// excluded the PKI, so every observation the agent tried failed with
// "certificate required" and the benchmark could not be run at all -- which is
// the one failure worse than a benchmark that measures the wrong thing, because
// it looks like the agent found nothing.
//
// A certificate of its own rather than the controller's. Transport identity is
// not authorisation here -- the node agents decide what a caller may do from
// its bearer token, and the agent's token is the read-only, single-lab one --
// but handing out the controller's private key to something under evaluation is
// not a thing to do when issuing another key costs nothing. This one is valid
// for hours, not months, and its subject says what it is.
func IssueDiagnostic(pkiDir, outDir, lab string, valid time.Duration) (Material, error) {
	caCert, caKey, err := loadCA(pkiDir)
	if err != nil {
		return Material{}, err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return Material{}, err
	}
	claims, err := authz.URIs(authz.RoleDiagnostic, []string{lab}, []string{authz.ActionObserve})
	if err != nil {
		return Material{}, err
	}
	m, err := issueForClaims(outDir, "diagnostic", caCert, caKey, nil, claims,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, valid)
	if err != nil {
		return Material{}, err
	}
	// The agent needs the authority to verify the nodes it talks to.
	ca, err := os.ReadFile(filepath.Join(pkiDir, "ca_cert.pem"))
	if err != nil {
		return Material{}, err
	}
	m.CAPath = filepath.Join(outDir, "ca_cert.pem")
	if err := os.WriteFile(m.CAPath, ca, 0o644); err != nil {
		return Material{}, err
	}
	return m, nil
}

// IssueScoped mints a short-lived operator identity limited to the named labs
// and actions.
func IssueScoped(pkiDir, outDir, name, role string, labs, actions []string,
	valid time.Duration) (Material, error) {
	caCert, caKey, err := loadCA(pkiDir)
	if err != nil {
		return Material{}, err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return Material{}, err
	}
	claims, err := authz.URIs(role, labs, actions)
	if err != nil {
		return Material{}, err
	}
	m, err := issueForClaims(outDir, name, caCert, caKey, nil, claims,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, valid)
	if err != nil {
		return Material{}, err
	}
	ca, err := os.ReadFile(filepath.Join(pkiDir, "ca_cert.pem"))
	if err != nil {
		return Material{}, err
	}
	m.CAPath = filepath.Join(outDir, "ca_cert.pem")
	if err := os.WriteFile(m.CAPath, ca, 0o644); err != nil {
		return Material{}, err
	}
	return m, nil
}

// loadCA reads the cluster authority from a PKI directory.
func loadCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca_cert.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("read the cluster authority: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca_key.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("read the cluster authority's key: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, fmt.Errorf("%s does not hold a usable authority", dir)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}
