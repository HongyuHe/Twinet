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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	// Nodes holds server-only material. A server certificate is never used to
	// authorize a peer request, so leaking a node's TLS listener key cannot
	// also create a replication client.
	Nodes map[string]Material
	// Peers holds the node-specific, peer-state-only client credentials used
	// for durable replication.
	Peers map[string]Material
}

const (
	// caValidity is long because rotating a teaching cluster's CA mid-term is
	// worse than the marginal risk of a longer-lived key kept offline.
	caValidity   = 5 * 365 * 24 * time.Hour
	leafValidity = 2 * 365 * 24 * time.Hour
)

// Generate issues a CA, one server certificate and one replication-only peer
// certificate per node, and a client certificate for the controller.
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

	b := &Bundle{Dir: dir, Nodes: map[string]Material{}, Peers: map[string]Material{}}
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
		if err := validateMaterialName(name); err != nil {
			return nil, fmt.Errorf("node %q: %w", name, err)
		}
		// The listener key is server-only. Replication receives its own key
		// below, so a node certificate used for state exchange cannot also be
		// accidentally installed as a broadly trusted API client.
		m, err := issueForClaimsSubject(dir, name+"_server", name, caCert, caKey, sans, nil,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, leafValidity)
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", name, err)
		}
		m.CAPath = b.CA.CertPath
		b.Nodes[name] = m

		claims, err := authz.URIs(authz.RolePeer, []string{"*"}, []string{authz.ActionPeerState})
		if err != nil {
			return nil, err
		}
		peer, err := issueForClaimsSubject(dir, name+"_peer", name, caCert, caKey, nil, claims,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, leafValidity)
		if err != nil {
			return nil, fmt.Errorf("node peer %s: %w", name, err)
		}
		peer.CAPath = b.CA.CertPath
		b.Peers[name] = peer
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
// A certificate of its own rather than the controller's. Its URI claim is the
// authorization boundary -- one lab and observe only -- while a bearer token
// remains only defense in depth. Handing out the controller's private key to
// something under evaluation is not a thing to do when issuing another key
// costs nothing. This one is valid for hours, not months, and its subject says
// what it is.
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
	if role != authz.RoleOperator {
		return Material{}, fmt.Errorf("scoped credential issuance supports only the operator/TA role; use the dedicated diagnostic or node-peer issuer")
	}
	if err := validateMaterialName(name); err != nil {
		return Material{}, err
	}
	if valid <= 0 {
		return Material{}, fmt.Errorf("credential lifetime must be positive")
	}
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

// IssueNodePeer mints one node's replication-only client identity. It is
// intentionally separate from IssueScoped: an operator/TA command must never
// be able to mint a peer certificate, and a peer certificate cannot be used on
// any controller route.
func IssueNodePeer(pkiDir, outDir, node string, valid time.Duration) (Material, error) {
	if err := validateMaterialName(node); err != nil {
		return Material{}, err
	}
	if valid <= 0 {
		return Material{}, fmt.Errorf("peer credential lifetime must be positive")
	}
	caCert, caKey, err := loadCA(pkiDir)
	if err != nil {
		return Material{}, err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return Material{}, err
	}
	claims, err := authz.URIs(authz.RolePeer, []string{"*"}, []string{authz.ActionPeerState})
	if err != nil {
		return Material{}, err
	}
	m, err := issueForClaimsSubject(outDir, node+"_peer", node, caCert, caKey, nil, claims,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, valid)
	if err != nil {
		return Material{}, err
	}
	m.CAPath = filepath.Join(outDir, "ca_cert.pem")
	ca, err := os.ReadFile(filepath.Join(pkiDir, "ca_cert.pem"))
	if err != nil {
		return Material{}, err
	}
	if err := os.WriteFile(m.CAPath, ca, 0o644); err != nil {
		return Material{}, err
	}
	return m, nil
}

// RotateNodePeer replaces a node's replication-only leaf while retaining a
// non-secret serial audit record. Peer leaves share the cluster CA, so agents
// already serving that CA accept the new leaf during a rolling restart; the
// outgoing dialer reloads this path for every durability attempt.
func RotateNodePeer(pkiDir, outDir, node string, valid time.Duration) (Material, Rotation, error) {
	certPath := filepath.Join(outDir, node+"_peer_cert.pem")
	previous, err := leafSerial(certPath)
	if err != nil && !os.IsNotExist(err) {
		return Material{}, Rotation{}, err
	}
	if os.IsNotExist(err) {
		return Material{}, Rotation{}, fmt.Errorf("cannot rotate peer %s: existing certificate %s is absent", node, certPath)
	}
	m, err := IssueNodePeer(pkiDir, outDir, node, valid)
	if err != nil {
		return Material{}, Rotation{}, err
	}
	cert, err := readCertificate(m.CertPath)
	if err != nil {
		return Material{}, Rotation{}, err
	}
	rotation := Rotation{
		Name: node, Role: authz.RolePeer, PreviousSerial: previous,
		CurrentSerial: cert.SerialNumber.Text(16), RotatedAt: time.Now().UTC(), NotAfter: cert.NotAfter.UTC(),
	}
	raw, err := json.Marshal(rotation)
	if err != nil {
		return Material{}, Rotation{}, err
	}
	if err := os.WriteFile(filepath.Join(outDir, node+"_peer_rotation.json"), append(raw, '\n'), 0o600); err != nil {
		return Material{}, Rotation{}, err
	}
	return m, rotation, nil
}

// Rotation records a credential replacement without retaining key material.
// The serials are enough to correlate agent audit events during a rollout.
type Rotation struct {
	Name           string    `json:"name"`
	Role           string    `json:"role"`
	PreviousSerial string    `json:"previous_serial,omitempty"`
	CurrentSerial  string    `json:"current_serial"`
	RotatedAt      time.Time `json:"rotated_at"`
	NotAfter       time.Time `json:"not_after"`
}

// RotateScoped replaces an existing operator/TA credential and writes a
// non-secret audit record next to it. A caller must choose rotation explicitly;
// ordinary issuance never silently converts a long-lived broad legacy key into
// a replacement credential.
func RotateScoped(pkiDir, outDir, name string, labs, actions []string,
	valid time.Duration) (Material, Rotation, error) {
	certPath := filepath.Join(outDir, name+"_cert.pem")
	previous, err := leafSerial(certPath)
	if err != nil && !os.IsNotExist(err) {
		return Material{}, Rotation{}, err
	}
	if os.IsNotExist(err) {
		return Material{}, Rotation{}, fmt.Errorf("cannot rotate %s: existing certificate %s is absent", name, certPath)
	}
	m, err := IssueScoped(pkiDir, outDir, name, authz.RoleOperator, labs, actions, valid)
	if err != nil {
		return Material{}, Rotation{}, err
	}
	cert, err := readCertificate(m.CertPath)
	if err != nil {
		return Material{}, Rotation{}, err
	}
	rotation := Rotation{
		Name: name, Role: authz.RoleOperator, PreviousSerial: previous,
		CurrentSerial: cert.SerialNumber.Text(16), RotatedAt: time.Now().UTC(), NotAfter: cert.NotAfter.UTC(),
	}
	raw, err := json.Marshal(rotation)
	if err != nil {
		return Material{}, Rotation{}, err
	}
	if err := os.WriteFile(filepath.Join(outDir, name+"_rotation.json"), append(raw, '\n'), 0o600); err != nil {
		return Material{}, Rotation{}, err
	}
	return m, rotation, nil
}

func leafSerial(path string) (string, error) {
	cert, err := readCertificate(path)
	if err != nil {
		return "", err
	}
	return cert.SerialNumber.Text(16), nil
}

func validateMaterialName(name string) error {
	if name == "" || filepath.Base(name) != name {
		return fmt.Errorf("credential name must be a single safe path component")
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return fmt.Errorf("credential name %q contains unsafe characters", name)
		}
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("credential name %q contains a traversal sequence", name)
	}
	return nil
}

func readCertificate(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s contains no certificate", path)
	}
	return x509.ParseCertificate(block.Bytes)
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
