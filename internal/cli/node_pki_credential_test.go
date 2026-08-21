package cli

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/authz"
	"github.com/HongyuHe/twinet/internal/pki"
)

func TestScopedOperatorCredentialCannotEscapeItsGrant(t *testing.T) {
	dir := t.TempDir()
	if _, err := pki.Generate(dir,
		map[string][]string{"node-0": {"127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	m, err := pki.IssueScoped(dir, out, "ta", authz.RoleOperator,
		[]string{"cos461"}, []string{"inspect", "deploy"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Clean(m.CertPath))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("issued certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	id, err := authz.FromCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Allows("cos461", "deploy") {
		t.Fatal("the declared grant was not carried by the certificate")
	}
	if id.Allows("advnet", "deploy") || id.Allows("cos461", "destroy") {
		t.Fatal("the certificate escaped its declared lab or action")
	}
}
