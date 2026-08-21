package authz

import (
	"crypto/x509"
	"testing"
)

func TestCertificateIdentityScopesLabsAndActions(t *testing.T) {
	uris, err := URIs(RoleOperator,
		[]string{"cos461", "advnet", "cos461"},
		[]string{"inspect", "deploy", "inspect"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromCertificate(&x509.Certificate{URIs: uris})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Allows("cos461", "deploy") || !got.Allows("advnet", "inspect") {
		t.Fatal("the declared scope was not admitted")
	}
	if got.Allows("multicast", "inspect") || got.Allows("cos461", "destroy") {
		t.Fatal("the certificate escaped its declared scope")
	}
}

func TestControllerWildcard(t *testing.T) {
	uris, err := URIs(RoleController, []string{"*"}, []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromCertificate(&x509.Certificate{URIs: uris})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Allows("any-lab", "any-action") {
		t.Fatal("the controller wildcard did not authorize the cluster")
	}
}

func TestIncompleteOrUnknownClaimsAreRefused(t *testing.T) {
	if _, err := URIs("root", []string{"*"}, []string{"*"}); err == nil {
		t.Fatal("an unknown role was issued")
	}
	if _, err := URIs(RoleOperator, nil, []string{"inspect"}); err == nil {
		t.Fatal("an identity with no lab boundary was issued")
	}
	if _, err := FromCertificate(&x509.Certificate{}); err == nil {
		t.Fatal("a certificate with no identity was accepted")
	}
}
