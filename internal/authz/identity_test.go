package authz

import (
	"crypto/x509"
	"testing"
)

func TestCertificateIdentityScopesLabsAndActions(t *testing.T) {
	uris, err := URIs(RoleOperator,
		[]string{"cos461", "advnet", "cos461"},
		[]string{ActionObserve, ActionDeploy, ActionObserve})
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromCertificate(&x509.Certificate{URIs: uris})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Allows("cos461", ActionDeploy) || !got.Allows("advnet", ActionObserve) {
		t.Fatal("the declared scope was not admitted")
	}
	if got.Allows("multicast", ActionObserve) || got.Allows("cos461", ActionDestroy) {
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

func TestMultipleCertificateIdentitiesFailClosed(t *testing.T) {
	controller, err := URIs(RoleController, []string{"*"}, []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	operator, err := URIs(RoleOperator, []string{"lab-a"}, []string{ActionObserve})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromCertificate(&x509.Certificate{URIs: append(controller, operator...)}); err == nil {
		t.Fatal("certificate with conflicting identities was accepted")
	}
}

func TestIncompleteOrUnknownClaimsAreRefused(t *testing.T) {
	if _, err := URIs("root", []string{"*"}, []string{"*"}); err == nil {
		t.Fatal("an unknown role was issued")
	}
	if _, err := URIs(RoleOperator, nil, []string{"inspect"}); err == nil {
		t.Fatal("an identity with no lab boundary was issued")
	}
	if _, err := URIs(RoleOperator, []string{"cos461"}, []string{"deply"}); err == nil {
		t.Fatal("a misspelled action was issued as a working credential")
	}
	if _, err := URIs(RoleDiagnostic, []string{"*"}, []string{ActionObserve}); err == nil {
		t.Fatal("a diagnostic credential was issued for every lab")
	}
	if _, err := FromCertificate(&x509.Certificate{}); err == nil {
		t.Fatal("a certificate with no identity was accepted")
	}
}
