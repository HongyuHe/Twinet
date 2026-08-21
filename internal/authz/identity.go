// Package authz defines the identity and authorization claims carried by
// Twinet client certificates.
package authz

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"sort"
)

const (
	RoleController = "controller"
	RoleOperator   = "operator"
	RoleDiagnostic = "diagnostic"
	// RolePeer is issued only to node agents. It has one narrow capability:
	// exchange durable replicas over the peer API. It is intentionally not a
	// controller role, even though a node certificate is also used for TLS.
	RolePeer = "peer"

	ActionObserve   = "observe"
	ActionExec      = "exec"
	ActionDeploy    = "deploy"
	ActionDestroy   = "destroy"
	ActionLifecycle = "lifecycle"
	ActionFault     = "fault"
	ActionState     = "state"
	ActionAdmin     = "admin"
	ActionPeerState = "peer-state"

	claimScheme = "spiffe"
	claimHost   = "twinet.dev"
	claimPath   = "/identity"
)

// Identity is the authorization boundary encoded in one client certificate.
type Identity struct {
	Role    string
	Labs    map[string]bool
	Actions map[string]bool
}

// Allows reports whether the identity may perform action in lab.
func (i Identity) Allows(lab, action string) bool {
	if i.Role == "" {
		return false
	}
	return (i.Labs["*"] || i.Labs[lab]) &&
		(i.Actions["*"] || i.Actions[action])
}

// URIs creates the canonical certificate claim for an identity.
func URIs(role string, labs, actions []string) ([]*url.URL, error) {
	switch role {
	case RoleController, RoleOperator, RoleDiagnostic, RolePeer:
	default:
		return nil, fmt.Errorf("unknown certificate role %q", role)
	}
	labs = canonical(labs)
	actions = canonical(actions)
	if len(labs) == 0 {
		return nil, fmt.Errorf("certificate role %s has no lab scope", role)
	}
	if len(actions) == 0 {
		return nil, fmt.Errorf("certificate role %s has no action scope", role)
	}
	if err := validateScope(role, labs, actions); err != nil {
		return nil, err
	}
	q := url.Values{}
	for _, lab := range labs {
		q.Add("lab", lab)
	}

	for _, action := range actions {
		q.Add("action", action)
	}
	return []*url.URL{{
		Scheme:   claimScheme,
		Host:     claimHost,
		Path:     claimPath + "/" + role,
		RawQuery: q.Encode(),
	}}, nil
}

func validateScope(role string, labs, actions []string) error {
	known := map[string]bool{
		ActionObserve: true, ActionExec: true, ActionDeploy: true,
		ActionDestroy: true, ActionLifecycle: true, ActionFault: true,
		ActionState: true, ActionAdmin: true, ActionPeerState: true,
	}
	switch role {
	case RoleController:
		if len(labs) != 1 || labs[0] != "*" ||
			len(actions) != 1 || actions[0] != "*" {
			return fmt.Errorf("controller certificates must carry the cluster wildcard scope")
		}
	case RoleOperator:
		for _, lab := range labs {
			if lab == "*" {
				return fmt.Errorf("an operator must name each lab; use a controller identity for the cluster")
			}
		}
		for _, action := range actions {
			if !known[action] {
				return fmt.Errorf("unknown operator action %q", action)
			}
		}
	case RoleDiagnostic:
		if len(labs) != 1 || labs[0] == "*" {
			return fmt.Errorf("a diagnostic certificate must name exactly one lab")
		}
		if len(actions) != 1 || actions[0] != ActionObserve {
			return fmt.Errorf("a diagnostic certificate may only observe")
		}
	case RolePeer:
		if len(labs) != 1 || labs[0] != "*" ||
			len(actions) != 1 || actions[0] != ActionPeerState {
			return fmt.Errorf("peer certificates may only carry the peer-state cluster scope")
		}
	}
	return nil
}

// FromCertificate reads a Twinet identity from a verified client certificate.
func FromCertificate(cert *x509.Certificate) (Identity, error) {
	if cert == nil {
		return Identity{}, fmt.Errorf("no client certificate")
	}
	for _, u := range cert.URIs {
		if u == nil || u.Scheme != claimScheme || u.Host != claimHost {
			continue
		}
		prefix := claimPath + "/"
		if len(u.Path) <= len(prefix) || u.Path[:len(prefix)] != prefix {
			continue
		}
		role := u.Path[len(prefix):]
		switch role {
		case RoleController, RoleOperator, RoleDiagnostic, RolePeer:
		default:
			return Identity{}, fmt.Errorf("client certificate has unknown Twinet role %q", role)
		}
		out := Identity{
			Role: role, Labs: map[string]bool{}, Actions: map[string]bool{},
		}
		for _, lab := range u.Query()["lab"] {
			if lab != "" {
				out.Labs[lab] = true
			}
		}
		for _, action := range u.Query()["action"] {
			if action != "" {
				out.Actions[action] = true
			}
		}
		if len(out.Labs) == 0 || len(out.Actions) == 0 {
			return Identity{}, fmt.Errorf("client certificate role %s has incomplete scope", role)
		}
		return out, nil
	}
	return Identity{}, fmt.Errorf("client certificate carries no Twinet identity")
}

func canonical(in []string) []string {
	seen := map[string]bool{}
	for _, s := range in {
		if s != "" {
			seen[s] = true
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
