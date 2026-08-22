package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/HongyuHe/twinet/internal/authz"
	"github.com/HongyuHe/twinet/internal/deploy"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// Every route deliberately names one of these policies. A route that has not
// selected an action cannot be registered through authorize, which keeps a new
// API method from inheriting broad controller access by accident.
type endpointPolicy struct {
	Action         string
	Mutation       bool
	AllowCluster   bool
	ResolveRequest func(*Server, *http.Request) (requestScope, error)
}

type requestScope struct {
	Lab             string
	Action          string
	Target          string
	Generation      string
	FenceGeneration uint64
}

type requestPrincipal struct {
	Identity          authz.Identity
	Name              string
	CertificateSerial string
	Diagnostic        bool
	Insecure          bool
}

type requestPrincipalKey struct{}
type requestScopeKey struct{}

var labNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var errPeerCertificate = errors.New("node peer identity is reserved for replication")

// authorize enforces the certificate claim and (when configured) the
// defense-in-depth bearer token before a handler receives a request. The
// certificate is the authority boundary; a shared bearer can only corroborate
// it and can never turn a diagnostic or lab-scoped identity into a controller.
func (s *Server) authorize(policy endpointPolicy, h http.HandlerFunc) http.HandlerFunc {
	if !authz.KnownAction(policy.Action) || policy.Action == authz.ActionPeerState {
		panic("agent endpoint registered with an unknown or peer-only action")
	}
	if policy.ResolveRequest == nil {
		panic("agent endpoint registered without a lab/action resolver")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del(scopeHeader)
		principal, err := s.authenticateRequest(r)
		if err != nil {
			if policy.Mutation {
				s.recordAuthorizationAudit(r, requestScope{Action: policy.Action}, requestPrincipal{},
					"denied", "authentication refused")
			}
			status := http.StatusUnauthorized
			if errors.Is(err, errPeerCertificate) {
				status = http.StatusForbidden
			}
			http.Error(w, "unauthorised", status)
			return
		}
		scope, err := policy.ResolveRequest(s, r)
		if err != nil {
			if policy.Mutation {
				s.recordAuthorizationAudit(r, requestScope{Action: policy.Action}, principal,
					"denied", "request has no valid lab/action scope")
			}
			http.Error(w, "invalid authorization scope", http.StatusBadRequest)
			return
		}
		scope.Action = policy.Action
		if scope.Lab == "" {
			if principal.Diagnostic {
				scope.Lab = onlyLab(principal.Identity)
			} else if policy.AllowCluster {
				scope.Lab = "*"
			}
		}
		if scope.Lab == "" || (scope.Lab == "*" && !policy.AllowCluster) ||
			(scope.Lab != "*" && !labNameRE.MatchString(scope.Lab)) {
			if policy.Mutation {
				s.recordAuthorizationAudit(r, scope, principal, "denied", "request has no valid lab scope")
			}
			http.Error(w, "a known lab scope is required", http.StatusBadRequest)
			return
		}
		if !principal.Identity.Allows(scope.Lab, policy.Action) {
			if policy.Mutation {
				s.recordAuthorizationAudit(r, scope, principal, "denied", "certificate scope denied request")
			}
			http.Error(w, "certificate identity is not authorised for this lab and action", http.StatusForbidden)
			return
		}
		if principal.Diagnostic {
			// A diagnostic claim has exactly one lab and observe-only scope,
			// but keep this explicit at the enforcement point. A malformed
			// future claim must fail closed rather than rely on issuance code.
			if policy.Action != authz.ActionObserve || scope.Lab == "*" ||
				!principal.Identity.Allows(scope.Lab, authz.ActionObserve) {
				if policy.Mutation {
					s.recordAuthorizationAudit(r, scope, principal, "denied",
						"diagnostic certificate attempted a non-observe action")
				}
				http.Error(w, "a diagnostic identity may only observe its one lab", http.StatusForbidden)
				return
			}
			r.Header.Set(scopeHeader, scope.Lab)
		}

		ctx := context.WithValue(r.Context(), requestPrincipalKey{}, principal)
		ctx = context.WithValue(ctx, requestScopeKey{}, scope)
		r = r.WithContext(ctx)
		if !policy.Mutation {
			h(w, r)
			return
		}
		observed := &authorizationResponseWriter{ResponseWriter: w}
		h(observed, r)
		result := "success"
		if observed.status >= http.StatusBadRequest {
			result = "error"
		}
		s.recordAuthorizationAudit(r, scope, principal, result, "")
	}
}

func (s *Server) authenticateRequest(r *http.Request) (requestPrincipal, error) {
	full := []byte("Bearer " + s.cfg.Token)
	got := []byte(r.Header.Get("Authorization"))
	fullToken := len(s.cfg.Token) > 0 && subtle.ConstantTimeCompare(got, full) == 1
	diagnosticLab, diagnosticToken := diagnosticScope(s.cfg.Token,
		strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if !fullToken && !diagnosticToken {
		return requestPrincipal{}, errors.New("missing defense-in-depth bearer credential")
	}

	if r.TLS != nil {
		if len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
			return requestPrincipal{}, errors.New("a verified client certificate is required")
		}
		cert := r.TLS.PeerCertificates[0]
		identity, err := authz.FromCertificate(cert)
		if err != nil {
			return requestPrincipal{}, err
		}
		if identity.Role == authz.RolePeer {
			return requestPrincipal{}, errPeerCertificate
		}
		diagnostic := identity.Role == authz.RoleDiagnostic
		if diagnosticToken && (!diagnostic || !identity.Allows(diagnosticLab, authz.ActionObserve)) {
			return requestPrincipal{}, errors.New("diagnostic token does not match certificate scope")
		}
		name := cert.Subject.CommonName
		if name == "" {
			return requestPrincipal{}, errors.New("client certificate has no subject identity")
		}
		return requestPrincipal{
			Identity: identity, Name: name,
			CertificateSerial: hex.EncodeToString(cert.SerialNumber.Bytes()),
			Diagnostic:        diagnostic,
		}, nil
	}

	// Plain HTTP is intentionally not a migration fallback. It is available
	// only when the operator explicitly selected loopback development mode.
	if !s.insecureLoopbackMode() {
		return requestPrincipal{}, errors.New("mutual TLS is required")
	}
	if diagnosticToken {
		return requestPrincipal{
			Identity: authz.Identity{
				Role:    authz.RoleDiagnostic,
				Labs:    map[string]bool{diagnosticLab: true},
				Actions: map[string]bool{authz.ActionObserve: true},
			},
			Name: "insecure-diagnostic", Diagnostic: true, Insecure: true,
		}, nil
	}
	if !fullToken {
		return requestPrincipal{}, errors.New("invalid development bearer credential")
	}
	return requestPrincipal{
		Identity: authz.Identity{
			Role:    authz.RoleController,
			Labs:    map[string]bool{"*": true},
			Actions: map[string]bool{"*": true},
		},
		Name: "insecure-loopback", Insecure: true,
	}, nil
}

func (s *Server) insecureLoopbackMode() bool {
	return s.cfg.Insecure && loopbackOnly(s.cfg.Listen)
}

func onlyLab(identity authz.Identity) string {
	for lab := range identity.Labs {
		if lab != "*" {
			return lab
		}
	}
	return ""
}

func principalOf(r *http.Request) (requestPrincipal, bool) {
	if r == nil {
		return requestPrincipal{}, false
	}
	value, ok := r.Context().Value(requestPrincipalKey{}).(requestPrincipal)
	return value, ok
}

func scopedRequestOf(r *http.Request) (requestScope, bool) {
	if r == nil {
		return requestScope{}, false
	}
	value, ok := r.Context().Value(requestScopeKey{}).(requestScope)
	return value, ok
}

type authorizationResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *authorizationResponseWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *authorizationResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

// Hijack preserves the attach path's raw terminal stream while retaining the
// authorization/audit wrapper. Without this forwarding method the wrapper
// itself would hide http.Hijacker and turn every authenticated attach into a
// misleading "server cannot stream" error.
func (w *authorizationResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return hijacker.Hijack()
}

func (w *authorizationResponseWriter) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if flush, ok := w.ResponseWriter.(http.Flusher); ok {
		flush.Flush()
	}
}

func (s *Server) recordAuthorizationAudit(r *http.Request, scope requestScope,
	principal requestPrincipal, result, detail string,
) {
	generation := scope.Generation
	if generation == "" && scope.Lab != "" && scope.Lab != "*" {
		s.mu.Lock()
		generation = s.generations[scope.Lab].Committed
		s.mu.Unlock()
	}
	identity := principal.Identity.Role
	if identity != "" && principal.Name != "" {
		identity += ":" + principal.Name
	}
	if principal.Insecure {
		identity = "development:" + identity
	}
	s.eventLog().append(Event{
		Node: s.cfg.Node, Lab: scope.Lab, Generation: generation,
		FenceGeneration: scope.FenceGeneration, Identity: identity,
		CertificateSerial: principal.CertificateSerial, Target: scope.Target,
		Scope: "api", CorrelationID: s.requestCorrelation(r), Action: scope.Action,
		Result: result, Detail: detail,
	})
}

func scopeFromQuery(action string, allowCluster bool) func(*Server, *http.Request) (requestScope, error) {
	return func(_ *Server, r *http.Request) (requestScope, error) {
		lab := strings.TrimSpace(r.URL.Query().Get("lab"))
		if lab == "" && !allowCluster {
			return requestScope{}, errors.New("lab is required")
		}
		return requestScope{Lab: lab, Action: action}, nil
	}
}

func scopeCluster(action string) func(*Server, *http.Request) (requestScope, error) {
	return func(_ *Server, _ *http.Request) (requestScope, error) {
		return requestScope{Lab: "*", Action: action}, nil
	}
}

func scopeFromJSONLab(action string) func(*Server, *http.Request) (requestScope, error) {
	return func(_ *Server, r *http.Request) (requestScope, error) {
		values, err := requestJSONObject(r)
		if err != nil {
			return requestScope{}, err
		}
		lab := jsonString(values["lab"])
		if lab == "" {
			return requestScope{}, errors.New("lab is required")
		}
		generation := jsonString(values["generation"])
		return requestScope{
			Lab: lab, Action: action, Target: lab, Generation: generation,
			FenceGeneration: jsonFenceGeneration(values["fence"]),
		}, nil
	}
}

func scopeForApply(_ *Server, r *http.Request) (requestScope, error) {
	values, err := requestJSONObject(r)
	if err != nil {
		return requestScope{}, err
	}
	lab := jsonString(values["lab"])
	if lab == "" && len(values["topology"]) > 0 {
		var topology struct {
			Lab string `json:"lab"`
		}
		if err := json.Unmarshal(values["topology"], &topology); err == nil {
			lab = topology.Lab
		}
	}
	if lab == "" {
		return requestScope{}, errors.New("apply lab is required")
	}
	return requestScope{
		Lab: lab, Target: lab, Generation: jsonString(values["generation"]),
		FenceGeneration: jsonFenceGeneration(values["fence"]),
	}, nil
}

func scopeForContainer(action string) func(*Server, *http.Request) (requestScope, error) {
	return func(s *Server, r *http.Request) (requestScope, error) {
		values, err := requestJSONObject(r)
		if err != nil {
			return requestScope{}, err
		}
		return s.containerScope(action, jsonString(values["container"]),
			jsonString(values["generation"]), jsonFenceGeneration(values["fence"]))
	}
}

// scopeForExecBatch proves every requested container belongs to the same lab.
// A batch crossing lab boundaries would turn one authorization decision into
// an enumeration primitive, so it is refused before the handler sees it.
func scopeForExecBatch(action string) func(*Server, *http.Request) (requestScope, error) {
	return func(s *Server, r *http.Request) (requestScope, error) {
		values, err := requestJSONObject(r)
		if err != nil {
			return requestScope{}, err
		}
		raw := values["requests"]
		var requests []struct {
			Container string `json:"container"`
		}
		if len(raw) == 0 || json.Unmarshal(raw, &requests) != nil || len(requests) == 0 {
			return requestScope{}, errors.New("one or more exec requests are required")
		}
		var scope requestScope
		for index, request := range requests {
			current, err := s.containerScope(action, request.Container, "", 0)
			if err != nil {
				return requestScope{}, err
			}
			if index == 0 {
				scope = current
				continue
			}
			if current.Lab != scope.Lab {
				return requestScope{}, errors.New("all exec batch containers must belong to one lab")
			}
		}
		return scope, nil
	}
}

func scopeForAttach(s *Server, r *http.Request) (requestScope, error) {
	return s.containerScope(authz.ActionExec, strings.TrimSpace(r.URL.Query().Get("container")), "", 0)
}

func (s *Server) containerScope(action, container, generation string, fence uint64) (requestScope, error) {
	if container == "" {
		return requestScope{}, errors.New("container is required")
	}
	if s.rt == nil {
		return requestScope{}, errors.New("runtime is unavailable")
	}
	c, err := s.rt.Inspect(context.Background(), container)
	if err != nil {
		return requestScope{}, err
	}
	if c.State == rt.StateAbsent || c.Labels[deploy.LabelManaged] != "true" {
		return requestScope{}, errors.New("container is not a managed topology device")
	}
	if isInternalControlContainer(c) {
		return requestScope{}, errors.New("control sidecars are not API devices")
	}
	lab := c.Labels[deploy.LabelLab]
	if lab == "" {
		return requestScope{}, errors.New("container has no lab label")
	}
	return requestScope{
		Lab: lab, Action: action, Target: container, Generation: generation,
		FenceGeneration: fence,
	}, nil
}

func requestJSONObject(r *http.Request) (map[string]json.RawMessage, error) {
	if r == nil || r.Body == nil {
		return nil, errors.New("JSON request body is required")
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("JSON request body is required")
	}
	out := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func jsonString(raw json.RawMessage) string {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func jsonFenceGeneration(raw json.RawMessage) uint64 {
	var fence struct {
		Generation uint64 `json:"generation"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &fence) != nil {
		return 0
	}
	return fence.Generation
}

func isInternalControlContainer(c rt.Container) bool {
	return c.Labels[deploy.LabelFRRControl] == "true" ||
		c.Labels[deploy.LabelInternal] == "true"
}
