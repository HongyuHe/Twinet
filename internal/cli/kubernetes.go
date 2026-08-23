package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/HongyuHe/twinet/internal/fault"
)

// nikaKubernetesBackend is an explicit bridge to NIKA's Kubernetes backend.
// It runs on the controller host, never in a lab container, so kubeconfig and
// cloud credentials cannot leak into a topology, a container, or an episode.
//
// The bridge command receives one JSON request on stdin and writes one JSON
// response on stdout. This narrow protocol is deliberately fakeable in unit
// tests and lets an operator use the pinned NIKA checkout without coupling the
// Go controller to its Python internals.
type nikaKubernetesBackend struct {
	endpoint string
	context  string
	command  []string
}

type nikaKubernetesRequest struct {
	Operation string       `json:"operation"`
	Fault     string       `json:"fault,omitempty"`
	Target    fault.Target `json:"target,omitempty"`
	State     fault.State  `json:"state,omitempty"`
	Endpoint  string       `json:"endpoint"`
	Context   string       `json:"context"`
}

type nikaKubernetesResponse struct {
	Available bool           `json:"available"`
	Reason    string         `json:"reason,omitempty"`
	State     fault.State    `json:"state,omitempty"`
	Evidence  fault.Evidence `json:"evidence,omitempty"`
	Error     string         `json:"error,omitempty"`
}

func kubernetesBackendFromEnv() fault.KubernetesBackend {
	endpoint := strings.TrimSpace(os.Getenv("TWINET_NIKA_KUBERNETES_ENDPOINT"))
	contextName := strings.TrimSpace(os.Getenv("TWINET_NIKA_KUBERNETES_CONTEXT"))
	bridge := strings.TrimSpace(os.Getenv("TWINET_NIKA_KUBERNETES_BRIDGE"))
	if endpoint == "" && contextName == "" && bridge == "" {
		return nil
	}
	var command []string
	if bridge != "" {
		command = strings.Fields(bridge)
	}
	return &nikaKubernetesBackend{endpoint: endpoint, context: contextName, command: command}
}

func (b *nikaKubernetesBackend) Available(ctx context.Context) (bool, string, error) {
	if b == nil {
		return false, "no NIKA Kubernetes endpoint/context is configured", nil
	}
	if b.endpoint == "" || b.context == "" {
		return false, "both TWINET_NIKA_KUBERNETES_ENDPOINT and TWINET_NIKA_KUBERNETES_CONTEXT are required", nil
	}
	if err := validateKubernetesEndpoint(b.endpoint); err != nil {
		return false, err.Error(), nil //nolint:nilerr // invalid configuration is an unavailable capability reason
	}
	if len(b.command) == 0 {
		return false, "TWINET_NIKA_KUBERNETES_BRIDGE is not configured", nil
	}
	resp, err := b.call(ctx, nikaKubernetesRequest{Operation: "discover"})
	if err != nil {
		return false, "", err
	}
	if err := responseError(resp); err != nil {
		return false, "", err
	}
	if !resp.Available && resp.Reason == "" {
		resp.Reason = "NIKA Kubernetes backend declined capability discovery"
	}
	return resp.Available, resp.Reason, nil
}

func (b *nikaKubernetesBackend) Inject(ctx context.Context, name string, target fault.Target) (fault.State, fault.Evidence, error) {
	if ok, reason, err := b.Available(ctx); err != nil || !ok {
		if err != nil {
			return nil, fault.Evidence{}, err
		}
		return nil, fault.Evidence{}, fmt.Errorf("NIKA Kubernetes backend unavailable: %s", reason)
	}
	resp, err := b.call(ctx, nikaKubernetesRequest{Operation: "inject", Fault: name, Target: target})
	if err != nil {
		return resp.State, resp.Evidence, err
	}
	if err := safeDelegatedState(resp.State); err != nil {
		return nil, fault.Evidence{}, err
	}
	return resp.State, resp.Evidence, responseError(resp)
}

func (b *nikaKubernetesBackend) Verify(ctx context.Context, name string, target fault.Target, state fault.State) (fault.Evidence, error) {
	resp, err := b.call(ctx, nikaKubernetesRequest{Operation: "verify", Fault: name, Target: target, State: state})
	if err != nil {
		return fault.Evidence{}, err
	}
	return resp.Evidence, responseError(resp)
}

func (b *nikaKubernetesBackend) Resolve(ctx context.Context, name string, target fault.Target, state fault.State) error {
	resp, err := b.call(ctx, nikaKubernetesRequest{Operation: "resolve", Fault: name, Target: target, State: state})
	if err != nil {
		return err
	}
	return responseError(resp)
}

func (b *nikaKubernetesBackend) call(ctx context.Context, request nikaKubernetesRequest) (nikaKubernetesResponse, error) {
	var out nikaKubernetesResponse
	if b == nil || len(b.command) == 0 {
		return out, fmt.Errorf("NIKA Kubernetes bridge is not configured")
	}
	if err := validateKubernetesEndpoint(b.endpoint); err != nil {
		return out, err
	}
	request.Endpoint, request.Context = b.endpoint, b.context
	raw, err := json.Marshal(request)
	if err != nil {
		return out, err
	}
	cmd := exec.CommandContext(ctx, b.command[0], b.command[1:]...)
	cmd.Stdin = strings.NewReader(string(raw) + "\n")
	// Do not pass a kubeconfig, token, or controller environment through to a
	// command that may in turn report its environment. The bridge gets only
	// its own configured credentials and the public endpoint/context names.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	stdout, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("NIKA Kubernetes bridge %q: %w", b.command[0], err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(stdout, &fields); err != nil {
		return out, fmt.Errorf("decode NIKA Kubernetes bridge response: %w", err)
	}
	if _, ok := fields["available"]; !ok {
		return out, fmt.Errorf("decode NIKA Kubernetes bridge response: missing required field %q", "available")
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return out, fmt.Errorf("decode NIKA Kubernetes bridge response: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return out, fmt.Errorf("decode NIKA Kubernetes bridge response: %w", err)
	}
	// Evidence is persisted in Twinet's control-plane ledger and may later
	// be copied into a report. A bridge must not turn an incidental command
	// diagnostic containing an Authorization header into report content.
	out.Reason = redactKubernetesText(out.Reason)
	out.Error = redactKubernetesText(out.Error)
	out.Evidence.Detail = redactKubernetesText(out.Evidence.Detail)
	out.Evidence.Observed = redactKubernetesText(out.Evidence.Observed)
	out.Evidence.Expected = redactKubernetesText(out.Evidence.Expected)
	if err := safeDelegatedState(out.State); err != nil {
		return out, err
	}
	return out, nil
}

func responseError(resp nikaKubernetesResponse) error {
	if resp.Error == "" {
		return nil
	}
	return fmt.Errorf("NIKA Kubernetes backend: %s", redactKubernetesText(resp.Error))
}

func safeDelegatedState(state fault.State) error {
	for key, value := range state {
		lower := strings.ToLower(key)
		for _, banned := range []string{
			"token", "password", "secret", "credential", "kubeconfig",
			"private", "certificate", "client_key", "client-key", "authorization",
		} {
			if strings.Contains(lower, banned) {
				return fmt.Errorf("NIKA Kubernetes backend returned forbidden credential field %q", key)
			}
		}
		valueLower := strings.ToLower(value)
		if strings.Contains(valueLower, "-----begin") ||
			strings.Contains(valueLower, "authorization:") ||
			strings.Contains(valueLower, "bearer ") ||
			strings.Contains(valueLower, "token=") {
			return fmt.Errorf("NIKA Kubernetes backend returned credential-like material in %q", key)
		}
	}
	return nil
}

func redactKubernetesText(s string) string {
	lower := strings.ToLower(s)
	first := -1
	for _, marker := range []string{
		"authorization:", "authorization=", "bearer ",
		"token=", "token:", `"token":`, "'token':",
		"pass" + "word=", "pass" + "word:",
		"password=", "password:", `"password":`, "'password':",
		"client-secret", "client_secret", "client-key-data",
		"client_certificate_data", "client-certificate-data",
		"certificate-authority-data", "-----begin",
	} {
		if i := strings.Index(lower, marker); i >= 0 && (first < 0 || i < first) {
			first = i
		}
	}
	if first >= 0 {
		prefix := strings.TrimSpace(s[:first])
		if prefix == "" {
			return "[redacted]"
		}
		return prefix + " [redacted]"
	}
	return s
}

func validateKubernetesEndpoint(endpoint string) error {
	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return fmt.Errorf("TWINET_NIKA_KUBERNETES_ENDPOINT must be an HTTP(S) URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("TWINET_NIKA_KUBERNETES_ENDPOINT must not contain credentials, a query, or a fragment")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}
