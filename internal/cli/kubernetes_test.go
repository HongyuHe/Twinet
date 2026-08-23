package cli

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/fault"
)

func TestKubernetesBridgeUsesStrictProtocolAndSafeEnvironment(t *testing.T) {
	t.Setenv("KUBECONFIG", "/credentials/should-not-cross")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "should-not-cross")
	t.Setenv("TWINET_TOKEN", "should-not-cross")

	backend := &nikaKubernetesBackend{
		endpoint: "https://127.0.0.1:6443",
		context:  "kind-twinet",
		command:  kubernetesHelperCommand("safe"),
	}
	state, evidence, err := backend.Inject(context.Background(),
		"k8s_networkpolicy_deny",
		fault.Target{
			Device: "k8s/twinet-nika-unit/client",
			Params: map[string]string{"namespace": "twinet-nika-unit"},
		})
	if err != nil {
		t.Fatal(err)
	}
	if state["namespace"] != "twinet-nika-unit" {
		t.Fatalf("bridge state was not decoded: %#v", state)
	}
	for name, value := range map[string]string{
		"detail":   evidence.Detail,
		"observed": evidence.Observed,
		"expected": evidence.Expected,
	} {
		if strings.Contains(value, "should-not-cross") ||
			strings.Contains(strings.ToLower(value), "authorization") ||
			strings.Contains(strings.ToLower(value), "private key") {
			t.Fatalf("%s leaked bridge credentials: %q", name, value)
		}
	}
}

func TestKubernetesBridgeRejectsCredentialState(t *testing.T) {
	backend := &nikaKubernetesBackend{
		endpoint: "https://127.0.0.1:6443",
		context:  "kind-twinet",
		command:  kubernetesHelperCommand("credential-state"),
	}
	_, _, err := backend.Inject(context.Background(),
		"k8s_networkpolicy_deny", fault.Target{})
	if err == nil || !strings.Contains(err.Error(), "forbidden credential field") {
		t.Fatalf("credential-bearing state was accepted: %v", err)
	}
	if strings.Contains(err.Error(), "should-not-cross") {
		t.Fatalf("credential value leaked in the rejection: %v", err)
	}
}

func TestKubernetesBridgeRejectsNonProtocolOutput(t *testing.T) {
	for _, mode := range []string{"missing-available", "unknown-response-field", "multiple-responses"} {
		t.Run(mode, func(t *testing.T) {
			backend := &nikaKubernetesBackend{
				endpoint: "https://127.0.0.1:6443",
				context:  "kind-twinet",
				command:  kubernetesHelperCommand(mode),
			}
			_, _, err := backend.Inject(context.Background(),
				"k8s_networkpolicy_deny", fault.Target{})
			if err == nil || !strings.Contains(err.Error(), "decode NIKA Kubernetes bridge response") {
				t.Fatalf("non-protocol output was accepted: %v", err)
			}
		})
	}
}

func TestKubernetesDiscoverySurfacesBridgeError(t *testing.T) {
	backend := &nikaKubernetesBackend{
		endpoint: "https://127.0.0.1:6443",
		context:  "kind-twinet",
		command:  kubernetesHelperCommand("discover-error"),
	}
	_, _, err := backend.Available(context.Background())
	if err == nil || !strings.Contains(err.Error(), "discovery failed") {
		t.Fatalf("discovery error was discarded: %v", err)
	}
}

func TestKubernetesEndpointCannotCarryCredentials(t *testing.T) {
	for _, endpoint := range []string{
		"https://user:" + "not-a-real-" + "credential@example.invalid:6443",
		"https://user:password@example.invalid:6443",
		"https://example.invalid:6443?token=should-not-cross",
		"https://example.invalid:6443#credential",
	} {
		if err := validateKubernetesEndpoint(endpoint); err == nil {
			t.Errorf("credential-bearing endpoint %q was accepted", endpoint)
		}
	}
	if err := validateKubernetesEndpoint("https://127.0.0.1:6443"); err != nil {
		t.Fatalf("ordinary endpoint was rejected: %v", err)
	}
}

func TestRedactKubernetesText(t *testing.T) {
	for _, input := range []string{
		"request Authorization: Bearer " + "should-not-cross",
		"error pass" + "word=should-not-cross",
		"request Authorization: Bearer should-not-cross",
		`response {"token":"should-not-cross"}`,
		"error password=should-not-cross",
		"-----BEGIN PRIVATE KEY-----\nshould-not-cross",
	} {
		got := redactKubernetesText(input)
		if strings.Contains(got, "should-not-cross") {
			t.Errorf("credential was not redacted from %q: %q", input, got)
		}
	}
}

func kubernetesHelperCommand(mode string) []string {
	return []string{
		os.Args[0],
		"-test.run=^TestKubernetesBridgeHelper$",
		"--",
		"--kubernetes-bridge-helper",
		mode,
	}
}

func TestKubernetesBridgeHelper(t *testing.T) {
	index := slices.Index(os.Args, "--kubernetes-bridge-helper")
	if index < 0 {
		return
	}
	mode := os.Args[index+1]
	var request nikaKubernetesRequest
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		os.Exit(3)
	}
	for _, name := range []string{
		"KUBECONFIG", "AWS_SECRET_ACCESS_KEY", "TWINET_TOKEN",
		"GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET",
	} {
		if os.Getenv(name) != "" {
			_ = json.NewEncoder(os.Stdout).Encode(nikaKubernetesResponse{
				Available: true,
				Error:     "controller credential environment crossed the bridge",
			})
			os.Exit(0)
		}
	}

	if request.Operation == "discover" {
		switch mode {
		case "discover-error":
			_ = json.NewEncoder(os.Stdout).Encode(nikaKubernetesResponse{
				Error: "discovery failed",
			})
		case "missing-available":
			_, _ = os.Stdout.WriteString("{}\n")
		case "unknown-response-field":
			_, _ = os.Stdout.WriteString(`{"available":true,"unexpected":true}` + "\n")
		case "multiple-responses":
			_, _ = os.Stdout.WriteString("{\"available\":true}\n{\"available\":true}\n")
		default:
			_ = json.NewEncoder(os.Stdout).Encode(nikaKubernetesResponse{Available: true})
		}
		os.Exit(0)
	}
	if mode == "credential-state" {
		_ = json.NewEncoder(os.Stdout).Encode(nikaKubernetesResponse{
			Available: true,
			State:     fault.State{"service_account_token": "should-not-cross"},
		})
		os.Exit(0)
	}
	_ = json.NewEncoder(os.Stdout).Encode(nikaKubernetesResponse{
		Available: true,
		State: fault.State{
			"namespace": "twinet-nika-unit",
			"owner":     "0123456789abcdef",
		},
		Evidence: fault.Evidence{
			Verified: true,
			Detail:   "request Authorization: Bearer should-not-cross",
			Observed: `{"token":"should-not-cross"}`,
			Expected: "-----BEGIN PRIVATE KEY----- should-not-cross",
		},
	})
	os.Exit(0)
}
