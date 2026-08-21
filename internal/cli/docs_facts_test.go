package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/fault"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
	"github.com/HongyuHe/twinet/internal/nos"
	"github.com/HongyuHe/twinet/internal/place"
	twinetruntime "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

const (
	documentationFactsStart = "<!-- BEGIN SOURCE-GENERATED CAPABILITY FACTS -->"
	documentationFactsEnd   = "<!-- END SOURCE-GENERATED CAPABILITY FACTS -->"
)

type documentationFacts struct {
	Binaries            []string                      `json:"binaries"`
	RuntimeBackends     []string                      `json:"runtime_backends"`
	RuntimeBackendCount int                           `json:"runtime_backend_count"`
	NetworkOSes         []string                      `json:"network_operating_systems"`
	NetworkOSCount      int                           `json:"network_operating_system_count"`
	InteriorGenerators  []string                      `json:"interior_generators"`
	InteriorCount       int                           `json:"interior_generator_count"`
	Faults              documentationFaultFacts       `json:"faults"`
	ShippedCapabilities []string                      `json:"shipped_capabilities"`
	BundledExampleStats map[string]documentationStats `json:"bundled_examples"`
}

type documentationFaultFacts struct {
	Total int `json:"total"`
	NIKA  int `json:"nika"`
}

type documentationStats struct {
	ASes    int `json:"ases"`
	Devices int `json:"devices"`
	Links   int `json:"links"`
}

// TestDocumentationFactsMatchSource makes the human-readable status ledger a
// checked projection of registries and the CLI rather than a second ledger that
// somebody has to remember to update by hand.
func TestDocumentationFactsMatchSource(t *testing.T) {
	root := documentationRepoRoot(t)
	want := sourceDocumentationFacts(t, root)
	got := documentedFacts(t, filepath.Join(root, "docs", "09_status.md"))

	wantJSON, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("docs/09_status.md source facts are stale.\n\nwant:\n%s\n\ngot:\n%s\n",
			wantJSON, gotJSON)
	}
}

func documentationRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repository root")
		}
		dir = parent
	}
}

func sourceDocumentationFacts(t *testing.T, root string) documentationFacts {
	t.Helper()
	capabilities := proveDocumentedCapabilities(t)
	runtimes := twinetruntime.RuntimeNames()
	networkOSes := nos.Names()
	interiors := model.Generators.Kinds(model.GeneratorInterior)

	return documentationFacts{
		Binaries:            commandBinaries(t, root),
		RuntimeBackends:     runtimes,
		RuntimeBackendCount: len(runtimes),
		NetworkOSes:         networkOSes,
		NetworkOSCount:      len(networkOSes),
		InteriorGenerators:  interiors,
		InteriorCount:       len(interiors),
		Faults:              faultFacts(t, root),
		ShippedCapabilities: capabilities,
		BundledExampleStats: bundledExampleStats(t, root),
	}
}

func commandBinaries(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "cmd"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := os.Stat(filepath.Join(root, "cmd", entry.Name(), "main.go"))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if info.Mode().IsRegular() {
			out = append(out, entry.Name())
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("cmd contains no buildable main packages")
	}
	return out
}

func faultFacts(t *testing.T, root string) documentationFaultFacts {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "internal", "fault", "nika_types.json"))
	if err != nil {
		t.Fatal(err)
	}
	var nika map[string]string
	if err := json.Unmarshal(raw, &nika); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, registered := range fault.All() {
		have[registered.Name] = true
	}
	nikaCount := 0
	for name := range nika {
		if have[name] {
			nikaCount++
		}
	}
	return documentationFaultFacts{Total: len(have), NIKA: nikaCount}
}

// bundledExampleStats intentionally invokes `go run ./cmd/twinet`, not helper
// functions from this package. A documentation fact about a bundle is useful
// only if the command a reader runs can still produce it from the checked
// source tree.
func bundledExampleStats(t *testing.T, root string) map[string]documentationStats {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("source-built CLI documentation check needs go: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "examples"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]documentationStats{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		example := entry.Name()
		if _, err := os.Stat(filepath.Join(root, "examples", example, "twinet.yaml")); err != nil {
			continue
		}
		cmd := exec.Command(goTool, "run", "./cmd/twinet",
			"--manifest", filepath.Join("examples", example), "validate", "--json")
		cmd.Dir = root
		raw, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("source CLI validate examples/%s: %v\n%s", example, err, raw)
		}
		var response struct {
			Stats struct {
				ASes    int
				Devices int
				Links   int
			} `json:"stats"`
		}
		found := false
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "{") {
				continue
			}
			if err := json.Unmarshal([]byte(line), &response); err == nil {
				found = true
			}
		}
		if !found {
			t.Fatalf("source CLI validate examples/%s emitted no JSON:\n%s", example, raw)
		}
		out[example] = documentationStats{
			ASes: response.Stats.ASes, Devices: response.Stats.Devices, Links: response.Stats.Links,
		}
	}
	if len(out) == 0 {
		t.Fatal("no bundled examples were validated")
	}
	return out
}

func documentedFacts(t *testing.T, path string) documentationFacts {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	start := strings.Index(body, documentationFactsStart)
	end := strings.Index(body, documentationFactsEnd)
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("%s must contain one generated source-facts block", path)
	}
	block := strings.TrimSpace(body[start+len(documentationFactsStart) : end])
	block = strings.TrimPrefix(block, "```json")
	block = strings.TrimPrefix(block, "```")
	block = strings.TrimSpace(block)
	block = strings.TrimSuffix(block, "```")
	block = strings.TrimSpace(block)

	var out documentationFacts
	if err := json.Unmarshal([]byte(block), &out); err != nil {
		t.Fatalf("parse source facts in %s: %v", path, err)
	}
	return out
}

// proveDocumentedCapabilities is deliberately a table of executable source
// probes, not a second prose feature ledger. If a capability API disappears,
// the generated documentation cannot continue to call it shipped.
func proveDocumentedCapabilities(t *testing.T) []string {
	t.Helper()
	proofs := []struct {
		name  string
		fact  string
		prove func(*testing.T)
	}{
		{
			name: "agent HTTP/mTLS surface",
			fact: "agent-http-json-mtls",
			prove: func(t *testing.T) {
				requireMethod(t, reflect.TypeOf(&agent.Server{}), "Serve")
				requireFields(t, reflect.TypeOf(agent.Config{}), "TLSCert", "TLSKey", "ClientCA")
			},
		},
		{
			name: "persistent state",
			fact: "persistent-state",
			prove: func(t *testing.T) {
				requireMethod(t, reflect.TypeOf(&state.Store{}), "Put")
				requireMethod(t, reflect.TypeOf(&state.Store{}), "PutRecord")
				requireMethod(t, reflect.TypeOf(&state.Store{}), "PutReplicaStatus")
			},
		},
		{
			name: "fenced mutation leases",
			fact: "fenced-mutation-leases",
			prove: func(t *testing.T) {
				requireFields(t, reflect.TypeOf(agent.Fence{}), "Token", "Generation")
				requireFields(t, reflect.TypeOf(agent.LeaseAcquireRequest{}), "Lab", "TTLSeconds")
			},
		},
		{
			name: "Docker Engine API runtime",
			fact: "docker-engine-api-runtime",
			prove: func(t *testing.T) {
				if !documentationContains(twinetruntime.RuntimeNames(), "docker") {
					t.Fatal("docker is no longer a registered runtime")
				}
				caps, ok := twinetruntime.CapabilitiesFor("docker")
				if !ok || !caps.Lifecycle || !caps.Exec || !caps.NetworkNamespaces || !caps.Events {
					t.Fatalf("docker runtime capabilities are incomplete: %#v, registered=%t", caps, ok)
				}
			},
		},
		{
			name: "shared VXLAN overlay",
			fact: "shared-vxlan-overlays",
			prove: func(t *testing.T) {
				requireFields(t, reflect.TypeOf(netx.MultiplexOverlaySpec{}),
					"Lab", "LocalNode", "RemoteNode", "VNI", "VLAN")
				_ = netx.EnsureMultiplexOverlay
				_ = netx.AssignOverlayVLANs
			},
		},
		{
			name: "replicated state and services",
			fact: "replicated-state-and-services",
			prove: func(t *testing.T) {
				requireFields(t, reflect.TypeOf(model.StatePolicy{}), "ReplicationFactor", "CaptureInterval", "FailClosed")
				requireFields(t, reflect.TypeOf(model.ServiceReplicationPolicy{}), "Mode")
			},
		},
		{
			name: "generated interiors",
			fact: "generated-interiors",
			prove: func(t *testing.T) {
				for _, kind := range []string{"explicit", "ring", "two-tier", "clos"} {
					if !model.Generators.Has(model.GeneratorInterior, kind) {
						t.Fatalf("interior generator %q is no longer registered", kind)
					}
				}
			},
		},
		{
			name: "BIRD NOS",
			fact: "bird-nos",
			prove: func(t *testing.T) {
				provider, ok := nos.Lookup("bird")
				if !ok || provider.Name() != "bird" {
					t.Fatal("BIRD is no longer a registered NOS provider")
				}
			},
		},
		{
			name: "metrics and events",
			fact: "metrics-and-events",
			prove: func(t *testing.T) {
				requireFields(t, reflect.TypeOf(agent.Config{}), "EventCapacity")
				requireMethod(t, reflect.TypeOf(&client.Node{}), "Events")
				requireMethod(t, reflect.TypeOf(&client.Node{}), "WatchEvents")
			},
		},
		{
			name: "strict admission",
			fact: "strict-admission",
			prove: func(t *testing.T) {
				_ = place.AdmitPlaced
				requireFields(t, reflect.TypeOf(model.ResourceRequest{}),
					"CPUs", "Memory", "Pids", "EphemeralStorage", "NetDevices")
			},
		},
	}
	facts := make([]string, 0, len(proofs))
	for _, proof := range proofs {
		t.Run(proof.name, proof.prove)
		facts = append(facts, proof.fact)
	}
	return facts
}

func requireMethod(t *testing.T, typ reflect.Type, method string) {
	t.Helper()
	if _, ok := typ.MethodByName(method); !ok {
		t.Fatalf("%s has no exported %s method", typ, method)
	}
}

func requireFields(t *testing.T, typ reflect.Type, fields ...string) {
	t.Helper()
	for _, field := range fields {
		if _, ok := typ.FieldByName(field); !ok {
			t.Fatalf("%s has no %s field", typ, field)
		}
	}
}

func documentationContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestDocumentationRejectsKnownStaleClaims(t *testing.T) {
	root := documentationRepoRoot(t)
	paths := []string{
		filepath.Join(root, "README.md"),
		filepath.Join(root, "docs", "README.md"),
		filepath.Join(root, "docs", "02_architecture.md"),
		filepath.Join(root, "docs", "03_topology_model.md"),
		filepath.Join(root, "docs", "04_networking_and_scaleout.md"),
		filepath.Join(root, "docs", "05_services.md"),
		filepath.Join(root, "docs", "06_grading.md"),
		filepath.Join(root, "docs", "07_roadmap.md"),
		filepath.Join(root, "docs", "08_resources_needed.md"),
	}
	forbidden := []string{
		"twinet is two go binaries and nothing else",
		"gRPC/mTLS",
		"twinet has **no state store**",
		"one binary, no runtime dependencies",
		"point-to-point vxlan for cross-node",
		"per-link **vxlan**",
		"event stream *(planned",
		"multicast has neither an exercise nor a check",
		"the cos-461 hijack scenarios (q2.6) are not scripted",
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(raw))
		for _, claim := range forbidden {
			if strings.Contains(lower, strings.ToLower(claim)) {
				t.Errorf("%s retains stale claim %q", filepath.Base(path), claim)
			}
		}
	}
}

// TestDocumentationLinksAndBenchmarkLabels makes the standalone checker part
// of the ordinary Go documentation gate as well as a command an author can run
// directly.
func TestDocumentationLinksAndBenchmarkLabels(t *testing.T) {
	root := documentationRepoRoot(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("documentation link/path check needs python3: %v", err)
	}
	cmd := exec.Command(python, "scripts/check_docs.py")
	cmd.Dir = root
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("documentation link/path check: %v\n%s", err, raw)
	}
}
