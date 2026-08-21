//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

// e2eNodeObservation is the stable, machine-readable part of `node status`.
// Keep the raw status visible in the release artifact, but test the fields
// needed to tell an unreachable node from a healthy one with no capacity.
type e2eNodeObservation struct {
	Node   string `json:"node"`
	Error  string `json:"error,omitempty"`
	Status struct {
		Node        string            `json:"node"`
		Version     string            `json:"version"`
		Runtime     string            `json:"runtime"`
		RuntimeVer  string            `json:"runtime_version"`
		CPUs        int               `json:"cpus"`
		Containers  int               `json:"containers"`
		Labs        []string          `json:"labs"`
		Busy        []string          `json:"busy"`
		Overlays    map[string]string `json:"overlays"`
		Generations map[string]string `json:"generations"`
	} `json:"status"`
}

func statusObservations(t *testing.T, dir string) ([]e2eNodeObservation, error) {
	t.Helper()
	out, err := twinet(t, "--json", "node", "status", "-m", dir)
	var got []e2eNodeObservation
	if jsonErr := json.Unmarshal([]byte(out), &got); jsonErr != nil {
		return nil, fmt.Errorf("parse node status JSON (command error %v): %w\n%s", err, jsonErr, out)
	}
	if len(got) == 0 {
		return nil, fmt.Errorf("node status named no nodes")
	}
	sort.Slice(got, func(i, j int) bool { return got[i].Node < got[j].Node })
	return got, err
}

func requireHealthyMultiNodeCluster(t *testing.T, dir string) []e2eNodeObservation {
	t.Helper()
	got, err := statusObservations(t, dir)
	if err != nil {
		t.Fatalf("cluster status is not clean: %v", err)
	}
	if len(got) < 2 {
		t.Fatalf("missing capability: reliability tests require at least two node agents, found %d", len(got))
	}
	for _, node := range got {
		if node.Error != "" {
			t.Fatalf("node %s could not be measured: %s", node.Node, node.Error)
		}
		if node.Status.Node == "" || node.Status.Runtime == "" || node.Status.RuntimeVer == "" {
			t.Fatalf("node %s did not expose a complete status/resource payload", node.Node)
		}
		if node.Status.CPUs < 1 || node.Status.Containers < 0 {
			t.Fatalf("node %s exposed invalid resources: cpus=%d containers=%d",
				node.Node, node.Status.CPUs, node.Status.Containers)
		}
	}
	return got
}

func waitForHealthyMultiNodeCluster(t *testing.T, dir string, timeout time.Duration) []e2eNodeObservation {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		got, err := statusObservations(t, dir)
		if err == nil && len(got) >= 2 {
			healthy := true
			for _, node := range got {
				if node.Error != "" || node.Status.Node == "" || node.Status.Runtime == "" ||
					node.Status.RuntimeVer == "" || node.Status.CPUs < 1 || node.Status.Containers < 0 {
					healthy = false
					break
				}
			}
			if healthy {
				return got
			}
		}
		last = err
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("cluster did not return to a complete, healthy multi-node status within %s: %v", timeout, last)
	return nil
}

func generationFor(t *testing.T, nodes []e2eNodeObservation, lab string) string {
	t.Helper()
	var generation string
	for _, node := range nodes {
		got := node.Status.Generations[lab]
		if got == "" {
			t.Fatalf("node %s does not report a committed generation for %s; "+
				"missing capability: committed generation status is required for a partial-apply test",
				node.Node, lab)
		}
		if generation == "" {
			generation = got
			continue
		}
		if got != generation {
			t.Fatalf("mixed committed generation for %s: node %s has %q, want %q",
				lab, node.Node, got, generation)
		}
	}
	return generation
}

func topologyForCluster(t *testing.T, dir string) *model.Topology {
	t.Helper()
	path := filepath.Join(dir, "twinet.yaml")
	lab, err := manifest.Load(path)
	if err != nil {
		t.Fatalf("load cluster manifest for direct agent checks: %v", err)
	}
	res, err := expand.Expand(lab.Lab)
	if err != nil {
		t.Fatalf("expand cluster manifest for direct agent checks: %v", err)
	}
	return res.Topology
}

func clusterClient(t *testing.T, dir string) (*client.Cluster, *model.Topology) {
	t.Helper()
	token := os.Getenv("TWINET_TOKEN")
	if token == "" {
		t.Fatal("TWINET_TOKEN is required; TestMain should have refused to start")
	}
	top := topologyForCluster(t, dir)
	return client.NewCluster(top.Lab, token), top
}

func e2eArtifactDir(t *testing.T, prefix string) string {
	t.Helper()
	root := os.Getenv("TWINET_E2E_ARTIFACT_DIR")
	if root == "" {
		root = filepath.Join("..", "..", "reports", "e2e")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("create e2e evidence directory %s: %v", root, err)
	}
	dir, err := os.MkdirTemp(root, prefix+"-")
	if err != nil {
		t.Fatalf("create e2e scratch directory under %s: %v", root, err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove e2e scratch directory %s: %v", dir, err)
		}
	})
	return dir
}

func deviceFingerprint(t *testing.T, dir, device string) string {
	t.Helper()
	out, err := twinet(t, "exec", "-m", dir, device, "--", "sh", "-c",
		"sha256sum /etc/frr/frr.conf; ip -o -4 addr show | sort")
	if err != nil {
		t.Fatalf("fingerprint %s: %v\n%s", device, err, out)
	}
	fingerprint := strings.TrimSpace(stripCLINoise(out))
	if fingerprint == "" {
		t.Fatalf("fingerprint %s returned no configuration evidence", device)
	}
	return fingerprint
}

type runtimeNode struct {
	Name string `json:"name"`
	Node string `json:"node"`
}

func runtimeNodeLocations(t *testing.T, dir string) map[string]string {
	t.Helper()
	out, err := twinet(t, "runtime", "nodes", "-m", dir)
	if err != nil {
		t.Fatalf("list runtime nodes: %v\n%s", err, out)
	}
	var doc struct {
		Nodes []runtimeNode `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("parse runtime nodes: %v\n%s", err, out)
	}
	if len(doc.Nodes) == 0 {
		t.Fatal("runtime nodes response has no devices")
	}
	outByDevice := make(map[string]string, len(doc.Nodes))
	for _, node := range doc.Nodes {
		if node.Name == "" || node.Node == "" {
			t.Fatalf("runtime nodes response has incomplete placement: %+v", node)
		}
		outByDevice[node.Name] = node.Node
	}
	return outByDevice
}

func runController(t *testing.T, ctx context.Context, args ...string) (string, error) {
	t.Helper()
	binary := os.Getenv("TWINET_BIN")
	if binary == "" {
		binary = controller(t)
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func requireDestructiveChaos(t *testing.T) {
	t.Helper()
	if os.Getenv("TWINET_CHAOS_ALLOW_DESTRUCTIVE") == "1" {
		return
	}
	if os.Getenv("TWINET_CHAOS_REQUIRED") == "1" {
		t.Fatal("TWINET_CHAOS_REQUIRED is set but TWINET_CHAOS_ALLOW_DESTRUCTIVE=1 is not; " +
			"the dedicated chaos target must never turn destructive coverage into skips")
	}
	t.Skip("set TWINET_CHAOS_ALLOW_DESTRUCTIVE=1 to run destructive cluster chaos")
}

func chaosHook(t *testing.T, variable, node, peer string) {
	t.Helper()
	command := os.Getenv(variable)
	if command == "" {
		t.Fatalf("missing capability: %s must name the self-hosted runner command that safely performs this fault; "+
			"the test will not silently skip a node or underlay failure", variable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Env = append(os.Environ(),
		"TWINET_CHAOS_NODE="+node,
		"TWINET_CHAOS_PEER_NODE="+peer,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed for node=%s peer=%s: %v\n%s", variable, node, peer, err, out)
	}
}

func chaosCleanupHook(t *testing.T, variable, node, peer string) {
	t.Helper()
	command := os.Getenv(variable)
	if command == "" {
		t.Errorf("missing cleanup capability %s after faulting node=%s peer=%s", variable, node, peer)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Env = append(os.Environ(),
		"TWINET_CHAOS_NODE="+node,
		"TWINET_CHAOS_PEER_NODE="+peer,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("%s cleanup failed for node=%s peer=%s: %v\n%s", variable, node, peer, err, out)
	}
}

func sweepMustBeClean(t *testing.T, dir string) {
	t.Helper()
	out, err := twinet(t, "node", "sweep", "-m", dir)
	if err != nil {
		t.Fatalf("inspect stale overlays: %v\n%s", err, out)
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] == "NODE" {
			continue
		}
		if fields[1] != "0" {
			t.Fatalf("node %s has %s stale overlay object(s):\n%s", fields[0], fields[1], out)
		}
	}
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(destination, 0o700)
		}
		if entry.IsDir() {
			if entry.Name() == ".twinet" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(destination, rel), 0o700)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		target := filepath.Join(destination, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		t.Fatalf("copy manifest tree %s: %v", source, err)
	}
}
