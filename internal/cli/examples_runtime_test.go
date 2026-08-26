package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
	twinetruntime "github.com/HongyuHe/twinet/internal/runtime"
)

// bundledExamples returns every lab that ships with the source tree.
//
// Found rather than listed: a bundled lab that nothing checks is a lab that
// stops being deployable without anybody noticing, which is exactly how six of
// the seven came to require Docker while the documented cluster ran containerd.
func bundledExamples(t *testing.T) map[string]string {
	t.Helper()
	root := documentationRepoRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "examples"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, "examples", entry.Name())
		if _, err := os.Stat(filepath.Join(dir, "twinet.yaml")); err != nil {
			continue
		}
		out[entry.Name()] = dir
	}
	if len(out) == 0 {
		t.Fatal("no bundled examples were found")
	}
	return out
}

// Every bundled lab must be deployable, unmodified, on the cluster the
// documentation tells an operator to build.
//
// Six of the seven declared no runtime at all, which means Docker for
// compatibility with manifests older than the runtime registry. On the
// documented containerd cluster each of them was refused by the agent
// backend check -- after the operator had installed a cluster, issued a PKI,
// and rolled out agents, following a guide whose own examples could not run on
// it. Only `examples/scale` said containerd, so the bundle had two contracts
// and no way to tell which lab followed which.
func TestEveryBundledExampleDeclaresTheClusterRuntime(t *testing.T) {
	for name, dir := range bundledExamples(t) {
		t.Run(name, func(t *testing.T) {
			loaded, err := manifest.Load(dir)
			if err != nil {
				t.Fatalf("load examples/%s: %v", name, err)
			}
			if !loaded.Lab.RuntimeDeclared() {
				t.Fatalf("examples/%s declares no container runtime, so it deploys on %q "+
					"by default and cannot run on the documented %s cluster",
					name, model.DefaultRuntime, model.RecommendedRuntime)
			}
			if got := loaded.Lab.RuntimeForNode(""); got != model.RecommendedRuntime {
				t.Errorf("examples/%s selects %q; the bundle has one runtime contract and it is %q",
					name, got, model.RecommendedRuntime)
			}
			for _, node := range loaded.Lab.Placement.Nodes {
				selected := loaded.Lab.RuntimeForNode(node.Name)
				if selected != model.RecommendedRuntime {
					t.Errorf("examples/%s node %s selects %q, not %q; a lab split across two "+
						"engines deploys half of itself",
						name, node.Name, selected, model.RecommendedRuntime)
				}
				if err := twinetruntime.ValidateSelection(selected, node.RuntimeSocket); err != nil {
					t.Errorf("examples/%s node %s: %v", name, node.Name, err)
				}
			}
			diags := loaded.Validate()
			if diags.HasErrors() {
				t.Fatalf("examples/%s does not validate:\n%s", name, diags.String())
			}
			for _, item := range diags.Items {
				if strings.Contains(item.Message, "no container runtime is declared") {
					t.Errorf("examples/%s: %s", name, item.Message)
				}
			}
		})
	}
}

// Docker and Podman remain usable, and remain something an operator states.
//
// The override is what keeps one manifest deployable on the cluster and on a
// workstation: it replaces the lab default and every per-node selection, so a
// lab cannot end up half on one engine because a node named its own.
func TestRuntimeOverrideMakesEveryExampleDeployableOnDockerOrPodman(t *testing.T) {
	for name, dir := range bundledExamples(t) {
		for _, backend := range []string{"docker", "podman", "containerd"} {
			t.Run(name+"/"+backend, func(t *testing.T) {
				loaded, err := manifest.Load(dir)
				if err != nil {
					t.Fatalf("load examples/%s: %v", name, err)
				}
				var notice strings.Builder
				opts := &Options{Manifest: dir, Runtime: backend}
				if err := applyRuntimeSelection(opts, loaded, &notice); err != nil {
					t.Fatalf("--runtime %s on examples/%s: %v", backend, name, err)
				}
				if !strings.Contains(notice.String(), backend) {
					t.Errorf("the override was applied silently: %q", notice.String())
				}
				if got := loaded.Lab.RuntimeForNode(""); got != backend {
					t.Errorf("lab default is %q after --runtime %s", got, backend)
				}
				for _, node := range loaded.Lab.Placement.Nodes {
					if got := loaded.Lab.RuntimeForNode(node.Name); got != backend {
						t.Errorf("node %s is %q after --runtime %s; the manifest's own "+
							"selection outlived the override", node.Name, got, backend)
					}
				}
				if diags := loaded.Validate(); diags.HasErrors() {
					t.Fatalf("examples/%s does not validate on %s:\n%s", name, backend, diags.String())
				}
			})
		}
	}
}

// An override that is not a registered backend is refused before it can reach a
// deployment, and an endpoint without a backend is refused rather than ignored.
func TestRuntimeOverrideRefusesWhatItCannotRun(t *testing.T) {
	dir := bundledExamples(t)["cos461"]
	if dir == "" {
		t.Fatal("examples/cos461 is missing")
	}
	loaded, err := manifest.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = applyRuntimeSelection(&Options{Manifest: dir, Runtime: "kubernetes"}, loaded, nil)
	if err == nil || !strings.Contains(err.Error(), "kubernetes") {
		t.Fatalf("an unregistered override was accepted: %v", err)
	}
	if got := loaded.Lab.RuntimeForNode(""); got != model.RecommendedRuntime {
		t.Fatalf("a refused override still changed the lab to %q", got)
	}
	err = applyRuntimeSelection(&Options{Manifest: dir, RuntimeSocket: "unix:///run/x.sock"}, loaded, nil)
	if err == nil || !strings.Contains(err.Error(), "--runtime") {
		t.Fatalf("an endpoint for no backend was accepted: %v", err)
	}
}
