//go:build k8sbackend

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/fault"
)

const (
	disposableClusterLabel  = "twinet.dev/disposable-cluster"
	bridgeManagedLabel      = "twinet.dev/managed-by"
	bridgeManagedValue      = "nika-kubernetes-acceptance"
	clusterMarkerName       = "twinet-nika-disposable-cluster"
	defaultK8sHelperImage   = "docker.io/nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b"
	defaultK8sWorkloadImage = "docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
)

var immutableK8sImage = regexp.MustCompile(`^.+@sha256:[0-9a-f]{64}$`)

type realKubernetesNode struct {
	Name     string
	Address  string
	Control  bool
	Ready    bool
	AuditPod string
}

type realKubernetesFixture struct {
	kubectl       string
	kubeconfig    string
	cacheDir      string
	context       string
	endpoint      string
	clusterID     string
	namespace     string
	control       realKubernetesNode
	target        realKubernetesNode
	other         realKubernetesNode
	nodes         []realKubernetesNode
	serviceIP     string
	serverIP      string
	controlIP     string
	helperImage   string
	workloadImage string
}

// TestRealNIKAKubernetesBackendLifecycle runs only on an explicitly marked,
// disposable multi-node cluster. The worker faults change the named node's
// network namespace, matching NIKA's node-filter semantics; fixture and audit
// pods independently prove the symptom and exact restoration.
func TestRealNIKAKubernetesBackendLifecycle(t *testing.T) {
	if os.Getenv("TWINET_K8S_FAULT_INTEGRATION_ALLOW_DESTRUCTIVE") != "1" {
		t.Fatal("k8sbackend requires TWINET_K8S_FAULT_INTEGRATION_ALLOW_DESTRUCTIVE=1")
	}
	if os.Getenv("TWINET_K8S_DISPOSABLE_CLUSTER") != "1" {
		t.Fatal("k8sbackend requires TWINET_K8S_DISPOSABLE_CLUSTER=1 and must never target production")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	fixture := createRealKubernetesFixture(t, ctx)

	backend := kubernetesBackendFromEnv()
	if backend == nil {
		t.Fatal("no NIKA Kubernetes endpoint/context/bridge is configured")
	}
	available, reason, err := backend.Available(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !available {
		t.Fatalf("configured NIKA Kubernetes backend is unavailable: %s", reason)
	}

	cases := []struct {
		name     string
		category fault.Category
	}{
		{"k8s_clusterip_routing_broken", fault.CatNodeError},
		{"k8s_coredns_isolated", fault.CatMisconfig},
		{"k8s_networkpolicy_deny", fault.CatMisconfig},
		{"k8s_worker_apiserver_partition", fault.CatMisconfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture.assertBaseline(t, ctx)
			before := fixture.snapshot(t, ctx)
			target := fault.Target{
				Device: "k8s/" + fixture.namespace + "/" + fixture.target.Name,
				Params: map[string]string{
					"namespace":  fixture.namespace,
					"cluster_id": fixture.clusterID,
					"node_name":  fixture.target.Name,
				},
			}
			env := &fault.Env{Kubernetes: backend}
			injection, err := fault.Inject(ctx, env, tc.name, target)
			if err != nil {
				t.Fatalf("common Twinet injection failed: %v", err)
			}
			resolved := false
			defer func() {
				if !resolved {
					_ = backend.Resolve(context.Background(), tc.name, target, injection.State)
				}
			}()
			if !injection.Evidence.Verified {
				t.Fatalf("injection did not manifest: %#v", injection.Evidence)
			}
			if injection.Truth.Category != string(tc.category) ||
				len(injection.Truth.Names) != 1 || injection.Truth.Names[0] != tc.name {
				t.Fatalf("common incident schema was not preserved: %#v", injection.Truth)
			}
			fixture.assertFault(t, ctx, tc.name, injection.State)

			evidence, err := fault.Verify(ctx, env, injection)
			if err != nil {
				t.Fatalf("common Twinet verification failed: %v", err)
			}
			if !evidence.Verified {
				t.Fatalf("fault stopped manifesting before resolve: %#v", evidence)
			}
			if err := fault.Resolve(ctx, env, injection); err != nil {
				t.Fatalf("common Twinet resolve failed: %v", err)
			}
			resolved = true

			baseline, err := backend.Verify(ctx, tc.name, target, injection.State)
			if err != nil {
				t.Fatalf("restored baseline could not be verified: %v", err)
			}
			if baseline.Verified ||
				!strings.Contains(strings.ToLower(baseline.Detail), "baseline restored") {
				t.Fatalf("resolve did not report the restored worker fixture: %#v", baseline)
			}
			fixture.assertBaseline(t, ctx)
			fixture.assertNoOwnerRules(t, ctx, injection.State["owner"])
			after := fixture.snapshot(t, ctx)
			if strings.Join(before, "\n") != strings.Join(after, "\n") {
				t.Fatalf("fixture objects were not restored exactly:\nbefore=%v\nafter=%v", before, after)
			}
		})
	}
}

func createRealKubernetesFixture(t *testing.T, ctx context.Context) *realKubernetesFixture {
	t.Helper()
	f := &realKubernetesFixture{
		kubectl:    os.Getenv("TWINET_K8S_KUBECTL"),
		kubeconfig: os.Getenv("TWINET_K8S_KUBECONFIG"),
		cacheDir:   os.Getenv("TWINET_K8S_CACHE_DIR"),
		context:    os.Getenv("TWINET_NIKA_KUBERNETES_CONTEXT"),
		endpoint:   os.Getenv("TWINET_NIKA_KUBERNETES_ENDPOINT"),
		clusterID:  fmt.Sprintf("twinet-nika-cluster-%d", os.Getpid()),
		namespace:  fmt.Sprintf("twinet-nika-fixture-%d", os.Getpid()),
	}
	if f.kubectl == "" {
		f.kubectl = "kubectl"
	}
	if f.cacheDir == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			t.Fatalf("resolve kubectl cache directory: %v", err)
		}
		f.cacheDir = filepath.Join(cache, "twinet-kubernetes-integration")
	}
	f.helperImage = os.Getenv("TWINET_K8S_HELPER_IMAGE")
	if f.helperImage == "" {
		f.helperImage = defaultK8sHelperImage
	}
	f.workloadImage = os.Getenv("TWINET_K8S_WORKLOAD_IMAGE")
	if f.workloadImage == "" {
		f.workloadImage = defaultK8sWorkloadImage
	}
	for name, image := range map[string]string{
		"TWINET_K8S_HELPER_IMAGE":   f.helperImage,
		"TWINET_K8S_WORKLOAD_IMAGE": f.workloadImage,
	} {
		if !immutableK8sImage.MatchString(image) {
			t.Fatalf("%s must be an immutable @sha256 image reference", name)
		}
	}
	t.Cleanup(func() { f.destroy(t) })
	var list struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Status struct {
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
				Addresses []struct {
					Type    string `json:"type"`
					Address string `json:"address"`
				} `json:"addresses"`
			} `json:"status"`
		} `json:"items"`
	}
	f.json(t, ctx, &list, "get", "nodes", "-o", "json")
	var workers []realKubernetesNode
	for _, item := range list.Items {
		node := realKubernetesNode{Name: item.Metadata.Name}
		_, controlPlane := item.Metadata.Labels["node-role.kubernetes.io/control-plane"]
		_, master := item.Metadata.Labels["node-role.kubernetes.io/master"]
		node.Control = controlPlane || master
		for _, condition := range item.Status.Conditions {
			node.Ready = node.Ready || condition.Type == "Ready" && condition.Status == "True"
		}
		for _, address := range item.Status.Addresses {
			if address.Type == "InternalIP" {
				node.Address = address.Address
			}
		}
		if !node.Ready || node.Address == "" {
			t.Fatalf("node %s is not a ready disposable baseline", node.Name)
		}
		if item.Metadata.Labels[disposableClusterLabel] != "" {
			t.Fatalf("node %s already carries %s", node.Name, disposableClusterLabel)
		}
		if node.Control {
			if f.control.Name != "" {
				t.Fatal("real gate requires exactly one control-plane node")
			}
			f.control = node
		} else {
			workers = append(workers, node)
		}
		f.nodes = append(f.nodes, node)
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].Name < workers[j].Name })
	if f.control.Name == "" || len(workers) < 2 {
		t.Fatal("real gate requires one control plane and at least two workers")
	}
	f.target, f.other = workers[0], workers[1]
	if f.optional(t, ctx, "-n", "kube-system", "get", "configmap", clusterMarkerName) {
		t.Fatalf("cluster marker %s already exists; refusing to reuse a cluster", clusterMarkerName)
	}

	marker := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      clusterMarkerName,
			"namespace": "kube-system",
			"annotations": map[string]string{
				"twinet.dev/allow-node-faults": "true",
			},
		},
		"data": map[string]string{
			"cluster_id": f.clusterID,
			"context":    f.context,
			"endpoint":   f.endpoint,
		},
	}
	f.apply(t, ctx, marker)
	for index := range f.nodes {
		f.run(t, ctx, "label", "node", f.nodes[index].Name,
			disposableClusterLabel+"="+f.clusterID, "--overwrite")
		switch f.nodes[index].Name {
		case f.control.Name:
			f.nodes[index].AuditPod = "audit-control"
		case f.target.Name:
			f.nodes[index].AuditPod = "audit-target"
		case f.other.Name:
			f.nodes[index].AuditPod = "audit-independent"
		default:
			f.nodes[index].AuditPod = fmt.Sprintf("audit-extra-%d", index)
		}
	}
	f.apply(t, ctx, f.fixtureManifest())
	names := []string{"server", "control-server", "client-target", "client-control"}
	for _, node := range f.nodes {
		names = append(names, node.AuditPod)
	}
	args := []string{"-n", f.namespace, "wait", "--for=condition=Ready"}
	for _, name := range names {
		args = append(args, "pod/"+name)
	}
	args = append(args, "--timeout=300s")
	f.run(t, ctx, args...)
	f.readAddresses(t, ctx)
	f.assertBaseline(t, ctx)
	return f
}

func (f *realKubernetesFixture) fixtureManifest() map[string]any {
	items := []any{
		map[string]any{
			"apiVersion": "v1", "kind": "Namespace",
			"metadata": map[string]any{
				"name": f.namespace,
				"labels": map[string]string{
					disposableClusterLabel: f.clusterID,
					bridgeManagedLabel:     bridgeManagedValue,
				},
			},
		},
		fixtureServerPod("server", "server", f.namespace, f.target.Name, f.workloadImage),
		fixtureServerPod("control-server", "control", f.namespace, f.other.Name, f.workloadImage),
		fixtureClientPod("client-target", f.namespace, f.target.Name, f.workloadImage),
		fixtureClientPod("client-control", f.namespace, f.other.Name, f.workloadImage),
		fixtureService("echo", "server", f.namespace),
		fixtureService("control", "control", f.namespace),
	}
	for _, node := range f.nodes {
		items = append(items, fixtureAuditPod(
			node.AuditPod, f.namespace, node.Name, f.helperImage))
	}
	return map[string]any{"apiVersion": "v1", "kind": "List", "items": items}
}

func fixtureServerPod(name, app, namespace, node, image string) map[string]any {
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{
			"name": name, "namespace": namespace,
			"labels": map[string]string{"app": app},
		},
		"spec": map[string]any{
			"nodeName": node, "restartPolicy": "Never",
			"automountServiceAccountToken": false,
			"tolerations":                  []any{map[string]any{"operator": "Exists"}},
			"securityContext": map[string]any{
				"runAsNonRoot": true, "runAsUser": 65534, "runAsGroup": 65534,
				"fsGroup": 65534, "seccompProfile": map[string]string{"type": "RuntimeDefault"},
			},
			"containers": []any{map[string]any{
				"name": name, "image": image, "imagePullPolicy": "IfNotPresent",
				"command": []string{"sh", "-c",
					"echo server-started; echo twinet-ok >/www/index.html; exec httpd -f -p 8080 -h /www"},
				"securityContext": map[string]any{
					"allowPrivilegeEscalation": false,
					"capabilities":             map[string]any{"drop": []string{"ALL"}},
				},
				"volumeMounts": []any{map[string]any{"name": "www", "mountPath": "/www"}},
			}},
			"volumes": []any{map[string]any{"name": "www", "emptyDir": map[string]any{}}},
		},
	}
}

func fixtureClientPod(name, namespace, node, image string) map[string]any {
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": namespace},
		"spec": map[string]any{
			"nodeName": node, "restartPolicy": "Never",
			"automountServiceAccountToken": false,
			"tolerations":                  []any{map[string]any{"operator": "Exists"}},
			"containers": []any{map[string]any{
				"name": name, "image": image, "imagePullPolicy": "IfNotPresent",
				"command": []string{"sh", "-c", "exec sleep 86400"},
			}},
		},
	}
}

func fixtureAuditPod(name, namespace, node, image string) map[string]any {
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": namespace},
		"spec": map[string]any{
			"nodeName": node, "hostNetwork": true, "dnsPolicy": "ClusterFirstWithHostNet",
			"restartPolicy": "Never", "automountServiceAccountToken": false,
			"tolerations": []any{map[string]any{"operator": "Exists"}},
			"containers": []any{map[string]any{
				"name": "audit", "image": image,
				"command": []string{"sh", "-c", "exec sleep 86400"},
				"securityContext": map[string]any{
					"allowPrivilegeEscalation": false, "runAsUser": 0, "runAsGroup": 0,
					"capabilities": map[string]any{
						"drop": []string{"ALL"}, "add": []string{"NET_ADMIN", "NET_RAW"},
					},
				},
			}},
		},
	}
}

func fixtureService(name, app, namespace string) map[string]any {
	return map[string]any{
		"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{"name": name, "namespace": namespace},
		"spec": map[string]any{
			"selector": map[string]string{"app": app},
			"ports": []any{map[string]any{
				"name": "http", "port": 80, "targetPort": 8080,
			}},
		},
	}
}

func (f *realKubernetesFixture) readAddresses(t *testing.T, ctx context.Context) {
	t.Helper()
	var service struct {
		Spec struct {
			ClusterIP string `json:"clusterIP"`
		} `json:"spec"`
	}
	f.json(t, ctx, &service, "-n", f.namespace, "get", "service", "echo", "-o", "json")
	f.serviceIP = service.Spec.ClusterIP
	f.json(t, ctx, &service, "-n", f.namespace, "get", "service", "control", "-o", "json")
	f.controlIP = service.Spec.ClusterIP
	var pod struct {
		Status struct {
			PodIP string `json:"podIP"`
		} `json:"status"`
	}
	f.json(t, ctx, &pod, "-n", f.namespace, "get", "pod", "server", "-o", "json")
	f.serverIP = pod.Status.PodIP
}

func (f *realKubernetesFixture) assertFault(
	t *testing.T, ctx context.Context, name string, state fault.State,
) {
	t.Helper()
	switch name {
	case "k8s_clusterip_routing_broken":
		f.wantHTTP(t, ctx, "client-target", f.serviceIP, 80, false)
		f.wantHTTP(t, ctx, "client-target", f.serverIP, 8080, true)
		f.wantHTTP(t, ctx, "client-control", f.serviceIP, 80, true)
		if !f.nodeReady(t, ctx, f.target.Name) {
			t.Fatal("ClusterIP fault made the target worker NotReady")
		}
		f.assertOwnerRules(t, ctx, state["owner"], f.target.Name)
	case "k8s_coredns_isolated":
		f.wantDNS(t, ctx, false)
		f.wantHTTP(t, ctx, "client-control", f.serviceIP, 80, true)
		var pods struct {
			Items []struct {
				Spec struct {
					NodeName string `json:"nodeName"`
				} `json:"spec"`
			} `json:"items"`
		}
		f.json(t, ctx, &pods, "-n", "kube-system", "get", "pods",
			"-l", "k8s-app=kube-dns", "-o", "json")
		for _, pod := range pods.Items {
			f.assertOwnerRules(t, ctx, state["owner"], pod.Spec.NodeName)
		}
	case "k8s_networkpolicy_deny":
		f.wantHTTP(t, ctx, "client-control", f.serviceIP, 80, false)
		f.wantHTTP(t, ctx, "client-control", f.controlIP, 80, true)
	case "k8s_worker_apiserver_partition":
		if f.workerAPIReachable(t, ctx, state) {
			t.Fatal("named worker still reaches the API server")
		}
		if f.nodeReady(t, ctx, f.target.Name) {
			t.Fatal("named worker remained Ready during API partition")
		}
		if f.succeeds(ctx, "-n", f.namespace, "logs", "server",
			"--tail=1", "--request-timeout=8s") {
			t.Fatal("kubectl logs still reached the partitioned worker")
		}
		f.wantHTTP(t, ctx, "client-control", f.serverIP, 8080, true)
		var pod struct {
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		}
		f.json(t, ctx, &pod, "-n", f.namespace, "get", "pod", state["stale_pod"], "-o", "json")
		if pod.Status.Phase == "Running" {
			t.Fatal("new workload started on the API-partitioned worker")
		}
	}
}

func (f *realKubernetesFixture) workerAPIReachable(
	t *testing.T, ctx context.Context, state fault.State,
) bool {
	t.Helper()
	var helpers []struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal([]byte(state["helpers"]), &helpers); err != nil || len(helpers) != 1 {
		t.Fatalf("decode worker helper state: %v", err)
	}
	const relay = `import json,sys,urllib.request;request=urllib.request.Request(sys.argv[1],headers={'X-Twinet-Owner':sys.argv[2]});print(urllib.request.urlopen(request,timeout=12).read().decode())`
	out := f.output(t, ctx, "-n", f.namespace, "exec", state["helper_relay"],
		"--", "python", "-c", relay,
		fmt.Sprintf("http://%s:18080/status", helpers[0].IP), state["owner"])
	var status struct {
		ProbeReachable *bool `json:"probe_reachable"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &status); err != nil {
		t.Fatalf("decode worker API-path status: %v", err)
	}
	if status.ProbeReachable == nil {
		t.Fatal("worker helper did not report its API path")
	}
	return *status.ProbeReachable
}

func (f *realKubernetesFixture) assertBaseline(t *testing.T, ctx context.Context) {
	t.Helper()
	if !f.nodeReady(t, ctx, f.target.Name) {
		t.Fatal("target worker is not Ready at baseline")
	}
	f.wantHTTP(t, ctx, "client-target", f.serviceIP, 80, true)
	f.wantHTTP(t, ctx, "client-control", f.serviceIP, 80, true)
	f.wantHTTP(t, ctx, "client-control", f.controlIP, 80, true)
	f.wantDNS(t, ctx, true)
	if !f.succeeds(ctx, "-n", f.namespace, "logs", "server",
		"--tail=1", "--request-timeout=10s") {
		t.Fatal("worker logs are unavailable at baseline")
	}
}

func (f *realKubernetesFixture) wantHTTP(
	t *testing.T, ctx context.Context, pod, address string, port int, reachable bool,
) {
	t.Helper()
	script := fmt.Sprintf(
		`if [ "$(wget -q -T 3 -O - http://%s:%d/ 2>/dev/null)" = twinet-ok ]; then echo reachable; else echo blocked; fi`,
		address, port)
	want := "blocked"
	if reachable {
		want = "reachable"
	}
	deadline := time.Now().Add(45 * time.Second)
	for {
		got := strings.TrimSpace(f.output(t, ctx, "-n", f.namespace, "exec", pod,
			"--", "sh", "-c", script))
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s HTTP probe to %s:%d = %q, want %q", pod, address, port, got, want)
		}
		time.Sleep(2 * time.Second)
	}
}

func (f *realKubernetesFixture) wantDNS(t *testing.T, ctx context.Context, reachable bool) {
	t.Helper()
	script := fmt.Sprintf(
		"if nslookup echo.%s.svc.cluster.local >/dev/null 2>&1; then echo reachable; else echo blocked; fi",
		f.namespace)
	want := "blocked"
	if reachable {
		want = "reachable"
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		got := strings.TrimSpace(f.output(t, ctx, "-n", f.namespace, "exec",
			"client-control", "--", "sh", "-c", script))
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("DNS probe = %q, want %q", got, want)
		}
		time.Sleep(2 * time.Second)
	}
}

func (f *realKubernetesFixture) nodeReady(t *testing.T, ctx context.Context, name string) bool {
	t.Helper()
	var node struct {
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
	}
	f.json(t, ctx, &node, "get", "node", name, "-o", "json")
	for _, condition := range node.Status.Conditions {
		if condition.Type == "Ready" {
			return condition.Status == "True"
		}
	}
	return false
}

func (f *realKubernetesFixture) auditPod(node string) string {
	for _, candidate := range f.nodes {
		if candidate.Name == node {
			return candidate.AuditPod
		}
	}
	return ""
}

func (f *realKubernetesFixture) assertOwnerRules(
	t *testing.T, ctx context.Context, owner, node string,
) {
	t.Helper()
	out := f.output(t, ctx, "-n", f.namespace, "exec", f.auditPod(node),
		"--", "sh", "-c", "iptables -t raw -S; ip6tables -t raw -S")
	if !strings.Contains(out, owner) {
		t.Fatalf("worker %s has no rule owned by injection %s", node, owner)
	}
}

func (f *realKubernetesFixture) assertNoOwnerRules(
	t *testing.T, ctx context.Context, owner string,
) {
	t.Helper()
	for _, node := range f.nodes {
		out := f.output(t, ctx, "-n", f.namespace, "exec", node.AuditPod,
			"--", "sh", "-c", "iptables -t raw -S; ip6tables -t raw -S")
		if strings.Contains(out, owner) {
			t.Fatalf("worker %s retained rule owned by injection %s", node.Name, owner)
		}
	}
}

func (f *realKubernetesFixture) snapshot(t *testing.T, ctx context.Context) []string {
	t.Helper()
	var list struct {
		Items []struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	f.json(t, ctx, &list, "-n", f.namespace, "get",
		"pods,services,networkpolicies,configmaps", "-o", "json")
	out := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		out = append(out, item.Kind+"/"+item.Metadata.Name)
	}
	sort.Strings(out)
	return out
}

func (f *realKubernetesFixture) destroy(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_ = f.command(ctx, "delete", "namespace", f.namespace,
		"--ignore-not-found", "--wait=true", "--timeout=120s").Run()
	_ = f.command(ctx, "-n", "kube-system", "delete", "configmap",
		clusterMarkerName, "--ignore-not-found").Run()
	for _, node := range f.nodes {
		_ = f.command(ctx, "label", "node", node.Name,
			disposableClusterLabel+"-").Run()
	}
}

func (f *realKubernetesFixture) apply(t *testing.T, ctx context.Context, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	cmd := f.command(ctx, "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader(raw)
	if err := cmd.Run(); err != nil {
		t.Fatalf("kubectl apply failed: %v", err)
	}
}

func (f *realKubernetesFixture) run(t *testing.T, ctx context.Context, args ...string) {
	t.Helper()
	if err := f.command(ctx, args...).Run(); err != nil {
		t.Fatalf("kubectl %s failed: %v", safeKubectlAction(args), err)
	}
}

func (f *realKubernetesFixture) output(
	t *testing.T, ctx context.Context, args ...string,
) string {
	t.Helper()
	out, err := f.command(ctx, args...).Output()
	if err != nil {
		t.Fatalf("kubectl %s failed: %v", safeKubectlAction(args), err)
	}
	return string(out)
}

func (f *realKubernetesFixture) json(
	t *testing.T, ctx context.Context, value any, args ...string,
) {
	t.Helper()
	raw := f.output(t, ctx, args...)
	if err := json.Unmarshal([]byte(raw), value); err != nil {
		t.Fatalf("decode kubectl %s JSON: %v", safeKubectlAction(args), err)
	}
}

func (f *realKubernetesFixture) optional(
	t *testing.T, ctx context.Context, args ...string,
) bool {
	t.Helper()
	args = append(args, "--ignore-not-found", "-o", "name")
	out, err := f.command(ctx, args...).Output()
	if err != nil {
		t.Fatalf("kubectl %s failed: %v", safeKubectlAction(args), err)
	}
	return strings.TrimSpace(string(out)) != ""
}

func (f *realKubernetesFixture) succeeds(ctx context.Context, args ...string) bool {
	return f.command(ctx, args...).Run() == nil
}

func (f *realKubernetesFixture) command(ctx context.Context, args ...string) *exec.Cmd {
	command := []string{}
	if f.kubeconfig != "" {
		command = append(command, "--kubeconfig", f.kubeconfig)
	}
	if f.context != "" {
		command = append(command, "--context", f.context)
	}
	if f.cacheDir != "" {
		command = append(command, "--cache-dir", f.cacheDir)
	}
	command = append(command, args...)
	cmd := exec.CommandContext(ctx, f.kubectl, command...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	return cmd
}

func safeKubectlAction(args []string) string {
	for _, arg := range args {
		switch arg {
		case "get", "apply", "delete", "wait", "exec", "logs", "label":
			return arg
		}
	}
	return "request"
}
