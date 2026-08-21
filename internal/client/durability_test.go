package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/state"
)

func durableClientTop() *model.Topology {
	lab := &model.Lab{Metadata: model.Meta{Name: "lab"},
		Placement: model.Placement{Nodes: []model.NodeSpec{
			{Name: "source", FailureDomain: "rack-a", Front: true},
			{Name: "replica", FailureDomain: "rack-b"},
		}},
		State: model.StatePolicy{ReplicationFactor: 2, CaptureInterval: "5m", ReplicaRetention: "168h"},
	}
	lab.Normalize()
	return &model.Topology{Lab: lab, Name: "lab", Devices: map[string]*model.Device{},
		ASes: map[int]*model.AS{}, Services: map[string]*model.Service{}}
}

func stateServer(t *testing.T, name string, freshErr bool, stored agent.StateExportResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/status":
			_ = json.NewEncoder(w).Encode(agent.StatusResponse{Node: name})
		case "/v1/state":
			if r.URL.Query().Get("fresh") != "false" && freshErr {
				http.Error(w, "fresh state capture: simulated source failure", http.StatusConflict)
				return
			}
			_ = json.NewEncoder(w).Encode(stored)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestFreshFailureDoesNotSilentlySubstituteStoredState(t *testing.T) {
	top := durableClientTop()
	snapshot := agent.WireSnapshot{Snapshot: state.Snapshot{
		Lab: top.Name, Device: "as1/R", Kind: state.KindFRR,
		TakenAt: time.Unix(1_700_000_000, 0).UTC(), Digest: "old",
	}, Content: []byte("old\n")}
	sourceServer := stateServer(t, "source", true, agent.StateExportResponse{
		Lab: top.Name, Snapshots: []agent.WireSnapshot{snapshot},
	})
	defer sourceServer.Close()
	cluster := &Cluster{Nodes: []*Node{NewNode("source", sourceServer.URL, "")}}
	_, _, err := cluster.freshOrReplicaState(t.Context(), top, "source", []string{"as1/R"}, false, false, &DurabilityReport{})
	if err == nil || !strings.Contains(err.Error(), "refusing to substitute stale") {
		t.Fatalf("fresh capture failure did not fail closed: %v", err)
	}

	report := DurabilityReport{}
	got, fresh, err := cluster.freshOrReplicaState(t.Context(), top, "source", []string{"as1/R"}, true, false, &report)
	if err != nil || fresh || len(got.Snapshots) != 1 {
		t.Fatalf("explicit stale-state escape hatch did not return audited stored state: fresh=%v got=%+v err=%v",
			fresh, got, err)
	}
	if len(report.Audit) == 0 || !strings.Contains(report.Audit[0], "--allow-stale-state") {
		t.Fatalf("stale-state escape hatch left no audit evidence: %v", report.Audit)
	}
}

func TestOneDiskLossFindsVerifiedReplica(t *testing.T) {
	top := durableClientTop()
	snapshot := agent.WireSnapshot{Snapshot: state.Snapshot{
		Lab: top.Name, Device: "as1/R", Kind: state.KindFRR,
		TakenAt: time.Unix(1_700_000_100, 0).UTC(), Digest: "verified",
	}, Content: []byte("router bgp 1\n")}
	replicaServer := stateServer(t, "replica", false, agent.StateExportResponse{
		Lab: top.Name, Snapshots: []agent.WireSnapshot{snapshot},
	})
	defer replicaServer.Close()
	cluster := &Cluster{Nodes: []*Node{NewNode("replica", replicaServer.URL, "")}}
	report := DurabilityReport{}
	got, fresh, err := cluster.freshOrReplicaState(t.Context(), top, "source", []string{"as1/R"}, false, false, &report)
	if err != nil {
		t.Fatal(err)
	}
	if fresh || len(got.Snapshots) != 1 || got.Snapshots[0].Digest != "verified" {
		t.Fatalf("source-loss fallback did not select the verified replica: fresh=%v state=%+v", fresh, got)
	}
	if len(report.Audit) != 1 || !strings.Contains(report.Audit[0], "source source is unavailable") {
		t.Fatalf("source-loss recovery has no explicit audit trail: %v", report.Audit)
	}
}

func TestReplicaDisagreementAtOneVersionFailsClosed(t *testing.T) {
	top := durableClientTop()
	makeReplica := func(name, digest string) *httptest.Server {
		return stateServer(t, name, false, agent.StateExportResponse{Lab: top.Name,
			Snapshots: []agent.WireSnapshot{{Snapshot: state.Snapshot{
				Lab: top.Name, Device: "as1/R", Kind: state.KindFRR,
				TakenAt: time.Unix(1_700_001_000, 0).UTC(), Digest: digest,
			}, Content: []byte(fmt.Sprintf("%s\n", digest))}}})
	}
	a, b := makeReplica("a", "a"), makeReplica("b", "b")
	defer a.Close()
	defer b.Close()
	cluster := &Cluster{Nodes: []*Node{NewNode("a", a.URL, ""), NewNode("b", b.URL, "")}}
	if _, err := cluster.findReplicaState(t.Context(), top.Name, "source", []string{"as1/R"}); err == nil {
		t.Fatal("replicas with conflicting current state were silently chosen")
	}
}

func TestHealthCheckTreatsLostStateDiskAsUnavailable(t *testing.T) {
	healthy := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/status" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(agent.StatusResponse{Node: "diskless", StateStoreHealthy: &healthy})
	}))
	defer server.Close()
	cluster := &Cluster{Nodes: []*Node{NewNode("diskless", server.URL, "")}}
	if err := cluster.HealthCheck(t.Context()); err == nil || !strings.Contains(err.Error(), "durable state store") {
		t.Fatalf("a live agent with a lost state disk passed health check: %v", err)
	}
}
