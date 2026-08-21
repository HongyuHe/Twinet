package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/model"
)

func TestStrictAdmissionRefusesBeforeAnyApplyRequest(t *testing.T) {
	var applies atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/status":
			_ = json.NewEncoder(w).Encode(agent.StatusResponse{
				Node: "a",
				Inventory: agent.HostInventory{Allocatable: agent.ResourceInventory{
					CPUs: float64Pointer(0.1), MemoryBytes: int64Pointer(1 << 30),
					DiskBytes: int64Pointer(1 << 30), Pids: int64Pointer(100),
					FileDescriptors: int64Pointer(1000), NetDevices: int64Pointer(10),
					Containers: intPointer(10),
				}},
			})
		case "/v1/apply":
			applies.Add(1)
			http.Error(w, "apply should not be reached", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	lab := &model.Lab{Placement: model.Placement{Nodes: []model.NodeSpec{{Name: "a", Addr: server.URL, Front: true}}}}
	d := &model.Device{
		ID: "as1/R", Name: "R", ASN: 1, Kind: model.KindRouter, Node: "a",
		Requests: model.ResourceRequest{
			CPUs: 0.5, Memory: "128Mi", Pids: 32, EphemeralStorage: "64Mi",
			FileDescriptors: 128, NetDevices: 2,
		},
	}
	top := &model.Topology{
		Lab: lab, Name: "lab", Devices: map[string]*model.Device{d.ID: d},
		ASes:     map[int]*model.AS{1: {ASN: 1, Devices: []*model.Device{d}}},
		Services: map[string]*model.Service{},
	}
	cluster := &Cluster{Nodes: []*Node{NewNode("a", server.URL, "")}}
	results := cluster.Apply(t.Context(), top, agent.ApplyRequest{StrictAdmission: true})
	if len(results) != 1 || results[0].Err == nil {
		t.Fatalf("over-capacity deployment was not refused: %+v", results)
	}
	if got := applies.Load(); got != 0 {
		t.Fatalf("strict refusal sent %d apply request(s)", got)
	}
}

func float64Pointer(v float64) *float64 { return &v }
func int64Pointer(v int64) *int64       { return &v }
func intPointer(v int) *int             { return &v }
