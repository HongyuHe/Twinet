package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type statusRuntime struct {
	rt.Runtime
	containers []rt.Container
	failFirst  bool
	calls      int
}

func (r *statusRuntime) Name() string                         { return "docker" }
func (r *statusRuntime) Ping(context.Context) (string, error) { return "test", nil }
func (r *statusRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	r.calls++
	if r.failFirst && r.calls == 1 {
		return nil, errors.New("temporary Docker list reset")
	}
	return append([]rt.Container(nil), r.containers...), nil
}

func TestStatusSeparatesPrimaryAndFRRControlContainers(t *testing.T) {
	containers := make([]rt.Container, 0, 105)
	for i := 0; i < 81; i++ {
		containers = append(containers, rt.Container{
			Name: "router", Labels: map[string]string{deploy.LabelManaged: "true"},
		})
	}
	for i := 0; i < 24; i++ {
		containers = append(containers, rt.Container{
			Name: "router-frr", Labels: map[string]string{
				deploy.LabelManaged: "true", deploy.LabelInternal: "true", deploy.LabelFRRControl: "true",
			},
		})
	}
	runtime := &statusRuntime{containers: containers, failFirst: true}
	server := &Server{cfg: Config{Node: "node-1"}, rt: runtime, current: map[string]*model.Topology{}}
	response := httptest.NewRecorder()
	server.handleStatus(response, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	var status StatusResponse
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.PrimaryContainers != 81 || status.ControlContainers != 24 ||
		status.ManagedContainers != 105 || status.Containers != 81 {
		t.Fatalf("status counts = primary=%d control=%d managed=%d legacy=%d",
			status.PrimaryContainers, status.ControlContainers, status.ManagedContainers, status.Containers)
	}
	if status.ContainerCount == nil || *status.ContainerCount != 81 || status.ContainerListError != "" {
		t.Fatalf("status did not recover retryable inventory: %+v", status)
	}
}

func TestStatusIncludesDegradedDeviceReason(t *testing.T) {
	runtime := &statusRuntime{}
	server := &Server{
		cfg:     Config{Node: "node-0"},
		rt:      runtime,
		current: map[string]*model.Topology{"lab": {Name: "lab"}},
		health: map[string]deviceObservation{
			"lab|as5/CHI": {Health: healthBroken, Reason: "FRR control daemon bgpd has 2 process(es), want exactly one"},
		},
	}
	response := httptest.NewRecorder()
	server.handleStatus(response, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	var status StatusResponse
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if got := status.SemanticHealth["lab"].Reasons["as5/CHI"]; !strings.Contains(got, "want exactly one") {
		t.Fatalf("degraded reason = %q", got)
	}
}
