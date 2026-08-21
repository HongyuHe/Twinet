package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type sidecarRuntime struct {
	rt.Runtime
	containers map[string]rt.Container
}

func (r *sidecarRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	out := make([]rt.Container, 0, len(r.containers))
	for _, container := range r.containers {
		out = append(out, container)
	}
	return out, nil
}

func (r *sidecarRuntime) Inspect(_ context.Context, name string) (rt.Container, error) {
	if container, ok := r.containers[name]; ok {
		return container, nil
	}
	return rt.Container{Name: name, State: rt.StateAbsent}, nil
}

func TestFRRControlSidecarIsNotAUserVisibleDevice(t *testing.T) {
	router := rt.Container{
		Name: "router", State: rt.StateRunning,
		Labels: map[string]string{deploy.LabelManaged: "true", deploy.LabelLab: "lab-a"},
	}
	sidecar := rt.Container{
		Name: "router-frr", State: rt.StateRunning,
		Labels: map[string]string{
			deploy.LabelManaged: "true", deploy.LabelLab: "lab-a",
			deploy.LabelFRRControl: "true", deploy.LabelInternal: "true",
		},
	}
	server := &Server{rt: &sidecarRuntime{containers: map[string]rt.Container{
		router.Name: router, sidecar.Name: sidecar,
	}}}

	list := httptest.NewRecorder()
	server.handleContainers(list, httptest.NewRequest(http.MethodGet, "/v1/containers?lab=lab-a", nil))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), sidecar.Name) ||
		!strings.Contains(list.Body.String(), router.Name) {
		t.Fatalf("device listing exposed FRR sidecar: status=%d body=%s", list.Code, list.Body.String())
	}
	if _, err := server.containerScope("exec", sidecar.Name, "", 0); err == nil {
		t.Fatal("authorization resolver accepted an internal sidecar as an exec target")
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/exec",
		strings.NewReader(`{"container":"router-frr","cmd":["id"]}`))
	response := httptest.NewRecorder()
	server.handleExec(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("direct exec endpoint admitted an internal sidecar: %d %s", response.Code, response.Body.String())
	}
}
