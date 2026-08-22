package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type execBatchRuntime struct {
	*sidecarRuntime
	calls atomic.Int64
}

func (r *execBatchRuntime) Exec(_ context.Context, _ string, command rt.ExecCmd) (rt.ExecResult, error) {
	r.calls.Add(1)
	return rt.ExecResult{Stdout: strings.Join(command.Cmd, " ")}, nil
}

func TestExecBatchReturnsOneResultPerDevice(t *testing.T) {
	runtime := &execBatchRuntime{sidecarRuntime: &sidecarRuntime{containers: map[string]rt.Container{
		"a": {Name: "a", State: rt.StateRunning, Labels: map[string]string{
			deploy.LabelManaged: "true", deploy.LabelLab: "lab-a",
		}},
		"b": {Name: "b", State: rt.StateRunning, Labels: map[string]string{
			deploy.LabelManaged: "true", deploy.LabelLab: "lab-a",
		}},
	}}}
	server := &Server{rt: runtime}
	request := httptest.NewRequest(http.MethodPost, "/v1/exec/batch", strings.NewReader(
		`{"requests":[{"container":"a","cmd":["echo","a"]},{"container":"b","cmd":["echo","b"]}]}`))
	response := httptest.NewRecorder()
	server.handleExecBatch(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("batch status=%d body=%s", response.Code, response.Body.String())
	}
	var got ExecBatchResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 2 || got.Results[0].Error != "" || got.Results[1].Error != "" {
		t.Fatalf("batch response=%#v", got)
	}
	if calls := runtime.calls.Load(); calls != 2 {
		t.Fatalf("runtime execs=%d, want one per device inside one HTTP batch", calls)
	}
}
