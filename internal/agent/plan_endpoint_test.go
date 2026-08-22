package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestPlanVerifyRejectsConcurrentFenceChange(t *testing.T) {
	top := &model.Topology{
		Name: "lab", Hash: "topology-hash",
		Lab: &model.Lab{},
	}
	server := &Server{
		cfg:            Config{Node: "node-a"},
		current:        map[string]*model.Topology{top.Name: top},
		generations:    map[string]generationState{top.Name: {Committed: "generation-a"}},
		fenceHighWater: map[string]uint64{top.Name: 7},
		modes:          map[string]string{top.Name: "platform"},
		ungraded:       map[string]int{top.Name: 0},
		transactions:   map[string]applyTransaction{},
	}
	body, err := json.Marshal(PlanRequest{
		Lab: top.Name, Topology: Serialise(top), Mode: "platform",
	})
	if err != nil {
		t.Fatal(err)
	}
	planRecorder := httptest.NewRecorder()
	server.handlePlan(planRecorder, httptest.NewRequest(http.MethodPost, "/v1/plan", bytes.NewReader(body)))
	if planRecorder.Code != http.StatusOK {
		t.Fatalf("plan status = %d: %s", planRecorder.Code, planRecorder.Body.String())
	}
	var plan PlanResponse
	if err := json.Unmarshal(planRecorder.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if !plan.Noop || plan.Token == "" || plan.FenceGeneration != 7 {
		t.Fatalf("plan response = %#v, want no-op witness for fence 7", plan)
	}

	server.mu.Lock()
	server.fenceHighWater[top.Name] = 8
	server.mu.Unlock()
	verifyBody, err := json.Marshal(PlanVerifyRequest{Lab: top.Name, Token: plan.Token})
	if err != nil {
		t.Fatal(err)
	}
	verifyRecorder := httptest.NewRecorder()
	server.handlePlanVerify(verifyRecorder,
		httptest.NewRequest(http.MethodPost, "/v1/plan/verify", bytes.NewReader(verifyBody)))
	if verifyRecorder.Code != http.StatusOK {
		t.Fatalf("verify status = %d: %s", verifyRecorder.Code, verifyRecorder.Body.String())
	}
	var verified PlanVerifyResponse
	if err := json.Unmarshal(verifyRecorder.Body.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if verified.Valid {
		t.Fatal("a witness survived a concurrent mutation fence change")
	}
}
