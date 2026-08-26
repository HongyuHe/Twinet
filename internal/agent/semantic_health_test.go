package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

// repairBackoffMax was unreachable: the shift was capped at eight, so the
// longest wait a device could ever get was 256 seconds while the constant,
// the comment, and the log all said five minutes. A backoff whose declared
// ceiling cannot occur is a ceiling nobody can reason about.
func TestRepairBackoffReachesItsDeclaredMaximum(t *testing.T) {
	previous := time.Duration(0)
	reached := false
	for attempt := 1; attempt <= 64; attempt++ {
		delay := repairDelay(attempt)
		if delay < previous {
			t.Fatalf("repairDelay(%d) = %s, which is shorter than repairDelay(%d) = %s",
				attempt, delay, attempt-1, previous)
		}
		if delay > repairBackoffMax {
			t.Fatalf("repairDelay(%d) = %s, which exceeds the declared maximum %s",
				attempt, delay, repairBackoffMax)
		}
		if delay == repairBackoffMax {
			reached = true
		}
		previous = delay
	}
	if !reached {
		t.Fatalf("no attempt ever waits the declared maximum of %s", repairBackoffMax)
	}
	for _, want := range []struct {
		attempt int
		delay   time.Duration
	}{
		{0, time.Second}, {1, time.Second}, {2, 2 * time.Second}, {3, 4 * time.Second},
		{9, 256 * time.Second}, {10, repairBackoffMax}, {40, repairBackoffMax},
	} {
		if got := repairDelay(want.attempt); got != want.delay {
			t.Fatalf("repairDelay(%d) = %s, want %s", want.attempt, got, want.delay)
		}
	}
}

// Unattended repair must never be able to replace a shared trunk. Forcing the
// receive socket is the operator's decision, because it is the one repair that
// touches links other than the broken one.
func TestAutomaticRepairNeverForcesOverlayReconcile(t *testing.T) {
	top, _ := solvedCrossNodeHost()
	server := &Server{
		cfg:      Config{Node: "node-0"},
		current:  map[string]*model.Topology{top.Name: top},
		modes:    map[string]string{top.Name: "solve"},
		ungraded: map[string]int{},
		peers:    map[string]map[string]string{top.Name: {"node-1": "10.0.1.2"}},
	}
	if server.autoRepairEngine(top).ForceOverlayReconcile {
		t.Fatal("automatic repair may replace an active shared trunk; one link's repair " +
			"would delete every other cross-node binding on the node pair")
	}
	if !server.repairEngine(top).ForceOverlayReconcile {
		t.Fatal("the explicit operator repair can no longer converge two endpoints " +
			"that disagree about the receive socket")
	}
}

// The controller asks for a no-op witness. A node that is publishing drifted
// devices must refuse it: `deploy` reported "0 devices, 0 links" and exit 0
// against nodes whose own status said a hundred devices had semantic or
// runtime drift.
func TestPlanRefusesNoopWhileTheNodePublishesDrift(t *testing.T) {
	top := &model.Topology{Name: "cos461", Hash: "cos461-hash", Lab: &model.Lab{}}
	server := &Server{
		cfg:            Config{Node: "node-0"},
		current:        map[string]*model.Topology{top.Name: top},
		generations:    map[string]generationState{top.Name: {Committed: "generation-a"}},
		fenceHighWater: map[string]uint64{top.Name: 3},
		modes:          map[string]string{top.Name: "solve"},
		ungraded:       map[string]int{top.Name: 0},
		transactions:   map[string]applyTransaction{},
		health:         map[string]deviceObservation{},
		repairTerminal: map[string]string{},
	}
	plan := func(t *testing.T) PlanResponse {
		t.Helper()
		body, err := json.Marshal(PlanRequest{Lab: top.Name, Topology: Serialise(top), Mode: "solve"})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		server.handlePlan(recorder, httptest.NewRequest(http.MethodPost, "/v1/plan", bytes.NewReader(body)))
		if recorder.Code != http.StatusOK {
			t.Fatalf("plan status = %d: %s", recorder.Code, recorder.Body.String())
		}
		var response PlanResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}

	if converged := plan(t); !converged.Noop || converged.Token == "" {
		t.Fatalf("converged plan = %#v, want a no-op witness", converged)
	}

	// An observation left behind by a device the lab no longer has must not
	// be published as live drift: nothing could ever repair it, so every
	// future deployment would refuse a no-op it cannot fix.
	server.mu.Lock()
	server.health[repairKey(top.Name, "as9/GONE")] = deviceObservation{
		Health: healthBroken, Reason: "container is absent",
	}
	server.mu.Unlock()
	if stale := plan(t); !stale.Noop || stale.SemanticHealth.Degraded() != 0 {
		t.Fatalf("plan republished a removed device as drift: %#v", stale.SemanticHealth)
	}

	drifted := &model.Device{
		ID: "as3/CHI", Name: "CHI", Kind: model.KindRouter, ASN: 3,
		Node: "node-0", Container: "twinet-cos461-as3-chi",
	}
	server.mu.Lock()
	top.Devices = map[string]*model.Device{drifted.ID: drifted}
	server.health[repairKey(top.Name, drifted.ID)] = deviceObservation{
		Health: healthBroken, Reason: "network semantics drifted: as3/CHI has no route to " +
			"reference host address(es) 10.5.0.2",
	}
	server.repairTerminal[repairKey(top.Name, drifted.ID)] = "binding vni:7140 is missing"
	server.mu.Unlock()

	refusal := noopRefusalReason(server.labSemanticHealth(top.Name))
	if !strings.Contains(refusal, "1 device(s) have semantic/runtime drift") ||
		!strings.Contains(refusal, "as3/CHI") {
		t.Fatalf("no-op refusal = %q, want it to name the drifted device", refusal)
	}
	health := server.labSemanticHealth(top.Name)
	if health.Degraded() != 1 || health.Terminal != 1 {
		t.Fatalf("published health = %+v, want one terminal degraded device", health)
	}
	if drift := health.Drift(); !strings.HasPrefix(drift, drifted.ID+": "+terminalReasonPrefix) {
		t.Fatalf("published drift = %q, want the abandoned device named", drift)
	}
	if noopRefusalReason(SemanticHealth{Healthy: 9, Unknown: 2}) != "" {
		t.Fatal("an unreadable device was treated as proof of drift")
	}
}

// A device the audit distrusts is re-observed rather than trusted, so a lab
// repaired by this very deployment stops being reported as drifted instead of
// blocking every future no-op.
func TestAuditedDriftIsReObservedRatherThanCached(t *testing.T) {
	server, top, host, runtime := driftedSolvedServer(t)
	server.mu.Lock()
	server.health[repairKey(top.Name, host.ID)] = deviceObservation{
		Health: healthBroken, Reason: "network semantics drifted: stale audit",
	}
	server.mu.Unlock()

	if reason := server.auditedDriftReason(context.Background(), top.Name, host); reason == "" {
		t.Fatal("a drifted device was accepted as converged")
	}
	runtime.mu.Lock()
	runtime.addresses["ixp_140"] = "179.2.3.2/24"
	runtime.mu.Unlock()
	if reason := server.auditedDriftReason(context.Background(), top.Name, host); reason != "" {
		t.Fatalf("a repaired device is still reported as drifted: %q", reason)
	}
	if health := server.labSemanticHealth(top.Name); health.Degraded() != 0 {
		t.Fatalf("cached health survived a fresh observation: %+v", health)
	}
}

// The controller and the node must agree about the name of the evidence, or
// the refusal above silently stops working: a field one side writes and the
// other cannot read looks exactly like a converged cluster.
func TestSemanticHealthCrossesTheProtocolBoundaryByName(t *testing.T) {
	health := SemanticHealth{
		Healthy: 402, Broken: 110, Partial: 1, Unknown: 2, Terminal: 3,
		Reasons: map[string]string{"as3/CHI": terminalReasonPrefix + "binding vni:7140 is missing"},
	}
	for name, encoded := range map[string]any{
		"plan":  PlanResponse{Node: "node-0", Noop: false, SemanticHealth: health},
		"apply": ApplyResponse{Node: "node-0", SemanticHealth: health},
	} {
		raw, err := json.Marshal(encoded)
		if err != nil {
			t.Fatal(err)
		}
		var wire struct {
			SemanticHealth SemanticHealth `json:"semantic_health"`
		}
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Fatalf("%s response: %v", name, err)
		}
		if wire.SemanticHealth.Degraded() != 111 || wire.SemanticHealth.Terminal != 3 {
			t.Fatalf("%s response carried %+v, want the published counts", name, wire.SemanticHealth)
		}
		if drift := wire.SemanticHealth.Drift(); !strings.Contains(drift, "as3/CHI") {
			t.Fatalf("%s response drift = %q", name, drift)
		}
		if !strings.Contains(string(raw), `"semantic_health"`) {
			t.Fatalf("%s response does not carry semantic_health: %s", name, raw)
		}
	}
	// An older agent that does not send the field must not be read as
	// degraded: absence of evidence is not drift.
	var legacy PlanResponse
	if err := json.Unmarshal([]byte(`{"node":"node-0","noop":true}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.SemanticHealth.Degraded() != 0 || noopRefusalReason(legacy.SemanticHealth) != "" {
		t.Fatalf("a response without semantic health was read as drift: %+v", legacy.SemanticHealth)
	}
}

// Status counts and status reasons are two views of one fact. When they
// disagreed, `node status` could call a node degraded for a device the lab no
// longer has while the plan endpoint accepted a no-op for the same node.
func TestConvergenceCountsAgreeWithPublishedReasons(t *testing.T) {
	top := &model.Topology{Name: "cos461", Devices: map[string]*model.Device{
		"as3/CHI": {ID: "as3/CHI", Node: "node-0"},
		"as5/MSP": {ID: "as5/MSP", Node: "node-0"},
		"as9/SFO": {ID: "as9/SFO", Node: "node-1"},
	}}
	health := map[string]deviceObservation{
		repairKey(top.Name, "as3/CHI"):  {Health: healthBroken, Reason: "network semantics drifted"},
		repairKey(top.Name, "as5/MSP"):  {Health: healthHealthy},
		repairKey(top.Name, "as9/SFO"):  {Health: healthBroken, Reason: "it is on another node"},
		repairKey(top.Name, "as9/GONE"): {Health: healthBroken, Reason: "it is not in the lab"},
	}
	published := semanticHealthLocked(health, map[string]string{},
		map[string]*model.Topology{top.Name: top}, "node-0", "")
	counts := convergenceCounts(published)
	if counts["broken"] != 1 || counts["healthy"] != 1 {
		t.Fatalf("convergence counts = %v, want one broken and one healthy local device", counts)
	}
	if got := len(published[top.Name].Reasons); got != 1 {
		t.Fatalf("published %d reasons, want only the local drifted device", got)
	}
	if counts["broken"] != published[top.Name].Degraded() {
		t.Fatalf("counts (%v) and published health (%+v) disagree", counts, published[top.Name])
	}
}
