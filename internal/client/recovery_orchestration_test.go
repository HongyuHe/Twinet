package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
)

type recoveryJoinStub struct {
	mu sync.Mutex

	status        agent.RecoveryStatus
	completeAfter int
	polls         int
	acquireCalls  int
	recoverCalls  int
	lastRecover   agent.RecoveryRequest
	lease         agent.Fence
}

func (s *recoveryJoinStub) handler(w http.ResponseWriter, r *http.Request) {
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	fail := func(code int, err error) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/v1/recovery":
		s.polls++
		if s.completeAfter > 0 && s.polls >= s.completeAfter {
			s.status.Phase = "committed"
			s.status.Generation = "old-generation"
			s.status.Consistent = true
			s.status.Error = ""
		}
		write(s.status)
	case "/v1/lease/acquire":
		s.acquireCalls++
		if s.status.Phase == "recovering" && !s.status.TakeoverAllowed {
			fail(http.StatusConflict, fmt.Errorf("leased by %s", s.status.Owner))
			return
		}
		s.lease = agent.Fence{Token: "fence", Generation: 1}
		write(agent.LeaseResponse{Lab: "lab", Fence: s.lease})
	case "/v1/lease/release":
		s.lease = agent.Fence{}
		write(struct{}{})
	case "/v1/lease/renew":
		write(agent.LeaseResponse{Lab: "lab", Fence: s.lease})
	case "/v1/recover":
		var req agent.RecoveryRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.recoverCalls++
		s.lastRecover = req
		if req.Fence != s.lease {
			fail(http.StatusConflict, fmt.Errorf("stale fence"))
			return
		}
		s.status.Phase = "committed"
		s.status.Generation = "old-generation"
		s.status.Consistent = true
		s.status.Error = ""
		write(agent.RecoveryResponse{Status: s.status})
	default:
		fail(http.StatusNotFound, fmt.Errorf("unexpected path %s", r.URL.Path))
	}
}

func recoveryJoinCluster(t *testing.T, status agent.RecoveryStatus, completeAfter int) (*Cluster, *recoveryJoinStub) {
	t.Helper()
	stub := &recoveryJoinStub{status: status, completeAfter: completeAfter}
	server := httptest.NewServer(http.HandlerFunc(stub.handler))
	t.Cleanup(server.Close)
	return &Cluster{Nodes: []*Node{NewNode("node-0", server.URL, "")}}, stub
}

func TestRecoverJoinsSameStrategyWithoutLeaseContention(t *testing.T) {
	now := time.Now()
	cluster, stub := recoveryJoinCluster(t, agent.RecoveryStatus{
		Lab: "lab", Phase: "recovering", Generation: "failed-generation",
		Owner: "agent recovery", Strategy: "rollback", StartedAt: now,
		LastProgressAt: now, Deadline: now.Add(time.Minute), Consistent: false,
	}, 2)
	progress := 0
	report, err := cluster.RecoverWithOptions(t.Context(), "lab", "rollback", RecoveryOptions{
		Wait: 2 * time.Second,
		Progress: func(RecoveryReport) {
			progress++
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Nodes["node-0"].Consistent || report.Nodes["node-0"].Phase != "committed" {
		t.Fatalf("joined recovery did not reach committed status: %+v", report)
	}
	stub.mu.Lock()
	acquires, recovers := stub.acquireCalls, stub.recoverCalls
	stub.mu.Unlock()
	if acquires != 0 || recovers != 0 {
		t.Fatalf("same-strategy join contended for a lease: acquire=%d recover=%d", acquires, recovers)
	}
	if progress < 2 {
		t.Fatalf("joined recovery did not poll progress: %d updates", progress)
	}
}

func TestRecoverRejectsConflictingActiveStrategyImmediately(t *testing.T) {
	now := time.Now()
	cluster, stub := recoveryJoinCluster(t, agent.RecoveryStatus{
		Lab: "lab", Phase: "recovering", Owner: "agent recovery", Strategy: "forward",
		StartedAt: now, LastProgressAt: now, Deadline: now.Add(time.Minute),
	}, 0)
	start := time.Now()
	if _, err := cluster.RecoverWithOptions(t.Context(), "lab", "rollback", RecoveryOptions{Wait: time.Second}); err == nil {
		t.Fatal("conflicting active strategy was accepted")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("conflicting recovery waited %s instead of returning immediately", elapsed)
	}
	stub.mu.Lock()
	acquires := stub.acquireCalls
	stub.mu.Unlock()
	if acquires != 0 {
		t.Fatalf("conflicting strategy attempted lease acquisition %d times", acquires)
	}
}

func TestRecoverStaleTakeoverUsesNewFence(t *testing.T) {
	now := time.Now()
	cluster, stub := recoveryJoinCluster(t, agent.RecoveryStatus{
		Lab: "lab", Phase: "recovering", Generation: "failed-generation",
		Owner: "agent recovery", Strategy: "rollback", StartedAt: now.Add(-time.Minute),
		LastProgressAt: now.Add(-time.Minute), Deadline: now.Add(-time.Second),
		TakeoverAllowed: true,
	}, 0)
	report, err := cluster.RecoverWithOptions(t.Context(), "lab", "rollback",
		RecoveryOptions{Wait: time.Second, Takeover: true})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Nodes["node-0"].Consistent {
		t.Fatalf("takeover did not complete: %+v", report)
	}
	stub.mu.Lock()
	acquires, recovers, request := stub.acquireCalls, stub.recoverCalls, stub.lastRecover
	stub.mu.Unlock()
	if acquires != 1 || recovers != 1 || !request.Takeover {
		t.Fatalf("takeover did not use one fenced request: acquire=%d recover=%d request=%+v",
			acquires, recovers, request)
	}
}

func TestRecoverWaitZeroReturnsStructuredProgressImmediately(t *testing.T) {
	now := time.Now()
	cluster, stub := recoveryJoinCluster(t, agent.RecoveryStatus{
		Lab: "lab", Phase: "recovering", Owner: "agent recovery", Strategy: "rollback",
		StartedAt: now, LastProgressAt: now, Deadline: now.Add(time.Minute), CurrentTarget: "restore runtime",
	}, 0)
	start := time.Now()
	report, err := cluster.RecoverWithOptions(t.Context(), "lab", "rollback", RecoveryOptions{})
	if err == nil {
		t.Fatal("wait=0 silently blocked or succeeded")
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("wait=0 did not return promptly")
	}
	if report.Nodes["node-0"].CurrentTarget != "restore runtime" {
		t.Fatalf("immediate response lost structured target: %+v", report)
	}
	stub.mu.Lock()
	acquires := stub.acquireCalls
	stub.mu.Unlock()
	if acquires != 0 {
		t.Fatalf("wait=0 contended for a healthy recovery lease")
	}
}
