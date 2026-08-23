package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
)

func TestStatusRequestUsesBoundedDefaultDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	node := NewNode("node-0", server.URL, "token")
	node.requestTimeout = 20 * time.Millisecond

	start := time.Now()
	if _, err := node.Status(context.Background()); err == nil {
		t.Fatal("hung status request unexpectedly succeeded")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("hung status request was not bounded: %s", elapsed)
	}
}

type deadlineRoundTripper func(*http.Request) (*http.Response, error)

func (fn deadlineRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestLargeApplyRequestDeadlineExceedsThirtyMinutes(t *testing.T) {
	var remaining time.Duration
	node := &Node{
		Name: "node-0", Addr: "http://agent",
		http: &http.Client{Transport: deadlineRoundTripper(func(req *http.Request) (*http.Response, error) {
			deadline, ok := req.Context().Deadline()
			if !ok {
				t.Fatal("large apply request had no deadline")
			}
			remaining = time.Until(deadline)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{}`)),
			}, nil
		})},
	}
	assigned := make([]string, 1000)
	for i := range assigned {
		assigned[i] = "device"
	}
	if _, err := node.Apply(context.Background(), agent.ApplyRequest{
		Phase: "apply", AssignmentKnown: true, AssignedDevices: assigned,
	}); err != nil {
		t.Fatal(err)
	}
	if remaining <= 30*time.Minute {
		t.Fatalf("1000-device apply deadline = %s, want more than 30m", remaining)
	}
	if remaining > maxMutationRequestTimeout {
		t.Fatalf("1000-device apply deadline = %s, exceeds cap %s",
			remaining, maxMutationRequestTimeout)
	}
}

func TestLargeDestroyAndRecoverRequestsUseLongMutationDeadlines(t *testing.T) {
	tests := []struct {
		name string
		run  func(*Node) error
		body string
	}{
		{
			name: "destroy",
			run: func(node *Node) error {
				return node.destroy(context.Background(), agent.DestroyRequest{
					Lab: "scale", WorkItems: 1000,
				})
			},
			body: `{"status":"destroyed","lab":"scale"}`,
		},
		{
			name: "recover",
			run: func(node *Node) error {
				_, err := node.Recover(context.Background(), agent.RecoveryRequest{
					Lab: "scale",
				})
				return err
			},
			body: `{"status":{"lab":"scale","phase":"committed","consistent":true}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var remaining time.Duration
			node := &Node{
				Name: "node-0", Addr: "http://agent",
				http: &http.Client{Transport: deadlineRoundTripper(func(req *http.Request) (*http.Response, error) {
					deadline, ok := req.Context().Deadline()
					if !ok {
						t.Fatal("large mutation request had no deadline")
					}
					remaining = time.Until(deadline)
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(tc.body)),
					}, nil
				})},
			}
			if err := tc.run(node); err != nil {
				t.Fatal(err)
			}
			if remaining <= 30*time.Minute {
				t.Fatalf("1000-item %s deadline = %s, want more than 30m", tc.name, remaining)
			}
			if tc.name == "recover" && remaining < agent.MaximumRecoveryTotalTimeout-time.Second {
				t.Fatalf("recovery deadline = %s, want server recovery cap %s",
					remaining, agent.MaximumRecoveryTotalTimeout)
			}
			if remaining > maxMutationRequestTimeout {
				t.Fatalf("1000-item %s deadline = %s, exceeds cap %s",
					tc.name, remaining, maxMutationRequestTimeout)
			}
		})
	}
}
