package client

import (
	"errors"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/model"
)

func postCommitCluster(t *testing.T, configure func(a, b *coordinationStub)) []NodeResult[agent.ApplyResponse] {
	t.Helper()
	a := newCoordinationStub("a", nil)
	b := newCoordinationStub("b", nil)
	configure(a, b)
	na, closeA := stubNode("a", a)
	defer closeA()
	nb, closeB := stubNode("b", b)
	defer closeB()
	return (&Cluster{Nodes: []*Node{na, nb}}).Apply(t.Context(),
		&model.Topology{Name: "cos461", Lab: &model.Lab{}},
		agent.ApplyRequest{Generation: "g1", Mode: "solve"})
}

// Commit is fanned out to every node and returns only when all of them
// acknowledge it. Nothing after that point rolls the generation back, so a
// failure in finalization or in the post-commit inventory proof must not be
// reported as a mutation that did not commit: an operator told that would
// redeploy a lab that is already live.
func TestPostCommitFailuresDoNotClaimTheMutationDidNotCommit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(a, b *coordinationStub)
		stage     string
	}{
		{
			name:      "finalize",
			configure: func(_, b *coordinationStub) { b.failFinalize = true },
			stage:     "finalization did not complete",
		},
		{
			name:      "recovery verify",
			configure: func(_, b *coordinationStub) { b.staleRecovery = true },
			stage:     "post-commit inventory verification did not complete",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results := postCommitCluster(t, tc.configure)
			if !CommittedResults(results) {
				t.Fatalf("a post-commit %s failure was not reported as committed: %v", tc.name, results)
			}
			for _, result := range results {
				if result.Err == nil {
					t.Fatalf("%s reported success while %s failed", result.Node, tc.name)
				}
				if !errors.Is(result.Err, ErrCommitted) {
					t.Errorf("%s error does not carry ErrCommitted: %v", result.Node, result.Err)
				}
				if strings.Contains(result.Err.Error(), "did not commit") {
					t.Errorf("%s says the durable commit did not happen: %v", result.Node, result.Err)
				}
				if !strings.Contains(result.Err.Error(), tc.stage) {
					t.Errorf("%s does not name the stage that failed: %v", result.Node, result.Err)
				}
				if !strings.Contains(result.Err.Error(), "the new generation is live") {
					t.Errorf("%s does not say the generation is live: %v", result.Node, result.Err)
				}
			}
		})
	}
}

// The distinction has to cut both ways, or it is only a rewording. A failure
// before commit is still a mutation that did not commit, and must not claim a
// durable generation the cluster never took.
func TestPreCommitFailureStillReportsThatNothingCommitted(t *testing.T) {
	results := postCommitCluster(t, func(_, b *coordinationStub) { b.failApply = true })
	if CommittedResults(results) {
		t.Fatal("a pre-commit failure was reported as a durable commit")
	}
	for _, result := range results {
		if result.Err == nil {
			t.Fatalf("%s reported success while apply failed", result.Node)
		}
		if errors.Is(result.Err, ErrCommitted) {
			t.Errorf("%s carries ErrCommitted before any node committed: %v", result.Node, result.Err)
		}
		if !strings.Contains(result.Err.Error(), "did not commit") {
			t.Errorf("%s does not say the mutation did not commit: %v", result.Node, result.Err)
		}
	}
}

// A clean transaction is neither, so the helper cannot be reading "no
// pre-commit failure" as "committed".
func TestCommittedResultsIsFalseForASuccessfulTransaction(t *testing.T) {
	results := postCommitCluster(t, func(_, _ *coordinationStub) {})
	for _, result := range results {
		if result.Err != nil {
			t.Fatalf("%s failed an otherwise clean transaction: %v", result.Node, result.Err)
		}
	}
	if CommittedResults(results) {
		t.Fatal("a successful transaction was reported as a post-commit failure")
	}
}
