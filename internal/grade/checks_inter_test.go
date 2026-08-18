package grade

import (
	"context"
	"fmt"
	"strings"
	"testing"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// A session is a thing two routers agree about.
//
// The check read the session out of the submission's own router: an address, a
// state and a remote AS number, all of them things the submission controls.
// Taking the real link down, routing the neighbour's address into one's own AS
// and running a four-message BGP speaker on a host there produced
// "Established, remote AS 4" and full marks for a session with a system that
// was never contacted.
func TestAPeerThatSeesNoSuchSessionIsNotASession(t *testing.T) {
	cases := []struct {
		name    string
		summary string
		want    string
	}{
		{
			name:    "the neighbour has no session with us at all",
			summary: `{"ipv4Unicast":{"peers":{"10.0.0.9":{"remoteAs":9,"state":"Established"}}}}`,
			want:    "no session with 10.0.0.1 at all",
		},
		{
			name:    "the neighbour sees us as somebody else",
			summary: `{"ipv4Unicast":{"peers":{"10.0.0.1":{"remoteAs":66,"state":"Established"}}}}`,
			want:    "as AS 66, not AS 3",
		},
		{
			name:    "the neighbour does not think it is up",
			summary: `{"ipv4Unicast":{"peers":{"10.0.0.1":{"remoteAs":3,"state":"Active"}}}}`,
			want:    "as Active",
		},
	}
	for _, c := range cases {
		env := &Env{AS: 3, Exec: func(_ context.Context, _ string, _ []string) (rt.ExecResult, error) {
			return rt.ExecResult{ExitCode: 0, Stdout: c.summary}, nil
		}}
		got, _, _ := peerAgrees(context.Background(), env, "as4/BOS", "10.0.0.1", 3)
		if got == "" {
			t.Errorf("%s: the neighbour was taken to agree, so an impersonated session "+
				"would score full marks", c.name)
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: the report says %q, which does not say %q", c.name, got, c.want)
		}
	}

	// And a neighbour that does agree must not be reported as a problem.
	env := &Env{AS: 3, Exec: func(_ context.Context, _ string, _ []string) (rt.ExecResult, error) {
		return rt.ExecResult{ExitCode: 0,
			Stdout: `{"ipv4Unicast":{"peers":{"10.0.0.1":{"remoteAs":3,"state":"Established"}}}}`}, nil
	}}
	if got, _, _ := peerAgrees(context.Background(), env, "as4/BOS", "10.0.0.1", 3); got != "" {
		t.Errorf("a genuine session was reported as a problem: %s", got)
	}
}

// A neighbour that cannot be asked has not agreed. Reading silence as assent
// is how the evidence the submission does not control stops being evidence.
func TestANeighbourThatCannotBeAskedHasNotAgreed(t *testing.T) {
	env := &Env{AS: 3, Exec: func(_ context.Context, _ string, _ []string) (rt.ExecResult, error) {
		return rt.ExecResult{}, fmt.Errorf("container is not running")
	}}
	if got, _, _ := peerAgrees(context.Background(), env, "as4/BOS", "10.0.0.1", 3); got == "" {
		t.Error("an unreachable neighbour was taken to confirm the session")
	}
}
