package agent

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/integrity"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// A program planted between two grading runs must not be believed by the
// second.
//
// The first version of this kept a container's verdict for the life of the
// container, on the reasoning that a replaced program could only come into use
// after a restart. That is wrong: `docker exec` resolves the program every
// time, so a file written after one run answers every call in the next, and a
// container checked once was trusted for as long as it kept running.
func TestATamperedContainerIsFoundAfterAnEarlierRunSaidItWasClean(t *testing.T) {
	var tampered atomic.Bool
	var calls atomic.Int32
	s := &Server{
		toolsSeen: map[string]toolsVerdict{},
		tools: func(context.Context, rt.Container) ([]integrity.Finding, error) {
			calls.Add(1)
			if !tampered.Load() {
				return nil, nil
			}
			return []integrity.Finding{{Tool: "ping", Want: "/bin/ping",
				Got: "/usr/local/bin/ping", Why: "shadowed"}}, nil
		},
	}
	c := rt.Container{ID: "abc", Name: "twinet-cos461-as3-atl_host", PID: 42}

	if err := s.verifyTools(context.Background(), c); err != nil {
		t.Fatalf("an untouched container was refused: %v", err)
	}
	// The student writes their ping, and the cache still says the container is
	// clean. Age it past the window rather than sleeping through it.
	tampered.Store(true)
	s.toolsMu.Lock()
	s.toolsSeen["abc/42"] = toolsVerdict{at: time.Now().Add(-toolsCheckEvery - time.Second)}
	s.toolsMu.Unlock()

	err := s.verifyTools(context.Background(), c)
	if err == nil {
		t.Fatal("a program planted after an earlier run was believed, because the verdict " +
			"from that run was kept for the life of the container")
	}
	var ie *integrity.Error
	if !errors.As(err, &ie) {
		t.Fatalf("the refusal is not an integrity error: %v", err)
	}
	if !strings.Contains(err.Error(), "twinet-cos461-as3-atl_host") {
		t.Errorf("the refusal does not name the container: %v", err)
	}
}

// A run making hundreds of calls into one container must not hash its programs
// hundreds of times.
func TestTheToolCheckIsNotRepeatedForEveryCommand(t *testing.T) {
	var calls atomic.Int32
	s := &Server{
		toolsSeen: map[string]toolsVerdict{},
		tools: func(context.Context, rt.Container) ([]integrity.Finding, error) {
			calls.Add(1)
			return nil, nil
		},
	}
	c := rt.Container{ID: "abc", Name: "r1", PID: 7}
	for i := 0; i < 50; i++ {
		if err := s.verifyTools(context.Background(), c); err != nil {
			t.Fatalf("call %d was refused: %v", i, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("the programs were read %d times for 50 commands; a grading run would "+
			"spend longer hashing than checking", got)
	}
}

// A container that could not be checked at all is the grader's problem, and
// must be retried rather than remembered as a verdict.
func TestAFailureToCheckIsNotRemembered(t *testing.T) {
	var calls atomic.Int32
	s := &Server{
		toolsSeen: map[string]toolsVerdict{},
		tools: func(context.Context, rt.Container) ([]integrity.Finding, error) {
			calls.Add(1)
			return nil, errors.New("the image is not on this node")
		},
	}
	c := rt.Container{ID: "abc", Name: "r1", PID: 7, Image: "twinet-router:0.1"}
	for i := 0; i < 3; i++ {
		if err := s.verifyTools(context.Background(), c); err == nil {
			t.Fatalf("call %d passed although the container could not be checked", i)
		}
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("a failure to read the image was cached (%d attempts for 3 calls)", got)
	}
}
