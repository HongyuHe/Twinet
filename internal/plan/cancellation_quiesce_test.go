package plan

import (
	"context"
	"errors"
	"testing"
)

func TestExecuteCancellationWaitsForLateMutationToQuiesce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	lateMutation := make(chan struct{})
	release := make(chan struct{})
	p := New()
	p.Add(&Step{ID: "create", Stage: StageCreate, Describe: "late create",
		Run: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(lateMutation)
			<-release
			return ctx.Err()
		}})

	done := make(chan error, 1)
	go func() {
		_, err := p.Execute(ctx, Options{Workers: 1})
		done <- err
	}()
	<-started
	cancel()
	<-lateMutation
	select {
	case err := <-done:
		t.Fatalf("execute returned before the accepted runtime call quiesced: %v", err)
	default:
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("execute error = %v, want cancellation", err)
	}
}
