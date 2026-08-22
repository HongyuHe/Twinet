package cli

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
)

// TestLiveCOSNoopPreflight is opt-in because it contacts the settled teaching
// cluster. It invokes only /v1/plan and /v1/plan/verify, so it never acquires
// a lease or starts a transaction.
func TestLiveCOSNoopPreflight(t *testing.T) {
	if os.Getenv("TWINET_LIVE_COS_NOOP") != "1" {
		t.Skip("set TWINET_LIVE_COS_NOOP=1 to run against the settled COS cluster")
	}
	token := strings.TrimSpace(os.Getenv("TWINET_TOKEN"))
	if token == "" {
		t.Fatal("TWINET_TOKEN is required for live no-op preflight")
	}
	top, err := load(&Options{Manifest: "../../examples/cos461"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := placeWithRecord(top, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	result := client.NewCluster(top.Lab, token).NoopPreflight(ctx, top, agent.ApplyRequest{
		Mode: modeName(true),
	})
	if !result.Noop {
		t.Fatalf("live COS no-op preflight fell back: %#v", result.Reasons)
	}
	if elapsed := time.Since(start); elapsed >= 30*time.Second {
		t.Fatalf("live COS no-op preflight took %s, want under 30s", elapsed)
	} else {
		t.Logf("live COS no-op preflight completed in %s", elapsed.Round(time.Millisecond))
	}
}
