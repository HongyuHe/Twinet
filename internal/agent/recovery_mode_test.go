package agent

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/render"
)

func TestRecoveryModeUsesPersistedPreviousModeBeforeLegacyFallback(t *testing.T) {
	mode, ungraded := recoveredMode(applyTransaction{
		PreviousMode: string(render.ModePlatform), PreviousUngraded: 7,
		Mode: string(render.ModeSolve), Ungraded: 0,
	}, Wire{Mode: string(render.ModeSolve)})
	if mode != render.ModePlatform || ungraded != 7 {
		t.Fatalf("persisted previous mode lost: mode=%s ungraded=%d", mode, ungraded)
	}
	mode, ungraded = recoveredMode(applyTransaction{Mode: string(render.ModeSolve), Ungraded: 9}, Wire{})
	if mode != render.ModeSolve || ungraded != 9 {
		t.Fatalf("legacy solve transaction fell back to teaching mode: mode=%s ungraded=%d", mode, ungraded)
	}
}
