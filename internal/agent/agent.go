// Package agent implements the Twinet node agent.
package agent

import (
	"context"
	"errors"
)

// Main is the agent entry point. The agent is introduced in the cluster
// milestone; until then the CLI drives the local runtime directly.
func Main(ctx context.Context, args []string) error {
	return errors.New("the node agent is not part of this build yet")
}
