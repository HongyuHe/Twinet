// Command twinet is the Twinet control plane and command-line interface.
//
// It is stateless: every invocation re-derives the desired state from the
// manifest and the observed state from the node agents, then converges the
// difference. There is no local database to corrupt and nothing to migrate.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/HongyuHe/twinet/internal/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := cli.Root().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "twinet: "+err.Error())
		os.Exit(1)
	}
}
