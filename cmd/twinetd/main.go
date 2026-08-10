// Command twinetd is the Twinet node agent.
//
// It is the only long-running privileged component: it owns the containers,
// network namespaces, veths, VXLAN tunnels and traffic shaping on one machine,
// and exposes them to the control plane over an authenticated API.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/HongyuHe/twinet/internal/agent"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := agent.Main(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "twinetd: "+err.Error())
		os.Exit(1)
	}
}
