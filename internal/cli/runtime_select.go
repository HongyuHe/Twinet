package cli

import (
	"fmt"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/runtime"
)

// localRuntime returns the backend selected by the manifest for this machine.
// Every single-node command goes through this helper so deploy, exec, save,
// faults, and destroy cannot quietly switch back to Docker after a Podman
// deployment succeeded.
func localRuntime(top *model.Topology) (runtime.Runtime, error) {
	name := model.DefaultRuntime
	socket := ""
	if top != nil && top.Lab != nil {
		node := localNode(top)
		name = top.Lab.RuntimeForNode(node)
		socket = top.Lab.RuntimeSocketForNode(node)
	}
	if err := runtime.ValidateSelection(name, socket); err != nil {
		return nil, fmt.Errorf("validate local runtime selection: %w", err)
	}
	selected, err := runtime.NewRuntime(name)
	if err != nil {
		return nil, err
	}
	if err := runtime.ConfigureEndpoint(selected, socket); err != nil {
		return nil, err
	}
	return selected, nil
}
