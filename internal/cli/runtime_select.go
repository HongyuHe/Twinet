package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/HongyuHe/twinet/internal/manifest"
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
	return localRuntimeNamed(name, socket)
}

// localRuntimeNamed opens a named backend when there is no manifest to read the
// selection from.
//
// Nothing may call this with a guess. A command that cannot read a manifest
// does not know which engine created the lab, and asking the wrong one answers
// "no containers here" -- which reads exactly like "the lab is already gone",
// and is why destroy has to be told rather than assuming.
func localRuntimeNamed(name, socket string) (runtime.Runtime, error) {
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

// applyRuntimeSelection applies --runtime/--runtime-socket to a loaded
// manifest, before validation and before anything reads a backend from it.
//
// The override is deliberately total: it replaces the lab default and every
// per-node selection, so a lab cannot end up half on one engine and half on
// another because one node named its own. It is also announced, because a
// deployment that quietly ignored what the manifest says is the failure this
// exists to prevent, not one to reproduce more discreetly.
func applyRuntimeSelection(opts *Options, l *manifest.Loaded, notice io.Writer) error {
	if opts == nil || l == nil || l.Lab == nil {
		return nil
	}
	name := strings.ToLower(strings.TrimSpace(opts.Runtime))
	socket := strings.TrimSpace(opts.RuntimeSocket)
	if name == "" {
		if socket != "" {
			return fmt.Errorf("--runtime-socket %q names an endpoint for no backend; "+
				"pass --runtime with it", socket)
		}
		return nil
	}
	if err := runtime.ValidateSelection(name, socket); err != nil {
		return fmt.Errorf("--runtime %s: %w", name, err)
	}
	l.Lab.SelectRuntime(name, socket)
	if notice != nil {
		where := ""
		if socket != "" {
			where = " at " + socket
		}
		fmt.Fprintf(notice, "runtime override: every node of %s uses %s%s\n",
			l.Lab.Metadata.Name, name, where)
	}
	return nil
}
