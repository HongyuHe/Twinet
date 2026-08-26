package cli

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	"github.com/HongyuHe/twinet/internal/nos"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// This file is the only place where saving, restoring and loading a router's
// routing configuration decides which network operating system it is talking
// to -- and it decides by asking the device's registered provider rather than
// by assuming.
//
// Every one of these paths used to run `vtysh` unconditionally. A course that
// put BIRD in a student AS therefore had `twinet save` fail on every router,
// and a submission loaded through FRR's reload tool into a container that has
// no FRR at all. Neither failure produced a wrong mark, because neither could
// get far enough to produce a mark at all -- but the second one is one shell
// script away from writing an FRR configuration into a BIRD device and grading
// the empty control plane that results.

// providerExec adapts the CLI's exec function to the executor a NOS provider
// expects. It is a type rather than a closure so the two never diverge.
type providerExec struct {
	exec execFn
}

func (p providerExec) Exec(ctx context.Context, deviceID string, command []string) (rt.ExecResult, error) {
	if p.exec == nil {
		return rt.ExecResult{}, fmt.Errorf("no executor for %s", deviceID)
	}
	return p.exec(ctx, deviceID, command)
}

// captureRouterConfig reads a router's routing configuration through its own
// provider and reports which NOS it belongs to.
func captureRouterConfig(ctx context.Context, exec execFn, d *model.Device) (string, nos.ConfigFile, error) {
	provider, err := nos.Resolve(d)
	if err != nil {
		return "", nos.ConfigFile{}, fmt.Errorf("%s: its network operating system could not be "+
			"resolved: %w", d.ID, err)
	}
	body, err := provider.CaptureConfig(ctx, d, providerExec{exec: exec})
	if err != nil {
		return "", nos.ConfigFile{}, err
	}
	// Providers report the configuration text without deciding how it is
	// stored. An archive member is a configuration file and ends in a newline,
	// as it did when this was vtysh-specific: a file whose last line has no
	// terminator is a poor thing to hand back to a parser, and changing the
	// saved bytes would change every archive digest for no reason.
	return strings.TrimRight(body, "\n") + "\n", provider.ConfigFile(), nil
}

// loadRouterConfig installs a configuration through the device's own provider.
//
// declared is the NOS the archive says the configuration was captured from. An
// archive that does not record one is accepted only for FRR, which is what
// every archive collected before this field existed contains; anything else is
// refused by name rather than loaded into a device that cannot read it.
func loadRouterConfig(ctx context.Context, exec execFn, d *model.Device,
	declared, body string, opts nos.LoadOptions,
) error {
	provider, err := nos.Resolve(d)
	if err != nil {
		return fmt.Errorf("its network operating system could not be resolved: %w", err)
	}
	actual := provider.ConfigFile().NOS
	switch {
	case declared == "":
		// A legacy archive. FRR is what those contain; assuming it for a
		// device that runs something else would install one vendor's syntax
		// into another's parser.
		if actual != model.DefaultNOS {
			return &nos.ConfigMismatchError{
				Device: d.ID, Declared: "", Actual: actual,
				Artefact: "an archive that does not record which NOS it was captured from",
			}
		}
	case !strings.EqualFold(declared, actual):
		return &nos.ConfigMismatchError{Device: d.ID, Declared: declared, Actual: actual}
	}
	if opts.RequireDaemons && len(opts.Daemons) == 0 && actual == model.DefaultNOS {
		// Which daemons this lab enables is the caller's policy; how they are
		// proven alive belongs to the provider.
		opts.Daemons = render.EnabledDaemons()
	}
	return provider.LoadConfig(ctx, d, providerExec{exec: exec}, body, opts)
}

// submissionConfigNOS reports the NOS an archive recorded for a router's
// configuration, and "" when the archive predates the field.
//
// The manifest keys members by file name and the loaders key them by router,
// so the lookup accepts either spelling rather than making every caller
// remember which one it holds.
func submissionConfigNOS(declared map[string]string, name string) string {
	if len(declared) == 0 || name == "" {
		return ""
	}
	if value, ok := declared[name]; ok {
		return value
	}
	for key, value := range declared {
		base := strings.TrimSuffix(key, path.Ext(key))
		if strings.EqualFold(base, name) || strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

var _ netstate.Executor = providerExec{}
