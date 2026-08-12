package fault

import (
	"context"
	"strings"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// InjectedMarker is written inside a device that is broken on purpose.
//
// The nodes run a loop that repairs devices which have stopped working, and it
// cannot tell a fault somebody injected from a fault that happened. Stopping
// FRR on a router is a supported fault, and the repair loop restarted it within
// the minute -- so an episode kept open for an agent to diagnose lost its fault
// while the recorded ground truth went on saying the fault was live. Every
// answer graded against that truth is wrong, and nothing anywhere reports it.
//
// A hold would work while a command is running and not afterwards: an episode
// held open with --keep, or a fault injected by hand for a class exercise,
// outlives the process that created it. So the marker lives in the device, is
// written when the fault goes in and removed when it comes out, and is
// therefore exactly as durable as the fault it describes.
const InjectedMarker = "/etc/twinet/faulted"

// markInjected records on the device that it is broken deliberately.
//
// Best effort. Failing to write the marker must not fail an injection: what it
// costs is protection from the repair loop, and refusing to inject at all costs
// more. Faults that do not act on a single device -- a link's shaping, say --
// have nothing to mark, and pass a device of "".
func markInjected(ctx context.Context, env *Env, deviceID, name string) {
	if env == nil || env.Exec == nil || deviceID == "" {
		return
	}
	_, _ = env.Exec(ctx, deviceID, []string{"sh", "-c",
		"mkdir -p /etc/twinet && echo " + shQuote(name) + " >> " + InjectedMarker})
}

// clearInjected removes one fault's mark, and the file when it was the last.
func clearInjected(ctx context.Context, env *Env, deviceID, name string) {
	if env == nil || env.Exec == nil || deviceID == "" {
		return
	}
	_, _ = env.Exec(ctx, deviceID, []string{"sh", "-c",
		"[ -f " + InjectedMarker + " ] || exit 0; " +
			"grep -vxF " + shQuote(name) + " " + InjectedMarker + " > " + InjectedMarker + ".tmp 2>/dev/null; " +
			"mv " + InjectedMarker + ".tmp " + InjectedMarker + "; " +
			"[ -s " + InjectedMarker + " ] || rm -f " + InjectedMarker})
}

// InjectedOn reports the faults a device has been deliberately given.
func InjectedOn(ctx context.Context, exec func(context.Context, string, []string) (rt.ExecResult, error),
	deviceID string) []string {

	if exec == nil {
		return nil
	}
	res, err := exec(ctx, deviceID, []string{"cat", InjectedMarker})
	if err != nil || res.ExitCode != 0 {
		return nil
	}
	return strings.Fields(res.Stdout)
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
