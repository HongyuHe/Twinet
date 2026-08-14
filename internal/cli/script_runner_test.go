package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// localExec runs what would have been run inside a container, here, so the
// runner's actual shell behaviour is what is tested rather than a description
// of it.
func localExec(t *testing.T) execFn {
	t.Helper()
	return func(ctx context.Context, _ string, cmd []string) (rt.ExecResult, error) {
		c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
		var out, errb strings.Builder
		c.Stdout, c.Stderr = &out, &errb
		err := c.Run()
		code := 0
		var ee *exec.ExitError
		if err != nil {
			if !errors.As(err, &ee) {
				return rt.ExecResult{}, err
			}
			code = ee.ExitCode()
		}
		return rt.ExecResult{ExitCode: code, Stdout: out.String(), Stderr: errb.String()}, nil
	}
}

// The checker accepts guarded lines -- `ip link show tun6 >/dev/null 2>&1 || ip
// tunnel add ...` -- because that is the ordinary form, and the reference
// answer itself uses it. The runner then ran the line as a bare `$c`, which
// word-splits and globs but does not act on operators: ip(8) was run with
// ">/dev/null", "2>&1" and "||" as arguments, failed, and the failure was
// reported to the student as their mistake. `true && echo` silently ran only
// `true`, so the configuration was never installed and the submission was
// marked on a device where nothing had happened.
func TestASubmittedScriptRunsWithTheSyntaxItWasAcceptedWith(t *testing.T) {
	d := &model.Device{ID: "as3/ATL", ASN: 3, Kind: model.KindRouter}
	dir := t.TempDir()

	// Each case leaves a file behind if -- and only if -- the shell acted on
	// the operator. Asserting on the exit status alone proves nothing: run
	// without a shell, `true && echo x` becomes true("&&", "echo", "x"), which
	// exits 0 and does nothing at all.
	cases := []struct {
		name string
		body string
	}{
		{"a chain, where the second command must run",
			"true && echo ran > " + dir + "/chain"},
		{"a guard, where the fallback must run",
			"ip link show twinet-no-such-device >/dev/null 2>&1 || echo ran > " + dir + "/guard"},
		{"a redirection, which must not become an argument",
			"ip -o link show > " + dir + "/redirect"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := checkSubmittedScript(c.body); err != nil {
				t.Fatalf("the checker rejected %q: %v", c.body, err)
			}
			if err := applyDeviceScript(context.Background(), localExec(t), d, c.body); err != nil {
				t.Fatalf("the checker accepted %q and the runner could not run it: %v\n"+
					"A submission is then marked on a device where its configuration was "+
					"never installed.", c.body, err)
			}
		})
	}
	for _, name := range []string{"chain", "guard", "redirect"} {
		if _, err := os.Stat(dir + "/" + name); err != nil {
			t.Errorf("%s: the line reported success and did nothing (%v).\n"+
				"Run without a shell, an operator becomes an argument: the guarded form "+
				"the checker accepts -- and the reference answer uses -- installs nothing, "+
				"and the student is marked on a device where their configuration never "+
				"arrived.", name, err)
		}
	}

	// And a line that genuinely fails must still fail, or the runner is back
	// to reporting success for a script that installed nothing.
	bad := "ip link show twinet-no-such-device && true"
	if err := applyDeviceScript(context.Background(), localExec(t), d, bad); err == nil {
		t.Error("a failing line was reported as applied")
	}
}
