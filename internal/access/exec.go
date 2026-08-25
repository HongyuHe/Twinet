package access

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// LocalExec runs an interactive session in a container on this machine.
type LocalExec struct {
	Topology *model.Topology
	Runtime  rt.Runtime

	commandContext func(context.Context, string, ...string) *exec.Cmd
}

// Shell attaches a student's terminal to a device.
//
// It shells out to the container engine rather than going through the runtime
// interface, because an interactive session is a stream in both directions for
// as long as the student wants it, and the batch Exec used everywhere else
// collects output and returns. Conflating the two would either give the batch
// path a streaming interface it never needs or give the shell a buffered one
// that shows nothing until the student disconnects.
func (l *LocalExec) Shell(ctx context.Context, deviceID string, cmd []string,
	stdin io.Reader, stdout, stderr io.Writer, tty bool, rows, cols int) (int, error) {

	d, ok := l.Topology.Device(deviceID)
	if !ok {
		return 1, fmt.Errorf("no device %q", deviceID)
	}
	if l.Runtime == nil {
		return 1, errors.New("no local container runtime is configured")
	}
	env := map[string]string(nil)
	if tty {
		env = map[string]string{
			"LINES": strconv.Itoa(rows), "COLUMNS": strconv.Itoa(cols),
			"TERM": "xterm-256color",
		}
	}
	if stream, ok := l.Runtime.(rt.StreamExecRuntime); ok {
		return stream.StreamExec(ctx, d.Container, rt.ExecCmd{
			Cmd: cmd, Env: env, Stdin: stdin, TTY: tty,
		}, uint32(rows), uint32(cols), stdout, stderr)
	}

	args := []string{"exec", "--interactive"}
	if tty {
		args = append(args, "--tty",
			"--env", fmt.Sprintf("LINES=%d", rows),
			"--env", fmt.Sprintf("COLUMNS=%d", cols),
			"--env", "TERM=xterm-256color")
	}
	args = append(args, d.Container)
	args = append(args, cmd...)

	cli, args, processEnv, err := localAttachCLI(l.Runtime.Name(), rt.Endpoint(l.Runtime), args)
	if err != nil {
		return 1, err
	}
	commandContext := l.commandContext
	if commandContext == nil {
		commandContext = exec.CommandContext
	}
	c := commandContext(ctx, cli, args...)
	if len(processEnv) > 0 {
		c.Env = append(os.Environ(), processEnv...)
	}
	c.Stdin, c.Stdout, c.Stderr = stdin, stdout, stderr
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok {
			return ee.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}

func localAttachCLI(name, endpoint string, args []string) (string, []string, []string, error) {
	switch name {
	case "docker":
		env := []string(nil)
		if endpoint != "" {
			env = append(env, "DOCKER_HOST="+endpoint)
		}
		return "docker", args, env, nil
	case "podman":
		if endpoint == "" {
			return "podman", args, nil, nil
		}
		podmanArgs := append([]string{"--remote", "--url", endpoint}, args...)
		return "podman", podmanArgs, nil, nil
	default:
		return "", nil, nil, fmt.Errorf(
			"runtime %q does not provide an interactive attach command", name)
	}
}

func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

// ClusterExec runs a session on whichever node holds the device, through the
// node agent.
//
// It goes through the agent rather than SSH-ing between nodes because the agent
// already runs with the privilege required and already authenticates; the
// alternative would make the gateway depend on root-to-root SSH trust across
// the cluster, a second and much broader credential existing only so a student
// can look at a routing table.
type ClusterExec struct {
	Topology *model.Topology
	Attach   func(ctx context.Context, node, container string, cmd []string,
		tty bool, rows, cols int, stdin io.Reader, stdout io.Writer) (int, error)
}

// Shell attaches a student's terminal to a device on any node.
func (r *ClusterExec) Shell(ctx context.Context, deviceID string, cmd []string,
	stdin io.Reader, stdout, stderr io.Writer, tty bool, rows, cols int) (int, error) {

	d, ok := r.Topology.Device(deviceID)
	if !ok {
		return 1, fmt.Errorf("no device %q", deviceID)
	}
	if r.Attach == nil {
		return 1, fmt.Errorf("no way to reach node %s", d.Node)
	}
	return r.Attach(ctx, d.Node, d.Container, cmd, tty, rows, cols, stdin, stdout)
}
