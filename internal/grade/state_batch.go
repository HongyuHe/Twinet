package grade

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// stateBatchExecutor lets a NOS provider retain its ordinary typed parser
// while executing its complete passive survey as one agent-side shell. A
// provider still asks for individual native commands; the executor satisfies
// them from the tagged batch result and falls back safely for an unexpected
// command.
type stateBatchExecutor struct {
	device   *model.Device
	query    netstate.Query
	commands [][]string
	batch    func(context.Context, string, [][]string) ([]rt.ExecResult, error)
	fallback netstate.Executor

	mu      sync.Mutex
	loaded  bool
	results map[string]rt.ExecResult
	err     error
}

func newStateBatchExecutor(device *model.Device, query netstate.Query,
	extra [][]string,
	batch func(context.Context, string, [][]string) ([]rt.ExecResult, error),
	fallback netstate.Executor,
) *stateBatchExecutor {
	return &stateBatchExecutor{
		device: device, query: query, commands: uniqueCommands(append(stateCommands(device, query), extra...)),
		batch: batch, fallback: fallback, results: map[string]rt.ExecResult{},
	}
}

func (e *stateBatchExecutor) Exec(ctx context.Context, device string, command []string) (rt.ExecResult, error) {
	if e == nil || e.device == nil || device != e.device.ID || len(e.commands) == 0 {
		return e.fallback.Exec(ctx, device, command)
	}
	if err := e.ensure(ctx); err != nil {
		return rt.ExecResult{}, err
	}
	if result, ok := e.results[commandKey(device, command)]; ok {
		return result, nil
	}
	return e.fallback.Exec(ctx, device, command)
}

func (e *stateBatchExecutor) ensure(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.loaded {
		return e.err
	}
	e.loaded = true
	results, err := e.batch(ctx, e.device.ID, e.commands)
	if err != nil {
		e.err = err
		return err
	}
	if len(results) != len(e.commands) {
		e.err = fmt.Errorf("observation batch on %s returned %d results for %d commands",
			e.device.ID, len(results), len(e.commands))
		return e.err
	}
	for index, command := range e.commands {
		e.results[commandKey(e.device.ID, command)] = results[index]
	}
	return nil
}

func stateCommands(device *model.Device, query netstate.Query) [][]string {
	if device == nil {
		return nil
	}
	var commands [][]string
	if query.Has(netstate.QueryInterfaces) {
		commands = append(commands, []string{"ip", "-j", "address", "show"})
	}
	if query.Has(netstate.QueryKernel) {
		commands = append(commands,
			[]string{"ip", "-j", "route", "show", "table", "all"},
			[]string{"sysctl", "-n", "net.ipv4.ip_forward"},
			[]string{"sysctl", "-n", "net.ipv6.conf.all.forwarding"},
		)
	}
	switch device.EffectiveNOS() {
	case model.DefaultNOS:
		if query.Has(netstate.QueryBGPSessions) {
			commands = append(commands, []string{"vtysh", "-c", "show ip bgp summary json"})
		}
		if query.Has(netstate.QueryBGPRIB) {
			commands = append(commands, []string{"vtysh", "-c", "show ip bgp json"})
		}
		if query.Has(netstate.QueryOSPF) {
			commands = append(commands, []string{"vtysh", "-c", "show ip ospf neighbor json"})
		}
		if query.Has(netstate.QueryPolicy) {
			commands = append(commands, []string{"vtysh", "-c", "show running-config"})
		}
	case "bird":
		const socket = "/run/bird.ctl"
		if query.Has(netstate.QueryBGPSessions) {
			commands = append(commands, []string{"birdc", "-r", "-s", socket, "show", "protocols", "all"})
		}
		if query.Has(netstate.QueryBGPRIB) {
			commands = append(commands, []string{"birdc", "-r", "-s", socket, "show", "route", "all"})
		}
		if query.Has(netstate.QueryOSPF) {
			commands = append(commands, []string{"birdc", "-r", "-s", socket, "show", "ospf", "neighbors"})
		}
		if query.Has(netstate.QueryPolicy) {
			commands = append(commands, []string{"cat", "/etc/bird/bird.conf"})
		}
	}
	return uniqueCommands(commands)
}

func uniqueCommands(in [][]string) [][]string {
	seen := map[string]bool{}
	out := make([][]string, 0, len(in))
	for _, command := range in {
		key := strings.Join(command, "\x00")
		if !seen[key] {
			seen[key] = true
			out = append(out, command)
		}
	}
	return out
}

// observationBatch executes commands sequentially in one container exec. The
// node agent still applies its ExecProbe limiter to that one request, avoiding
// an HTTP/Docker exec storm while retaining a result for every native command.
func (s *ObservationSnapshot) observationBatch(ctx context.Context, source, device string,
	commands [][]string,
) ([]rt.ExecResult, error) {
	if len(commands) == 0 {
		return nil, nil
	}
	script, marker, err := observationBatchScript(commands)
	if err != nil {
		return nil, err
	}
	result, err := s.command(ctx, source, device, []string{"sh", "-c", script})
	if err != nil {
		return nil, err
	}
	return s.finishObservationBatch(device, source, commands, marker, result)
}

func (s *ObservationSnapshot) finishObservationBatch(device, source string,
	commands [][]string, marker string, raw rt.ExecResult,
) ([]rt.ExecResult, error) {
	results, err := parseObservationBatch(raw.Stdout, len(commands), marker)
	if err != nil {
		return nil, fmt.Errorf("parse observation batch on %s: %w", device, err)
	}
	for index, command := range commands {
		s.storeBatchedCommand(device, command, source, results[index])
	}
	return results, nil
}

func (s *ObservationSnapshot) storeBatchedCommand(device string, command []string,
	source string, result rt.ExecResult,
) {
	if s == nil {
		return
	}
	key := commandKey(device, command)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.commands[key]; exists {
		return
	}
	s.commands[key] = observationCommand{
		at: time.Now().UTC(), source: source, device: device,
		command: append([]string(nil), command...), result: result,
	}
}

func observationBatchScript(commands [][]string) (string, string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", "", fmt.Errorf("draw observation batch marker: %w", err)
	}
	marker := "__TWINET_OBS_" + hex.EncodeToString(nonce[:])
	var body strings.Builder
	for index, command := range commands {
		words := make([]string, 0, len(command))
		for _, word := range command {
			words = append(words, shellWord(word))
		}
		fmt.Fprintf(&body, "out=$(%s 2>&1); rc=$?; ", strings.Join(words, " "))
		fmt.Fprintf(&body, "printf '%s_%d_RC=%%s\\n%%s\\n%s_%d_END\\n' \"$rc\" \"$out\";\n",
			marker, index, marker, index)
	}
	body.WriteString("exit 0\n")
	return body.String(), marker, nil
}

func parseObservationBatch(body string, want int, marker string) ([]rt.ExecResult, error) {
	out := make([]rt.ExecResult, want)
	rest := body
	for index := 0; index < want; index++ {
		head := fmt.Sprintf("%s_%d_RC=", marker, index)
		start := strings.Index(rest, head)
		if start < 0 {
			return nil, fmt.Errorf("missing result %d", index)
		}
		rest = rest[start+len(head):]
		line, content, found := strings.Cut(rest, "\n")
		if !found {
			return nil, fmt.Errorf("missing result %d status terminator", index)
		}
		var code int
		if _, err := fmt.Sscanf(line, "%d", &code); err != nil {
			return nil, fmt.Errorf("parse result %d exit code %q: %w", index, line, err)
		}
		end := fmt.Sprintf("\n%s_%d_END", marker, index)
		at := strings.Index(content, end)
		if at < 0 {
			return nil, fmt.Errorf("missing result %d end marker", index)
		}
		text := content[:at]
		result := rt.ExecResult{ExitCode: code}
		if code == 0 {
			result.Stdout = text
		} else {
			result.Stderr = text
		}
		out[index] = result
		rest = content[at+len(end):]
	}
	return out, nil
}
