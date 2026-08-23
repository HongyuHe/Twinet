package agent

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// controlDaemonCounts reads the process namespace owned by the private FRR
// control sidecar. Matching comm rather than a shell command line prevents a
// cleanup probe from matching and killing its own `sh -c` process.
func (s *Server) controlDaemonCounts(ctx context.Context, d *model.Device, as *model.AS) (map[string]int, error) {
	names := render.EnabledDaemonsFor(as)
	counts := make(map[string]int, len(names))
	if len(names) == 0 {
		return counts, nil
	}
	var script strings.Builder
	containerd := runtimeNameForReconcile(s.rt) == "containerd"
	script.WriteString("for p in")
	for _, name := range names {
		script.WriteByte(' ')
		script.WriteString(name)
	}
	// ldpd intentionally forks -L and -E privilege-separated children. The
	// daemon health contract is the one main `-d` process, not every child
	// whose comm happens to be ldpd.
	if containerd {
		script.WriteString(`; do n=$(ps -eo comm=,args= | awk -v want="$p" '$1 == want && (want != "ldpd" || $0 !~ /[[:space:]]-[LE]([[:space:]]|$)/) {n++} END {print n+0}'); printf '__TWINET_DAEMON__%s\t%s\n' "$p" "$n"; done`)
	} else {
		script.WriteString(`; do n=$(ps -eo comm=,args= | awk -v want="$p" '$1 == want && $0 ~ /[[:space:]]-d([[:space:]]|$)/ {n++} END {print n+0}'); printf '__TWINET_DAEMON__%s\t%s\n' "$p" "$n"; done`)
	}
	result, err := s.probeExec(ctx, s.frrContainer(ctx, d), rt.ExecCmd{
		Cmd: []string{"sh", "-c", script.String()},
	})
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("FRR control daemon count exited %d", result.ExitCode)
	}
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimPrefix(line, "__TWINET_DAEMON__")
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			continue
		}
		count, parseErr := strconv.Atoi(strings.TrimSpace(parts[1]))
		if parseErr != nil {
			return nil, fmt.Errorf("parse control daemon count for %s: %w", parts[0], parseErr)
		}
		counts[strings.TrimSpace(parts[0])] = count
	}
	for _, name := range names {
		if _, found := counts[name]; !found {
			return nil, fmt.Errorf("FRR control daemon count omitted %s", name)
		}
	}
	return counts, nil
}

func (s *Server) verifyControlDaemonSet(ctx context.Context, d *model.Device, as *model.AS) error {
	counts, err := s.controlDaemonCounts(ctx, d, as)
	if err != nil {
		return err
	}
	for _, name := range render.EnabledDaemonsFor(as) {
		if count := counts[name]; count != 1 {
			return fmt.Errorf("FRR control daemon %s has %d process(es), want exactly one", name, count)
		}
	}
	result, err := s.probeExec(ctx, s.frrContainer(ctx, d), rt.ExecCmd{
		Cmd: []string{"vtysh", "-c", "show version"},
	})
	if err != nil {
		return fmt.Errorf("FRR control vty socket is unreadable: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("FRR control vty socket check exited %d", result.ExitCode)
	}
	return nil
}

func (s *Server) stopControlDaemonSet(ctx context.Context, d *model.Device) error {
	const processes = `watchfrr|zebra|bgpd|ospfd|ospf6d|isisd|ldpd|pimd|staticd|bfdd|ripd|ripngd|pathd|sharpd|mgmtd`
	script := strings.Join([]string{
		`find_frr() { ps -eo pid=,comm= | awk '$2 ~ /^(` + processes + `)$/ {print $1}'; }`,
		`wait_gone() { i=0; while [ "$i" -lt 20 ]; do test -z "$(find_frr)" && return 0; i=$((i+1)); sleep 0.2; done; return 1; }`,
		`/usr/lib/frr/frrinit.sh stop >/dev/null 2>&1 || true`,
		`pids="$(find_frr)"; test -z "$pids" || kill $pids 2>/dev/null || true`,
		`wait_gone || { pids="$(find_frr)"; test -z "$pids" || kill -9 $pids 2>/dev/null || true; wait_gone; }`,
		`test -z "$(find_frr)"`,
		`rm -f /var/run/frr/*.pid /var/run/frr/*.vty 2>/dev/null || true`,
	}, "\n")
	result, err := s.probeExec(ctx, s.frrContainer(ctx, d), rt.ExecCmd{
		Cmd: []string{"sh", "-c", script},
	})
	if err != nil {
		return err
	}
	if err := result.Err(); err != nil {
		return fmt.Errorf("FRR control daemon cleanup failed: %w", err)
	}
	return nil
}
