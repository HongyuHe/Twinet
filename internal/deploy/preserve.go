package deploy

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// Capturing and restoring student-owned configuration.
//
// The rule this implements: a deployment must never be able to destroy a
// student's work. Before any container is replaced, whatever the student had
// configured is captured; after it comes back, it is replayed. A group that has
// spent three weeks on their AS must not lose it because an operator changed a
// link's delay or a machine rebooted.

// Capture reads a device's student-owned configuration out of its container.
//
// It returns nil, nil when the device is not running or has nothing to capture,
// because a missing snapshot must never be mistaken for an empty one: writing
// "empty" over a good snapshot would destroy exactly what this protects.
func Capture(ctx context.Context, r rt.Runtime, d *model.Device, lab, topoHash string) ([]state.Snapshot, error) {
	c, err := r.Inspect(ctx, d.Container)
	if err != nil {
		return nil, err
	}
	if !c.State.Joinable() {
		return nil, nil
	}

	var out []state.Snapshot
	add := func(kind state.Kind, body string) {
		body = strings.TrimSpace(body)
		if body == "" {
			return
		}
		out = append(out, state.Snapshot{
			Lab: lab, AS: d.ASN, Device: d.ID, Kind: kind,
			TakenAt: time.Now().UTC(), Topology: topoHash,
			Content: []byte(body + "\n"),
		})
	}

	switch d.Kind {
	case model.KindRouter:
		res, err := r.Exec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"vtysh", "-c", "show running-config"}})
		if err == nil && res.ExitCode == 0 {
			add(state.KindFRR, res.Stdout)
		}
		// Tunnels are configured with ip(8) rather than through FRR, so they
		// are captured separately or the 6in4 exercise would be lost.
		if res, err := r.Exec(ctx, d.Container, rt.ExecCmd{
			Cmd: []string{"sh", "-c", "ip -d tunnel show 2>/dev/null; ip -6 route show 2>/dev/null"},
		}); err == nil && res.ExitCode == 0 {
			add(state.KindTunnels, res.Stdout)
		}
		if res, err := r.Exec(ctx, d.Container, rt.ExecCmd{
			Cmd: []string{"sh", "-c", "ip -o addr show; echo ---; ip -o link show type vlan"},
		}); err == nil && res.ExitCode == 0 {
			add(state.KindAddrs, res.Stdout)
		}

	case model.KindHost:
		if res, err := r.Exec(ctx, d.Container, rt.ExecCmd{
			Cmd: []string{"sh", "-c", "ip -o addr show; echo ---; ip -o route show; echo ---; ip -o -6 route show"},
		}); err == nil && res.ExitCode == 0 {
			add(state.KindAddrs, res.Stdout)
		}

	case model.KindSwitch:
		// ovs-vsctl show is human-oriented; the port/VLAN facts are what a
		// restore needs, so they are captured in a directly replayable form.
		script := `for p in $(ovs-vsctl list-ports br0 2>/dev/null); do
  tag=$(ovs-vsctl get port "$p" tag 2>/dev/null | tr -d '[]')
  trunks=$(ovs-vsctl get port "$p" trunks 2>/dev/null | tr -d '[]')
  mode=$(ovs-vsctl get port "$p" vlan_mode 2>/dev/null | tr -d '"')
  echo "port $p tag=${tag} trunks=${trunks} mode=${mode}"
done`
		if res, err := r.Exec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", script}}); err == nil && res.ExitCode == 0 {
			add(state.KindOVS, res.Stdout)
		}
	}
	return out, nil
}

// CaptureAll snapshots every student-owned device on this node.
func (e *Engine) CaptureAll(ctx context.Context, top *model.Topology, store *state.Store) (int, error) {
	if store == nil {
		return 0, nil
	}
	saved := 0
	var problems []string
	for _, d := range top.DevicesOnNode(e.Node) {
		if !studentOwned(top, d) {
			continue
		}
		snaps, err := Capture(ctx, e.Runtime, d, top.Name, top.Hash)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", d.ID, err))
			continue
		}
		for _, s := range snaps {
			changed, err := store.Put(s)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s/%s: %v", d.ID, s.Kind, err))
				continue
			}
			if changed {
				saved++
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return saved, fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return saved, nil
}

// Restore replays a device's captured configuration into a fresh container.
func Restore(ctx context.Context, r rt.Runtime, d *model.Device, lab string, store *state.Store) (bool, error) {
	if store == nil {
		return false, nil
	}
	restored := false

	switch d.Kind {
	case model.KindRouter:
		if snap, err := store.Current(lab, d.ID, state.KindFRR); err == nil && len(snap.Content) > 0 {
			// The captured configuration is replayed through vtysh's own file
			// loader, which is the same path `restore_configs` used and the
			// only one that accepts a running-config verbatim.
			if err := r.CopyTo(ctx, d.Container, "/etc/twinet/restore.conf", 0o600, snap.Content); err != nil {
				return false, fmt.Errorf("copy saved configuration into %s: %w", d.ID, err)
			}
			res, err := r.Exec(ctx, d.Container, rt.ExecCmd{
				Cmd: []string{"sh", "-c", "vtysh -f /etc/twinet/restore.conf"}})
			if err != nil {
				return false, fmt.Errorf("restore %s: %w", d.ID, err)
			}
			if res.ExitCode != 0 {
				return false, fmt.Errorf("restore %s: vtysh exited %d: %s",
					d.ID, res.ExitCode, firstLine(res.Stderr))
			}
			restored = true
		}
		if snap, err := store.Current(lab, d.ID, state.KindTunnels); err == nil && len(snap.Content) > 0 {
			for _, cmd := range tunnelReplay(string(snap.Content)) {
				_, _ = r.Exec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", cmd}})
			}
			restored = true
		}
		if snap, err := store.Current(lab, d.ID, state.KindAddrs); err == nil && len(snap.Content) > 0 {
			for _, cmd := range addrReplay(string(snap.Content)) {
				_, _ = r.Exec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", cmd}})
			}
			restored = true
		}

	case model.KindHost:
		if snap, err := store.Current(lab, d.ID, state.KindAddrs); err == nil && len(snap.Content) > 0 {
			for _, cmd := range addrReplay(string(snap.Content)) {
				_, _ = r.Exec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", cmd}})
			}
			restored = true
		}

	case model.KindSwitch:
		if snap, err := store.Current(lab, d.ID, state.KindOVS); err == nil && len(snap.Content) > 0 {
			for _, cmd := range ovsReplay(string(snap.Content)) {
				_, _ = r.Exec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", cmd}})
			}
			restored = true
		}
	}
	return restored, nil
}

// addrReplay turns captured `ip -o` output back into commands.
func addrReplay(body string) []string {
	var out []string
	section := 0
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "---" {
			section++
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		switch section {
		case 0: // addresses
			if len(fields) < 4 {
				continue
			}
			iface := strings.TrimSuffix(fields[1], ":")
			for i := 2; i+1 < len(fields); i++ {
				if fields[i] != "inet" && fields[i] != "inet6" {
					continue
				}
				addr := fields[i+1]
				// Link-local and loopback addresses are the kernel's, not the
				// student's, and re-adding them fails noisily.
				if strings.HasPrefix(addr, "fe80:") || strings.HasPrefix(addr, "127.") ||
					strings.HasPrefix(addr, "::1") {
					continue
				}
				flag := ""
				if fields[i] == "inet6" {
					flag = "-6 "
				}
				out = append(out, fmt.Sprintf("ip %saddr replace %s dev %s 2>/dev/null || true", flag, addr, iface))
			}
		case 1, 2: // routes
			if strings.HasPrefix(line, "default") || strings.Contains(line, " via ") {
				flag := ""
				if section == 2 {
					flag = "-6 "
				}
				out = append(out, fmt.Sprintf("ip %sroute replace %s 2>/dev/null || true", flag, line))
			}
		}
	}
	return out
}

// tunnelReplay reconstructs 6in4 tunnels from captured output.
func tunnelReplay(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		// `ip tunnel show` prints e.g. "tun6: ipv6/ip remote 3.153.0.1 local 3.156.0.1 ttl 64"
		if !strings.Contains(line, "remote ") || !strings.Contains(line, "local ") {
			continue
		}
		name := strings.TrimSuffix(strings.Fields(line)[0], ":")
		if name == "" || name == "sit0" {
			continue
		}
		remote, local := fieldAfter(line, "remote"), fieldAfter(line, "local")
		if remote == "" || local == "" || remote == "any" || local == "any" {
			continue
		}
		out = append(out,
			fmt.Sprintf("ip link show %s >/dev/null 2>&1 || ip tunnel add %s mode sit remote %s local %s ttl 64",
				name, name, remote, local),
			fmt.Sprintf("ip link set %s up 2>/dev/null || true", name))
	}
	return out
}

// ovsReplay reconstructs a switch's port VLAN assignment.
func ovsReplay(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || fields[0] != "port" {
			continue
		}
		port := fields[1]
		var tag, trunks, mode string
		for _, f := range fields[2:] {
			switch {
			case strings.HasPrefix(f, "tag="):
				tag = strings.TrimPrefix(f, "tag=")
			case strings.HasPrefix(f, "trunks="):
				trunks = strings.TrimPrefix(f, "trunks=")
			case strings.HasPrefix(f, "mode="):
				mode = strings.TrimPrefix(f, "mode=")
			}
		}
		if tag != "" && tag != "[]" {
			out = append(out, fmt.Sprintf("ovs-vsctl set port %s tag=%s 2>/dev/null || true", port, tag))
		}
		if trunks != "" {
			out = append(out, fmt.Sprintf("ovs-vsctl set port %s trunks=%s 2>/dev/null || true", port, trunks))
		}
		if mode != "" {
			out = append(out, fmt.Sprintf("ovs-vsctl set port %s vlan_mode=%s 2>/dev/null || true", port, mode))
		}
	}
	return out
}

func fieldAfter(line, key string) string {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == key && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// studentOwned reports whether a device holds configuration a student wrote.
func studentOwned(top *model.Topology, d *model.Device) bool {
	as, ok := top.ASes[d.ASN]
	if !ok {
		return false
	}
	return as.Role == model.RoleStudent
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return strings.TrimSpace(s)
}
