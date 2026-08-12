package deploy

import (
	"context"
	"fmt"
	"os"
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
// switchCapture records each port's VLAN assignment in a directly replayable
// form. ovs-vsctl prints lists as "[10, 20]"; the space is stripped along with
// the brackets, because a trunk written as "trunks=10, 20" is split by the
// shell and silently loses every VLAN after the first.
const switchCapture = `for p in $(ovs-vsctl list-ports br0 2>/dev/null); do
  tag=$(ovs-vsctl get port "$p" tag 2>/dev/null | tr -d '[] ')
  trunks=$(ovs-vsctl get port "$p" trunks 2>/dev/null | tr -d '[] ')
  mode=$(ovs-vsctl get port "$p" vlan_mode 2>/dev/null | tr -d '"')
  echo "port $p tag=${tag} trunks=${trunks} mode=${mode}"
done`

func Capture(ctx context.Context, r rt.Runtime, d *model.Device, lab, topoHash string) ([]state.Snapshot, error) {
	c, err := r.Inspect(ctx, d.Container)
	if err != nil {
		return nil, err
	}
	if !c.State.Joinable() {
		return nil, nil
	}

	var out []state.Snapshot
	// A read that does not happen is not the same as a device with nothing to
	// save, and the difference matters because the caller acts on the answer by
	// destroying the container. Silently returning an empty set on a failed
	// read is how a student's work is deleted by a routine image change.
	//
	// So failures are collected and returned. The caller may then decline to
	// replace a container whose contents it could not read.
	var missed []string
	read := func(what string, cmd []string) (string, bool) {
		res, err := r.Exec(ctx, d.Container, rt.ExecCmd{Cmd: cmd})
		if err != nil {
			missed = append(missed, fmt.Sprintf("%s could not be read: %v", what, err))
			return "", false
		}
		if res.ExitCode != 0 {
			missed = append(missed, fmt.Sprintf("%s could not be read: %s exited %d: %s",
				what, cmd[0], res.ExitCode, firstLine(res.Stderr)))
			return "", false
		}
		return res.Stdout, true
	}
	// readFRRConfig captures the routing configuration, and is separate from the
	// generic reader because a dead FRR is not a lost configuration.
	//
	// vtysh asks the running daemons for the configuration, so when they are
	// not answering it fails -- but the student's work is a file on disk,
	// /etc/frr/frr.conf, which is still there. Treating "the daemons are down"
	// as "there is nothing to preserve" let the replacement delete that file.
	// So when the daemons do not answer, the file is read directly; only if
	// that read also fails is the configuration truly unreachable, and then the
	// replacement is refused rather than allowed to destroy it.
	readFRRConfig := func() (string, bool) {
		res, err := r.Exec(ctx, d.Container,
			rt.ExecCmd{Cmd: []string{"vtysh", "-c", "show running-config"}})
		if err != nil {
			missed = append(missed, fmt.Sprintf(
				"the routing configuration of %s could not be read: %v", d.ID, err))
			return "", false
		}
		if res.ExitCode == 0 {
			return res.Stdout, true
		}
		if strings.Contains(res.Stderr, "failed to connect to any daemons") ||
			strings.Contains(res.Stdout, "failed to connect to any daemons") {
			fb, ferr := r.Exec(ctx, d.Container,
				rt.ExecCmd{Cmd: []string{"cat", "/etc/frr/frr.conf"}})
			if ferr == nil && fb.ExitCode == 0 {
				return fb.Stdout, true
			}
			detail := ""
			if ferr != nil {
				detail = ferr.Error()
			} else {
				detail = fmt.Sprintf("cat exited %d: %s", fb.ExitCode, firstLine(fb.Stderr))
			}
			missed = append(missed, fmt.Sprintf(
				"the routing configuration of %s could not be read: FRR is not answering and "+
					"/etc/frr/frr.conf could not be read either (%s); replacing the container "+
					"would destroy the student's configuration, so recover the file or bring "+
					"FRR back before retrying", d.ID, detail))
			return "", false
		}
		missed = append(missed, fmt.Sprintf(
			"the routing configuration of %s could not be read: vtysh exited %d: %s",
			d.ID, res.ExitCode, firstLine(res.Stderr)))
		return "", false
	}
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
		if body, ok := readFRRConfig(); ok {
			add(state.KindFRR, cleanRunningConfig(body))
		}
		// Tunnels are configured with ip(8) rather than through FRR, so they
		// are captured separately or the 6in4 exercise would be lost.
		if body, ok := read("the tunnels", []string{"sh", "-c",
			"ip -d tunnel show 2>/dev/null; ip -6 route show 2>/dev/null"}); ok {
			add(state.KindTunnels, body)
		}
		if body, ok := read("the addresses", []string{"sh", "-c",
			"ip -o addr show; echo ---; ip -o link show type vlan"}); ok {
			add(state.KindAddrs, body)
		}

	case model.KindHost:
		if body, ok := read("the addresses and routes", []string{"sh", "-c",
			"ip -o addr show; echo ---; ip -o route show; echo ---; ip -o -6 route show"}); ok {
			add(state.KindAddrs, body)
		}

	case model.KindSwitch:
		// ovs-vsctl show is human-oriented; the port/VLAN facts are what a
		// restore needs, so they are captured in a directly replayable form.
		if body, ok := read("the switch ports", []string{"sh", "-c", switchCapture}); ok {
			add(state.KindOVS, body)
		}
	}
	if len(missed) > 0 {
		return out, fmt.Errorf("%s", strings.Join(missed, "; "))
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
			// Whatever was read is still stored: a partial snapshot is worth
			// more than none, and the failure is reported either way.
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

// cleanRunningConfig strips the preamble vtysh prints before a configuration.
//
// "show running-config" begins with "Building configuration..." and a
// "Current configuration:" banner, which are not configuration and which vtysh
// itself rejects when the text is fed back in. Capturing them means every
// restore fails on its first line, and the failure appears only later, when a
// container is replaced and a class's work is due to be replayed into it.
func cleanRunningConfig(out string) string {
	lines := strings.Split(out, "\n")
	start := 0
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "Building configuration") ||
			strings.HasPrefix(t, "Current configuration") {
			start = i + 1
			continue
		}
		break
	}
	return strings.TrimRight(strings.Join(lines[start:], "\n"), "\n")
}

// Restore replays a device's captured configuration into a fresh container.
func Restore(ctx context.Context, r rt.Runtime, d *model.Device, lab string, store *state.Store) (bool, error) {
	if store == nil {
		return false, nil
	}
	restored := false

	// A replay that quietly does nothing is worse than one that refuses: the
	// device comes back believable but wrong, and the student is left debugging
	// a topology that no longer matches what they configured. Every command is
	// therefore allowed to fail, and any failure is reported rather than logged.
	replay := func(kind state.Kind, build func(string) []string) error {
		snap, err := store.Current(lab, d.ID, kind)
		switch {
		case os.IsNotExist(err):
			// Nothing was ever captured for this device and kind, which is the
			// normal case for a device the student has not touched.
			return nil
		case err != nil:
			// A snapshot that exists but cannot be read is not the same thing
			// as no snapshot. Treating them alike means a corrupt or
			// unreadable capture is silently skipped and the device comes back
			// looking clean, which is the failure this whole path exists to
			// prevent.
			return fmt.Errorf("reading the saved %s of %s: %w", kind, d.ID, err)
		case len(snap.Content) == 0:
			return nil
		}
		cmds := build(string(snap.Content))
		if len(cmds) == 0 {
			return nil
		}
		var failed []string
		for _, cmd := range cmds {
			res, err := r.Exec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", cmd}})
			switch {
			case err != nil:
				failed = append(failed, fmt.Sprintf("%s: %v", cmd, err))
			case res.ExitCode != 0:
				failed = append(failed, fmt.Sprintf("%s: %s", cmd, firstLine(res.Stderr)))
			}
		}
		if len(failed) > 0 {
			return fmt.Errorf("restore %s %s: %d of %d commands failed: %s",
				d.ID, kind, len(failed), len(cmds), strings.Join(failed, "; "))
		}
		restored = true
		return nil
	}

	switch d.Kind {
	case model.KindRouter:
		snap, err := store.Current(lab, d.ID, state.KindFRR)
		if err != nil && !os.IsNotExist(err) {
			return false, fmt.Errorf("reading the saved configuration of %s: %w", d.ID, err)
		}
		if err == nil && len(snap.Content) > 0 {
			// The captured configuration is replayed through vtysh's own file
			// loader, which is the same path `restore_configs` used and the
			// only one that accepts a running-config verbatim.
			//
			// The preamble is stripped again on the way in, not only on the
			// way out. Snapshots outlive the code that wrote them, and a
			// snapshot taken by an older build must still restore rather than
			// permanently fail every future deployment of that device.
			body := []byte(cleanRunningConfig(string(snap.Content)) + "\n")
			if err := r.CopyTo(ctx, d.Container, "/etc/twinet/restore.conf", 0o600, body); err != nil {
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
		if err := replay(state.KindTunnels, tunnelReplay); err != nil {
			return restored, err
		}
		if err := replay(state.KindAddrs, addrReplay); err != nil {
			return restored, err
		}

	case model.KindHost:
		if err := replay(state.KindAddrs, addrReplay); err != nil {
			return restored, err
		}

	case model.KindSwitch:
		if err := replay(state.KindOVS, ovsReplay); err != nil {
			return restored, err
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
				out = append(out, fmt.Sprintf("ip %saddr replace %s dev %s", flag, addr, iface))
			}
		case 1, 2: // routes
			if strings.HasPrefix(line, "default") || strings.Contains(line, " via ") {
				flag := ""
				if section == 2 {
					flag = "-6 "
				}
				out = append(out, fmt.Sprintf("ip %sroute replace %s", flag, line))
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
			fmt.Sprintf("ip link set %s up", name))
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
			out = append(out, fmt.Sprintf("ovs-vsctl set port %s tag=%s", port, tag))
		}
		if trunks != "" {
			out = append(out, fmt.Sprintf("ovs-vsctl set port %s trunks=%s", port, trunks))
		}
		if mode != "" {
			out = append(out, fmt.Sprintf("ovs-vsctl set port %s vlan_mode=%s", port, mode))
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
