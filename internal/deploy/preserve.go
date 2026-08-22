package deploy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/limiter"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/nos"
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
//
// Every bridge, not br0. The reference answer builds one bridge and this asked
// for it by name, so a submission that made another -- which is a perfectly
// good way to build a switch -- had those ports read as absent, and came back
// from its own snapshot with their VLANs gone.
const switchCapture = `bridges=$(ovs-vsctl list-br) || exit $?
for b in $bridges; do
  ports=$(ovs-vsctl list-ports "$b") || exit $?
  for p in $ports; do
    tag=$(ovs-vsctl get port "$p" tag) || exit $?
    trunks=$(ovs-vsctl get port "$p" trunks) || exit $?
    mode=$(ovs-vsctl get port "$p" vlan_mode) || exit $?
    tag=$(printf '%s' "$tag" | tr -d '[] ')
    trunks=$(printf '%s' "$trunks" | tr -d '[] ')
    mode=$(printf '%s' "$mode" | tr -d '"')
    echo "port $p tag=${tag} trunks=${trunks} mode=${mode}"
  done
done`

// ErrNotRunning reports that a device's container exists but is not running, so
// its contents could not be read.
//
// This used to be indistinguishable from "there was nothing to save": Capture
// returned no snapshots and no error, and the caller that asks before
// destroying a container took that at face value and destroyed it. A stopped
// container still holds the student's work -- the configuration is a file on
// its filesystem, not something the daemons are keeping in memory -- so the one
// device most likely to be replaced, the one that had crashed, was the one
// whose work was thrown away.
var ErrNotRunning = errors.New("the container is not running")

// preserveExecutor adapts the existing Runtime to the NOS save contract
// without making preservation depend on a particular container backend.
type preserveExecutor struct{ runtime rt.Runtime }

func (e preserveExecutor) Exec(ctx context.Context, deviceID string, command []string) (rt.ExecResult, error) {
	return e.runtime.Exec(ctx, deviceID, rt.ExecCmd{Cmd: command})
}

func Capture(ctx context.Context, r rt.Runtime, d *model.Device, lab, topoHash string) ([]state.Snapshot, error) {
	c, err := r.Inspect(ctx, d.Container)
	if err != nil {
		return nil, err
	}
	if c.State == rt.StateAbsent {
		// There is genuinely nothing there to read.
		return nil, nil
	}
	if !c.State.Joinable() {
		return nil, fmt.Errorf("%s: %w", d.Container, ErrNotRunning)
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
		body = CanonicalDynamicSnapshot(kind, body)
		if body == "" {
			return
		}
		if !strings.HasSuffix(body, "\n") {
			body += "\n"
		}
		out = append(out, state.Snapshot{
			Lab: lab, AS: d.ASN, Device: d.ID, Kind: kind,
			TakenAt: time.Now().UTC(), Topology: topoHash,
			Content: []byte(body),
		})
	}

	switch d.Kind {
	case model.KindRouter:
		provider, providerErr := nos.Resolve(d)
		if providerErr != nil {
			missed = append(missed, fmt.Sprintf("the NOS configuration of %s could not be read: %v", d.ID, providerErr))
		} else if provider.Name() == model.DefaultNOS {
			if body, ok := readFRRConfig(); ok {
				add(state.KindFRR, cleanRunningConfig(body))
			}
		} else {
			snaps, saveErr := provider.Save(ctx, d, preserveExecutor{runtime: r}, lab, topoHash)
			if saveErr != nil {
				missed = append(missed, fmt.Sprintf("the %s configuration of %s could not be read: %v",
					provider.Name(), d.ID, saveErr))
			} else {
				out = append(out, snaps...)
			}
		}
		// Tunnels are configured with ip(8) rather than through FRR, so they
		// are captured separately or the 6in4 exercise would be lost.
		if body, ok := read("the tunnels", []string{"sh", "-c",
			"ip -d tunnel show || exit $?; ip -6 route show"}); ok {
			add(state.KindTunnels, body)
		}
		if body, ok := read("the addresses and routes", []string{"sh", "-c",
			"ip -o addr show || exit $?; echo ---; ip -o route show || exit $?; echo ---; " +
				"ip -o -6 route show || exit $?; echo ---; ip -o link show type vlan"}); ok {
			add(state.KindAddrs, body)
		}

	case model.KindHost:
		if body, ok := read("the addresses and routes", []string{"sh", "-c",
			"ip -o addr show || exit $?; echo ---; ip -o route show || exit $?; echo ---; " +
				"ip -o -6 route show"}); ok {
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

const dynamicStateVersion = "twinet-state/v2"

// CanonicalDynamicSnapshot returns the deterministic typed representation used
// for content-addressed addresses, tunnels, and OVS state. Raw `ip -o` output
// carries interface indices, peer suffixes, link-local addresses, lifetimes,
// and route cache details that change across an otherwise exact restore. It
// accepts legacy raw output too, so verification remains compatible with
// snapshots written before canonical dynamic state shipped.
func CanonicalDynamicSnapshot(kind state.Kind, raw string) string {
	if canonical, ok := normalizedCanonicalDynamic(kind, raw); ok {
		return canonical
	}
	switch kind {
	case state.KindAddrs:
		return canonicalAddresses(raw)
	case state.KindTunnels:
		return canonicalTunnels(raw)
	case state.KindOVS:
		return canonicalOVS(raw)
	default:
		return strings.TrimSpace(raw)
	}
}

func normalizedCanonicalDynamic(kind state.Kind, raw string) (string, bool) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != dynamicStateVersion+" "+string(kind) {
		return "", false
	}
	set := map[string]bool{}
	for _, line := range lines[1:] {
		if kind == state.KindOVS {
			addCanonicalOVSPort(line, set)
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		set[strings.Join(fields, " ")] = true
	}
	return canonicalLines(string(kind), set), true
}

func canonicalAddresses(raw string) string {
	sections := 0
	set := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "---" {
			sections++
			continue
		}
		if line == "" {
			continue
		}
		switch sections {
		case 0:
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			iface := strings.TrimSuffix(fields[1], ":")
			iface, _, _ = strings.Cut(iface, "@")
			for i := 2; i+1 < len(fields); i++ {
				family := fields[i]
				if family != "inet" && family != "inet6" {
					continue
				}
				address := fields[i+1]
				if dynamicKernelAddress(address) {
					continue
				}
				set["addr "+family+" "+iface+" "+address] = true
			}
		case 1:
			if route := canonicalRoute(line); route != "" {
				set["route inet "+route] = true
			}
		default:
			if route := canonicalRoute(line); route != "" {
				set["route inet6 "+route] = true
			}
		}
	}
	return canonicalLines("addrs", set)
}

func dynamicKernelAddress(address string) bool {
	host, _, _ := strings.Cut(address, "/")
	return strings.HasPrefix(host, "127.") || host == "::1" ||
		strings.HasPrefix(strings.ToLower(host), "fe80:")
}

func canonicalRoute(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 || !routeStart(fields[0]) {
		return ""
	}
	var out []string
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "proto", "src", "pref", "expires", "cache":
			i++ // their following value is runtime decoration, not user state
			continue
		case "linkdown":
			continue
		}
		out = append(out, fields[i])
	}
	return strings.Join(out, " ")
}

func routeStart(first string) bool {
	switch first {
	case "default", "blackhole", "unreachable", "prohibit", "throw", "nat", "local", "broadcast", "anycast", "multicast":
		return true
	}
	if _, err := netip.ParsePrefix(first); err == nil {
		return true
	}
	_, err := netip.ParseAddr(first)
	return err == nil
}

func canonicalTunnels(raw string) string {
	set := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "remote ") && strings.Contains(line, "local ") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			name := strings.TrimSuffix(fields[0], ":")
			remote, local := fieldAfter(line, "remote"), fieldAfter(line, "local")
			if name != "" && name != "sit0" && remote != "" && local != "" &&
				remote != "any" && local != "any" {
				set["tunnel "+name+" "+remote+" "+local] = true
			}
			continue
		}
		if route := canonicalRoute(line); route != "" {
			set["route inet6 "+route] = true
		}
	}
	return canonicalLines("tunnels", set)
}

func canonicalOVS(raw string) string {
	set := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		addCanonicalOVSPort(line, set)
	}
	return canonicalLines("ovs", set)
}

func addCanonicalOVSPort(line string, set map[string]bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 || fields[0] != "port" {
		return
	}
	port := fields[1]
	tag, trunks, mode := "", "", ""
	for _, field := range fields[2:] {
		switch {
		case strings.HasPrefix(field, "tag="):
			tag = strings.Trim(strings.TrimPrefix(field, "tag="), "[]")
		case strings.HasPrefix(field, "trunks="):
			trunks = canonicalVLANList(strings.TrimPrefix(field, "trunks="))
		case strings.HasPrefix(field, "mode="):
			mode = strings.Trim(strings.TrimPrefix(field, "mode="), "[]")
		}
	}
	// A port with no VLAN state is platform plumbing, not student-owned
	// switch configuration. Excluding it prevents an extra empty veth
	// from making an otherwise exact restore fail verification.
	if tag != "" || trunks != "" || mode != "" {
		set["port "+port+" tag="+tag+" trunks="+trunks+" mode="+mode] = true
	}
}

func canonicalVLANList(raw string) string {
	raw = strings.Trim(raw, "[]")
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func canonicalLines(kind string, set map[string]bool) string {
	lines := make([]string, 0, len(set))
	for line := range set {
		lines = append(lines, line)
	}
	sort.Strings(lines)
	body := dynamicStateVersion + " " + kind + "\n"
	if len(lines) != 0 {
		body += strings.Join(lines, "\n") + "\n"
	}
	return body
}

// CaptureAll snapshots every student-owned device on this node.
func (e *Engine) CaptureAll(ctx context.Context, top *model.Topology, store *state.Store) (int, error) {
	return e.captureSelected(ctx, top, store, nil)
}

// CaptureDevices snapshots only named devices at a destructive deployment
// boundary. Periodic durability capture intentionally continues to use
// CaptureAll; a no-change deploy must not turn into a class-wide configuration
// survey.
func (e *Engine) CaptureDevices(ctx context.Context, top *model.Topology, store *state.Store, ids []string) (int, error) {
	only := make(map[string]bool, len(ids))
	for _, id := range ids {
		only[id] = true
	}
	return e.captureSelected(ctx, top, store, only)
}

// CaptureDirty snapshots only student-owned devices that this Engine's most
// recent Build marked as destructively touched. It is for deployment
// boundaries; periodic durability capture must continue to call CaptureAll.
func (e *Engine) CaptureDirty(ctx context.Context, top *model.Topology, store *state.Store) (int, error) {
	return e.CaptureDevices(ctx, top, store, e.DirtyCaptureDevices())
}

func (e *Engine) captureSelected(ctx context.Context, top *model.Topology, store *state.Store, only map[string]bool) (int, error) {
	if store == nil {
		return 0, nil
	}
	// Never while the reference solution is what is on the devices. Enforced
	// here as well as at the call sites, because there are five of them and
	// each was fixed separately as it was found.
	if e.WritesReference {
		return 0, nil
	}
	var devices []*model.Device
	for _, d := range top.DevicesOnNode(e.Node) {
		if studentOwned(top, d) && (only == nil || only[d.ID]) {
			devices = append(devices, d)
		}
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })

	captures := make([][]state.Snapshot, len(devices))
	_, captureErrs, ctxErr := e.runBounded(ctx, len(devices), func(i int) error {
		return e.limited(ctx, []limiter.Kind{limiter.Capture}, func() error {
			snaps, err := Capture(ctx, e.Runtime, devices[i], top.Name, top.Hash)
			captures[i] = snaps
			return err
		})
	})

	saved := 0
	var problems []string
	for i, d := range devices {
		err := captureErrs[i]
		if err != nil && !errors.Is(err, ErrNotRunning) {
			// A stopped device is not a problem for a periodic backup: the
			// snapshot already in the store is still the last thing that was
			// on it, and nothing is lost by not overwriting it. It is a
			// problem for the caller that is about to destroy the container,
			// and that caller is the one that must not ignore it.
			problems = append(problems, fmt.Sprintf("%s: %v", d.ID, err))
			// Whatever was read is still stored: a partial snapshot is worth
			// more than none, and the failure is reported either way.
		}
		for _, s := range captures[i] {
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
		return saved, deterministicError(ctxErr, problems)
	}
	return saved, ctxErr
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

// cleanRestoredFRRConfig removes kernel-forwarding directives from a captured
// running configuration. They are platform runtime policy, already restored
// by the persisted OCI sysctl contract; replaying the legacy `no ipv6
// forwarding` line through current FRR's mgmtd can fail even though the
// desired runtime is healthy. Student routing state remains intact.
func cleanRestoredFRRConfig(out string) string {
	lines := strings.Split(cleanRunningConfig(out), "\n")
	filtered := lines[:0]
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "ipv6 forwarding", trimmed == "no ipv6 forwarding",
			strings.HasPrefix(trimmed, "hostname "),
			strings.HasPrefix(trimmed, "frr version "),
			strings.HasPrefix(trimmed, "frr defaults "),
			trimmed == "service integrated-vtysh-config",
			trimmed == "end":
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.TrimRight(strings.Join(filtered, "\n"), "\n")
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
		if err := resetDynamicState(ctx, r, d, kind); err != nil {
			return err
		}
		cmds := build(string(snap.Content))
		if len(cmds) == 0 {
			// An explicitly captured empty dynamic state is still a restore:
			// resetDynamicState removed stale facts that were not in it.
			if kind == state.KindAddrs || kind == state.KindTunnels || kind == state.KindOVS {
				restored = true
			}
			return nil
		}
		for _, cmd := range cmds {
			res, err := r.Exec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", cmd}})
			switch {
			case err != nil:
				return fmt.Errorf("restore %s %s command %q: %w", d.ID, kind, cmd, err)
			case res.ExitCode != 0:
				return fmt.Errorf("restore %s %s command %q exited %d: %s",
					d.ID, kind, cmd, res.ExitCode, firstLine(res.Stderr))
			}
		}
		restored = true
		return nil
	}

	switch d.Kind {
	case model.KindRouter:
		provider, providerErr := nos.Resolve(d)
		if providerErr != nil {
			return false, fmt.Errorf("resolve NOS for saved configuration of %s: %w", d.ID, providerErr)
		}
		// Network facts are restored before routing configuration. Resetting
		// stale routes after vtysh/birdc would flush routes the daemon just
		// installed; restoring interfaces first also gives the daemon its
		// endpoint addresses before it parses saved neighbors.
		if err := replay(state.KindAddrs, addrReplay); err != nil {
			return restored, err
		}
		if err := replay(state.KindTunnels, tunnelReplay); err != nil {
			return restored, err
		}
		if provider.Name() != model.DefaultNOS {
			snap, err := store.Current(lab, d.ID, provider.StateKind())
			switch {
			case os.IsNotExist(err):
				// No provider-owned configuration was ever saved.
			case err != nil:
				return false, fmt.Errorf("reading the saved %s configuration of %s: %w",
					provider.Name(), d.ID, err)
			case len(snap.Content) > 0:
				if provider.Name() == "bird" {
					if err := waitForBIRDRestoreReady(ctx, r, d); err != nil {
						return false, err
					}
				}
				if err := provider.Restore(ctx, d, r, snap); err != nil {
					return false, err
				}
				restored = true
			}
			return restored, nil
		}
		snap, err := store.Current(lab, d.ID, state.KindFRR)
		if err != nil && !os.IsNotExist(err) {
			return false, fmt.Errorf("reading the saved configuration of %s: %w", d.ID, err)
		}
		if err == nil && len(snap.Content) > 0 {
			if err := waitForFRRRestoreReady(ctx, r, d); err != nil {
				return false, err
			}
			// The captured configuration is replayed through vtysh's own file
			// loader, which is the same path `restore_configs` used and the
			// only one that accepts a running-config verbatim.
			//
			// The preamble is stripped again on the way in, not only on the
			// way out. Snapshots outlive the code that wrote them, and a
			// snapshot taken by an older build must still restore rather than
			// permanently fail every future deployment of that device.
			body := []byte(cleanRestoredFRRConfig(string(snap.Content)) + "\n")
			if err := r.CopyTo(ctx, d.Container, "/etc/twinet/restore.conf", 0o600, body); err != nil {
				return false, fmt.Errorf("copy saved configuration into %s: %w", d.ID, err)
			}
			// The file is removed whatever happens next.
			//
			// It stayed, and it holds a complete routing configuration. On a
			// lab deployed at the reference that is the answer, sitting in
			// /etc/twinet where any root shell can read it -- and root inside
			// the container is exactly what a student has, and what an agent
			// being evaluated on root-cause analysis has. It was found on
			// sampled routers of three autonomous systems on this cluster.
			//
			// It is deleted in the same shell that loads it, so there is no
			// window in which the process could die and leave it behind.
			res, err := r.Exec(ctx, d.Container, rt.ExecCmd{
				Cmd: []string{"sh", "-c",
					"vtysh -f /etc/twinet/restore.conf; rc=$?; " +
						"rm -f /etc/twinet/restore.conf; exit $rc"}})
			if err != nil {
				_, _ = r.Exec(ctx, d.Container, rt.ExecCmd{
					Cmd: []string{"rm", "-f", "/etc/twinet/restore.conf"}})
				return false, fmt.Errorf("restore %s: %w", d.ID, err)
			}
			if res.ExitCode != 0 {
				return false, fmt.Errorf("restore %s: vtysh exited %d: %s",
					d.ID, res.ExitCode, firstLine(res.Stderr))
			}
			restored = true
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

// resetDynamicState removes stale dynamic facts before a canonical replay.
// Captures contain all meaningful facts for a student-owned device, so adding
// the saved facts without first clearing the old ones could leave a failed
// solve-mode address, route, tunnel, or VLAN behind. Every reset command is
// required: an error leaves recovery pending rather than claiming an exact
// restore that has known extra state.
func resetDynamicState(ctx context.Context, r rt.Runtime, d *model.Device, kind state.Kind) error {
	var script string
	switch kind {
	case state.KindAddrs:
		// Addresses and routes may have been installed by a failed reference
		// apply even when the saved teaching state was intentionally blank.
		// Enumerate live interfaces instead of snapshot interfaces so a legacy
		// blank snapshot can still remove that stale reference address.
		script = `links=$(ip -o link show) || exit $?
ifaces=$(printf '%s\n' "$links" | sed -n 's/^[0-9][0-9]*: \([^:@]*\).*/\1/p') || exit $?
for iface in $ifaces; do
  ip addr flush dev "$iface" scope global || exit $?
  ip -6 addr flush dev "$iface" scope global || exit $?
  ip route flush dev "$iface" || exit $?
  ip -6 route flush dev "$iface" || exit $?
done`
	case state.KindTunnels:
		// sit0 is the kernel's built-in tunnel and must never be deleted.
		script = `tunnels=$(ip -d tunnel show) || exit $?
printf '%s\n' "$tunnels" | while IFS= read -r line; do
  case "$line" in *" remote "*" local "*) ;; *) continue ;; esac
  name=${line%%:*}
  case "$name" in ""|sit0) continue ;; esac
  ip tunnel del "$name" || exit $?
done || exit $?`
	case state.KindOVS:
		script = `bridges=$(ovs-vsctl list-br) || exit $?
for bridge in $bridges; do
  ports=$(ovs-vsctl list-ports "$bridge") || exit $?
  for port in $ports; do
    ovs-vsctl clear port "$port" tag || exit $?
    ovs-vsctl clear port "$port" trunks || exit $?
    ovs-vsctl clear port "$port" vlan_mode || exit $?
  done
done`
	default:
		return nil
	}
	res, err := r.Exec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", script}})
	if err != nil {
		return fmt.Errorf("reset restored %s state on %s: %w", kind, d.ID, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("reset restored %s state on %s exited %d: %s",
			kind, d.ID, res.ExitCode, firstLine(res.Stderr))
	}
	return nil
}

// waitForFRRRestoreReady avoids replaying a saved configuration while the
// control sidecar has started but zebra's vty socket is not usable yet. A
// vtysh exit 13 is transient at that point, not evidence that a valid student
// snapshot should be discarded.
func waitForFRRRestoreReady(ctx context.Context, r rt.Runtime, d *model.Device) error {
	const timeout = 30 * time.Second
	readyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var last string
	for {
		result, err := r.Exec(readyCtx, d.Container, rt.ExecCmd{
			Cmd: []string{"vtysh", "-c", "show version"},
		})
		if err == nil && result.ExitCode == 0 {
			return nil
		}
		if err != nil {
			last = err.Error()
		} else {
			last = fmt.Sprintf("vtysh exited %d: %s", result.ExitCode, firstLine(result.Stderr))
		}
		select {
		case <-readyCtx.Done():
			if last == "" {
				last = readyCtx.Err().Error()
			}
			return fmt.Errorf("wait for routing daemon readiness on %s: %s", d.ID, last)
		case <-ticker.C:
		}
	}
}

func waitForBIRDRestoreReady(ctx context.Context, r rt.Runtime, d *model.Device) error {
	const timeout = 30 * time.Second
	readyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var last string
	for {
		result, err := r.Exec(readyCtx, d.Container, rt.ExecCmd{
			Cmd: []string{"birdc", "-r", "-s", "/run/bird.ctl", "show", "status"},
		})
		if err == nil && result.ExitCode == 0 {
			return nil
		}
		if err != nil {
			last = err.Error()
		} else {
			last = fmt.Sprintf("birdc exited %d: %s", result.ExitCode, firstLine(result.Stderr))
		}
		select {
		case <-readyCtx.Done():
			if last == "" {
				last = readyCtx.Err().Error()
			}
			return fmt.Errorf("wait for BIRD daemon readiness on %s: %s", d.ID, last)
		case <-ticker.C:
		}
	}
}

// addrReplay turns captured `ip -o` output back into commands.
func addrReplay(body string) []string {
	return canonicalAddrReplay(CanonicalDynamicSnapshot(state.KindAddrs, body))
}

func canonicalAddrReplay(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		switch fields[0] {
		case "addr":
			if len(fields) != 4 {
				continue
			}
			flag := ""
			if fields[1] == "inet6" {
				flag = "-6 "
			}
			out = append(out, fmt.Sprintf("ip %saddr replace %s dev %s", flag, fields[3], fields[2]))
		case "route":
			if len(fields) < 3 {
				continue
			}
			flag := ""
			if fields[1] == "inet6" {
				flag = "-6 "
			}
			out = append(out, "ip "+flag+"route replace "+strings.Join(fields[2:], " "))
		}
	}
	return out
}

// tunnelReplay reconstructs 6in4 tunnels from captured output.
func tunnelReplay(body string) []string {
	return canonicalTunnelReplay(CanonicalDynamicSnapshot(state.KindTunnels, body))
}

func canonicalTunnelReplay(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		switch fields[0] {
		case "tunnel":
			if len(fields) != 4 {
				continue
			}
			name, remote, local := fields[1], fields[2], fields[3]
			out = append(out,
				fmt.Sprintf("if ip link show %s >/dev/null 2>&1; then ip tunnel del %s; fi; "+
					"ip tunnel add %s mode sit remote %s local %s ttl 64", name, name, name, remote, local),
				fmt.Sprintf("ip link set %s up", name))
		case "route":
			if len(fields) >= 3 && fields[1] == "inet6" {
				out = append(out, "ip -6 route replace "+strings.Join(fields[2:], " "))
			}
		}
	}
	return out
}

// ovsReplay reconstructs a switch's port VLAN assignment.
func ovsReplay(body string) []string {
	body = CanonicalDynamicSnapshot(state.KindOVS, body)
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
// StudentOwned reports whether a device's configuration belongs to a student,
// which is what decides whether it is captured before being destroyed.
func StudentOwned(top *model.Topology, d *model.Device) bool { return studentOwned(top, d) }

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
