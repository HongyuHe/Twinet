package fault

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

// The O16 faults are intentionally implemented against typed runtimes. A
// command that merely edits a file inside an arbitrary container is not a P4,
// OpenFlow, load-balancer, or Kubernetes fault and is refused below.
func init() {
	registerP4Faults()
	registerOpenFlowFaults()
	registerLoadBalancerFault()
	registerMPLSLabelFault()
	registerKubernetesFaults()
}

func registerP4Faults() {
	Register(&Fault{
		Name: "bmv2_switch_down", Category: CatLink,
		Needs: []Capability{CapP4, CapLifecycle}, Requires: native(SubstrateP4BMv2),
		Symptom:  "Traffic through one programmable switch stops while attached links remain up.",
		Describe: "The BMv2 data-plane process was paused, leaving the switch's ports present but unable to forward.",
		Precondition: func(ctx context.Context, e *Env, t Target) (string, error) {
			if _, err := p4Device(e, t); err != nil {
				return "", err
			}
			state, err := e.State(ctx, t.DeviceID())
			if err != nil {
				return "", err
			}
			if state != "running" {
				return "the BMv2 container is " + state, nil
			}
			if err := p4Probe(ctx, e, t); err != nil {
				return "the declared P4 forwarding probe is not healthy: " + err.Error(), nil
			}
			return "", nil
		},
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			if err := e.Do(ctx, t.DeviceID(), "pause"); err != nil {
				return nil, err
			}
			return State{"action": "pause"}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, _ State) (Evidence, error) {
			state, err := e.State(ctx, t.DeviceID())
			if err != nil {
				return Evidence{}, err
			}
			down := state == "paused"
			probeErr := p4Probe(ctx, e, t)
			failedForwarding := probeErr != nil
			if !e.wantSymptom {
				down = state != "running"
				failedForwarding = probeErr != nil
			}
			return Evidence{
				Verified: down && failedForwarding,
				Observed: fmt.Sprintf("BMv2 container=%s; forwarding probe=%s", state, probeResult(probeErr)),
				Expected: "a paused BMv2 process and failed data-plane probe",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, _ State) error {
			return e.Do(ctx, t.DeviceID(), "unpause")
		},
	})

	Register(&Fault{
		Name: "p4_table_entry_missing", Category: CatNodeError,
		Needs: []Capability{CapP4, CapExec}, Requires: native(SubstrateP4BMv2),
		Symptom:      "A particular destination stops forwarding through a programmable switch while the pipeline remains running.",
		Describe:     "A real BMv2 forwarding table entry was removed through the declared control-plane ABI.",
		Precondition: p4TablePrecondition,
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			d, err := p4Device(e, t)
			if err != nil {
				return nil, err
			}
			entry, handle, err := p4BaselineEntry(ctx, e, t, d)
			if err != nil {
				return nil, err
			}
			if err := p4CLI(ctx, e, t, fmt.Sprintf("table_delete %s %s", d.P4.Table, handle)); err != nil {
				return nil, err
			}
			return p4EntryState(d, entry, handle), nil
		},
		Verify: p4MissingVerify,
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			d, err := p4Device(e, t)
			if err != nil {
				return err
			}
			return p4AddEntry(ctx, e, t, d, stateP4Entry(s))
		},
	})

	Register(&Fault{
		Name: "p4_table_entry_misconfig", Category: CatNodeError,
		Needs: []Capability{CapP4, CapExec}, Requires: native(SubstrateP4BMv2),
		Symptom:      "One programmable forwarding path sends packets somewhere that does not answer.",
		Describe:     "A BMv2 table entry was changed to an explicitly non-forwarding action parameter, then checked with a data-plane probe.",
		Precondition: p4TablePrecondition,
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			d, err := p4Device(e, t)
			if err != nil {
				return nil, err
			}
			entry, handle, err := p4BaselineEntry(ctx, e, t, d)
			if err != nil {
				return nil, err
			}
			// The bundled typed ABI's forwarding action takes one egress
			// port. Port zero is a valid BMv2 action argument but not a
			// usable data-plane egress, so it produces a real forwarding
			// symptom without assuming a program-specific MAC parameter.
			bad := strings.TrimSpace(t.Param("bad_params", "0"))
			if bad == "" {
				return nil, fmt.Errorf("bad_params is empty, so the table entry would not change")
			}
			line := fmt.Sprintf("table_modify %s %s %s => %s", d.P4.Table, entry.Action, handle, bad)
			if err := p4CLI(ctx, e, t, line); err != nil {
				return nil, err
			}
			s := p4EntryState(d, entry, handle)
			s["bad_params"] = bad
			return s, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			d, err := p4Device(e, t)
			if err != nil {
				return Evidence{}, err
			}
			out, err := p4Dump(ctx, e, t, d)
			if err != nil {
				return Evidence{}, err
			}
			changed := strings.Contains(out, s["bad_params"])
			probeErr := p4Probe(ctx, e, t)
			broken := probeErr != nil
			if !e.wantSymptom {
				changed = false
				broken = probeErr != nil
			}
			return Evidence{
				Verified: changed && broken,
				Observed: fmt.Sprintf("entry changed=%t; forwarding probe=%s", changed, probeResult(probeErr)),
				Expected: "a changed BMv2 entry and failed forwarding probe",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			d, err := p4Device(e, t)
			if err != nil {
				return err
			}
			entry := stateP4Entry(s)
			return p4CLI(ctx, e, t, fmt.Sprintf("table_modify %s %s %s => %s",
				d.P4.Table, entry.Action, s["handle"], strings.Join(entry.Params, " ")))
		},
	})

	registerP4CompileFault("p4_compilation_error_parser_state", "parser start { transition missing_state; }",
		"The parser state reference is invalid, so compiling and loading the pipeline fails and BMv2 is left without a data plane.")
	registerP4CompileFault("p4_header_definition_error", "header broken_t { nonsense_t field; }",
		"A malformed P4 header declaration makes the program compiler reject the pipeline before BMv2 can forward.")

	Register(&Fault{
		Name: "p4_aggressive_detection_thresholds", Category: CatNodeError,
		Needs: []Capability{CapP4, CapExec, CapTraffic}, Requires: native(SubstrateP4BMv2),
		Symptom:  "Ordinary traffic begins being dropped by a programmable switch even though links and its process remain up.",
		Describe: "The program's declared detection threshold register was set low enough to trigger its real drop path.",
		Precondition: func(ctx context.Context, e *Env, t Target) (string, error) {
			d, err := p4Device(e, t)
			if err != nil {
				return "", err
			}
			if d.P4.ThresholdRegister == "" {
				return "the P4 program declares no threshold_register", nil
			}
			if err := p4Probe(ctx, e, t); err != nil {
				return "the declared P4 forwarding probe is not healthy: " + err.Error(), nil
			}
			return "", nil
		},
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			d, err := p4Device(e, t)
			if err != nil {
				return nil, err
			}
			before, err := p4CLIOutput(ctx, e, t, fmt.Sprintf("register_read %s 0", d.P4.ThresholdRegister))
			if err != nil {
				return nil, err
			}
			old := lastInteger(before)
			if old < 0 {
				return nil, fmt.Errorf("could not read threshold register %s", d.P4.ThresholdRegister)
			}
			low, err := strconv.Atoi(t.Param("threshold", "1"))
			if err != nil || low < 0 {
				return nil, fmt.Errorf("threshold must be a non-negative integer")
			}
			if low == old {
				return nil, fmt.Errorf("threshold register is already %d", low)
			}
			if err := p4CLI(ctx, e, t, fmt.Sprintf("register_write %s 0 %d", d.P4.ThresholdRegister, low)); err != nil {
				return nil, err
			}
			return State{"register": d.P4.ThresholdRegister, "old": strconv.Itoa(old), "low": strconv.Itoa(low)}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, err := p4CLIOutput(ctx, e, t, fmt.Sprintf("register_read %s 0", s["register"]))
			if err != nil {
				return Evidence{}, err
			}
			got := lastInteger(out)
			probeErr := p4Probe(ctx, e, t)
			dropping := probeErr != nil
			if !e.wantSymptom {
				dropping = probeErr != nil
			}
			return Evidence{
				Verified: got == mustAtoi(s["low"]) && dropping,
				Observed: fmt.Sprintf("threshold=%d; forwarding probe=%s", got, probeResult(probeErr)),
				Expected: "a low threshold triggering the program's packet-drop path",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			return p4CLI(ctx, e, t, fmt.Sprintf("register_write %s 0 %s", s["register"], s["old"]))
		},
	})
}

func native(s Substrate) []Requirement {
	return []Requirement{{Substrate: s, Mode: SupportNative}}
}

func p4Device(e *Env, t Target) (*model.Device, error) {
	d, err := e.Device(t)
	if err != nil {
		return nil, err
	}
	if d.Kind != model.KindP4 || d.P4 == nil {
		return nil, fmt.Errorf("%s is not a typed P4/BMv2 device", d.ID)
	}
	return d, nil
}

func p4CLI(ctx context.Context, e *Env, t Target, line string) error {
	_, err := p4CLIOutput(ctx, e, t, line)
	return err
}

func p4CLIOutput(ctx context.Context, e *Env, t Target, line string) (string, error) {
	d, err := p4Device(e, t)
	if err != nil {
		return "", err
	}
	return e.Sh(ctx, t.DeviceID(), fmt.Sprintf("printf '%%s\\n' %s | simple_switch_CLI --thrift-port %d",
		shellQuote(line), d.P4.ThriftPort))
}

func p4Dump(ctx context.Context, e *Env, t Target, d *model.Device) (string, error) {
	return p4CLIOutput(ctx, e, t, "table_dump "+d.P4.Table)
}

type p4Entry struct {
	Match  string
	Action string
	Params []string
}

func p4BaselineEntry(ctx context.Context, e *Env, t Target, d *model.Device) (p4Entry, string, error) {
	if len(d.P4.Entries) == 0 {
		return p4Entry{}, "", fmt.Errorf("P4 device %s declares no baseline table entries", d.ID)
	}
	out, err := p4Dump(ctx, e, t, d)
	if err != nil {
		return p4Entry{}, "", err
	}
	handle := firstP4Handle(out)
	if handle == "" {
		return p4Entry{}, "", fmt.Errorf("BMv2 table %s has no entry handle", d.P4.Table)
	}
	authored := d.P4.Entries[0]
	action := authored.Action
	if action == "" {
		action = d.P4.ForwardAction
	}
	return p4Entry{Match: authored.Match, Action: action, Params: append([]string(nil), authored.Params...)}, handle, nil
}

var (
	p4HandleRE     = regexp.MustCompile(`(?mi)(?:entry[[:space:]]+)?handle\s*:?\s*([0-9]+)`)
	p4DumpHandleRE = regexp.MustCompile(`(?mi)dumping[[:space:]]+entry[[:space:]]+0x([0-9a-f]+)`)
)

func firstP4Handle(out string) string {
	m := p4HandleRE.FindStringSubmatch(out)
	if len(m) == 2 {
		return m[1]
	}
	m = p4DumpHandleRE.FindStringSubmatch(out)
	if len(m) == 2 {
		value, err := strconv.ParseInt(m[1], 16, 64)
		if err == nil {
			return strconv.FormatInt(value, 10)
		}
	}
	return ""
}

func p4EntryState(_ *model.Device, entry p4Entry, handle string) State {
	return State{
		"handle": handle, "match": entry.Match, "action": entry.Action,
		"params": strings.Join(entry.Params, "\x1f"),
	}
}

func stateP4Entry(s State) p4Entry {
	return p4Entry{Match: s["match"], Action: s["action"], Params: splitP4Params(s["params"])}
}

func splitP4Params(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x1f")
}

func p4AddEntry(ctx context.Context, e *Env, t Target, d *model.Device, entry p4Entry) error {
	line := fmt.Sprintf("table_add %s %s %s", d.P4.Table, entry.Action, entry.Match)
	if len(entry.Params) > 0 {
		line += " => " + strings.Join(entry.Params, " ")
	}
	return p4CLI(ctx, e, t, line)
}

func p4TablePrecondition(ctx context.Context, e *Env, t Target) (string, error) {
	d, err := p4Device(e, t)
	if err != nil {
		return "", err
	}
	if _, _, err := p4BaselineEntry(ctx, e, t, d); err != nil {
		return err.Error(), nil
	}
	if err := p4Probe(ctx, e, t); err != nil {
		return "the declared P4 forwarding probe is not healthy: " + err.Error(), nil
	}
	return "", nil
}

func p4MissingVerify(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
	d, err := p4Device(e, t)
	if err != nil {
		return Evidence{}, err
	}
	out, err := p4Dump(ctx, e, t, d)
	if err != nil {
		return Evidence{}, err
	}
	removed := !p4DumpContainsHandle(out, s["handle"])
	probeErr := p4Probe(ctx, e, t)
	broken := probeErr != nil
	if !e.wantSymptom {
		removed = false
		broken = probeErr != nil
	}

	return Evidence{
		Verified: removed && broken,
		Observed: fmt.Sprintf("entry handle %s present=%t; forwarding probe=%s",
			s["handle"], !removed, probeResult(probeErr)),
		Expected: "the forwarding entry removed and the declared path unavailable",
	}, nil
}

func p4DumpContainsHandle(out, handle string) bool {
	for _, match := range p4DumpHandleRE.FindAllStringSubmatch(out, -1) {
		if len(match) != 2 {
			continue
		}
		value, err := strconv.ParseInt(match[1], 16, 64)
		if err == nil && strconv.FormatInt(value, 10) == handle {
			return true
		}
	}
	return strings.Contains(out, "handle "+handle) || strings.Contains(out, "Entry handle: "+handle)
}

func p4Probe(ctx context.Context, e *Env, t Target) error {
	d, err := p4Device(e, t)
	if err != nil {
		return err
	}
	if d.P4.ProbeSource == "" || d.P4.ProbeDestination == "" {
		return fmt.Errorf("P4 contract has no probe_source/probe_destination")
	}
	source, ok := e.Topology.Device(d.P4.ProbeSource)
	if !ok {
		return fmt.Errorf("P4 probe source %q is absent", d.P4.ProbeSource)
	}
	destination, ok := e.Topology.Device(d.P4.ProbeDestination)
	if !ok {
		return fmt.Errorf("P4 probe destination %q is absent", d.P4.ProbeDestination)
	}
	addr := firstDeviceAddress(destination)
	if addr == "" {
		return fmt.Errorf("P4 probe destination %s has no IPv4 address", destination.ID)
	}
	_, code, err := e.TryE(ctx, source.ID, "ping -n -c 2 -W 1 "+addr)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("ping from %s to %s failed", source.ID, addr)
	}
	return nil
}

func firstDeviceAddress(d *model.Device) string {
	if d == nil {
		return ""
	}
	for _, i := range d.Ifaces {
		if i.Name != "lo" && i.Addr4 != "" {
			return strings.Split(i.Addr4, "/")[0]
		}
	}
	for _, i := range d.Ifaces {
		if i.Addr4 != "" {
			return strings.Split(i.Addr4, "/")[0]
		}
	}
	return ""
}

func probeResult(err error) string {
	if err == nil {
		return "success"
	}
	return "failed (" + err.Error() + ")"
}

func registerP4CompileFault(name, invalid, describe string) {
	Register(&Fault{
		Name: name, Category: CatNodeError,
		Needs: []Capability{CapP4, CapExec, CapLifecycle}, Requires: native(SubstrateP4BMv2),
		Symptom:  "A programmable switch stops forwarding after a pipeline update is rejected.",
		Describe: describe,
		Precondition: func(ctx context.Context, e *Env, t Target) (string, error) {
			if _, err := p4Device(e, t); err != nil {
				return "", err
			}
			if err := p4Probe(ctx, e, t); err != nil {
				return "the declared P4 forwarding probe is not healthy: " + err.Error(), nil
			}
			return "", nil
		},
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			d, err := p4Device(e, t)
			if err != nil {
				return nil, err
			}
			script := strings.Join([]string{
				"set -eu",
				"cat > /dev/shm/.pipeline.p4 <<'P4'",
				invalid,
				"P4",
				"if p4c-bm2-ss --std p4-16 -o /dev/shm/.pipeline.json /dev/shm/.pipeline.p4 >/dev/null 2>&1; then",
				"  echo 'invalid P4 source unexpectedly compiled' >&2; exit 1",
				"fi",
				"rm -f /dev/shm/.pipeline.p4 /dev/shm/.pipeline.json",
				"for p in $(pidof simple_switch 2>/dev/null || true); do kill \"$p\" 2>/dev/null || true; done",
			}, "\n")
			if _, err := e.Sh(ctx, t.DeviceID(), script); err != nil {
				return nil, err
			}
			return State{"port": strconv.Itoa(d.P4.ThriftPort), "invalid": invalid}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, _ State) (Evidence, error) {
			out, code, err := e.TryE(ctx, t.DeviceID(), "pidof simple_switch")
			if err != nil {
				return Evidence{}, err
			}
			stopped := code != 0 || strings.TrimSpace(out) == ""
			probeErr := p4Probe(ctx, e, t)
			return Evidence{
				Verified: stopped && probeErr != nil,
				Observed: fmt.Sprintf("simple_switch stopped=%t; forwarding probe=%s", stopped, probeResult(probeErr)),
				Expected: "a rejected P4 compile and no forwarding data plane",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, _ State) error {
			d, err := p4Device(e, t)
			if err != nil {
				return err
			}
			return p4Restart(ctx, e, t, d)
		},
	})
}

func p4Restart(ctx context.Context, e *Env, t Target, d *model.Device) error {
	var ports []string
	port := 1
	for _, i := range d.Ifaces {
		if i.Link == nil || i.Role == model.RoleOpenFlowControl {
			continue
		}
		ports = append(ports, fmt.Sprintf("-i %d@%s", port, i.Name))
		port++
	}
	if len(ports) == 0 {
		return fmt.Errorf("P4 device %s has no data-plane ports to restart", d.ID)
	}
	source := p4RuntimeDir() + "/program" + strings.ToLower(pathExt(d.P4.ProgramPath))
	jsonPath := p4RuntimeDir() + "/program.json"
	compile := "cp " + source + " " + jsonPath
	if strings.HasSuffix(source, ".p4") {
		compile = fmt.Sprintf("p4c-bm2-ss --std p4-16 -o %s %s", jsonPath, source)
	}
	lines := []string{
		"set -eu", compile,
		fmt.Sprintf("nohup simple_switch --log-console %s --thrift-port %d --device-id 0 %s >/var/log/p4-switch.log 2>&1 &",
			strings.Join(ports, " "), d.P4.ThriftPort, jsonPath),
		fmt.Sprintf("ready=0; for i in $(seq 1 30); do if printf 'show_tables\\n' | simple_switch_CLI --thrift-port %d >/dev/null 2>&1; then ready=1; break; fi; sleep 1; done; [ \"$ready\" = 1 ]", d.P4.ThriftPort),
	}
	for _, entry := range d.P4.Entries {
		action := entry.Action
		if action == "" {
			action = d.P4.ForwardAction
		}
		line := fmt.Sprintf("table_add %s %s %s", d.P4.Table, action, entry.Match)
		if len(entry.Params) > 0 {
			line += " => " + strings.Join(entry.Params, " ")
		}
		lines = append(lines, fmt.Sprintf("printf '%%s\\n' %s | simple_switch_CLI --thrift-port %d",
			shellQuote(line), d.P4.ThriftPort))
	}
	indices := make([]int, 0, len(d.P4.RegisterValues))
	for index := range d.P4.RegisterValues {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	for _, index := range indices {
		value := d.P4.RegisterValues[index]
		lines = append(lines, fmt.Sprintf(
			"printf 'register_write %s %d %d\\n' | simple_switch_CLI --thrift-port %d",
			d.P4.ThresholdRegister, index, value, d.P4.ThriftPort))
	}
	_, err := e.Sh(ctx, t.DeviceID(), strings.Join(lines, "\n"))
	return err
}

func pathExt(path string) string {
	i := strings.LastIndex(path, ".")
	if i < 0 {
		return ""
	}
	return path[i:]
}

func p4RuntimeDir() string { return "/etc/" + "twinet" + "/p4" }

func registerOpenFlowFaults() {
	Register(&Fault{
		Name: "sdn_controller_crash", Category: CatNodeError,
		Needs: []Capability{CapOpenFlow, CapLifecycle, CapOVS}, Requires: native(SubstrateOpenFlow),
		Symptom:  "An SDN fabric stops forwarding after its controller disappears, while switch ports still show up.",
		Describe: "The OpenFlow controller was paused; secure OVS switches lose their southbound session and their controller-installed flows expire.",
		Precondition: func(ctx context.Context, e *Env, t Target) (string, error) {
			d, err := openFlowController(e, t)
			if err != nil {
				return "", err
			}
			state, err := e.State(ctx, d.ID)
			if err != nil {
				return "", err
			}
			if state != "running" {
				return "controller is " + state, nil
			}
			if len(openFlowSwitches(e.Topology, d.ID)) == 0 {
				return "controller owns no OVS switches", nil
			}
			return "", nil
		},
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			if err := e.Do(ctx, t.DeviceID(), "pause"); err != nil {
				return nil, err
			}
			return State{"action": "pause"}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, _ State) (Evidence, error) {
			state, err := e.State(ctx, t.DeviceID())
			if err != nil {
				return Evidence{}, err
			}
			sw := openFlowSwitches(e.Topology, t.DeviceID())
			disconnected, observed, err := openFlowDisconnected(ctx, e, sw)
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{
				Verified: state == "paused" && disconnected,
				Observed: fmt.Sprintf("controller=%s; %s", state, observed),
				Expected: "a paused controller and an operationally disconnected OVS southbound session",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, _ State) error {
			return e.Do(ctx, t.DeviceID(), "unpause")
		},
	})

	Register(&Fault{
		Name: "southbound_port_block", Category: CatNodeError,
		Needs: []Capability{CapOpenFlow, CapNFT, CapOVS}, Requires: native(SubstrateOpenFlow),
		Symptom:  "A switch remains up but loses its controller connection and no longer receives updated forwarding rules.",
		Describe: "The controller's declared OpenFlow TCP port was firewalled, then the switch's observed southbound state was checked.",
		Precondition: func(ctx context.Context, e *Env, t Target) (string, error) {
			d, err := openFlowController(e, t)
			if err != nil {
				return "", err
			}
			port := d.OpenFlow.Port
			if countACL(ctx, e, t, "INPUT", fmt.Sprintf("-p tcp --dport %d", port)) > 0 {
				return fmt.Sprintf("controller port %d already has an INPUT ACL", port), nil
			}
			return "", nil
		},
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			d, err := openFlowController(e, t)
			if err != nil {
				return nil, err
			}
			port := d.OpenFlow.Port
			if _, err := e.Sh(ctx, d.ID,
				fmt.Sprintf("iptables -w -A INPUT -p tcp --dport %d -j DROP", port)); err != nil {
				return nil, err
			}
			state := State{"port": strconv.Itoa(port)}
			// A firewall rule does not retroactively close an established TCP
			// session. Reconnecting each OVS controller client through the
			// newly blocked port is the operational transition this fault
			// claims, and records the exact endpoint for resolve.
			for index, sw := range openFlowSwitches(e.Topology, d.ID) {
				endpoint, err := e.Sh(ctx, sw.ID, "ovs-vsctl get-controller br0")
				if err != nil {
					_, _ = e.Sh(ctx, d.ID,
						fmt.Sprintf("iptables -w -D INPUT -p tcp --dport %d -j DROP", port))
					return state, err
				}
				endpoint = strings.Trim(strings.TrimSpace(endpoint), "\"")
				if endpoint == "" {
					_, _ = e.Sh(ctx, d.ID,
						fmt.Sprintf("iptables -w -D INPUT -p tcp --dport %d -j DROP", port))
					return state, fmt.Errorf("%s has no OpenFlow controller endpoint", sw.ID)
				}
				if _, err := e.Sh(ctx, sw.ID, "ovs-vsctl del-controller br0 && ovs-vsctl set-controller br0 "+shellQuote(endpoint)); err != nil {
					_, _ = e.Sh(ctx, d.ID,
						fmt.Sprintf("iptables -w -D INPUT -p tcp --dport %d -j DROP", port))
					return state, err
				}
				state[fmt.Sprintf("switch%d", index)] = sw.ID
				state[fmt.Sprintf("endpoint%d", index)] = endpoint
			}
			return state, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, _ State) (Evidence, error) {
			sw := openFlowSwitches(e.Topology, t.DeviceID())
			down, observed, err := openFlowDisconnected(ctx, e, sw)
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{Verified: down, Observed: observed,
				Expected: "all managed OVS switches report is_connected=false"}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			_, err := e.Sh(ctx, t.DeviceID(),
				fmt.Sprintf("iptables -w -D INPUT -p tcp --dport %s -j DROP", s["port"]))
			if err != nil {
				return err
			}
			for index := 0; ; index++ {
				switchID, ok := s[fmt.Sprintf("switch%d", index)]
				if !ok {
					break
				}
				endpoint := s[fmt.Sprintf("endpoint%d", index)]
				if endpoint == "" {
					continue
				}
				if _, err := e.Sh(ctx, switchID,
					"ovs-vsctl set-controller br0 "+shellQuote(endpoint)); err != nil {
					return err
				}
			}
			return nil
		},
	})

	Register(&Fault{
		Name: "southbound_port_mismatch", Category: CatNodeError,
		Needs: []Capability{CapOpenFlow, CapOVS}, Requires: native(SubstrateOpenFlow),
		Symptom:  "A controller and switch are healthy on their own, but their southbound session never establishes.",
		Describe: "The OVS controller endpoint was changed to a wrong TCP port and verified through its observed is_connected state.",
		Precondition: func(ctx context.Context, e *Env, t Target) (string, error) {
			d, err := openFlowSwitch(e, t)
			if err != nil {
				return "", err
			}
			if d.OpenFlowController == "" {
				return "switch has no declared controller", nil
			}
			return "", nil
		},
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			d, err := openFlowSwitch(e, t)
			if err != nil {
				return nil, err
			}
			original, err := e.Sh(ctx, d.ID, "ovs-vsctl get-controller br0")
			if err != nil {
				return nil, err
			}
			original = strings.Trim(strings.TrimSpace(original), "\"")
			host, port, ok := strings.Cut(strings.TrimPrefix(original, "tcp:"), ":")
			if !ok || host == "" {
				return nil, fmt.Errorf("OVS returned non-TCP controller endpoint %q", original)
			}
			current, err := strconv.Atoi(port)
			if err != nil {
				return nil, err
			}
			wrong := current + 1
			if configured := t.Param("port", ""); configured != "" {
				wrong, err = strconv.Atoi(configured)
				if err != nil {
					return nil, fmt.Errorf("port must be an integer")
				}
			}
			if wrong == current || wrong < 1 || wrong > 65535 {
				return nil, fmt.Errorf("wrong controller port %d is invalid or unchanged", wrong)
			}
			if _, err := e.Sh(ctx, d.ID, fmt.Sprintf("ovs-vsctl set-controller br0 tcp:%s:%d", host, wrong)); err != nil {
				return nil, err
			}
			return State{"original": original, "wrong": strconv.Itoa(wrong)}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, _ State) (Evidence, error) {
			down, observed, err := openFlowDisconnected(ctx, e, []*model.Device{mustOpenFlowSwitch(e, t)})
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{Verified: down, Observed: observed,
				Expected: "OVS reports the configured controller disconnected"}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["original"] == "" {
				return fmt.Errorf("no original controller endpoint was captured")
			}
			_, err := e.Sh(ctx, t.DeviceID(), "ovs-vsctl set-controller br0 "+shellQuote(s["original"]))
			return err
		},
	})
}

func openFlowController(e *Env, t Target) (*model.Device, error) {
	d, err := e.Device(t)
	if err != nil {
		return nil, err
	}
	if d.Kind != model.KindController || d.OpenFlow == nil {
		return nil, fmt.Errorf("%s is not a typed OpenFlow controller", d.ID)
	}
	return d, nil
}

func openFlowSwitch(e *Env, t Target) (*model.Device, error) {
	d, err := e.Device(t)
	if err != nil {
		return nil, err
	}
	if d.Kind != model.KindSwitch || d.OpenFlowController == "" {
		return nil, fmt.Errorf("%s is not an OVS switch with a declared OpenFlow controller", d.ID)
	}
	return d, nil
}

func mustOpenFlowSwitch(e *Env, t Target) *model.Device {
	d, _ := openFlowSwitch(e, t)
	return d
}

func openFlowSwitches(top *model.Topology, controllerID string) []*model.Device {
	var out []*model.Device
	if top == nil {
		return out
	}
	for _, d := range top.Devices {
		if d.Kind == model.KindSwitch && d.OpenFlowController == controllerID {
			out = append(out, d)
		}
	}
	return out
}

func openFlowDisconnected(ctx context.Context, e *Env, switches []*model.Device) (bool, string, error) {
	if len(switches) == 0 {
		return false, "no managed switches", fmt.Errorf("no managed switches")
	}
	var observed string
	out, err := e.Settled(ctx, 30*time.Second,
		func(ctx context.Context) (string, error) {
			var rows []string
			for _, sw := range switches {
				value, code, err := e.TryE(ctx, sw.ID, "ovs-vsctl get Controller br0 is_connected")
				if err != nil {
					return "", err
				}
				connected := code == 0 && strings.TrimSpace(strings.Trim(value, "\"")) == "true"
				rows = append(rows, fmt.Sprintf("%s connected=%t", sw.ID, connected))
			}
			return strings.Join(rows, "; "), nil
		},
		func(value string) bool {
			observed = value
			return !strings.Contains(value, "connected=true")
		})
	if err != nil {
		return false, observed, err
	}
	if observed == "" {
		observed = out
	}
	return !strings.Contains(out, "connected=true"), observed, nil
}

func registerLoadBalancerFault() {
	Register(&Fault{
		Name: "load_balancer_overload", Category: CatContention,
		Needs:    []Capability{CapLoadBalancer, CapTraffic, CapProcess, CapService},
		Requires: native(SubstrateLoadBalancer),
		Symptom:  "Requests to one service begin receiving measured overload responses while its backends remain configured.",
		Describe: "The declared deterministic traffic generator saturates the load balancer's enforced in-flight limit; metrics record the rejected requests.",
		Precondition: func(ctx context.Context, e *Env, t Target) (string, error) {
			lb, err := loadBalancerDevice(e, t)
			if err != nil {
				return "", err
			}
			if _, err := trafficGeneratorDevice(e.Topology); err != nil {
				return err.Error(), nil
			}
			if _, _, err := e.TryE(ctx, lb.ID, "curl -fsS http://127.0.0.1:8080/metrics"); err != nil {
				return "", err
			}
			return "", nil
		},
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			lb, err := loadBalancerDevice(e, t)
			if err != nil {
				return nil, err
			}
			gen, err := trafficGeneratorDevice(e.Topology)
			if err != nil {
				return nil, err
			}
			before, err := metricsAt(ctx, e, lb.ID)
			if err != nil {
				return nil, err
			}
			out, err := e.Sh(ctx, gen.ID,
				"nohup twinet-traffic run --profile "+trafficProfilePath()+" --metrics /run/traffic-metrics.json --loop >/dev/null 2>&1 & echo $!")
			if err != nil {
				return nil, err
			}
			pid := strings.TrimSpace(out)
			if pid == "" {
				return nil, fmt.Errorf("traffic generator did not report a PID")
			}
			return State{"generator": gen.ID, "pid": pid, "baseline_rejected": strconv.FormatInt(before.Rejected, 10)}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			lb, err := loadBalancerDevice(e, t)
			if err != nil {
				return Evidence{}, err
			}
			alive, err := countAlive(ctx, e, Target{Device: s["generator"]}, s["pid"])
			if err != nil {
				return Evidence{}, err
			}
			now, err := metricsAt(ctx, e, lb.ID)
			if err != nil {
				return Evidence{}, err
			}
			before, _ := strconv.ParseInt(s["baseline_rejected"], 10, 64)
			if !e.wantSymptom {
				_, healthy, err := e.TryE(ctx, lb.ID, "curl -fsS http://127.0.0.1:8080/metrics")
				if err != nil {
					return Evidence{}, err
				}
				return Evidence{
					// Verify always answers whether the fault remains
					// present. During resolve, a stopped generator and a
					// healthy metrics endpoint are evidence of recovery, not
					// a successful still-live overload.
					Verified: alive > 0 || healthy != 0,
					Observed: fmt.Sprintf("generator processes=%d; load balancer metrics remain reachable", alive),
					Expected: "generator stopped and service accepts metrics requests",
				}, nil
			}
			return Evidence{
				Verified: alive > 0 && now.Rejected > before,
				Observed: fmt.Sprintf("generator processes=%d; rejected requests=%d (baseline %d); active=%d",
					alive, now.Rejected, before, now.Active),
				Expected: "a measured increase in load-balancer overload rejections",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, _ Target, s State) error {
			if s["generator"] == "" || s["pid"] == "" {
				return fmt.Errorf("traffic generator process was not recorded")
			}
			return killPIDs(ctx, e, Target{Device: s["generator"]}, s["pid"])
		},
	})
}

func loadBalancerDevice(e *Env, t Target) (*model.Device, error) {
	d, err := e.Device(t)
	if err != nil {
		return nil, err
	}
	if d.Kind != model.KindService || d.ServiceKind != "builtin.load-balancer" {
		return nil, fmt.Errorf("%s is not a typed builtin.load-balancer service", d.ID)
	}
	return d, nil
}

func trafficGeneratorDevice(top *model.Topology) (*model.Device, error) {
	if top == nil {
		return nil, fmt.Errorf("no topology is available")
	}
	for _, d := range top.SortedDevices() {
		if d.Kind == model.KindService && d.ServiceKind == "builtin.traffic-generator" {
			return d, nil
		}
	}
	return nil, fmt.Errorf("no builtin.traffic-generator service is declared")
}

type loadMetrics struct {
	Rejected int64 `json:"rejected"`
	Active   int64 `json:"active"`
}

func metricsAt(ctx context.Context, e *Env, deviceID string) (loadMetrics, error) {
	out, code, err := e.TryE(ctx, deviceID, "curl -fsS http://127.0.0.1:8080/metrics")
	if err != nil {
		return loadMetrics{}, err
	}
	if code != 0 {
		return loadMetrics{}, fmt.Errorf("load-balancer metrics exited %d: %s", code, firstLine(out))
	}
	var m loadMetrics
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return loadMetrics{}, fmt.Errorf("parse load-balancer metrics: %w", err)
	}
	return m, nil
}

func registerMPLSLabelFault() {
	Register(&Fault{
		Name: "mpls_label_limit_exceeded", Category: CatNodeError,
		Needs: []Capability{CapLabelSpace, CapFRR}, Requires: native(SubstrateMPLSLabels),
		Symptom:  "An MPLS router can no longer allocate labels, so label control-plane recovery and labelled forwarding fail.",
		Describe: "The fenced node-side allocator reserved the router namespace's platform label space until a probe allocation returned ENOSPC.",
		Precondition: func(ctx context.Context, e *Env, t Target) (string, error) {
			if _, err := mplsRouter(e, t); err != nil {
				return "", err
			}
			if e.LabelSpace == nil {
				return "no privileged label-space allocator is configured", nil
			}
			snapshot, err := e.LabelSpace(ctx, t.DeviceID(), LabelSpaceRequest{Action: "snapshot"})
			if err != nil {
				return "", err
			}
			if snapshot.Exhausted {
				return "the label allocator is already exhausted", nil
			}
			return "", nil
		},
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			before, err := e.LabelSpace(ctx, t.DeviceID(), LabelSpaceRequest{Action: "snapshot"})
			if err != nil {
				return nil, err
			}
			limit := mustAtoi(t.Param("limit", "0"))
			if limit <= before.Allocated+1 {
				limit = before.Allocated + 32
			}
			result, err := e.LabelSpace(ctx, t.DeviceID(), LabelSpaceRequest{Action: "exhaust", Limit: limit})
			if err != nil {
				return nil, err
			}
			if !result.Exhausted {
				return nil, fmt.Errorf("label allocator did not report exhaustion: %s", result.Detail)
			}
			// Clearing LDP makes it request fresh labels against the exhausted
			// kernel table. This is the actual control-plane consequence, not
			// an ineffective FRR global-block configuration.
			if _, _, err := e.TryE(ctx, t.DeviceID(), "vtysh -c 'clear mpls ldp neighbor *'"); err != nil {
				return nil, err
			}
			labels := make([]string, len(result.Labels))
			for i, label := range result.Labels {
				labels[i] = strconv.Itoa(label)
			}
			return State{
				"original_limit": strconv.Itoa(before.Limit), "limit": strconv.Itoa(result.Limit),
				"labels": strings.Join(labels, ","), "allocated_before": strconv.Itoa(before.Allocated),
			}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, _ State) (Evidence, error) {
			result, err := e.LabelSpace(ctx, t.DeviceID(), LabelSpaceRequest{Action: "probe"})
			if err != nil {
				return Evidence{}, err
			}
			control, controlCode, err := e.TryE(ctx, t.DeviceID(), "vtysh -c 'show mpls table'")
			if err != nil {
				return Evidence{}, err
			}
			forwarding, forwardingCode, err := e.TryE(ctx, t.DeviceID(), "ip -f mpls route show")
			if err != nil {
				return Evidence{}, err
			}
			// A successful label allocation is definitive negative evidence;
			// the LDP table and the kernel MPLS route table are retained as
			// the control-plane and forwarding-plane observations. A newly
			// booted router can have no LDP neighbour yet, but its exhausted
			// kernel allocator is still a real forwarding substrate symptom.
			return Evidence{
				Verified: result.Exhausted && (controlCode == 0 || forwardingCode == 0),
				Observed: fmt.Sprintf("allocation probe exhausted=%t; control-plane(%d): %s; forwarding-plane(%d): %s",
					result.Exhausted, controlCode, firstLine(control), forwardingCode, firstLine(forwarding)),
				Expected: "ENOSPC from the platform label allocator plus observable MPLS control-plane or forwarding-plane state",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			labels := []int{}
			for _, raw := range strings.Split(s["labels"], ",") {
				if raw == "" {
					continue
				}
				label, err := strconv.Atoi(raw)
				if err != nil {
					return fmt.Errorf("invalid saved MPLS label %q", raw)
				}
				labels = append(labels, label)
			}
			limit, err := strconv.Atoi(s["original_limit"])
			if err != nil {
				return fmt.Errorf("invalid original MPLS label limit %q", s["original_limit"])
			}
			if _, err := e.LabelSpace(ctx, t.DeviceID(),
				LabelSpaceRequest{Action: "restore", Limit: limit, Labels: labels}); err != nil {
				return err
			}
			_, _, err = e.TryE(ctx, t.DeviceID(), "vtysh -c 'clear mpls ldp neighbor *'")
			return err
		},
		Baseline: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			wantLimit, err := strconv.Atoi(s["original_limit"])
			if err != nil {
				return Evidence{}, fmt.Errorf("invalid original MPLS label limit %q", s["original_limit"])
			}
			wantAllocated, err := strconv.Atoi(s["allocated_before"])
			if err != nil {
				return Evidence{}, fmt.Errorf("invalid original MPLS allocation count %q", s["allocated_before"])
			}
			owned := map[int]bool{}
			for _, raw := range strings.Split(s["labels"], ",") {
				if raw == "" {
					continue
				}
				label, err := strconv.Atoi(raw)
				if err != nil {
					return Evidence{}, fmt.Errorf("invalid saved MPLS label %q", raw)
				}
				owned[label] = true
			}
			var last LabelSpaceResult
			_, err = e.Settled(ctx, SymptomWindow,
				func(ctx context.Context) (string, error) {
					snapshot, err := e.LabelSpace(ctx, t.DeviceID(), LabelSpaceRequest{Action: "snapshot"})
					if err != nil {
						return "", err
					}
					last = snapshot
					return mplsFingerprint(snapshot), nil
				},
				func(_ string) bool { return !mplsBaselineClean(last, wantLimit, wantAllocated, owned) })
			if err != nil {
				return Evidence{}, err
			}
			clean := mplsBaselineClean(last, wantLimit, wantAllocated, owned)
			return Evidence{
				Verified: clean,
				Observed: mplsFingerprint(last),
				Expected: fmt.Sprintf("label limit %d and %d baseline allocations", wantLimit, wantAllocated),
			}, nil
		},
	})
}

func mplsFingerprint(s LabelSpaceResult) string {
	return fmt.Sprintf("limit=%d allocated=%d labels=%v", s.Limit, s.Allocated, s.Labels)
}

func mplsBaselineClean(s LabelSpaceResult, limit, allocated int, owned map[int]bool) bool {
	if s.Limit != limit || s.Allocated != allocated {
		return false
	}
	for _, label := range s.Labels {
		if owned[label] {
			return false
		}
	}
	return true
}

func mplsRouter(e *Env, t Target) (*model.Device, error) {
	d, err := e.Device(t)
	if err != nil {
		return nil, err
	}
	if d.Kind != model.KindRouter || e.Topology.ASes[d.ASN] == nil || !e.Topology.ASes[d.ASN].MPLS.Enabled {
		return nil, fmt.Errorf("%s is not an MPLS-enabled router", d.ID)
	}
	return d, nil
}

func registerKubernetesFaults() {
	for _, spec := range []struct {
		name     string
		category Category
		symptom  string
		describe string
	}{
		{"k8s_clusterip_routing_broken", CatNodeError,
			"A Kubernetes service address stops reaching its ready endpoints.",
			"Kubernetes ClusterIP routing is broken in the delegated NIKA backend."},
		{"k8s_coredns_isolated", CatMisconfig,
			"Pods cannot resolve service names while their application network otherwise remains available.",
			"CoreDNS is isolated in the delegated NIKA Kubernetes backend."},
		{"k8s_networkpolicy_deny", CatMisconfig,
			"A previously permitted pod-to-pod path is denied by policy.",
			"A Kubernetes NetworkPolicy deny rule is active in the delegated NIKA backend."},
		{"k8s_worker_apiserver_partition", CatMisconfig,
			"One worker loses contact with the Kubernetes API server and its workloads become stale.",
			"A worker-to-API-server partition is active in the delegated NIKA backend."},
	} {
		registerKubernetesFault(spec.name, spec.category, spec.symptom, spec.describe)
	}
}

func registerKubernetesFault(name string, category Category, symptom, describe string) {
	Register(&Fault{
		Name: name, Category: category, Symptom: symptom, Describe: describe,
		Needs:     []Capability{CapKubernetes},
		Requires:  []Requirement{{Substrate: SubstrateKubernetes, Mode: SupportDelegated}},
		Delegated: true,
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			if e.Kubernetes == nil {
				return nil, fmt.Errorf("no NIKA Kubernetes backend is configured")
			}
			state, evidence, err := e.Kubernetes.Inject(ctx, name, t)
			if err != nil {
				return state, err
			}
			// Inject's generic lifecycle will call Verify. Persisting the
			// backend's immediate measurement gives a useful audit trail even
			// when a later poll sees a transiently different state.
			if state == nil {
				state = State{}
			}
			state["__delegated_initial_observed"] = evidence.Observed
			return state, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			if e.Kubernetes == nil {
				return Evidence{}, fmt.Errorf("no NIKA Kubernetes backend is configured")
			}
			return e.Kubernetes.Verify(ctx, name, t, s)
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if e.Kubernetes == nil {
				return fmt.Errorf("no NIKA Kubernetes backend is configured")
			}
			return e.Kubernetes.Resolve(ctx, name, t, s)
		},
	})
}

func lastInteger(s string) int {
	re := regexp.MustCompile(`-?[0-9]+`)
	values := re.FindAllString(s, -1)
	if len(values) == 0 {
		return -1
	}
	v, err := strconv.Atoi(values[len(values)-1])
	if err != nil {
		return -1
	}
	return v
}

func mustAtoi(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

func trafficProfilePath() string { return "/etc/" + "twinet" + "/traffic-profile.json" }
