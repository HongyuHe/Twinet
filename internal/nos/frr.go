package nos

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

const (
	frrConfigPath  = "/etc/frr/frr.conf"
	frrDaemonsPath = "/etc/frr/daemons"
	frrRestorePath = "/etc/twinet/restore-frr.conf"
)

type frrProvider struct{}

func init() { Register(frrProvider{}) }

func (frrProvider) Name() string { return model.DefaultNOS }

func (frrProvider) StateKind() state.Kind { return state.KindFRR }

func (frrProvider) Capabilities() Capabilities {
	return NewCapabilities(
		FeatureIPv4, FeatureIPv6, FeatureForwarding, FeatureOSPF, FeatureBGP, FeaturePolicy,
		FeatureCommunity, FeatureRPKI, FeatureVLAN, FeatureTunnels,
		FeatureMPLS, FeatureLDP, FeatureVRF, FeatureMulticast, FeatureDHCP,
	)
}

func (frrProvider) Render(request RenderRequest) (Rendered, error) {
	if request.Device == nil {
		return Rendered{}, fmt.Errorf("render FRR for nil device")
	}
	body := request.Platform
	if request.Mode == ModeSolve {
		body += request.Expected
	}
	if request.Daemons == "" {
		return Rendered{}, fmt.Errorf("render FRR for %s: no daemon declaration", request.Device.ID)
	}
	return Rendered{Files: map[string]FileSpec{
		frrDaemonsPath: {Content: []byte(request.Daemons), Mode: 0o640},
		frrConfigPath:  {Content: []byte(body), Mode: 0o640},
	}}, nil
}

// Apply returns only vendor-specific lifecycle work. The common renderer
// supplies kernel and service commands separately.
func (frrProvider) Apply(request RenderRequest) ([]Command, error) {
	if request.Device == nil {
		return nil, fmt.Errorf("apply FRR for nil device")
	}
	return []Command{{
		Describe: "start FRR",
		Args:     []string{"sh", "-c", "/usr/lib/frr/frrinit.sh start || /etc/init.d/frr start"},
	}}, nil
}

func (frrProvider) Ready(d *model.Device, rt runtime.Runtime) *plan.Waiter {
	if d == nil {
		return nil
	}
	return &plan.Waiter{
		Describe:  "FRR on " + d.ID + " to answer",
		Interval:  200 * time.Millisecond,
		Timeout:   90 * time.Second,
		StableFor: 2,
		Check: func(ctx context.Context) (bool, error) {
			res, err := rt.Exec(ctx, d.Container, runtime.ExecCmd{Cmd: []string{"vtysh", "-c", "show version"}})
			if err != nil {
				return false, err
			}
			if res.ExitCode != 0 {
				return false, fmt.Errorf("vtysh exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
			}
			return true, nil
		},
	}
}

func (frrProvider) ReadState(ctx context.Context, d *model.Device, exec netstate.Executor, query netstate.Query) (netstate.State, error) {
	out, err := netstate.ReadKernel(ctx, d, exec, query&(netstate.QueryInterfaces|netstate.QueryKernel))
	if err != nil {
		return netstate.State{}, err
	}
	if query.Has(netstate.QueryBGP) {
		bgp, err := readFRRBGP(ctx, d, exec, query)
		if err != nil {
			return netstate.State{}, err
		}
		out.BGP = bgp
	}
	if query.Has(netstate.QueryOSPF) {
		ospf, err := readFRROSPF(ctx, d, exec)
		if err != nil {
			return netstate.State{}, err
		}
		out.OSPF = ospf
	}
	if query.Has(netstate.QueryPolicy) {
		policy, err := readFRRPolicy(ctx, d, exec)
		if err != nil {
			return netstate.State{}, err
		}
		out.Policy = policy
	}
	out.Sort()
	return out, nil
}

func (frrProvider) Save(ctx context.Context, d *model.Device, exec netstate.Executor, lab, topology string) ([]state.Snapshot, error) {
	if d == nil {
		return nil, fmt.Errorf("save FRR for nil device")
	}
	res, err := exec.Exec(ctx, d.ID, []string{"vtysh", "-c", "show running-config"})
	body := ""
	if err == nil && res.ExitCode == 0 {
		body = cleanFRRConfig(res.Stdout)
	} else {
		fallback, fallbackErr := exec.Exec(ctx, d.ID, []string{"cat", frrConfigPath})
		if fallbackErr != nil || fallback.ExitCode != 0 {
			detail := ""
			if err != nil {
				detail = err.Error()
			} else {
				detail = fmt.Sprintf("vtysh exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
			}
			return nil, fmt.Errorf("save FRR configuration from %s: %s; fallback %s unavailable",
				d.ID, detail, frrConfigPath)
		}
		body = cleanFRRConfig(fallback.Stdout)
	}
	return []state.Snapshot{{
		Lab: lab, AS: d.ASN, Device: d.ID, Kind: state.KindFRR,
		Topology: topology, Content: []byte(body + "\n"),
	}}, nil
}

func (frrProvider) Restore(ctx context.Context, d *model.Device, rt runtime.Runtime, snap state.Snapshot) error {
	if snap.Kind != state.KindFRR {
		return fmt.Errorf("restore %s on FRR device %s", snap.Kind, d.ID)
	}
	if err := rt.CopyTo(ctx, d.Container, frrRestorePath, 0o600, snap.Content); err != nil {
		return fmt.Errorf("copy saved FRR configuration into %s: %w", d.ID, err)
	}
	res, err := rt.Exec(ctx, d.Container, runtime.ExecCmd{Cmd: []string{
		"sh", "-c", "vtysh -f " + frrRestorePath + "; rc=$?; rm -f " + frrRestorePath + "; exit $rc",
	}})
	if err != nil {
		return fmt.Errorf("restore FRR configuration on %s: %w", d.ID, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("restore FRR configuration on %s: vtysh exited %d: %s",
			d.ID, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

func (frrProvider) ConfigFile() ConfigFile {
	return ConfigFile{NOS: model.DefaultNOS, Path: frrConfigPath, Extension: ".conf", Kind: state.KindFRR}
}

// CaptureConfig reads the running configuration rather than the file on disk.
// A student configures through vtysh, so the file is whatever the last write
// left behind and the running configuration is the work.
func (frrProvider) CaptureConfig(ctx context.Context, d *model.Device, exec netstate.Executor) (string, error) {
	if d == nil {
		return "", fmt.Errorf("capture FRR configuration for nil device")
	}
	res, err := exec.Exec(ctx, d.ID, []string{"vtysh", "-c", "show running-config"})
	if err != nil {
		return "", fmt.Errorf("%s: its routing configuration could not be read: %w; "+
			"re-run once the device is reachable", d.ID, err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%s: its routing configuration could not be read: "+
			"vtysh exited %d: %s; re-run once the device is reachable",
			d.ID, res.ExitCode, firstLine(res.Stderr))
	}
	return cleanFRRConfig(res.Stdout), nil
}

// LoadConfig installs a submitted configuration and reloads FRR onto it.
//
// The obvious approach, feeding the file to "vtysh -f", does not work for a
// whole configuration: vtysh accepts commands, and a configuration file also
// contains directives such as "frr version" that exist only for the daemons'
// own startup parser. Feeding one in fails at that line, and the failure looks
// like a student error when it is the grader's.
//
// So the submission is installed exactly where a real deployment puts it and
// FRR's packaged exact-reload tool reconciles the running configuration to it.
// The router shell and its private FRR control sidecar share /etc/frr and the
// vty directory; stopping daemons from the unprivileged shell cannot work and
// removes the sidecar's sockets out from under otherwise healthy daemons.
func (frrProvider) LoadConfig(ctx context.Context, d *model.Device, exec netstate.Executor,
	body string, opts LoadOptions,
) error {
	if d == nil {
		return fmt.Errorf("load FRR configuration into nil device")
	}
	// The configuration is base64-encoded rather than written through a shell
	// heredoc. A submission is a file a student controls, and a line reading
	// exactly TWINET_EOF ends the heredoc early -- everything after it becomes
	// shell, running as root inside the container. Encoding removes the
	// delimiter entirely, so there is nothing left to escape.
	script := strings.Join([]string{
		"set -e",
		"printf '%s' " + shellQuote(base64.StdEncoding.EncodeToString([]byte(body))) +
			" | base64 -d > " + frrConfigPath,
		"chown frr:frr " + frrConfigPath + " 2>/dev/null || true",
		"chmod 640 " + frrConfigPath,
		"PYTHONWARNINGS=ignore /usr/lib/frr/frr-reload.py --reload " +
			"--bindir /usr/bin --confdir /etc/frr --rundir /run/frr " + frrConfigPath,
	}, "\n")

	res, err := exec.Exec(ctx, d.ID, []string{"sh", "-c", script})
	if err != nil {
		return fmt.Errorf("installing the configuration: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("installing the configuration: %s", firstLine(res.Stdout+res.Stderr))
	}
	if !opts.RequireDaemons {
		return nil
	}
	daemons := opts.Daemons
	if len(daemons) == 0 {
		daemons = []string{"zebra", "bgpd", "ospfd"}
	}
	wait := opts.Wait
	if wait <= 0 {
		wait = frrStartWait
	}

	// Every enabled daemon must answer on its own vty socket. PID namespaces
	// are intentionally private, so pidof in the router shell cannot observe
	// sidecar processes and would report every healthy daemon as absent.
	//
	// This used to ask `vtysh -c "show version"`, which answers as long as any
	// one daemon is up. A submission whose OSPF configuration was rejected
	// therefore loaded successfully with ospfd dead, and was then marked on a
	// network in which its routers could not learn a route -- against a lab
	// that looked healthy. Every process the daemons file enables is now
	// checked by name.
	// Polled rather than slept on.
	//
	// A fixed two-second wait is a guess about how long FRR takes to bind, and
	// on a node running two hundred containers it is sometimes wrong -- so a
	// perfectly good submission was quarantined for being slow. Waiting for the
	// answer instead is both faster in the common case and correct in the rare
	// one; the deadline is what keeps a genuinely rejected configuration from
	// hanging the run.
	probe := "for d in " + strings.Join(daemons, " ") +
		"; do vtysh -d \"$d\" -c 'show version' >/dev/null 2>&1 || printf '%s ' \"$d\"; done"
	deadline := time.Now().Add(wait)
	var down []string
	for {
		res, err = exec.Exec(ctx, d.ID, []string{"sh", "-c", probe})
		if err != nil {
			return fmt.Errorf("checking that frr came up: %w", err)
		}
		down = strings.Fields(res.Stdout)
		if len(down) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("frr did not come up on the submitted configuration within %s: %s "+
		"%s not running, which usually means %s rejected a line of it",
		wait, strings.Join(down, ", "),
		map[bool]string{true: "is", false: "are"}[len(down) == 1],
		map[bool]string{true: "it", false: "they"}[len(down) == 1])
}

// frrStartWait bounds how long a submission's routing daemons are given to
// bind. Long enough for a loaded node, short enough that a rejected
// configuration is reported rather than waited on.
var frrStartWait = 30 * time.Second

func (frrProvider) StateCommands(d *model.Device, query netstate.Query) [][]string {
	if d == nil {
		return nil
	}
	var commands [][]string
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
	return commands
}

type frrSummary struct {
	IPv4 struct {
		Peers map[string]struct {
			RemoteAS int    `json:"remoteAs"`
			State    string `json:"state"`
			PfxRcd   int    `json:"pfxRcd"`
			PfxSnt   int    `json:"pfxSnt"`
			MsgRcvd  int    `json:"msgRcvd"`
			MsgSent  int    `json:"msgSent"`
		} `json:"peers"`
	} `json:"ipv4Unicast"`
}

type frrRoute struct {
	Valid     bool   `json:"valid"`
	BestPath  bool   `json:"bestpath"`
	Best      bool   `json:"best"`
	LocalPref int    `json:"locPrf"`
	Origin    string `json:"origin"`
	Path      string `json:"path"`
	Peer      string `json:"peerId"`
	PathFrom  string `json:"pathFrom"`
	NextHop   string `json:"nextHop"`
	RPKI      string `json:"rpkiValidationState"`
	RPKIAlt   string `json:"rpki"`
	Community *struct {
		String string `json:"string"`
	} `json:"community"`
	NextHops []struct {
		IP string `json:"ip"`
	} `json:"nexthops"`
}

func readFRRBGP(ctx context.Context, d *model.Device, exec netstate.Executor, query netstate.Query) (netstate.BGP, error) {
	out := netstate.BGP{}
	if query.Has(netstate.QueryBGPSessions) {
		summaryRaw, err := execFRR(ctx, d, exec, "show ip bgp summary json")
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "instance not found") {
				return netstate.BGP{}, nil
			}
			return netstate.BGP{}, err
		}
		var summary frrSummary
		summaryJSON, err := jsonOutput(summaryRaw)
		if err != nil {
			return netstate.BGP{}, fmt.Errorf("parse BGP summary on %s: %w", d.ID, err)
		}
		if err := json.Unmarshal(summaryJSON, &summary); err != nil {
			return netstate.BGP{}, fmt.Errorf("parse BGP summary on %s: %w", d.ID, err)
		}
		for neighbor, peer := range summary.IPv4.Peers {
			out.Sessions = append(out.Sessions, netstate.BGPSession{
				Neighbor: neighbor, RemoteAS: uint32(peer.RemoteAS), State: peer.State,
				PrefixesIn: peer.PfxRcd, PrefixesOut: peer.PfxSnt,
				UpdatesReceived: peer.MsgRcvd, UpdatesSent: peer.MsgSent,
			})
		}
	}
	if !query.Has(netstate.QueryBGPRIB) {
		return out, nil
	}
	routesRaw, err := execFRR(ctx, d, exec, "show ip bgp json")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "instance not found") {
			return out, nil
		}
		return netstate.BGP{}, err
	}
	var document struct {
		Routes map[string]json.RawMessage `json:"routes"`
	}
	routesJSON, err := jsonOutput(routesRaw)
	if err != nil {
		return netstate.BGP{}, fmt.Errorf("parse BGP table on %s: %w", d.ID, err)
	}
	if err := json.Unmarshal(routesJSON, &document); err != nil {
		return netstate.BGP{}, fmt.Errorf("parse BGP table on %s: %w", d.ID, err)
	}
	for prefix, raw := range document.Routes {
		paths, err := decodeFRRPaths(raw)
		if err != nil {
			return netstate.BGP{}, fmt.Errorf("parse BGP route %s on %s: %w", prefix, d.ID, err)
		}
		for _, path := range paths {
			rpki := path.RPKI
			if rpki == "" {
				rpki = path.RPKIAlt
			}
			normalized := netstate.BGPPath{
				Prefix: prefix, ASPath: strings.TrimSpace(path.Path), ASNs: parseASNs(path.Path),
				Best: path.BestPath || path.Best, Valid: path.Valid, LocalPref: path.LocalPref,
				Origin: path.Origin, Peer: path.Peer, Source: path.PathFrom, RPKI: normalizeRPKI(rpki),
			}
			// FRR 10 can label a locally originated `network` path as
			// pathFrom=external. Its synthetic (unspec) peer is the reliable
			// discriminator: no external session has that peer identity.
			if normalized.Peer == "(unspec)" {
				normalized.Source = "local"
			}
			if path.Community != nil {
				normalized.Communities = strings.Fields(path.Community.String)
			}
			for _, next := range path.NextHops {
				if next.IP != "" {
					normalized.NextHops = append(normalized.NextHops, netstate.NextHop{Address: next.IP})
				}
			}
			if path.NextHop != "" {
				normalized.NextHops = append(normalized.NextHops, netstate.NextHop{Address: path.NextHop})
			}
			out.Paths = append(out.Paths, normalized)
		}
	}
	return out, nil
}

func decodeFRRPaths(raw json.RawMessage) ([]frrRoute, error) {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		var paths []frrRoute
		if err := json.Unmarshal(raw, &paths); err != nil {
			return nil, err
		}
		return paths, nil
	}
	var one frrRoute
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []frrRoute{one}, nil
}

func readFRROSPF(ctx context.Context, d *model.Device, exec netstate.Executor) ([]netstate.OSPFPeer, error) {
	raw, err := execFRR(ctx, d, exec, "show ip ospf neighbor json")
	if err != nil {
		return nil, err
	}
	type neighbor struct {
		Address   string `json:"address"`
		Interface string `json:"ifaceName"`
		State     string `json:"nbrState"`
		// DeadTimerMsec is how long this neighbour has left before it is
		// declared gone, which is what tells a live adjacency from one being
		// held up by a timer nobody has revised yet.
		DeadTimerMsec int64 `json:"routerDeadIntervalTimerDueMsec"`
	}
	var wrapped struct {
		Neighbors map[string][]neighbor `json:"neighbors"`
	}
	documentJSON, err := jsonOutput(raw)
	if err != nil {
		return nil, fmt.Errorf("parse OSPF neighbours on %s: %w", d.ID, err)
	}
	if err := json.Unmarshal(documentJSON, &wrapped); err != nil {
		return nil, fmt.Errorf("parse OSPF neighbours on %s: %w", d.ID, err)
	}
	document := wrapped.Neighbors
	if document == nil {
		if err := json.Unmarshal(documentJSON, &document); err != nil {
			return nil, fmt.Errorf("parse OSPF neighbours on %s: %w", d.ID, err)
		}
	}
	var out []netstate.OSPFPeer
	for routerID, peers := range document {
		for _, peer := range peers {
			observed := netstate.OSPFPeer{
				RouterID: routerID, Address: peer.Address, Interface: peer.Interface,
				State: peer.State, DeadTimerMsec: peer.DeadTimerMsec,
			}
			if peer.DeadTimerMsec <= 0 {
				observed.MarkUnknown(netstate.FieldDeadTimer)
			}
			out = append(out, observed)
		}
	}
	return out, nil
}

func readFRRPolicy(ctx context.Context, d *model.Device, exec netstate.Executor) ([]netstate.PolicyFact, error) {
	raw, err := execFRR(ctx, d, exec, "show running-config")
	if err != nil {
		return nil, err
	}
	var out []netstate.PolicyFact
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 4 && fields[0] == "neighbor" && fields[2] == "route-map" {
			direction := ""
			if len(fields) >= 5 {
				direction = fields[4]
			}
			out = append(out, netstate.PolicyFact{Name: fields[3], Peer: fields[1], Direction: direction})
		}
		if len(fields) >= 5 && fields[0] == "bgp" && fields[1] == "community-list" {
			out = append(out, netstate.PolicyFact{
				Name: fields[3], Action: fields[4], Match: strings.Join(fields[5:], " "),
			})
		}
	}
	return out, nil
}

func execFRR(ctx context.Context, d *model.Device, exec netstate.Executor, command string) (string, error) {
	res, err := exec.Exec(ctx, d.ID, []string{"vtysh", "-c", command})
	if err != nil {
		return "", fmt.Errorf("run %q on %s: %w", command, d.ID, err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("run %q on %s exited %d: %s", command, d.ID, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return res.Stdout, nil
}

func jsonOutput(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexByte(raw, '{'); i > 0 {
		raw = raw[i:]
	}
	if raw == "" {
		return nil, fmt.Errorf("empty JSON output")
	}
	return []byte(raw), nil
}

func parseASNs(path string) []uint32 {
	fields := strings.Fields(path)
	out := make([]uint32, 0, len(fields))
	for _, field := range fields {
		value, err := strconv.ParseUint(field, 10, 32)
		if err == nil {
			out = append(out, uint32(value))
		}
	}
	return out
}

func normalizeRPKI(value string) netstate.RPKIState {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "valid":
		return netstate.RPKIValid
	case "invalid":
		return netstate.RPKIInvalid
	case "notfound", "not-found", "not_found":
		return netstate.RPKINotFound
	default:
		return netstate.RPKIUnknown
	}
}

func cleanFRRConfig(body string) string {
	lines := strings.Split(body, "\n")
	start := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "Building configuration") ||
			strings.HasPrefix(trimmed, "Current configuration") {
			start = i + 1
			continue
		}
		break
	}
	return strings.TrimRight(strings.Join(lines[start:], "\n"), "\n")
}

// RefreshBGP asks each named neighbour to re-send its table. The commands are
// combined into one vtysh invocation, which is what the grader has always done
// and keeps one exec per router.
func (frrProvider) RefreshBGP(d *model.Device, neighbors []string) [][]string {
	if d == nil || len(neighbors) == 0 {
		return nil
	}
	args := []string{"vtysh"}
	for _, neighbor := range neighbors {
		args = append(args, "-c", "clear bgp "+neighbor+" soft in")
	}
	return [][]string{args}
}
