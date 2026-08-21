package nos

import (
	"context"
	"fmt"
	"regexp"
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
	birdConfigPath  = "/etc/bird/bird.conf"
	birdSocketPath  = "/run/bird.ctl"
	birdRestorePath = "/etc/twinet/restore-bird.conf"
)

type birdProvider struct{}

func init() { Register(birdProvider{}) }

func (birdProvider) Name() string { return "bird" }

func (birdProvider) StateKind() state.Kind { return state.KindBIRD }

// BIRD 2 deliberately does not claim tunnels, MPLS/LDP, VRF, multicast, DHCP, or RPKI
// here. BIRD has plugins or adjacent tooling for some of these, but Twinet's
// provider does not render, apply, and observe them end to end yet.
func (birdProvider) Capabilities() Capabilities {
	return NewCapabilities(
		FeatureIPv4, FeatureIPv6, FeatureOSPF, FeatureBGP, FeaturePolicy,
		FeatureCommunity, FeatureVLAN,
	)
}

func (birdProvider) Render(request RenderRequest) (Rendered, error) {
	if request.Device == nil {
		return Rendered{}, fmt.Errorf("render BIRD for nil device")
	}
	body := request.Platform
	if request.Mode == ModeSolve {
		body += request.Expected
	}
	if strings.TrimSpace(body) == "" {
		return Rendered{}, fmt.Errorf("render BIRD for %s: empty configuration", request.Device.ID)
	}
	return Rendered{Files: map[string]FileSpec{
		birdConfigPath: {Content: []byte(body), Mode: 0o640},
	}}, nil
}

func (birdProvider) Apply(request RenderRequest) ([]Command, error) {
	if request.Device == nil {
		return nil, fmt.Errorf("apply BIRD for nil device")
	}
	return []Command{{
		Describe: "start BIRD 2",
		Args: []string{"sh", "-c", strings.Join([]string{
			"for p in $(ps -ef | awk '/[b]ird( |$)/ {print $1}'); do kill $p 2>/dev/null || true; done",
			"rm -f " + birdSocketPath,
			"bird -c " + birdConfigPath + " -s " + birdSocketPath,
			"for i in 1 2 3 4 5 6 7 8 9 10; do birdc -r -s " + birdSocketPath +
				" show status >/dev/null 2>&1 && exit 0; sleep 1; done",
			"echo 'BIRD did not become ready' >&2; exit 1",
		}, "\n")},
	}}, nil
}

func (birdProvider) Ready(d *model.Device, rt runtime.Runtime) *plan.Waiter {
	if d == nil {
		return nil
	}
	return &plan.Waiter{
		Describe:  "BIRD on " + d.ID + " to answer",
		Interval:  200 * time.Millisecond,
		Timeout:   90 * time.Second,
		StableFor: 2,
		Check: func(ctx context.Context) (bool, error) {
			res, err := rt.Exec(ctx, d.Container, runtime.ExecCmd{
				Cmd: []string{"birdc", "-r", "-s", birdSocketPath, "show", "status"},
			})
			if err != nil {
				return false, err
			}
			if res.ExitCode != 0 {
				return false, fmt.Errorf("birdc exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
			}
			return true, nil
		},
	}
}

func (birdProvider) ReadState(ctx context.Context, d *model.Device, exec netstate.Executor, query netstate.Query) (netstate.State, error) {
	out, err := netstate.ReadKernel(ctx, d, exec, query&(netstate.QueryInterfaces|netstate.QueryKernel))
	if err != nil {
		return netstate.State{}, err
	}
	if query.Has(netstate.QueryBGP) {
		bgp, err := readBirdBGP(ctx, d, exec, query)
		if err != nil {
			return netstate.State{}, err
		}
		out.BGP = bgp
	}
	if query.Has(netstate.QueryOSPF) {
		ospf, err := readBirdOSPF(ctx, d, exec)
		if err != nil {
			return netstate.State{}, err
		}
		out.OSPF = ospf
	}
	if query.Has(netstate.QueryPolicy) {
		policy, err := readBirdPolicy(ctx, d, exec)
		if err != nil {
			return netstate.State{}, err
		}
		out.Policy = policy
	}
	out.Sort()
	return out, nil
}

func (birdProvider) Save(ctx context.Context, d *model.Device, exec netstate.Executor, lab, topology string) ([]state.Snapshot, error) {
	if d == nil {
		return nil, fmt.Errorf("save BIRD for nil device")
	}
	res, err := exec.Exec(ctx, d.ID, []string{"cat", birdConfigPath})
	if err != nil {
		return nil, fmt.Errorf("save BIRD configuration from %s: %w", d.ID, err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("save BIRD configuration from %s: cat exited %d: %s",
			d.ID, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return []state.Snapshot{{
		Lab: lab, AS: d.ASN, Device: d.ID, Kind: state.KindBIRD,
		Topology: topology, Content: []byte(strings.TrimRight(res.Stdout, "\n") + "\n"),
	}}, nil
}

func (birdProvider) Restore(ctx context.Context, d *model.Device, rt runtime.Runtime, snap state.Snapshot) error {
	if snap.Kind != state.KindBIRD {
		return fmt.Errorf("restore %s on BIRD device %s", snap.Kind, d.ID)
	}
	if err := rt.CopyTo(ctx, d.Container, birdRestorePath, 0o600, snap.Content); err != nil {
		return fmt.Errorf("copy saved BIRD configuration into %s: %w", d.ID, err)
	}
	res, err := rt.Exec(ctx, d.Container, runtime.ExecCmd{Cmd: []string{"sh", "-c",
		"cp " + birdRestorePath + " " + birdConfigPath + "; rc=$?; rm -f " + birdRestorePath +
			"; [ $rc -eq 0 ] && birdc -r -s " + birdSocketPath + " configure; exit $?"}})
	if err != nil {
		return fmt.Errorf("restore BIRD configuration on %s: %w", d.ID, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("restore BIRD configuration on %s exited %d: %s",
			d.ID, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

func birdCommand(ctx context.Context, d *model.Device, exec netstate.Executor, words ...string) (string, error) {
	command := append([]string{"birdc", "-r", "-s", birdSocketPath}, words...)
	res, err := exec.Exec(ctx, d.ID, command)
	if err != nil {
		return "", fmt.Errorf("run %q on %s: %w", strings.Join(command, " "), d.ID, err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("run %q on %s exited %d: %s",
			strings.Join(command, " "), d.ID, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return res.Stdout, nil
}

var (
	birdNeighborRE = regexp.MustCompile(`(?i)^\s*neighbor address:\s*([0-9a-f:.]+)`)
	birdASRE       = regexp.MustCompile(`(?i)^\s*neighbor AS:\s*([0-9]+)`)
	birdRouteRE    = regexp.MustCompile(`^\s*([0-9a-fA-F:.]+/[0-9]+|default)\s+.*?\s\[(.+?)\].*$`)
	birdViaRE      = regexp.MustCompile(`\bvia\s+([0-9a-fA-F:.]+)`)
	birdPathRE     = regexp.MustCompile(`\]?\s+\[([0-9 ]+)\]`)
)

func readBirdBGP(ctx context.Context, d *model.Device, exec netstate.Executor, query netstate.Query) (netstate.BGP, error) {
	out := netstate.BGP{}
	if query.Has(netstate.QueryBGPSessions) {
		protocols, err := birdCommand(ctx, d, exec, "show", "protocols", "all")
		if err != nil {
			return netstate.BGP{}, err
		}
		var current *netstate.BGPSession
		for _, raw := range strings.Split(protocols, "\n") {
			line := strings.TrimSpace(raw)
			fields := strings.Fields(line)
			if len(fields) >= 4 && strings.EqualFold(fields[1], "BGP") {
				state := birdBGPState(fields[3])
				out.Sessions = append(out.Sessions, netstate.BGPSession{State: state})
				current = &out.Sessions[len(out.Sessions)-1]
				continue
			}
			if current == nil {
				continue
			}
			if matches := birdNeighborRE.FindStringSubmatch(line); len(matches) == 2 {
				current.Neighbor = matches[1]
				continue
			}
			if matches := birdASRE.FindStringSubmatch(line); len(matches) == 2 {
				value, _ := strconv.ParseUint(matches[1], 10, 32)
				current.RemoteAS = uint32(value)
			}
		}
	}
	if !query.Has(netstate.QueryBGPRIB) {
		return out, nil
	}
	routes, err := birdCommand(ctx, d, exec, "show", "route", "all")
	if err != nil {
		return netstate.BGP{}, err
	}
	var current *netstate.BGPPath
	for _, raw := range strings.Split(routes, "\n") {
		matches := birdRouteRE.FindStringSubmatch(raw)
		if len(matches) != 3 {
			if current == nil {
				continue
			}
			line := strings.TrimSpace(raw)
			switch {
			case strings.HasPrefix(line, "BGP.community:"):
				current.Communities = birdCommunities(strings.TrimSpace(strings.TrimPrefix(line, "BGP.community:")))
			case strings.HasPrefix(line, "BGP.local_pref:"):
				value := strings.TrimSpace(strings.TrimPrefix(line, "BGP.local_pref:"))
				current.LocalPref, _ = strconv.Atoi(value)
			case strings.HasPrefix(line, "BGP.as_path:"):
				current.ASPath = strings.TrimSpace(strings.TrimPrefix(line, "BGP.as_path:"))
				current.ASPath = strings.Trim(current.ASPath, "[]")
				current.ASNs = parseASNs(current.ASPath)
			}
			continue
		}
		path := netstate.BGPPath{Prefix: matches[1], Valid: true, Best: strings.Contains(raw, " * ")}
		if via := birdViaRE.FindStringSubmatch(raw); len(via) == 2 {
			path.NextHops = []netstate.NextHop{{Address: via[1]}}
		}
		if asPath := birdPathRE.FindStringSubmatch(raw); len(asPath) == 2 {
			path.ASPath = strings.TrimSpace(asPath[1])
			path.ASNs = parseASNs(path.ASPath)
		}
		out.Paths = append(out.Paths, path)
		current = &out.Paths[len(out.Paths)-1]
	}
	return out, nil
}

func birdCommunities(raw string) []string {
	raw = strings.TrimSpace(strings.Trim(raw, "[]"))
	if raw == "" {
		return nil
	}
	fields := strings.Fields(raw)
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.Trim(field, "(),")
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

func birdBGPState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "up":
		return "Established"
	case "down":
		return "Idle"
	default:
		return state
	}
}

func readBirdOSPF(ctx context.Context, d *model.Device, exec netstate.Executor) ([]netstate.OSPFPeer, error) {
	raw, err := birdCommand(ctx, d, exec, "show", "ospf", "neighbors")
	if err != nil {
		return nil, err
	}
	var out []netstate.OSPFPeer
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || strings.EqualFold(fields[0], "Router") {
			continue
		}
		// BIRD's tabular format is router-id, address, interface, state.
		out = append(out, netstate.OSPFPeer{
			RouterID: fields[0], Address: fields[1], Interface: fields[2], State: fields[len(fields)-1],
		})
	}
	return out, nil
}

func readBirdPolicy(ctx context.Context, d *model.Device, exec netstate.Executor) ([]netstate.PolicyFact, error) {
	res, err := exec.Exec(ctx, d.ID, []string{"cat", birdConfigPath})
	if err != nil {
		return nil, fmt.Errorf("read BIRD policy on %s: %w", d.ID, err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("read BIRD policy on %s: cat exited %d: %s",
			d.ID, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	var out []netstate.PolicyFact
	for _, line := range strings.Split(res.Stdout, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "filter" {
			out = append(out, netstate.PolicyFact{Name: strings.TrimSuffix(fields[1], "{")})
		}
	}
	return out, nil
}
