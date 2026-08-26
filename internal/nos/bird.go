package nos

import (
	"context"
	"encoding/base64"
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
		FeatureIPv4, FeatureIPv6, FeatureForwarding, FeatureOSPF, FeatureBGP, FeaturePolicy,
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
			// Match the executable column, not a regex over the shell command:
			// this script itself contains `bird -c`, and the old grep pattern
			// killed its own exec shell with SIGTERM (143).
			"for p in $(ps -eo pid=,comm= | awk '$2 == \"bird\" {print $1}'); do kill $p 2>/dev/null || true; done",
			"rm -f " + birdSocketPath,
			// bird stays in the foreground by default. Launch it in the
			// container background before probing, or the deployment exec is
			// eventually cancelled and reports SIGTERM (143) even though the
			// configuration itself was valid.
			"bird -c " + birdConfigPath + " -s " + birdSocketPath + " >/tmp/bird.log 2>&1 &",
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
	// One `show route all` serves both the RIB and the kernel attribution
	// below, so asking for both costs one command rather than two.
	var routes string
	if query.Has(netstate.QueryBGPRIB) || query.Has(netstate.QueryKernel) {
		routes, err = birdCommand(ctx, d, exec, "show", "route", "all")
		if err != nil {
			return netstate.State{}, err
		}
	}
	if query.Has(netstate.QueryKernel) {
		// Linux records which *daemon* installed a route, and BIRD is one
		// daemon for every protocol: OSPF, BGP and static routes all arrive
		// as `proto bird`. A check that asks "was this learned by OSPF or
		// hand-installed" -- which is exactly what the ECMP question is about
		// -- would read every BIRD route as neither, and fail a correct
		// submission. BIRD does know, so the provider says so here rather
		// than leaving each check to guess.
		birdAttributeKernelRoutes(out.Kernel.Routes, birdRouteProtocols(routes))
	}
	if query.Has(netstate.QueryBGPSessions) {
		bgp, err := readBirdBGP(ctx, d, exec, netstate.QueryBGPSessions)
		if err != nil {
			return netstate.State{}, err
		}
		out.BGP.Sessions = bgp.Sessions
	}
	if query.Has(netstate.QueryBGPRIB) {
		out.BGP.Paths = readBirdRIB(routes)
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

// birdOwnKernelProtocols are the labels Linux uses for a route BIRD installed.
// Anything else in the kernel table came from somewhere BIRD is not, and its
// own label is the more truthful one.
var birdOwnKernelProtocols = map[string]bool{"bird": true, "12": true, "": true}

// birdAttributeKernelRoutes replaces BIRD's single kernel protocol label with
// the protocol that actually produced each route.
func birdAttributeKernelRoutes(routes []netstate.Route, byPrefix map[string]string) {
	for i := range routes {
		if !birdOwnKernelProtocols[strings.ToLower(routes[i].Protocol)] {
			continue
		}
		if protocol, ok := byPrefix[routes[i].Prefix]; ok {
			routes[i].Protocol = protocol
		} else if routes[i].Protocol == "bird" || routes[i].Protocol == "12" {
			// BIRD installed it and no longer holds it: honest, and not the
			// same as claiming a protocol.
			routes[i].Protocol = ""
		}
	}
}

// birdRouteProtocols maps each prefix BIRD holds to the vendor-neutral name of
// the protocol that produced it, read from `show route all`.
func birdRouteProtocols(routes string) map[string]string {
	out := map[string]string{}
	prefix := ""
	for _, raw := range strings.Split(routes, "\n") {
		if matches := birdRouteRE.FindStringSubmatch(raw); len(matches) == 3 {
			prefix = matches[1]
			if protocol := birdKernelProtocol(matches[2]); protocol != "" {
				out[prefix] = protocol
			}
			continue
		}
		if prefix == "" {
			continue
		}
		line := strings.TrimSpace(raw)
		// `Type: OSPF univ` is BIRD's own statement of where the route came
		// from, and it is more reliable than a protocol instance name a
		// student chose.
		if body, ok := strings.CutPrefix(line, "Type:"); ok {
			if protocol := birdKernelProtocol(body); protocol != "" {
				out[prefix] = protocol
			}
		}
	}
	return out
}

// birdKernelProtocol maps a BIRD protocol name or route type onto the kernel
// protocol spelling every check already compares against.
func birdKernelProtocol(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	name := strings.ToLower(fields[0])
	switch {
	case strings.HasPrefix(name, "ospf"):
		return "ospf"
	case strings.HasPrefix(name, "bgp"), strings.HasPrefix(name, "ebgp"), strings.HasPrefix(name, "ibgp"):
		return "bgp"
	case strings.HasPrefix(name, "static"), strings.HasPrefix(name, "own"), strings.HasPrefix(name, "hijack"):
		return "static"
	case strings.HasPrefix(name, "direct"), strings.HasPrefix(name, "device"):
		return "kernel"
	case strings.HasPrefix(name, "kernel"):
		return "kernel"
	default:
		return ""
	}
}

func (birdProvider) Save(ctx context.Context, d *model.Device, exec netstate.Executor, lab, topology string) ([]state.Snapshot, error) {
	if d == nil {
		return nil, fmt.Errorf("save BIRD for nil device")
	}
	body, err := birdProvider{}.CaptureConfig(ctx, d, exec)
	if err != nil {
		return nil, fmt.Errorf("save BIRD configuration from %s: %w", d.ID, err)
	}
	return []state.Snapshot{{
		Lab: lab, AS: d.ASN, Device: d.ID, Kind: state.KindBIRD,
		Topology: topology, Content: []byte(body + "\n"),
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

func (birdProvider) ConfigFile() ConfigFile {
	return ConfigFile{NOS: "bird", Path: birdConfigPath, Extension: ".conf", Kind: state.KindBIRD}
}

// CaptureConfig reads the configuration file rather than a running-config
// dump, because BIRD has no such dump: `birdc show status` reports which file
// is loaded and nothing reproduces it. The file therefore *is* the running
// configuration, and BIRD refuses to reconfigure onto a file it cannot parse,
// so what is on disk is what the daemon accepted.
func (birdProvider) CaptureConfig(ctx context.Context, d *model.Device, exec netstate.Executor) (string, error) {
	if d == nil {
		return "", fmt.Errorf("capture BIRD configuration for nil device")
	}
	res, err := exec.Exec(ctx, d.ID, []string{"cat", birdConfigPath})
	if err != nil {
		return "", fmt.Errorf("%s: its routing configuration could not be read: %w; "+
			"re-run once the device is reachable", d.ID, err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%s: its routing configuration could not be read: "+
			"cat %s exited %d: %s; re-run once the device is reachable",
			d.ID, birdConfigPath, res.ExitCode, firstLine(res.Stderr))
	}
	return strings.TrimRight(res.Stdout, "\n"), nil
}

// LoadConfig installs a configuration and asks the running daemon to adopt it.
//
// `birdc configure` parses the new file first and keeps the old one on any
// error, so a rejected submission leaves a working daemon and a message naming
// the line -- which is the same property FRR's exact reload gives, and the
// reason neither path restarts the daemon. A restart would turn a syntax error
// into a router that is simply gone, and grade as a student who configured
// nothing.
func (birdProvider) LoadConfig(ctx context.Context, d *model.Device, exec netstate.Executor,
	body string, opts LoadOptions,
) error {
	if d == nil {
		return fmt.Errorf("load BIRD configuration into nil device")
	}
	// base64 for the same reason as FRR: the body is a file a student
	// controls, and no heredoc delimiter survives inside it to be closed.
	script := strings.Join([]string{
		"set -e",
		"printf '%s' " + shellQuote(base64.StdEncoding.EncodeToString([]byte(body))) +
			" | base64 -d > " + birdConfigPath,
		"chmod 640 " + birdConfigPath,
		"birdc -s " + birdSocketPath + " configure",
	}, "\n")
	res, err := exec.Exec(ctx, d.ID, []string{"sh", "-c", script})
	if err != nil {
		return fmt.Errorf("installing the configuration: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("installing the configuration: %s", firstLine(res.Stdout+res.Stderr))
	}
	// birdc exits zero when the *command* was delivered; a configuration it
	// refused is reported in the reply text. Reading it is what stops a
	// rejected submission being graded as an empty network.
	if reply := strings.ToLower(res.Stdout); strings.Contains(reply, "reconfiguration failed") ||
		strings.Contains(reply, "syntax error") {
		return fmt.Errorf("installing the configuration: %s", firstLine(res.Stdout))
	}
	if !opts.RequireDaemons {
		return nil
	}
	wait := opts.Wait
	if wait <= 0 {
		wait = birdStartWait
	}
	// One daemon, so "every enabled daemon answers" is "the control socket
	// answers and reports the configuration in force".
	deadline := time.Now().Add(wait)
	var last string
	for {
		res, err = exec.Exec(ctx, d.ID, []string{"birdc", "-r", "-s", birdSocketPath, "show", "status"})
		if err != nil {
			return fmt.Errorf("checking that bird came up: %w", err)
		}
		if res.ExitCode == 0 {
			status := strings.ToLower(res.Stdout)
			if !strings.Contains(status, "reconfiguration in progress") &&
				!strings.Contains(status, "shutdown") {
				return nil
			}
			last = firstLine(res.Stdout)
		} else {
			last = firstLine(res.Stderr)
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
	return fmt.Errorf("bird did not come up on the submitted configuration within %s: %s; "+
		"which usually means it rejected a line of it", wait, last)
}

// birdStartWait bounds how long BIRD is given to adopt a configuration.
var birdStartWait = 30 * time.Second

func (birdProvider) StateCommands(d *model.Device, query netstate.Query) [][]string {
	if d == nil {
		return nil
	}
	var commands [][]string
	if query.Has(netstate.QueryBGPSessions) {
		commands = append(commands, birdWords("show", "protocols", "all"))
	}
	// `show route all` twice over: once for the RIB a policy check reads, and
	// once because Linux cannot say which BIRD protocol installed a kernel
	// route. It is one command either way; the caller de-duplicates.
	if query.Has(netstate.QueryBGPRIB) || query.Has(netstate.QueryKernel) {
		commands = append(commands, birdWords("show", "route", "all"))
	}
	if query.Has(netstate.QueryOSPF) {
		commands = append(commands, birdWords("show", "ospf", "neighbors"))
	}
	if query.Has(netstate.QueryPolicy) {
		commands = append(commands, []string{"cat", birdConfigPath})
	}
	return commands
}

func birdWords(words ...string) []string {
	return append([]string{"birdc", "-r", "-s", birdSocketPath}, words...)
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
	birdNeighborRE = regexp.MustCompile(`(?i)^neighbor address:\s*([0-9a-f:.]+)`)
	birdASRE       = regexp.MustCompile(`(?i)^neighbor AS:\s*([0-9]+)`)
	birdStateRE    = regexp.MustCompile(`(?i)^BGP state:\s*(\S+)`)
	birdChannelRE  = regexp.MustCompile(`(?i)^Channel\s+(\S+)`)
	birdRoutesRE   = regexp.MustCompile(`(?i)^Routes:\s*(.*)$`)
	birdCountRE    = regexp.MustCompile(`([0-9]+)\s+([a-z]+)`)
	birdRouteRE    = regexp.MustCompile(`^\s*([0-9a-fA-F:.]+/[0-9]+|default)\s+.*?\s\[(.+?)\].*$`)
	birdAltRouteRE = regexp.MustCompile(`^\s+(?:unicast|blackhole|unreachable|prohibit)\s+\[(.+?)\].*$`)
	birdViaRE      = regexp.MustCompile(`\bvia\s+([0-9a-fA-F:.]+)(?:\s+on\s+(\S+))?`)
	birdOriginRE   = regexp.MustCompile(`\[AS([0-9]+)([ie?])\]\s*$`)
	birdParenRE    = regexp.MustCompile(`\(([^()]*)\)`)
	birdFromRE     = regexp.MustCompile(`\bfrom\s+([0-9a-fA-F:.]+)`)
)

// birdBGPSessionCounters are the normalized counters a BGP session carries.
// BIRD publishes them per channel rather than per session, so they are only
// known once a channel section has been seen.
var birdBGPSessionCounters = []netstate.Field{
	netstate.FieldPrefixesIn, netstate.FieldPrefixesOut,
	netstate.FieldUpdatesReceived, netstate.FieldUpdatesSent,
}

// readBirdBGPSessions normalizes `show protocols all`.
//
// The counters are the point of this function. Leaving them at zero made a
// BIRD session indistinguishable from one whose neighbour had sent nothing
// since it came up, and the eBGP check reads exactly that difference: a route
// refresh that moves no counter is reported as "held open by a timer and
// carrying nothing". A student running BIRD would have been told their working
// sessions were dead. Where BIRD publishes no equivalent at all the field is
// named in Unknown, so no check can mistake an unpublished number for a zero.
func readBirdBGPSessions(protocols string) []netstate.BGPSession {
	var out []netstate.BGPSession
	var current *netstate.BGPSession
	channel, counted := "", false
	for _, raw := range strings.Split(protocols, "\n") {
		line := strings.TrimSpace(raw)
		fields := strings.Fields(line)
		// A protocol header starts a block: "<name> BGP <table> <state>
		// <since...> <info...>". The Since column's width depends on BIRD's
		// configured time format, so nothing after it is read positionally.
		if len(fields) >= 4 && fields[1] == "BGP" && !strings.HasSuffix(fields[0], ":") {
			session := netstate.BGPSession{State: birdBGPState(fields[3], fields[4:])}
			session.MarkUnknown(birdBGPSessionCounters...)
			out = append(out, session)
			current = &out[len(out)-1]
			channel, counted = "", false
			continue
		}
		if current == nil {
			continue
		}
		if matches := birdStateRE.FindStringSubmatch(line); len(matches) == 2 {
			current.State = birdNormalizeBGPState(matches[1])
			continue
		}
		if matches := birdNeighborRE.FindStringSubmatch(line); len(matches) == 2 {
			current.Neighbor = matches[1]
			continue
		}
		if matches := birdASRE.FindStringSubmatch(line); len(matches) == 2 {
			value, _ := strconv.ParseUint(matches[1], 10, 32)
			current.RemoteAS = uint32(value)
			continue
		}
		if matches := birdChannelRE.FindStringSubmatch(line); len(matches) == 2 {
			channel = strings.ToLower(matches[1])
			continue
		}
		// FRR's summary is the IPv4 unicast view, so the IPv4 channel is the
		// comparable one. A session with only another channel still reports
		// that channel rather than pretending it has no counters.
		if counted && channel != "ipv4" {
			continue
		}
		switch {
		case birdRoutesRE.MatchString(line):
			values := birdCounts(birdRoutesRE.FindStringSubmatch(line)[1])
			current.PrefixesIn = values["imported"]
			current.PrefixesOut = values["exported"]
			current.Unknown = birdWithout(current.Unknown,
				netstate.FieldPrefixesIn, netstate.FieldPrefixesOut)
			counted = channel == "ipv4"
		case strings.HasPrefix(line, "Import updates:"):
			// received rejected filtered ignored accepted: the first column
			// counts what actually arrived on the wire, which is what a route
			// refresh has to move.
			if value, ok := birdStatColumn(line, 0); ok {
				current.UpdatesReceived = value
				current.Unknown = birdWithout(current.Unknown, netstate.FieldUpdatesReceived)
			}
		case strings.HasPrefix(line, "Export updates:"):
			// The last column is what was accepted for export, which is the
			// count of updates this router actually sent.
			if value, ok := birdStatColumn(line, -1); ok {
				current.UpdatesSent = value
				current.Unknown = birdWithout(current.Unknown, netstate.FieldUpdatesSent)
			}
		}
	}
	return out
}

// birdCounts reads BIRD's "5 imported, 0 filtered, 3 exported" phrasing.
func birdCounts(body string) map[string]int {
	out := map[string]int{}
	for _, match := range birdCountRE.FindAllStringSubmatch(body, -1) {
		value, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		out[strings.ToLower(match[2])] = value
	}
	return out
}

// birdStatColumn reads one column of a route change statistics row, counting
// from the left for index >= 0 and from the right for a negative index. BIRD
// prints "---" where a column does not apply, which is not a zero.
func birdStatColumn(line string, index int) (int, bool) {
	_, body, ok := strings.Cut(line, ":")
	if !ok {
		return 0, false
	}
	fields := strings.Fields(body)
	if len(fields) == 0 {
		return 0, false
	}
	if index < 0 {
		index += len(fields)
	}
	if index < 0 || index >= len(fields) {
		return 0, false
	}
	value, err := strconv.Atoi(fields[index])
	if err != nil {
		return 0, false
	}
	return value, true
}

func birdWithout(fields []netstate.Field, remove ...netstate.Field) []netstate.Field {
	drop := make(map[netstate.Field]bool, len(remove))
	for _, field := range remove {
		drop[field] = true
	}
	out := fields[:0]
	for _, field := range fields {
		if !drop[field] {
			out = append(out, field)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func readBirdBGP(ctx context.Context, d *model.Device, exec netstate.Executor, query netstate.Query) (netstate.BGP, error) {
	out := netstate.BGP{}
	if query.Has(netstate.QueryBGPSessions) {
		protocols, err := birdCommand(ctx, d, exec, "show", "protocols", "all")
		if err != nil {
			return netstate.BGP{}, err
		}
		out.Sessions = readBirdBGPSessions(protocols)
	}
	if !query.Has(netstate.QueryBGPRIB) {
		return out, nil
	}
	routes, err := birdCommand(ctx, d, exec, "show", "route", "all")
	if err != nil {
		return netstate.BGP{}, err
	}
	out.Paths = readBirdRIB(routes)
	return out, nil
}

func readBirdRIB(routes string) []netstate.BGPPath {
	var out []netstate.BGPPath
	var current *netstate.BGPPath
	var currentPrefix string
	for _, raw := range strings.Split(routes, "\n") {
		matches := birdRouteRE.FindStringSubmatch(raw)
		if len(matches) == 3 {
			currentPrefix = matches[1]
		} else if alternate := birdAltRouteRE.FindStringSubmatch(raw); len(alternate) == 2 &&
			currentPrefix != "" {
			matches = []string{alternate[0], currentPrefix, alternate[1]}
		}
		if len(matches) != 3 {
			if current == nil {
				continue
			}
			line := strings.TrimSpace(raw)
			switch {
			case birdViaRE.MatchString(line):
				via := birdViaRE.FindStringSubmatch(line)
				current.NextHops = []netstate.NextHop{{Address: via[1], Device: via[2]}}
			case strings.HasPrefix(line, "BGP.next_hop:"):
				// The attribute, alongside the resolved next hop, exactly as
				// the FRR provider reports both.
				for _, address := range strings.Fields(strings.TrimPrefix(line, "BGP.next_hop:")) {
					if !birdHasNextHop(current.NextHops, address) {
						current.NextHops = append(current.NextHops, netstate.NextHop{Address: address})
					}
				}
			case strings.HasPrefix(line, "BGP.community:"),
				strings.HasPrefix(line, "BGP.large_community:"):
				_, body, _ := strings.Cut(line, ":")
				current.Communities = append(current.Communities, birdCommunities(body)...)
			case strings.HasPrefix(line, "BGP.local_pref:"):
				value := strings.TrimSpace(strings.TrimPrefix(line, "BGP.local_pref:"))
				current.LocalPref, _ = strconv.Atoi(value)
			case strings.HasPrefix(line, "BGP.origin:"):
				current.Origin = birdOrigin(strings.TrimSpace(strings.TrimPrefix(line, "BGP.origin:")))
			case strings.HasPrefix(line, "BGP.as_path:"):
				current.ASPath = strings.TrimSpace(strings.TrimPrefix(line, "BGP.as_path:"))
				current.ASPath = strings.Trim(current.ASPath, "[]")
				current.ASNs = parseASNs(current.ASPath)
			}
			continue
		}
		path := netstate.BGPPath{
			Prefix: matches[1], Valid: true, Best: strings.Contains(raw, " * "),
			Source: birdPathSource(matches[2]),
		}
		if from := birdFromRE.FindStringSubmatch(matches[2]); len(from) == 2 {
			path.Peer = from[1]
		}
		if via := birdViaRE.FindStringSubmatch(raw); len(via) >= 2 {
			path.NextHops = []netstate.NextHop{{Address: via[1], Device: via[2]}}
		}
		// `[AS65002i]` is BIRD's summary of the path's origin attribute. Only
		// the origin is taken from it: the ASN in the bracket is the last hop
		// rather than the path, and reporting a one-element AS path would be
		// an invented fact rather than a missing one.
		if origin := birdOriginRE.FindStringSubmatch(strings.TrimRight(raw, " \t")); len(origin) == 3 {
			path.Origin = birdOrigin(origin[2])
		}
		out = append(out, path)
		current = &out[len(out)-1]
	}
	return out
}

func birdHasNextHop(hops []netstate.NextHop, address string) bool {
	for _, hop := range hops {
		if hop.Address == address {
			return true
		}
	}
	return false
}

// birdOrigin normalizes BIRD's origin spelling onto FRR's.
func birdOrigin(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "igp", "i":
		return "IGP"
	case "egp", "e":
		return "EGP"
	case "incomplete", "?":
		return "incomplete"
	default:
		return ""
	}
}

func birdPathSource(protocol string) string {
	fields := strings.Fields(protocol)
	if len(fields) == 0 {
		return ""
	}
	name := strings.ToLower(fields[0])
	switch {
	case strings.HasPrefix(name, "ibgp"):
		return "internal"
	case strings.HasPrefix(name, "ebgp"):
		return "external"
	case strings.HasPrefix(name, "own"), strings.HasPrefix(name, "hijack"), strings.HasPrefix(name, "static"):
		return "local"
	default:
		return ""
	}
}

// birdCommunities normalizes BIRD's "(65001,100)" tuples onto the
// "65001:100" spelling every vendor-neutral check compares against.
//
// The old field split produced "65001,100", which matches no FRR community and
// therefore no community-based policy check. Large communities are printed with
// spaces inside the parentheses -- "(65001, 100, 200)" -- so the groups are
// read as parentheses rather than as whitespace-separated words.
func birdCommunities(raw string) []string {
	var out []string
	for _, group := range birdParenRE.FindAllStringSubmatch(raw, -1) {
		parts := strings.Split(group[1], ",")
		values := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				values = append(values, part)
			}
		}
		if len(values) > 0 {
			out = append(out, strings.Join(values, ":"))
		}
	}
	if len(out) > 0 {
		return out
	}
	// Well-known communities are printed by name and carry no parentheses.
	for _, field := range strings.Fields(strings.Trim(strings.TrimSpace(raw), "[]")) {
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

// birdBGPState normalizes the protocol table's State column, using the Info
// column when BIRD supplied one.
//
// The State column is the generic protocol state -- up, down, start, stop --
// and mapping "start" to Established would report a session that is still
// trying to connect as established. Info carries the BGP FSM state, which is
// the fact a check about sessions is actually about.
func birdBGPState(state string, rest []string) string {
	for _, field := range rest {
		if normalized := birdKnownBGPState(field); normalized != "" {
			return normalized
		}
	}
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "up":
		return "Established"
	case "down", "stop":
		return "Idle"
	case "start":
		return "Active"
	default:
		return state
	}
}

func birdNormalizeBGPState(state string) string {
	if normalized := birdKnownBGPState(state); normalized != "" {
		return normalized
	}
	return state
}

// birdKnownBGPState maps a BGP FSM state onto FRR's spelling of it, so a check
// can compare states without knowing which NOS answered.
func birdKnownBGPState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "established":
		return "Established"
	case "idle":
		return "Idle"
	case "active":
		return "Active"
	case "connect":
		return "Connect"
	case "opensent":
		return "OpenSent"
	case "openconfirm":
		return "OpenConfirm"
	case "close", "down":
		return "Idle"
	default:
		return ""
	}
}

// readBirdOSPF normalizes `birdc show ospf neighbors`.
//
// The columns are Router ID, Pri, State, DTime, Interface, Router IP. They used
// to be read as router-id, address, interface, state, so State received the
// priority, Interface received the state, and the state a check compares
// against "Full" received the neighbour's address -- which is never "Full", so
// every BIRD adjacency read as not established. It went unnoticed only because
// the shipped labs give their BIRD ASes one router each and no adjacency.
func readBirdOSPF(ctx context.Context, d *model.Device, exec netstate.Executor) ([]netstate.OSPFPeer, error) {
	raw, err := birdCommand(ctx, d, exec, "show", "ospf", "neighbors")
	if err != nil {
		return nil, err
	}
	return parseBirdOSPFNeighbors(raw), nil
}

func parseBirdOSPFNeighbors(raw string) []netstate.OSPFPeer {
	var out []netstate.OSPFPeer
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		switch {
		case len(fields) < 5:
			// The "BIRD x.y ready." banner, a blank line, or the "ospf4:"
			// protocol heading that birdc prints above each instance.
			continue
		case strings.EqualFold(fields[0], "Router") && strings.EqualFold(fields[1], "ID"):
			continue
		}
		peer := netstate.OSPFPeer{
			RouterID: fields[0], State: fields[2], Interface: fields[4],
		}
		if len(fields) >= 6 {
			peer.Address = fields[5]
		}
		if msec, ok := birdDeadTime(fields[3]); ok {
			peer.DeadTimerMsec = msec
		} else {
			peer.MarkUnknown(netstate.FieldDeadTimer)
		}
		out = append(out, peer)
	}
	return out
}

// birdDeadTime reads BIRD's remaining dead time, printed as mm:ss or hh:mm:ss.
func birdDeadTime(value string) (int64, bool) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, false
	}
	var seconds int64
	for _, part := range parts {
		unit, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return 0, false
		}
		seconds = seconds*60 + unit
	}
	return seconds * 1000, true
}

// readBirdPolicy reports the filters a BIRD router actually binds to a peer.
//
// A bare list of filter names says only that the student wrote one. The FRR
// provider reports which route-map is attached to which neighbour in which
// direction, so a portable policy check can ask the same question of both: the
// protocol block is scanned for its neighbour address and its per-channel
// import/export filters, and the pair is reported the way FRR reports a
// `neighbor X route-map NAME in`.
func readBirdPolicy(ctx context.Context, d *model.Device, exec netstate.Executor) ([]netstate.PolicyFact, error) {
	res, err := exec.Exec(ctx, d.ID, []string{"cat", birdConfigPath})
	if err != nil {
		return nil, fmt.Errorf("read BIRD policy on %s: %w", d.ID, err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("read BIRD policy on %s: cat exited %d: %s",
			d.ID, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return parseBirdPolicy(res.Stdout), nil
}

var (
	birdProtocolRE = regexp.MustCompile(`^protocol\s+bgp\s+(\S+)`)
	birdPeerRE     = regexp.MustCompile(`^neighbor\s+([0-9a-fA-F:.]+)`)
	birdFilterRE   = regexp.MustCompile(`\b(import|export)\s+filter\s+([A-Za-z0-9_]+)`)
)

func parseBirdPolicy(body string) []netstate.PolicyFact {
	var out []netstate.PolicyFact
	var declared []string
	type binding struct {
		name, direction string
	}
	var protocol string
	var peer string
	var bindings []binding
	flush := func() {
		for _, bind := range bindings {
			out = append(out, netstate.PolicyFact{
				Name: bind.name, Peer: peer, Direction: bind.direction,
			})
		}
		protocol, peer, bindings = "", "", nil
	}
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if index := strings.Index(line, "#"); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "filter" {
			declared = append(declared, strings.TrimSuffix(fields[1], "{"))
			continue
		}
		if matches := birdProtocolRE.FindStringSubmatch(line); len(matches) == 2 {
			flush()
			protocol = matches[1]
			continue
		}
		if protocol == "" {
			continue
		}
		if matches := birdPeerRE.FindStringSubmatch(line); len(matches) == 2 {
			peer = matches[1]
		}
		for _, matches := range birdFilterRE.FindAllStringSubmatch(line, -1) {
			bindings = append(bindings, binding{name: matches[2], direction: matches[1]})
		}
		if line == "}" {
			flush()
		}
	}
	flush()
	// A filter the student declared but bound to nothing is still a fact about
	// the configuration, reported without a peer exactly as before.
	bound := map[string]bool{}
	for _, fact := range out {
		bound[fact.Name] = true
	}
	for _, name := range declared {
		if !bound[name] {
			out = append(out, netstate.PolicyFact{Name: name})
		}
	}
	return out
}

// RefreshBGP asks BIRD to re-import from its neighbours.
//
// BIRD names protocols rather than peer addresses, and `reload in all` is the
// portable spelling of "ask everyone again": it sends a ROUTE-REFRESH on every
// session that negotiated the capability, which is exactly the message the
// eBGP check needs to cross the wire while it is watching. It deliberately
// does not use the restricted socket mode, which permits only show commands.
func (birdProvider) RefreshBGP(d *model.Device, neighbors []string) [][]string {
	if d == nil || len(neighbors) == 0 {
		return nil
	}
	return [][]string{{"birdc", "-s", birdSocketPath, "reload", "in", "all"}}
}
