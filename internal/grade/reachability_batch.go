package grade

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/HongyuHe/twinet/internal/model"
)

// reachabilityProbe is one directed internal data-plane observation.
type reachabilityProbe struct {
	from, to *model.Device
	srcIface string
}

// batchedPingFailures runs all probes from one source in one agent-side shell.
// It returns complete=false whenever a source could not prove every individual
// command ran; callers then use the slower per-pair path rather than treating
// a missing marker as a failed network.
func batchedPingFailures(ctx context.Context, env *Env, probes []reachabilityProbe,
	addresses map[string]string,
) (failed []string, complete bool) {
	bySource := map[string][]int{}
	for index, probe := range probes {
		if _, err := netip.ParseAddr(addresses[probe.to.ID]); err != nil {
			return nil, false
		}
		key := probe.from.ID + "\x00" + probe.srcIface
		bySource[key] = append(bySource[key], index)
	}
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		ok      = true
		results = make(map[int]bool, len(probes))
	)
	for _, indexes := range bySource {
		indexes := append([]int(nil), indexes...)
		wg.Add(1)
		go func() {
			defer wg.Done()
			var body strings.Builder
			for _, index := range indexes {
				probe := probes[index]
				args := "ping -c 2 -W 2 -i 0.2"
				if probe.srcIface != "" {
					args += " -I " + shellWord(probe.srcIface)
				}
				fmt.Fprintf(&body, "( %s %s >/dev/null 2>&1; echo '@ %d '$? ) &\n",
					args, addresses[probe.to.ID], index)
			}
			body.WriteString("wait\n")
			res, err := env.Probe(ctx, probes[indexes[0]].from.ID, []string{"sh", "-c", body.String()})
			if err != nil || res.ExitCode != 0 {
				mu.Lock()
				ok = false
				mu.Unlock()
				return
			}
			seen := map[int]bool{}
			for _, line := range strings.Split(res.Stdout, "\n") {
				fields := strings.Fields(line)
				if len(fields) != 3 || fields[0] != "@" {
					continue
				}
				index, ierr := strconv.Atoi(fields[1])
				code, cerr := strconv.Atoi(fields[2])
				if ierr != nil || cerr != nil {
					continue
				}
				seen[index] = true
				mu.Lock()
				results[index] = code == 0
				mu.Unlock()
			}
			for _, index := range indexes {
				if !seen[index] {
					mu.Lock()
					ok = false
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()
	if !ok {
		return nil, false
	}
	for index, probe := range probes {
		if results[index] {
			continue
		}
		from := probe.from.Name
		if probe.srcIface != "" {
			from = probe.from.ID + " (the " + probe.from.Name + " network)"
		}
		failed = append(failed, fmt.Sprintf("%s cannot reach %s (%s)",
			from, probe.to.Name, addresses[probe.to.ID]))
	}
	sort.Strings(failed)
	return failed, true
}

// legacyPingFailures retains the original per-pair evidence path for a batch
// whose source shell could not account for every command.
func legacyPingFailures(ctx context.Context, env *Env, probes []reachabilityProbe,
	addresses map[string]string,
) []string {
	var (
		mu     sync.Mutex
		failed []string
		wg     sync.WaitGroup
	)
	sem := make(chan struct{}, 16)
	for _, probe := range probes {
		probe := probe
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			args := []string{"ping", "-c", "2", "-W", "2", "-i", "0.2"}
			if probe.srcIface != "" {
				args = append(args, "-I", probe.srcIface)
			}
			args = append(args, addresses[probe.to.ID])
			res, err := env.Probe(ctx, probe.from.ID, args)
			if err == nil && res.ExitCode == 0 {
				return
			}
			from := probe.from.Name
			if probe.srcIface != "" {
				from = probe.from.ID + " (the " + probe.from.Name + " network)"
			}
			mu.Lock()
			failed = append(failed, fmt.Sprintf("%s cannot reach %s (%s)",
				from, probe.to.Name, addresses[probe.to.ID]))
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Strings(failed)
	return failed
}

// batchedTransportVerified verifies every TCP and UDP pair with one capture
// per destination and one source-side agent exec per host. Captures identify
// each attempt by a unique source port; aggregate kernel counters ensure that
// frames observed at an interface were delivered to the destination kernel.
//
// Any ambiguity falls back to the established per-pair witnesses. The fast
// path therefore changes only scheduling on healthy networks, not the evidence
// standard or the way a wrong submission is detected.
func batchedTransportVerified(ctx context.Context, env *Env, hosts []*model.Device,
	addresses map[string]string,
) bool {
	attempts, ok := makeTransportAttempts(hosts, addresses)
	if !ok || len(attempts) == 0 {
		return false
	}
	return batchedTCPVerified(ctx, env, attempts) && batchedUDPVerified(ctx, env, attempts)
}

type transportAttempt struct {
	index                int
	from, to             *model.Device
	address              string
	sourcePort, destPort string
}

func makeTransportAttempts(hosts []*model.Device, addresses map[string]string) ([]transportAttempt, bool) {
	ports := map[string]string{}
	used := map[string]bool{}
	nextPort := func() string {
		for {
			port := probePort()
			if !used[port] {
				used[port] = true
				return port
			}
		}
	}
	for _, host := range hosts {
		if _, err := netip.ParseAddr(addresses[host.ID]); err != nil {
			return nil, false
		}
		ports[host.ID] = nextPort()
	}
	var out []transportAttempt
	for _, from := range hosts {
		for _, to := range hosts {
			if from.ID == to.ID {
				continue
			}
			out = append(out, transportAttempt{
				index: len(out), from: from, to: to, address: addresses[to.ID],
				sourcePort: nextPort(), destPort: ports[to.ID],
			})
		}
	}
	return out, true
}

func batchedTCPVerified(ctx context.Context, env *Env, attempts []transportAttempt) bool {
	before := tcpAnswerBatch(ctx, env, attempts)
	taps := startTransportTaps(ctx, env, attempts)
	sent, complete := sendTransportBatch(ctx, env, attempts, false)
	after := tcpAnswerBatch(ctx, env, attempts)
	readings := readTransportTapFlows(ctx, env, taps)
	return transportBatchVerified(attempts, sent, complete, before, after, readings, 1)
}

func batchedUDPVerified(ctx context.Context, env *Env, attempts []transportAttempt) bool {
	before := udpAnswerBatch(ctx, env, attempts)
	taps := startTransportTaps(ctx, env, attempts)
	sent, complete := sendTransportBatch(ctx, env, attempts, true)
	after := udpAnswerBatch(ctx, env, attempts)
	readings := readTransportTapFlows(ctx, env, taps)
	return transportBatchVerified(attempts, sent, complete, before, after, readings, datagramAttempts)
}

func startTransportTaps(ctx context.Context, env *Env, attempts []transportAttempt) map[string]*arrivalTap {
	ports := map[string]string{}
	for _, attempt := range attempts {
		ports[attempt.to.ID] = attempt.destPort
	}
	return startTaps(ctx, env, ports)
}

func tcpAnswerBatch(ctx context.Context, env *Env, attempts []transportAttempt) map[string]counterWitness {
	unique := transportDestinations(attempts)
	out := map[string]counterWitness{}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, destination := range unique {
		destination := destination
		wg.Add(1)
		go func() {
			defer wg.Done()
			if value, ok := tcpAnswers(ctx, env, destination); ok {
				mu.Lock()
				out[destination] = value
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

func udpAnswerBatch(ctx context.Context, env *Env, attempts []transportAttempt) map[string]counterWitness {
	unique := transportDestinations(attempts)
	out := map[string]counterWitness{}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, destination := range unique {
		destination := destination
		wg.Add(1)
		go func() {
			defer wg.Done()
			if value, ok := udpNoPortsV4(ctx, env, destination); ok {
				mu.Lock()
				out[destination] = value
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

func transportDestinations(attempts []transportAttempt) []string {
	seen := map[string]bool{}
	var out []string
	for _, attempt := range attempts {
		if !seen[attempt.to.ID] {
			seen[attempt.to.ID] = true
			out = append(out, attempt.to.ID)
		}
	}
	sort.Strings(out)
	return out
}

type transportTapReading struct {
	counts tapCounts
	ports  map[string]int
	live   bool
}

func readTransportTapFlows(ctx context.Context, env *Env,
	taps map[string]*arrivalTap,
) map[string]transportTapReading {
	out := map[string]transportTapReading{}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for device, tap := range taps {
		device, tap := device, tap
		wg.Add(1)
		go func() {
			defer wg.Done()
			counts, ports, live := tap.seenFlows(ctx, env)
			mu.Lock()
			out[device] = transportTapReading{counts: counts, ports: ports, live: live}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

func sendTransportBatch(ctx context.Context, env *Env, attempts []transportAttempt, udp bool) (map[int]bool, bool) {
	bySource := map[string][]transportAttempt{}
	for _, attempt := range attempts {
		bySource[attempt.from.ID] = append(bySource[attempt.from.ID], attempt)
	}
	sent := map[int]bool{}
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		complete = true
	)
	for source, group := range bySource {
		source, group := source, append([]transportAttempt(nil), group...)
		wg.Add(1)
		go func() {
			defer wg.Done()
			var body strings.Builder
			for _, attempt := range group {
				if udp {
					src := firstAddr(attempt.from)
					if _, err := netip.ParseAddr(src); err != nil {
						mu.Lock()
						complete = false
						mu.Unlock()
						return
					}
					fmt.Fprintf(&body, `( n=0; for x in 1 2 3; do e=$(printf twinet | nc -u -w 1 -s %s -p %s %s %s 2>&1); [ -z "$e" ] && n=$((n+1)); done; if [ "$n" -gt 0 ]; then echo "@ %d sent"; else echo "@ %d unsent"; fi ) &`+"\n",
						src, attempt.sourcePort, attempt.address, attempt.destPort, attempt.index, attempt.index)
					continue
				}
				fmt.Fprintf(&body, `( e=$(nc -v -w 3 -z -p %s %s %s 2>&1); case "$e" in *bind*) echo "@ %d unsent";; *) echo "@ %d sent";; esac ) &`+"\n",
					attempt.sourcePort, attempt.address, attempt.destPort, attempt.index, attempt.index)
			}
			body.WriteString("wait\n")
			res, err := env.Probe(ctx, source, []string{"sh", "-c", body.String()})
			if err != nil || res.ExitCode != 0 {
				mu.Lock()
				complete = false
				mu.Unlock()
				return
			}
			seen := map[int]bool{}
			for _, line := range strings.Split(res.Stdout, "\n") {
				fields := strings.Fields(line)
				if len(fields) != 3 || fields[0] != "@" {
					continue
				}
				index, err := strconv.Atoi(fields[1])
				if err != nil {
					continue
				}
				seen[index] = true
				mu.Lock()
				sent[index] = fields[2] == "sent"
				mu.Unlock()
			}
			for _, attempt := range group {
				if !seen[attempt.index] {
					mu.Lock()
					complete = false
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()
	return sent, complete
}

func transportBatchVerified(attempts []transportAttempt, sent map[int]bool, complete bool,
	before, after map[string]counterWitness, readings map[string]transportTapReading, packetsPerAttempt int,
) bool {
	if !complete {
		return false
	}
	expected := map[string]int{}
	captured := map[string]int{}
	for _, attempt := range attempts {
		if !sent[attempt.index] {
			return false
		}
		expected[attempt.to.ID]++
		reading, ok := readings[attempt.to.ID]
		if !ok || !reading.live || reading.ports[attempt.sourcePort] == 0 {
			return false
		}
		// Source ports are unique over this batch, so a frame on one is
		// evidence for this exact ordered pair rather than merely this host.
		captured[attempt.to.ID]++
	}
	for destination, count := range expected {
		b, okB := before[destination]
		a, okA := after[destination]
		if !okB || !okA || captured[destination] != count ||
			offBoxDelta(b, a) < count*packetsPerAttempt {
			return false
		}
	}
	return true
}

func shellWord(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
