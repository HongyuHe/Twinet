package cli

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// An evaluated agent gets a network with exactly two things on it: the node
// agents it must reach to observe the lab, and whatever the operator has
// explicitly allowed.
//
// It used to get the machine's own network. Masking the scenario file, the lab
// directory and the repository stopped the agent reading the answer locally,
// and the answer was on the internet: the example scenarios are published in a
// public repository, and each one names the fault, the device and the interface
// in plain YAML. An agent whose whole strategy was to fetch its own brief's
// repository over HTTPS scored a perfect 1.00 without asking a router anything.
// The same channel would let an agent exfiltrate a lab, or reach anything else
// this cluster can reach, on the strength of being handed a shell.
//
// So the agent runs in a network namespace of its own, joined to the host by
// one link, with a firewall that permits the node agents' addresses and ports
// and rejects everything else. There is no route to the internet, no DNS, and
// nothing to be reached by accident. Names the agent needs are resolved before
// it starts and given to it as a hosts file, so blocking DNS costs it nothing.
type agentNetwork struct {
	NS      string
	HostDev string
	HostIP  string
	AgentIP string
	Chain   string
	Allowed []string

	// hostsDir is the per-namespace /etc overlay, removed on close.
	hostsDir string
	// cleanup is run in reverse order, so a half-built network leaves nothing.
	cleanup []func()
}

// egressEndpoint is one place the agent may talk to.
type egressEndpoint struct {
	IP   string
	Port int
}

func (e egressEndpoint) String() string { return net.JoinHostPort(e.IP, strconv.Itoa(e.Port)) }

// newAgentNetwork builds the namespace, the link and the firewall.
//
// The allowed set is derived from the lab rather than configured, because an
// operator cannot be expected to keep a firewall in step with a placement: the
// agent must reach the node agents named in the manifest and nothing else
// follows from the lab. Anything further is the operator's explicit decision,
// passed as --allow-egress and recorded in the episode, so a published score
// says what the agent could reach while it earned it.
func newAgentNetwork(top *model.Topology, extra []string) (n *agentNetwork, err error) {
	if !haveTool("ip") || !haveTool("iptables") {
		return nil, fmt.Errorf("evaluating an agent needs ip and iptables: without them the " +
			"agent has this machine's network, and the scenarios it is being asked to " +
			"diagnose are published on the internet")
	}
	endpoints, names, err := agentEgress(top, extra)
	if err != nil {
		return nil, err
	}

	id := fmt.Sprintf("%06x", rand.Intn(1<<24))
	n = &agentNetwork{
		NS:      "twrca" + id,
		HostDev: "twrca" + id[:4],
		Chain:   "TWNET_RCA_" + strings.ToUpper(id),
	}
	defer func() {
		if err != nil {
			n.Close()
			n = nil
		}
	}()

	// A /30 out of the link-local range, which nothing in a lab uses: labs
	// address out of the plan's own blocks and the underlay is the operator's.
	octet, err := freeLinkLocal()
	if err != nil {
		return nil, err
	}
	n.HostIP = fmt.Sprintf("169.254.%d.1", octet)
	n.AgentIP = fmt.Sprintf("169.254.%d.2", octet)

	if err := run("ip", "netns", "add", n.NS); err != nil {
		return nil, fmt.Errorf("create the agent's network namespace: %w", err)
	}
	n.onClose(func() { _ = run("ip", "netns", "del", n.NS) })

	if err := run("ip", "link", "add", n.HostDev, "type", "veth", "peer", "name", "agent0",
		"netns", n.NS); err != nil {
		return nil, fmt.Errorf("link the agent's namespace to this machine: %w", err)
	}
	n.onClose(func() { _ = run("ip", "link", "del", n.HostDev) })

	steps := [][]string{
		{"ip", "addr", "add", n.HostIP + "/30", "dev", n.HostDev},
		{"ip", "link", "set", n.HostDev, "up"},
		{"ip", "netns", "exec", n.NS, "ip", "link", "set", "lo", "up"},
		{"ip", "netns", "exec", n.NS, "ip", "addr", "add", n.AgentIP + "/30", "dev", "agent0"},
		{"ip", "netns", "exec", n.NS, "ip", "link", "set", "agent0", "up"},
		{"ip", "netns", "exec", n.NS, "ip", "route", "add", "default", "via", n.HostIP},
	}
	for _, s := range steps {
		if err := run(s[0], s[1:]...); err != nil {
			return nil, fmt.Errorf("configure the agent's network (%s): %w", strings.Join(s, " "), err)
		}
	}

	// Forwarding is what carries the agent's observations to the other nodes.
	// It is normally already on wherever containers run; turning it on is not
	// undone, because turning it off again would break the machine.
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)

	if err := n.firewall(endpoints); err != nil {
		return nil, err
	}
	if err := n.writeHosts(names); err != nil {
		return nil, err
	}
	for _, e := range endpoints {
		n.Allowed = append(n.Allowed, e.String())
	}
	sort.Strings(n.Allowed)
	return n, nil
}

// firewall installs the one rule that matters -- reject -- and the exceptions
// the agent's work requires.
func (n *agentNetwork) firewall(endpoints []egressEndpoint) error {
	if err := run("iptables", "-N", n.Chain); err != nil {
		return fmt.Errorf("create the agent's firewall chain: %w", err)
	}
	n.onClose(func() { _ = run("iptables", "-X", n.Chain) })
	n.onClose(func() { _ = run("iptables", "-F", n.Chain) })

	rules := [][]string{
		{"-A", n.Chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
	for _, e := range endpoints {
		rules = append(rules, []string{"-A", n.Chain, "-p", "tcp", "-d", e.IP,
			"--dport", strconv.Itoa(e.Port), "-j", "ACCEPT"})
	}
	// Rejected rather than dropped: an agent that has been told no can spend
	// its time on the network instead of on a connect timeout, and a refusal
	// is visible in its transcript, which is where a reader should see it.
	rules = append(rules, []string{"-A", n.Chain, "-j", "REJECT",
		"--reject-with", "icmp-admin-prohibited"})
	for _, r := range rules {
		if err := run("iptables", r...); err != nil {
			return fmt.Errorf("install the agent's firewall: %w", err)
		}
	}
	// Both paths out of the namespace: INPUT is this machine's own services,
	// FORWARD is everything beyond it.
	for _, hook := range []string{"INPUT", "FORWARD"} {
		if err := run("iptables", "-I", hook, "1", "-s", n.AgentIP, "-j", n.Chain); err != nil {
			return fmt.Errorf("hook the agent's firewall into %s: %w", hook, err)
		}
		h := hook
		n.onClose(func() { _ = run("iptables", "-D", h, "-s", n.AgentIP, "-j", n.Chain) })
	}
	// The other nodes answer to this machine's address, not to a link-local
	// one they have no route back to.
	if err := run("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", n.AgentIP,
		"-j", "MASQUERADE"); err != nil {
		return fmt.Errorf("translate the agent's address: %w", err)
	}
	n.onClose(func() {
		_ = run("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", n.AgentIP, "-j", "MASQUERADE")
	})
	return nil
}

// writeHosts gives the namespace the names it needs and no resolver.
//
// `ip netns exec` bind-mounts /etc/netns/<ns>/hosts over /etc/hosts, so the
// agent can resolve the node agents by the names the manifest uses without a
// DNS server it is not allowed to reach.
func (n *agentNetwork) writeHosts(names map[string]string) error {
	dir := filepath.Join("/etc/netns", n.NS)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	n.hostsDir = dir
	n.onClose(func() { _ = os.RemoveAll(dir) })
	var b strings.Builder
	b.WriteString("127.0.0.1\tlocalhost\n::1\tlocalhost\n")
	keys := make([]string, 0, len(names))
	for k := range names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s\t%s\n", names[k], k)
	}
	return os.WriteFile(filepath.Join(dir, "hosts"), []byte(b.String()), 0o644)
}

// Wrap turns a command into the same command inside the agent's network.
func (n *agentNetwork) Wrap(argv []string) []string {
	if n == nil {
		return argv
	}
	return append([]string{"ip", "netns", "exec", n.NS}, argv...)
}

func (n *agentNetwork) onClose(f func()) { n.cleanup = append(n.cleanup, f) }

// Close removes the namespace, the link and every firewall rule.
func (n *agentNetwork) Close() {
	if n == nil {
		return
	}
	for i := len(n.cleanup) - 1; i >= 0; i-- {
		n.cleanup[i]()
	}
	n.cleanup = nil
}

// agentEgress works out what the agent is allowed to reach: the node agents
// from the placement, plus the operator's explicit additions.
func agentEgress(top *model.Topology, extra []string) ([]egressEndpoint, map[string]string, error) {
	seen := map[string]bool{}
	names := map[string]string{}
	var out []egressEndpoint
	add := func(spec, why string) error {
		host, portStr, err := net.SplitHostPort(spec)
		if err != nil {
			return fmt.Errorf("%s %q: expected host:port: %w", why, spec, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("%s %q: %q is not a port", why, spec, portStr)
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("%s %q: %w", why, spec, err)
		}
		found := false
		for _, ip := range ips {
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			found = true
			if net.ParseIP(host) == nil {
				names[host] = v4.String()
			}
			e := egressEndpoint{IP: v4.String(), Port: port}
			if !seen[e.String()] {
				seen[e.String()] = true
				out = append(out, e)
			}
		}
		if !found {
			return fmt.Errorf("%s %q: no IPv4 address", why, spec)
		}
		return nil
	}
	if top != nil && top.Lab != nil {
		for _, nd := range top.Lab.Placement.Nodes {
			if nd.Addr == "" {
				continue
			}
			if err := add(nd.Addr, "node"); err != nil {
				return nil, nil, err
			}
		}
	}
	for _, e := range extra {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if err := add(e, "--allow-egress"); err != nil {
			return nil, nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, names, nil
}

// freeLinkLocal picks a /30 no route on this machine already covers, so two
// episodes running at once do not land on the same addresses.
func freeLinkLocal() (int, error) {
	taken := map[int]bool{}
	if out, err := exec.Command("ip", "-4", "route", "show").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || !strings.HasPrefix(f[0], "169.254.") {
				continue
			}
			parts := strings.Split(strings.SplitN(f[0], "/", 2)[0], ".")
			if len(parts) == 4 {
				if v, err := strconv.Atoi(parts[2]); err == nil {
					taken[v] = true
				}
			}
		}
	}
	start := rand.Intn(254) + 1
	for i := 0; i < 254; i++ {
		c := (start+i)%254 + 1
		if !taken[c] {
			return c, nil
		}
	}
	return 0, fmt.Errorf("no free link-local /30 for the agent's network")
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err,
			strings.TrimSpace(string(out)))
	}
	return nil
}
