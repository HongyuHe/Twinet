package fault

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// aclBlock describes one protocol a firewall rule can silently discard.
//
// These are grouped because they are the same fault wearing different clothes,
// and because the interesting part is not the rule but what the operator sees:
// a dropped BGP session looks like a peering problem, dropped OSPF looks like a
// link problem, dropped ARP looks like a dead neighbour, and dropped HTTP looks
// like a broken server. The diagnosis has to run backwards from four very
// different symptoms to the same cause.
type aclBlock struct {
	name     string
	match    string
	symptom  string
	describe string
	needs    []Capability
}

func init() {
	blocks := []aclBlock{
		{
			name:     "icmp_acl_block",
			match:    "-p icmp --icmp-type echo-request",
			symptom:  "Some destinations do not respond to ping, though other traffic works.",
			describe: "A firewall rule discards ICMP echo requests.",
			needs:    []Capability{CapNFT},
		},
		{
			name:     "bgp_acl_block",
			match:    "-p tcp --dport 179",
			symptom:  "A router's peering sessions will not come up, though the links are fine.",
			describe: "A firewall rule discards BGP's TCP port, so sessions never establish.",
			needs:    []Capability{CapNFT, CapFRR},
		},
		{
			name:     "ospf_acl_block",
			match:    "-p ospf",
			symptom:  "Routers on one segment do not learn each other's internal routes.",
			describe: "A firewall rule discards OSPF, so adjacencies never form.",
			needs:    []Capability{CapNFT, CapFRR},
		},
		{
			name:     "http_acl_block",
			match:    "-p tcp --dport 80",
			symptom:  "A web service is unreachable, though the host answers ping.",
			describe: "A firewall rule discards HTTP, so connections are never accepted.",
			needs:    []Capability{CapNFT},
		},
	}

	for _, b := range blocks {
		b := b
		Register(&Fault{
			Name: b.name, Category: CatMisconfig, Needs: b.needs,
			Symptom: b.symptom, Describe: b.describe,
			Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
				return injectACL(ctx, e, t, b.match)
			},
			Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
				return verifyACL(ctx, e, t, s)
			},
			Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
				return resolveACL(ctx, e, t, s)
			},
		})
	}

	// ARP is not IP, so iptables cannot see it. It is filtered at the link
	// layer instead, which is a different mechanism for the same effect: the
	// neighbour stops resolving and every address on the segment goes quiet
	// while the interface itself stays up.
	Register(&Fault{
		Name: "arp_acl_block", Category: CatMisconfig, Needs: []Capability{CapInterface},
		Symptom:  "A host cannot reach anything on its own segment, though the link is up.",
		Describe: "Address resolution is disabled on an interface, so no neighbour can be resolved.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return nil, err
			}
			// noarp on the device rather than a filter: busybox images have no
			// arptables and ebtables is not in every base, so a rule-based
			// version would fail on exactly the hosts the fault is aimed at.
			if _, err := e.Sh(ctx, t.DeviceID(),
				fmt.Sprintf("ip link set %s arp off", iface)); err != nil {
				return nil, err
			}
			return State{"iface": iface}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _, err := e.TryE(ctx, t.DeviceID(),
				fmt.Sprintf("ip -o link show %s", s["iface"]))
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{
				Verified: strings.Contains(out, "NOARP"),
				Expected: "address resolution disabled on " + s["iface"],
				Observed: firstLine(out),
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["iface"] == "" {
				return fmt.Errorf("no interface was recorded, so the fault cannot be undone")
			}
			_, err := e.Sh(ctx, t.DeviceID(),
				fmt.Sprintf("ip link set %s arp on", s["iface"]))
			return err
		},
	})
}

// injectACL installs a drop rule in both directions.
//
// INPUT alone is not enough for a routed protocol: a session the device
// initiates would still complete, and the fault would appear to work from one
// side and not the other, which is the kind of half-injected state that makes a
// benchmark case unreproducible.
func injectACL(ctx context.Context, e *Env, t Target, match string) (State, error) {
	chains := []string{"INPUT", "OUTPUT"}
	// Nothing distinguishing is written into the rule.
	//
	// It used to carry an iptables comment so that resolving could tell the
	// injected rule from an identical one a student had written. The value was
	// random, but the *presence* of a comment on a DROP rule is itself the
	// giveaway: anyone who has read this source -- which for an agent being
	// evaluated on root-cause analysis is the whole difficulty removed --
	// finds the injected rule instantly, and its match tells them the fault.
	//
	// The count is recorded instead. Adding one copy and later removing
	// exactly one copy leaves a student's own identical rule untouched, which
	// is the property the marker was there to provide, and leaves nothing in
	// the device to find.
	before := map[string]int{}
	for _, c := range chains {
		before[c] = countACL(ctx, e, t, c, match)
		// A rule that is already there means this fault changes nothing.
		//
		// The count was recorded and not acted on, so injecting onto a device
		// that already dropped this traffic appended a duplicate, verified
		// happily -- `iptables -C` finds either copy -- and produced an episode
		// whose ground truth named a cause that was not the reason anything
		// was broken. A benchmark is worth nothing if the fault it records was
		// not the change that caused the symptom.
		if before[c] > 0 {
			return nil, fmt.Errorf("%s already has a rule in %s dropping %q, so injecting "+
				"another would change nothing while claiming to be the cause",
				t.DeviceID(), c, match)
		}
	}

	var installed []string
	for _, c := range chains {
		if _, err := e.Sh(ctx, t.DeviceID(),
			fmt.Sprintf("iptables -w -A %s %s -j DROP", c, match)); err != nil {
			// Roll back whatever was installed, or the device is left in a
			// state that is neither faulted nor clean.
			for _, done := range installed {
				_, _ = e.Try(ctx, t.DeviceID(),
					fmt.Sprintf("iptables -w -D %s %s -j DROP", done, match))
			}
			return nil, err
		}
		installed = append(installed, c)
	}

	st := State{"match": match, "chains": strings.Join(chains, " ")}
	for _, c := range chains {
		st["before/"+c] = strconv.Itoa(before[c])
	}
	return st, nil
}

// countACL counts how many rules in a chain drop this match.
func countACL(ctx context.Context, e *Env, t Target, chain, match string) int {
	// Counted by what the rule looks like once installed, not by the text that
	// installs it.
	//
	// A rule added as "-p icmp --icmp-type echo-request" is listed as
	// "-p icmp -m icmp --icmp-type 8", so searching for the input form matched
	// nothing: the count was always zero, and the guard that refuses to inject
	// onto a device already dropping this traffic never fired.
	out, code := e.Try(ctx, t.DeviceID(),
		fmt.Sprintf("iptables -w -S %s 2>/dev/null", chain))
	if code != 0 {
		return -1
	}
	want := specTokens(match)
	n := 0
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "-A ") || !strings.HasSuffix(t, "-j DROP") {
			continue
		}
		all := true
		for _, w := range want {
			if !strings.Contains(t, w) {
				all = false
				break
			}
		}
		if all {
			n++
		}
	}
	return n
}

func shellQuoteFault(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func verifyACL(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
	var missing []string
	for _, c := range strings.Fields(s["chains"]) {
		if _, code := e.Try(ctx, t.DeviceID(),
			fmt.Sprintf("iptables -w -C %s %s -j DROP", c, s["match"])); code != 0 {
			missing = append(missing, c)
		}
	}
	return Evidence{
		Verified: len(missing) == 0,
		Expected: fmt.Sprintf("a rule dropping %q in %s", s["match"], s["chains"]),
		Observed: describeACL(missing, s["chains"]),
	}, nil
}

func resolveACL(ctx context.Context, e *Env, t Target, s State) error {
	if s["match"] == "" {
		return fmt.Errorf("this fault's rule was not recorded, so it cannot be removed "+
			"without guessing (device %s)", t.DeviceID())
	}
	for _, c := range strings.Fields(s["chains"]) {
		// The rule is removed by position, not by specification.
		//
		// `iptables -D <chain> <spec>` deletes the *first* rule matching the
		// specification. The injected rule is appended, so if the device
		// already had an identical one, deleting by specification removes the
		// student's and leaves ours -- and the counts still match, so nothing
		// notices. Deleting the last matching position removes the one that
		// was added.
		pos := lastMatchingRule(ctx, e, t, c, s["match"])
		if pos <= 0 {
			// Already gone is not a failure; the checks below decide.
			continue
		}
		if _, code := e.Try(ctx, t.DeviceID(),
			fmt.Sprintf("iptables -w -D %s %d", c, pos)); code != 0 {
			continue
		}
		want, err := strconv.Atoi(s["before/"+c])
		if err != nil {
			continue
		}
		if got := countACL(ctx, e, t, c, s["match"]); got >= 0 && got != want {
			return fmt.Errorf("%s now has %d rule(s) dropping %q, and had %d before the "+
				"fault was injected", c, got, s["match"], want)
		}
	}
	return nil
}

func describeACL(missing []string, chains string) string {
	if len(missing) == 0 {
		return fmt.Sprintf("the rule is present in %s", chains)
	}
	return "the rule is absent from " + strings.Join(missing, " and ")
}

// lastMatchingRule returns the position of the last rule in a chain that drops
// this match, or 0 if there is none.
//
// Position rather than specification, because two identical rules are
// indistinguishable by specification and the injected one is always the later.
func lastMatchingRule(ctx context.Context, e *Env, t Target, chain, match string) int {
	out, code := e.Try(ctx, t.DeviceID(),
		fmt.Sprintf("iptables -w -S %s 2>/dev/null", chain))
	if code != 0 {
		return 0
	}
	return lastMatchingPosition(out, chain, specTokens(match))
}

// lastMatchingPosition returns the position of the last DROP rule in a chain
// that mentions every one of the given values.
//
// It reads `iptables -S`, not `iptables -L`. The human listing renders the
// protocol as a number -- an OSPF rule appears as "89", not "ospf" -- so
// matching the specification against it failed for every rule named by
// protocol, and the fault could not be removed at all. `-S` prints rules in
// the same syntax they were added with, and the Nth "-A <chain>" line is
// rule N.
func lastMatchingPosition(out, chain string, want []string) int {
	n, last := 0, 0
	prefix := "-A " + chain + " "
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, prefix) {
			continue
		}
		n++
		if !strings.HasSuffix(t, "-j DROP") {
			continue
		}
		all := true
		for _, w := range want {
			if !strings.Contains(t, w) {
				all = false
				break
			}
		}
		if all {
			last = n
		}
	}
	return last
}

// specTokens reduces an iptables specification to the values that also appear
// in a rule listing: addresses and protocol names, not option flags.
func specTokens(spec string) []string {
	var out []string
	f := strings.Fields(spec)
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "-p", "-s", "-d":
			if i+1 < len(f) {
				out = append(out, f[i+1])
				i++
			}
		}
	}
	return out
}
