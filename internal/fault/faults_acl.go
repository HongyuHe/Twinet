package fault

import (
	"context"
	"fmt"
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
	// A rule identical to one the student already wrote cannot be told apart
	// from it, and resolving used to delete every copy: the injection removed
	// the student's own firewall rule and the baseline check did not notice,
	// because it compares sets of lines and a duplicate line is one line.
	//
	// The injected rule therefore carries a comment nobody else will have
	// written. The value is random per injection and recorded only in the
	// controller, so it identifies the rule without announcing what it is.
	mark, err := randomCookie()
	if err != nil {
		return nil, err
	}
	tag := fmt.Sprintf("-m comment --comment %s", strings.TrimPrefix(mark, "0x"))
	for _, c := range chains {
		if _, err := e.Sh(ctx, t.DeviceID(),
			fmt.Sprintf("iptables -w -A %s %s %s -j DROP", c, match, tag)); err != nil {
			// Roll back whatever was installed, or the device is left in a
			// state that is neither faulted nor clean.
			for _, done := range chains {
				_, _ = e.Sh(ctx, t.DeviceID(),
					fmt.Sprintf("iptables -w -D %s %s %s -j DROP 2>/dev/null || true", done, match, tag))
			}
			return nil, err
		}
	}
	return State{"match": match, "tag": tag, "chains": strings.Join(chains, " ")}, nil
}

func verifyACL(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
	var missing []string
	for _, c := range strings.Fields(s["chains"]) {
		if _, code := e.Try(ctx, t.DeviceID(),
			fmt.Sprintf("iptables -w -C %s %s %s -j DROP", c, s["match"], s["tag"])); code != 0 {
			missing = append(missing, c)
		}
	}
	return Evidence{
		Verified: len(missing) == 0,
		Expected: fmt.Sprintf("a rule dropping %q in %s", s["match"], s["chains"]),
		Observed: describeACL(missing, s["chains"]),
	}, nil
}

func describeACL(missing []string, chains string) string {
	if len(missing) == 0 {
		return fmt.Sprintf("the rule is present in %s", chains)
	}
	return "the rule is absent from " + strings.Join(missing, " and ")
}

func resolveACL(ctx context.Context, e *Env, t Target, s State) error {
	if s["match"] == "" || s["tag"] == "" {
		return fmt.Errorf("this fault's rule was not recorded with an identifier, so it "+
			"cannot be told apart from a rule the student wrote; removing by match would "+
			"delete theirs too (device %s)", t.DeviceID())
	}
	for _, c := range strings.Fields(s["chains"]) {
		// Only rules carrying this injection's own marker are removed, and only
		// as many as it installed.
		for i := 0; i < 8; i++ {
			if _, code := e.Try(ctx, t.DeviceID(),
				fmt.Sprintf("iptables -w -D %s %s %s -j DROP", c, s["match"], s["tag"])); code != 0 {
				break
			}
		}
		if _, code := e.Try(ctx, t.DeviceID(),
			fmt.Sprintf("iptables -w -C %s %s %s -j DROP", c, s["match"], s["tag"])); code == 0 {
			return fmt.Errorf("the drop rule is still present in %s after removal", c)
		}
	}
	return nil
}
