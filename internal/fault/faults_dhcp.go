package fault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/HongyuHe/twinet/internal/svc"
)

// Faults against the lab's address server.
//
// The taxonomy this platform is measured against has five of them, and none was
// implementable while the lab had no DHCP at all: a fault against a service that
// does not exist produces an episode with no symptom, which is worse than an
// absent fault because inject, verify and resolve all pass and nothing has
// happened.
//
// Each of these changes what a client is told, not whether the server is
// reachable, except the one that is about the server being stopped. That
// distinction is the point: a host with no address, a host with an address and
// the wrong gateway, and a host with an address and the wrong resolver are
// three different symptoms with three different diagnoses, and an injector that
// produced the same observable state for all three would make the episodes
// unfalsifiable.

func init() {
	Register(&Fault{
		Name: "dhcp_service_down", Category: CatLink, Needs: []Capability{CapProcess},
		Symptom: "Hosts that reboot or renew come up with no address at all, while " +
			"hosts that already hold a lease keep working until it expires.",
		Describe: "The DHCP server was stopped.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			d, err := e.Device(t)
			if err != nil {
				return nil, err
			}
			// Nothing to stop is not a fault. Injecting onto a device that was
			// not running the server would report success while changing
			// nothing, and the episode's ground truth would name a cause that
			// is not the reason anything is broken.
			if _, code, err := e.TryE(ctx, d.ID, procRunning("twinet-dhcpd")); err != nil {
				return nil, err
			} else if code != 0 {
				return nil, fmt.Errorf("%s is not running a DHCP server, so stopping one "+
					"proves nothing", d.ID)
			}
			if _, err := e.Sh(ctx, d.ID, killMatching("twinet-dhcpd")); err != nil {
				return nil, err
			}
			return State{"device": d.ID}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			_, code, err := e.TryE(ctx, t.DeviceID(), procRunning("twinet-dhcpd"))
			if err != nil {
				return Evidence{}, err
			}
			// The process, not a client probe.
			//
			// Asking a host for a lease here was tried: through this path the
			// probe reported "no lease" for a fault whose symptom is a lease
			// with the wrong contents, while the identical command through
			// `twinet exec` obtained one every time. Evidence that cannot be
			// explained is worse than no evidence, because it reads as a
			// symptom. The symptoms are proved in the end-to-end suite, where
			// a client is asked over the same path a person would use.
			return Evidence{
				Verified: code != 0,
				Observed: boolWord(code == 0, "the DHCP server is running", "no DHCP server process"),
				Expected: "no DHCP server process",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			// The same command the deployment uses, from the same place, so
			// that resolving restores what was there rather than something
			// that resembles it.
			_, err := e.Sh(ctx, t.DeviceID(), svc.DHCPStartCommand+"\nsleep 1")
			return err
		},
	})

	Register(&Fault{
		Name: "dhcp_missing_subnet", Category: CatMisconfig, Needs: []Capability{CapFile},
		Symptom: "Hosts on one segment cannot get an address, while every other segment " +
			"is served normally.",
		Describe: "One subnet was removed from the DHCP server's configuration.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			cfg, raw, err := readDHCPConfig(ctx, e, t)
			if err != nil {
				return nil, err
			}
			if len(cfg.Subnets) < 2 {
				return nil, fmt.Errorf("%s serves %d subnet(s); removing one would stop the "+
					"server serving anything, which is a different fault with a different "+
					"symptom", t.DeviceID(), len(cfg.Subnets))
			}
			gone := cfg.Subnets[0]
			cfg.Subnets = cfg.Subnets[1:]
			if err := writeDHCPConfig(ctx, e, t, cfg); err != nil {
				return nil, err
			}
			return State{"device": t.DeviceID(), "subnet": gone.Subnet, "was": string(raw)}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			cfg, _, err := readDHCPConfig(ctx, e, t)
			if err != nil {
				return Evidence{}, err
			}
			want := s["subnet"]
			for _, sub := range cfg.Subnets {
				if sub.Subnet == want {
					return Evidence{
						Observed: fmt.Sprintf("%s is still configured", want),
						Expected: fmt.Sprintf("no configuration for %s", want),
					}, nil
				}
			}
			return Evidence{
				Verified: true,
				Observed: fmt.Sprintf("%s is not among the %d subnet(s) served", want, len(cfg.Subnets)),
				Expected: fmt.Sprintf("no configuration for %s", want),
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			return restoreDHCPConfig(ctx, e, t, s)
		},
	})

	// The three spoofing faults share a shape: the server keeps answering, and
	// what it answers with is wrong. They are separate faults rather than one
	// parameterised fault because they produce different symptoms and a
	// diagnosis has to name which.
	spoof := []struct {
		name     string
		option   string
		symptom  string
		describe string
		apply    func(sub *svc.DHCPSubnet, wrong string)
		reads    func(sub svc.DHCPSubnet) []string
	}{
		{
			name: "dhcp_spoofed_gateway", option: "gateway",
			symptom: "Hosts get an address and can reach their own segment, but nothing " +
				"beyond it.",
			describe: "The DHCP server hands out a default gateway that is not the router.",
			apply:    func(sub *svc.DHCPSubnet, wrong string) { sub.Routers = []string{wrong} },
			reads:    func(sub svc.DHCPSubnet) []string { return sub.Routers },
		},
		{
			name: "dhcp_spoofed_dns", option: "resolver",
			symptom: "Hosts get an address and reach everything by address, while every " +
				"name lookup times out.",
			describe: "The DHCP server hands out a resolver that does not answer.",
			apply:    func(sub *svc.DHCPSubnet, wrong string) { sub.DNS = []string{wrong} },
			reads:    func(sub svc.DHCPSubnet) []string { return sub.DNS },
		},
	}
	for _, sp := range spoof {
		sp := sp
		Register(&Fault{
			Name: sp.name, Category: CatAttack, Needs: []Capability{CapFile},
			Symptom: sp.symptom, Describe: sp.describe,
			Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
				cfg, raw, err := readDHCPConfig(ctx, e, t)
				if err != nil {
					return nil, err
				}
				if len(cfg.Subnets) == 0 {
					return nil, fmt.Errorf("%s serves no subnet, so there is no lease to "+
						"put a wrong %s in", t.DeviceID(), sp.option)
				}
				// An address inside the subnet that nothing holds, because the
				// interesting failure is a plausible one: a client configured
				// with an address that answers nothing looks configured, and
				// that is what makes this hard to diagnose. An obviously
				// foreign address would be spotted at a glance.
				sub := &cfg.Subnets[0]
				wrong, err := unusedInSubnet(sub.Subnet)
				if err != nil {
					return nil, err
				}
				for _, had := range sp.reads(*sub) {
					if had == wrong {
						return nil, fmt.Errorf("%s already hands out %s as the %s",
							t.DeviceID(), wrong, sp.option)
					}
				}
				sp.apply(sub, wrong)
				if err := writeDHCPConfig(ctx, e, t, cfg); err != nil {
					return nil, err
				}
				return State{
					"device": t.DeviceID(), "subnet": sub.Subnet,
					"wrong": wrong, "was": string(raw),
				}, nil
			},
			Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
				cfg, _, err := readDHCPConfig(ctx, e, t)
				if err != nil {
					return Evidence{}, err
				}
				want := s["wrong"]
				subnet := s["subnet"]
				for _, sub := range cfg.Subnets {
					if sub.Subnet != subnet {
						continue
					}
					for _, v := range sp.reads(sub) {
						if v != want {
							continue
						}
						return Evidence{
							Verified: true,
							Observed: fmt.Sprintf("%s is handed out as the %s for %s",
								want, sp.option, subnet),
							Expected: fmt.Sprintf("%s as the %s", want, sp.option),
						}, nil
					}
				}
				return Evidence{
					Observed: fmt.Sprintf("the %s for %s is not %s", sp.option, subnet, want),
					Expected: fmt.Sprintf("%s as the %s", want, sp.option),
				}, nil
			},
			Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
				return restoreDHCPConfig(ctx, e, t, s)
			},
		})
	}

	Register(&Fault{
		Name: "dhcp_spoofed_subnet", Category: CatAttack, Needs: []Capability{CapFile},
		Symptom: "Hosts come up with addresses on a network nobody else is on, and can " +
			"reach nothing at all.",
		Describe: "The DHCP server hands out addresses from the wrong network.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			cfg, raw, err := readDHCPConfig(ctx, e, t)
			if err != nil {
				return nil, err
			}
			if len(cfg.Subnets) == 0 {
				return nil, fmt.Errorf("%s serves no subnet", t.DeviceID())
			}
			sub := &cfg.Subnets[0]
			// The pool moves into a network that exists nowhere in the lab, so
			// a client that takes a lease is genuinely isolated rather than
			// accidentally landing on somebody else's segment.
			first, last, err := poolIn("10.255.255.0/24")
			if err != nil {
				return nil, err
			}
			if sub.First == first {
				return nil, fmt.Errorf("%s already hands out addresses from %s",
					t.DeviceID(), first)
			}
			sub.First, sub.Last = first, last
			if err := writeDHCPConfig(ctx, e, t, cfg); err != nil {
				return nil, err
			}
			return State{
				"device": t.DeviceID(), "subnet": sub.Subnet,
				"pool": first, "was": string(raw),
			}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			cfg, _, err := readDHCPConfig(ctx, e, t)
			if err != nil {
				return Evidence{}, err
			}
			want := s["pool"]
			subnet := s["subnet"]
			for _, sub := range cfg.Subnets {
				if sub.Subnet == subnet && sub.First == want {
					return Evidence{
						Verified: true,
						Observed: fmt.Sprintf("%s hands out addresses from %s, which is "+
							"outside it", subnet, want),
						Expected: fmt.Sprintf("a pool starting at %s", want),
					}, nil
				}
			}
			return Evidence{
				Observed: fmt.Sprintf("the pool for %s does not start at %s", subnet, want),
				Expected: fmt.Sprintf("a pool starting at %s", want),
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			return restoreDHCPConfig(ctx, e, t, s)
		},
	})
}

// readDHCPConfig reads a server's configuration and the bytes it came from.
func readDHCPConfig(ctx context.Context, e *Env, t Target) (*svc.DHCPConfig, []byte, error) {
	out, code, err := e.TryE(ctx, t.DeviceID(), "cat "+svc.DHCPConfigPath)
	if err != nil {
		return nil, nil, err
	}
	if code != 0 {
		return nil, nil, fmt.Errorf("%s is not running a DHCP server: there is no %s",
			t.DeviceID(), svc.DHCPConfigPath)
	}
	var cfg svc.DHCPConfig
	if err := json.Unmarshal([]byte(out), &cfg); err != nil {
		return nil, nil, fmt.Errorf("%s: %s could not be read: %w",
			t.DeviceID(), svc.DHCPConfigPath, err)
	}
	return &cfg, []byte(out), nil
}

// writeDHCPConfig replaces a server's configuration.
//
// Written through a temporary file and renamed, because the server re-reads
// this on its own schedule and a half-written one would be read as a shorter
// list -- which is a different fault, briefly, than the one being injected.
func writeDHCPConfig(ctx context.Context, e *Env, t Target, cfg *svc.DHCPConfig) error {
	_, err := e.Sh(ctx, t.DeviceID(), strings.Join([]string{
		"cat > " + svc.DHCPConfigPath + ".tmp <<'TWINET_DHCP'",
		strings.TrimRight(string(cfg.JSON()), "\n"),
		"TWINET_DHCP",
		"mv " + svc.DHCPConfigPath + ".tmp " + svc.DHCPConfigPath,
	}, "\n"))
	return err
}

// restoreDHCPConfig puts back exactly the bytes that were there.
//
// Recomputing the configuration from the topology would be close enough to look
// right and would silently discard anything an exercise had changed, so the
// original is carried in the injection's state and written back verbatim.
func restoreDHCPConfig(ctx context.Context, e *Env, t Target, s State) error {
	was := s["was"]
	if was == "" {
		return fmt.Errorf("the configuration this injection replaced was not recorded, so " +
			"it cannot be put back")
	}
	_, err := e.Sh(ctx, t.DeviceID(), strings.Join([]string{
		"cat > " + svc.DHCPConfigPath + ".tmp <<'TWINET_DHCP'",
		strings.TrimRight(was, "\n"),
		"TWINET_DHCP",
		"mv " + svc.DHCPConfigPath + ".tmp " + svc.DHCPConfigPath,
	}, "\n"))
	return err
}

// unusedInSubnet returns an address inside a network that the lab does not use.
//
// A plausible wrong answer, not an obviously foreign one: a client configured
// with an address on its own network that answers nothing looks configured, and
// that is what makes the fault worth diagnosing. .254 is the convention the
// taxonomy this follows uses for exactly this.
func unusedInSubnet(subnet string) (string, error) {
	pfx, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", fmt.Errorf("%q is not a network", subnet)
	}
	if !pfx.Addr().Is4() {
		return "", fmt.Errorf("%s is not an IPv4 network", subnet)
	}
	a := pfx.Masked().Addr().As4()
	a[3] = 254
	out := netip.AddrFrom4(a)
	if !pfx.Contains(out) {
		return "", fmt.Errorf("%s is too small to hold an unused address", subnet)
	}
	return out.String(), nil
}

// poolIn returns the first and last address of a pool inside a network.
func poolIn(subnet string) (string, string, error) {
	pfx, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", "", err
	}
	a := pfx.Masked().Addr().As4()
	a[3] = 200
	b := a
	b[3] = 240
	return netip.AddrFrom4(a).String(), netip.AddrFrom4(b).String(), nil
}
