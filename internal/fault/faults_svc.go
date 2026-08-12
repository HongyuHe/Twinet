package fault

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Faults against the lab's own services: DNS, and the layer-2 fabric.
//
// These became implementable only when the services stopped being stubs. A
// fault against a name server that nothing consults is not a fault, it is a
// file edit: the symptom never appears, an agent asked to diagnose it has
// nothing to find, and the episode measures nothing. That is worth stating,
// because "inject, verify, resolve" all pass in that situation.

func init() {
	// ---- DNS -----------------------------------------------------------

	Register(&Fault{
		Name: "dns_service_down", Category: CatNodeError, Needs: []Capability{CapProcess},
		Symptom:  "Users report that they cannot reach services by name, though addresses still work.",
		Describe: "The authoritative name server was stopped.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			d, err := e.Device(t)
			if err != nil {
				return nil, err
			}
			if _, code, err := e.TryE(ctx, d.ID, procRunning("named")); err != nil {
				return nil, err
			} else if code != 0 {
				return nil, fmt.Errorf("%s is not running a name server, so stopping one proves nothing", d.ID)
			}
			if _, err := e.Sh(ctx, d.ID, killMatching("named")); err != nil {
				return nil, err
			}
			return State{"device": d.ID}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			_, code, err := e.TryE(ctx, t.DeviceID(), procRunning("named"))
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{
				Verified: code != 0,
				Observed: boolWord(code == 0, "the name server is running", "no name server process"),
				Expected: "no name server process",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			_, err := e.Sh(ctx, t.DeviceID(), strings.Join([]string{
				"rm -f /var/run/named/named.pid 2>/dev/null || true",
				"named -c /etc/bind/named.conf -u named",
			}, "\n"))
			return err
		},
	})

	Register(&Fault{
		Name: "dns_port_blocked", Category: CatMisconfig, Needs: []Capability{CapNFT},
		Symptom:  "Name lookups time out from some places, while the server itself looks healthy.",
		Describe: "A firewall rule drops DNS queries arriving at the resolver.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			// Dropped rather than rejected: a rejection produces an immediate
			// error, which is a much easier thing to diagnose than a timeout,
			// and the timeout is what the symptom describes.
			//
			// Appended rather than inserted, and one at a time with rollback,
			// so that resolving can remove exactly the rules this injection
			// added. It used to insert both and then, on resolve, delete
			// *every* rule dropping port 53 -- including one that was already
			// there, or one another injection had added -- and report a clean
			// undo, because the fingerprint compares sets of lines and cannot
			// see a rule it removed that was never its own.
			var done []string
			for _, proto := range []string{"udp", "tcp"} {
				if _, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
					"iptables -w -A INPUT -p %s --dport 53 -j DROP", proto)); err != nil {
					for _, p := range done {
						_, _ = e.Try(ctx, t.DeviceID(), fmt.Sprintf(
							"iptables -w -D INPUT -p %s --dport 53 -j DROP", p))
					}
					return nil, err
				}
				done = append(done, proto)
			}
			return State{"device": t.DeviceID(), "protos": strings.Join(done, " ")}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _, err := e.TryE(ctx, t.DeviceID(), "iptables -w -S INPUT")
			if err != nil {
				return Evidence{}, err
			}
			n := strings.Count(out, "--dport 53 -j DROP")
			return Evidence{
				Verified: n > 0,
				Observed: fmt.Sprintf("%d rule(s) dropping port 53", n),
				Expected: "queries to the resolver are dropped",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			protos := strings.Fields(s["protos"])
			if len(protos) == 0 {
				protos = []string{"udp", "tcp"}
			}
			// Exactly one copy per protocol, and the last one, which is the
			// one this injection appended.
			for _, p := range protos {
				pos := lastMatchingRule(ctx, e, t, "INPUT",
					fmt.Sprintf("-p %s --dport 53", p))
				if pos <= 0 {
					continue
				}
				if _, err := e.Sh(ctx, t.DeviceID(),
					fmt.Sprintf("iptables -w -D INPUT %d", pos)); err != nil {
					return err
				}
			}
			return nil
		},
	})

	Register(&Fault{
		Name: "dns_record_error", Category: CatMisconfig, Needs: []Capability{CapFile, CapDNS},
		Symptom:  "One service resolves to the wrong machine; everything else looks fine.",
		Describe: "A record in a served zone points at an address that does not host the service.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			// The first forward zone is edited. Capturing it first is not
			// optional: a fault that cannot restore what it overwrote is a
			// fault that destroys a lab rather than perturbing it.
			zone, err := firstZoneFile(ctx, e, t)
			if err != nil {
				return nil, err
			}
			before, code, err := e.TryE(ctx, t.DeviceID(), "cat "+zone)
			if err != nil {
				return nil, err
			}
			if code != 0 || strings.TrimSpace(before) == "" {
				return nil, fmt.Errorf("%s is empty or unreadable; refusing to edit what cannot be restored", zone)
			}
			bad := t.Param("address", "")
			// awk rather than sed: busybox does not support sed's 0,/pat/
			// range, and silently changes nothing rather than failing, so the
			// fault reported success while the zone was untouched.
			//
			// The NS record is skipped deliberately. Repointing the authority
			// record breaks the whole zone, which is a different and much
			// louder fault than one service resolving to the wrong machine.
			// The name to repoint is chosen first, on its own, and printed to
			// standard output.
			//
			// It used to be announced from inside the editing script by
			// writing to /dev/stderr, because the script's own output is the
			// new zone file. Whether that reaches the caller depends on the
			// exec transport merging stderr, and when it does not, the fault
			// refuses with "no A record could be repointed" on a zone full of
			// A records -- which is what it did.
			pick := fmt.Sprintf(
				"awk '$1!=\"ns\" && $2==\"IN\" && $3==\"A\" {print $1; exit}' %s", zone)
			picked, err := e.Sh(ctx, t.DeviceID(), pick)
			if err != nil {
				return nil, err
			}
			name := firstNonEmptyLine(picked)
			if name == "" {
				return nil, fmt.Errorf("no A record in %s could be repointed, so the fault "+
					"would have reported success while changing nothing", zone)
			}

			// The wrong address has to be wrong.
			//
			// It defaulted to 192.0.2.66, which is the address this lab's own
			// zone already gives that name -- so the fault rewrote the record
			// to the value it already had, changed nothing, and was rolled
			// back with "it did not take effect". A fault whose default makes
			// it a no-op on the lab it ships with is worse than no fault.
			current := firstNonEmptyLine(mustTry(ctx, e, t, fmt.Sprintf(
				"awk -v want=%s '$1==want && $2==\"IN\" && $3==\"A\" {print $4; exit}' %s",
				shellQuoteFault(name), zone)))
			if bad == "" {
				bad = differentTestAddress(current)
			}
			if bad == current {
				return nil, fmt.Errorf("%s already resolves to %s, so pointing it there "+
					"would change nothing; pass --param address=<something else>",
					name, current)
			}

			// The NS record is skipped deliberately. Repointing the authority
			// record breaks the whole zone, which is a different and much
			// louder fault than one service resolving to the wrong machine.
			script := fmt.Sprintf(
				"awk -v want=%s -v bad=%s 'BEGIN{done=0} "+
					"{ if(!done && $1==want && $2==\"IN\" && $3==\"A\"){ "+
					"print $1\" IN A \"bad; done=1 } else print }' %s > %s.new && mv %s.new %s",
				shellQuoteFault(name), shellQuoteFault(bad), zone, zone, zone, zone)
			if _, err := e.Sh(ctx, t.DeviceID(), script); err != nil {
				return nil, err
			}
			if _, err := e.Sh(ctx, t.DeviceID(), reloadNamed()); err != nil {
				return nil, err
			}
			return State{"zone": zone, "before": before, "address": bad,
				"name": name, "origin": zoneOrigin(before)}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			// Ask the server, do not read the file. The fault claims a name
			// resolves to the wrong machine; a zone file containing the wrong
			// address proves only that a file was edited. If named failed to
			// reload -- a bad zone, a syntax error, a serial that did not
			// advance -- the file check passed and the server went on handing
			// out the correct address, so the episode had no symptom at all
			// and any agent asked to diagnose it was being misled.
			fqdn := strings.TrimSuffix(s["name"], ".")
			if o := s["origin"]; o != "" && !strings.HasSuffix(fqdn, o) {
				fqdn = fqdn + "." + o
			}
			answer, err := e.Settled(ctx, 30*time.Second,
				func(c context.Context) (string, error) {
					out, _, err := e.TryE(c, t.DeviceID(),
						"nslookup "+fqdn+" 127.0.0.1 2>/dev/null || true")
					return out, err
				},
				func(o string) bool { return strings.Contains(o, s["address"]) })
			if err != nil {
				return Evidence{}, err
			}
			got := strings.Contains(answer, s["address"])
			observed := fmt.Sprintf("the server was asked for %s and did not answer with %s; "+
				"it said: %s", fqdn, s["address"], firstNonEmptyLineAfter(answer, "Address:"))
			if got {
				observed = firstLine(matchingLine(answer, s["address"]))
			}
			return Evidence{
				Verified: got,
				Observed: observed,
				Expected: fqdn + " resolving to " + s["address"],
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["before"] == "" {
				return fmt.Errorf("the original zone was not captured, so it cannot be restored")
			}
			if _, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"cat > %s <<'TWINET_ZONE'\n%s\nTWINET_ZONE", s["zone"], s["before"])); err != nil {
				return err
			}
			_, err := e.Sh(ctx, t.DeviceID(), reloadNamed())
			return err
		},
	})

	Register(&Fault{
		Name: "dns_lookup_latency", Category: CatContention, Needs: []Capability{CapTC},
		Symptom:  "Everything works, but anything that starts with a name lookup is slow.",
		Describe: "Delay was added to the resolver's own interface, so every query waits.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return nil, err
			}
			delay := t.Param("delay", "800ms")
			if _, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"tc qdisc replace dev %s root netem delay %s", iface, delay)); err != nil {
				return nil, err
			}
			return State{"iface": iface, "delay": delay}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _, err := e.TryE(ctx, t.DeviceID(), "tc qdisc show dev "+s["iface"])
			if err != nil {
				return Evidence{}, err
			}
			// tc renormalises units on the way out -- 1500ms comes back as
			// "1.5s" -- so a string comparison against what was asked for
			// fails against a fault that worked perfectly. Both sides are
			// parsed instead.
			want := parseDuration(s["delay"])
			got := netemDelayMS(out)
			return Evidence{
				Verified: want > 0 && got >= want*0.9,
				Observed: firstLine(out),
				Expected: "netem delay " + s["delay"],
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			return restoreShaping(ctx, e, t, s["iface"])
		},
	})

	// ---- layer 2 -------------------------------------------------------

	Register(&Fault{
		Name: "arp_cache_poisoning", Category: CatAttack, Needs: []Capability{CapIP},
		Symptom:  "Traffic to one neighbour disappears, though the link is up and the address is right.",
		Describe: "A permanent ARP entry maps a neighbour's address to a MAC nobody answers on.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			victim, iface, err := arpVictim(e, t)
			if err != nil {
				return nil, err
			}
			mac := t.Param("mac", "02:00:00:de:ad:00")
			if _, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"ip neigh replace %s lladdr %s nud permanent dev %s", victim, mac, iface)); err != nil {
				return nil, err
			}
			return State{"victim": victim, "iface": iface, "mac": mac}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _, err := e.TryE(ctx, t.DeviceID(), "ip neigh show "+s["victim"])
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{
				Verified: strings.Contains(strings.ToLower(out), strings.ToLower(s["mac"])),
				Observed: strings.TrimSpace(out),
				Expected: s["victim"] + " resolves to a real neighbour",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["victim"] == "" {
				return fmt.Errorf("no poisoned entry was recorded")
			}
			_, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"ip neigh del %s dev %s 2>/dev/null || true", s["victim"], s["iface"]))
			return err
		},
	})

	Register(&Fault{
		Name: "mac_address_conflict", Category: CatMisconfig, Needs: []Capability{CapIP},
		Symptom:  "Two machines on the same segment intermittently lose traffic to each other.",
		Describe: "An interface was given the same MAC address as its neighbour.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return nil, err
			}
			before, code, err := e.TryE(ctx, t.DeviceID(),
				"cat /sys/class/net/"+iface+"/address")
			if err != nil {
				return nil, err
			}
			if code != 0 || strings.TrimSpace(before) == "" {
				return nil, fmt.Errorf("cannot read the current MAC of %s, so it could not be restored", iface)
			}
			peer := t.Param("mac", "")
			if peer == "" {
				p, err := peerMAC(e, t, iface)
				if err != nil {
					return nil, err
				}
				peer = p
			}
			if _, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"ip link set %s down && ip link set %s address %s && ip link set %s up",
				iface, iface, peer, iface)); err != nil {
				return nil, err
			}
			return State{"iface": iface, "before": strings.TrimSpace(before), "mac": peer}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _, err := e.TryE(ctx, t.DeviceID(), "cat /sys/class/net/"+s["iface"]+"/address")
			if err != nil {
				return Evidence{}, err
			}
			got := strings.TrimSpace(out)
			return Evidence{
				Verified: strings.EqualFold(got, s["mac"]),
				Observed: got,
				Expected: s["before"],
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["before"] == "" {
				return fmt.Errorf("the original MAC was not captured, so it cannot be restored")
			}
			_, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"ip link set %s down && ip link set %s address %s && ip link set %s up",
				s["iface"], s["iface"], s["before"], s["iface"]))
			return err
		},
	})

	Register(&Fault{
		Name: "link_detach", Category: CatLink, Needs: []Capability{CapIP},
		Symptom:  "Traffic across one link disappears, though the interface is up and addressed.",
		Describe: "An interface carries nothing in either direction, as though the cable were cut.",
		// The symptom said "the interface is not even listed", and it is: this
		// drops traffic rather than removing the device. An RCA benchmark that
		// describes evidence the agent will not find is worse than one that
		// describes none, because the agent spends its time looking for it.
		//
		// NIKA's link_failure deletes the interface. Twinet does not, because
		// removing a veth end from inside the namespace cannot be undone from
		// there, and a fault that cannot be undone destroys the lab rather than
		// perturbing it. See docs/10 for what that means for the coverage
		// claim.
		//
		// Distinct from link_down: the interface stays up and configured, so a
		// student or an agent looking at `ip link` sees nothing wrong on this
		// side. The traffic simply has nowhere to go.
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return nil, err
			}
			// Ingress and egress are both dropped inside the namespace, which
			// is the closest an unprivileged view has to an unplugged cable and
			// is reversible exactly.
			if _, err := e.Sh(ctx, t.DeviceID(), strings.Join([]string{
				fmt.Sprintf("tc qdisc replace dev %s root netem loss 100%%", iface),
				fmt.Sprintf("tc qdisc add dev %s handle ffff: ingress 2>/dev/null || true", iface),
				fmt.Sprintf("tc filter replace dev %s parent ffff: protocol all prio 1 u32 match u32 0 0 action drop", iface),
			}, "\n")); err != nil {
				return nil, err
			}
			return State{"iface": iface}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _, err := e.TryE(ctx, t.DeviceID(), "tc qdisc show dev "+s["iface"])
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{
				Verified: strings.Contains(out, "loss 100%"),
				Observed: firstLine(out),
				Expected: "the interface carries nothing",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if _, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"tc qdisc del dev %s ingress 2>/dev/null || true", s["iface"])); err != nil {
				return err
			}
			return restoreShaping(ctx, e, t, s["iface"])
		},
	})
}

// reloadNamed makes the server re-read its zones.
//
// rndc is not configured in the lab's image, so the daemon is restarted. The
// restart is not conditional on the reload failing: a conditional would leave
// the outcome dependent on which of two paths ran, and an episode has to be
// reproducible.
func reloadNamed() string {
	return strings.Join([]string{
		killMatching("named"),
		"sleep 1",
		"rm -f /var/run/named/named.pid 2>/dev/null || true",
		"named -c /etc/bind/named.conf -u named",
	}, "\n")
}

// netemDelayMS extracts a netem delay from tc output, in milliseconds.
func netemDelayMS(out string) float64 {
	f := strings.Fields(out)
	for i, w := range f {
		if w == "delay" && i+1 < len(f) {
			return parseDuration(f[i+1])
		}
	}
	return 0
}

// parseDuration reads a tc duration such as "800ms", "1.5s" or "250us".
func parseDuration(s string) float64 {
	s = strings.TrimSpace(s)
	unit := strings.TrimLeft(s, "0123456789.")
	var v float64
	if _, err := fmt.Sscanf(strings.TrimSuffix(s, unit), "%f", &v); err != nil {
		return 0
	}
	switch unit {
	case "s":
		return v * 1000
	case "us":
		return v / 1000
	default:
		return v
	}
}

// firstZoneFile finds a zone the resolver serves.
func firstZoneFile(ctx context.Context, e *Env, t Target) (string, error) {
	out, code, err := e.TryE(ctx, t.DeviceID(),
		"ls /var/named/db.* 2>/dev/null | grep -v in-addr | head -1")
	if err != nil {
		return "", err
	}
	z := strings.TrimSpace(out)
	if code != 0 || z == "" {
		return "", fmt.Errorf("%s serves no forward zone to corrupt", t.DeviceID())
	}
	return z, nil
}

// arpVictim picks a neighbour to poison the entry for.
func arpVictim(e *Env, t Target) (addr, iface string, err error) {
	if v := t.Param("victim", ""); v != "" {
		i, err := faultIface(e, t)
		return v, i, err
	}
	d, err := e.Device(t)
	if err != nil {
		return "", "", err
	}
	for _, i := range d.Ifaces {
		if i.Link == nil || i.Peer == nil || i.Peer.Addr4 == "" {
			continue
		}
		return addrOnly(i.Peer.Addr4), i.Name, nil
	}
	return "", "", fmt.Errorf("%s has no neighbour whose address is known", d.ID)
}

// peerMAC returns the MAC of the device on the other end of an interface.
func peerMAC(e *Env, t Target, iface string) (string, error) {
	d, err := e.Device(t)
	if err != nil {
		return "", err
	}
	for _, i := range d.Ifaces {
		if i.Name != iface || i.Peer == nil || i.Peer.MAC == "" {
			continue
		}
		return i.Peer.MAC, nil
	}
	return "", fmt.Errorf("the peer of %s has no known MAC address", iface)
}

func addrOnly(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i > 0 {
		return cidr[:i]
	}
	return cidr
}

func boolWord(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

// zoneOrigin reads $ORIGIN from a zone file so a bare record name can be turned
// into something resolvable.
// zoneOrigin returns the domain a zone file is rooted at.
//
// $ORIGIN is only one of the ways a zone says so, and not the one this lab's
// zones use: they name the origin in the SOA record instead. Returning ""
// meant the verifier asked the server for "all" rather than "all.group1",
// which resolves to nothing -- so the fault reported that it had not taken
// effect and rolled itself back, on a zone it had edited perfectly. Three
// faults were unusable for this reason and the message said only "it did not
// take effect", with nothing after the colon.
func zoneOrigin(zone string) string {
	for _, ln := range strings.Split(zone, "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 && f[0] == "$ORIGIN" {
			return strings.TrimSuffix(f[1], ".")
		}
	}
	// "@ IN SOA ns.group1. root.group1. (...)" -- the first label of the
	// primary name server is the host, the rest is the zone.
	for _, ln := range strings.Split(zone, "\n") {
		f := strings.Fields(ln)
		if len(f) >= 4 && f[1] == "IN" && f[2] == "SOA" {
			ns := strings.TrimSuffix(f[3], ".")
			if i := strings.IndexByte(ns, '.'); i > 0 {
				return ns[i+1:]
			}
			return ns
		}
	}
	return ""
}

// firstNonEmptyLine returns the first line of output that has content.
func firstNonEmptyLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			return t
		}
	}
	return ""
}

// mustTry runs a probe and returns whatever it produced, empty on failure.
func mustTry(ctx context.Context, e *Env, t Target, script string) string {
	out, _ := e.Try(ctx, t.DeviceID(), script)
	return out
}

// differentTestAddress picks an address in the documentation range that is not
// the one given.
//
// TEST-NET-1 is used because it is reserved for exactly this: it can never be
// something a student is trying to reach, so a name pointing there is
// unambiguously wrong rather than accidentally right.
func differentTestAddress(current string) string {
	const a, b = "192.0.2.66", "192.0.2.67"
	if strings.TrimSpace(current) == a {
		return b
	}
	return a
}

// firstNonEmptyLineAfter returns the first line containing a marker, for an
// error message that says what was actually seen rather than only what was not.
func firstNonEmptyLineAfter(out, marker string) string {
	var last string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, marker) {
			last = strings.TrimSpace(l)
		}
	}
	if last == "" {
		return "nothing usable (" + strings.TrimSpace(firstNonEmptyLine(out)) + ")"
	}
	return last
}
