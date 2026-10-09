package msc

import (
	"fmt"
	"strings"
	"testing"
)

func TestFirewallLocalControlsAcrossLayouts(t *testing.T) {
	for _, shared := range []bool{false, true} {
		for _, outer := range []int{1, 2, 3} {
			for _, gray := range []int{1, 2, 3} {
				s, err := Generate(Layout{Name: "controls", Levels: 3, OuterFirewalls: outer, GrayFirewalls: gray, SharedGray: shared})
				if err != nil {
					t.Fatal(err)
				}
				for _, d := range s.Devices {
					if d.Role != "firewall" && d.Role != "gray-firewall" {
						continue
					}
					rules := filterRules(s, &d)
					if !strings.Contains(rules, ":OUTPUT DROP [0:0]") {
						t.Fatalf("%s has permissive local output", d.ID)
					}
					allowed := map[string]bool{"-A INPUT -i lo -j ACCEPT": true, "-A OUTPUT -o lo -j ACCEPT": true}
					for _, port := range d.Interfaces {
						peer, pi := s.Peer(d.ID, port.Name)
						if peer == nil || !s.IsOSPF(&d) || !s.IsOSPF(peer) {
							continue
						}
						local, remote := strings.Split(port.Address, "/")[0], strings.Split(pi.Address, "/")[0]
						for _, target := range []string{local, "224.0.0.5"} {
							line := fmt.Sprintf("-A INPUT -i %s -s %s -d %s -p ospf -j ACCEPT", port.Name, remote, target)
							allowed[line] = true
							if !strings.Contains(rules, line+"\n") {
								t.Fatalf("missing incoming adjacency allowance: %s", line)
							}
						}
						for _, target := range []string{remote, "224.0.0.5"} {
							line := fmt.Sprintf("-A OUTPUT -o %s -s %s -d %s -p ospf -j ACCEPT", port.Name, local, target)
							allowed[line] = true
							if !strings.Contains(rules, line+"\n") {
								t.Fatalf("missing outgoing adjacency allowance: %s", line)
							}
						}
					}
					for _, line := range strings.Split(rules, "\n") {
						if !strings.HasPrefix(line, "-A INPUT ") && !strings.HasPrefix(line, "-A OUTPUT ") {
							continue
						}
						if strings.Contains(line, "-i mgmt ") || strings.Contains(line, "-o mgmt ") {
							continue
						}
						if !allowed[line] {
							t.Fatalf("unapproved local firewall allowance on %s: %s", d.ID, line)
						}
					}
				}
			}
		}
	}
}
