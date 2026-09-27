package msc

import "fmt"

// Example returns the two-site, two-level IPsec/IPsec profile. Every appliance
// and cable is explicit in the emitted JSON and can be inspected before deploy.
func Example() *Spec {
	s := &Spec{Version: 1, Name: "msc", Image: "hyhe/twinet-msc@sha256:6cfc920ac8df78b10746e78d730366781d3db2ab957dd13d9368cb7ca63264fa", MTU: 1400}
	add := func(id, role, site, level string) *Device {
		s.Devices = append(s.Devices, Device{ID: id, Role: role, Site: site, Level: level})
		return &s.Devices[len(s.Devices)-1]
	}
	cable := func(a, ai, aa, az, b, bi, ba, bz string) {
		s.Device(a).Interfaces = append(s.Device(a).Interfaces, Interface{Name: ai, Address: aa, Zone: az, Bridge: s.Device(a).Role == "switch"})
		s.Device(b).Interfaces = append(s.Device(b).Interfaces, Interface{Name: bi, Address: ba, Zone: bz, Bridge: s.Device(b).Role == "switch"})
		s.Links = append(s.Links, Link{Endpoint{a, ai}, Endpoint{b, bi}})
	}
	route := func(id, prefix, via string) { s.Device(id).Routes = append(s.Device(id).Routes, Route{prefix, via}) }
	add("BLACK", "transport", "", "")
	for n, site := range []string{"A", "B"} {
		idx := n + 1
		other := 3 - idx
		peerSite := []string{"B", "A"}[n]
		add("GF_"+site, "gray-firewall", site, "")
		for _, level := range []int{1, 2} {
			suffix := fmt.Sprintf("%s%d", site, level)
			remote := fmt.Sprintf("%s%d", peerSite, level)
			lev := fmt.Sprintf("S%d", level)
			red := fmt.Sprintf("10.%d.%d.", idx, level)
			remRed := fmt.Sprintf("10.%d.%d.", other, level)
			gray := fmt.Sprintf("10.%d.%d.", idx*100, level)
			remGray := fmt.Sprintf("10.%d.%d.", other*100, level)
			wan := fmt.Sprintf("172.20.%d.", idx*10+level)
			remWan := fmt.Sprintf("172.20.%d.", other*10+level)
			black := fmt.Sprintf("172.21.%d.", idx*10+level)
			for _, pair := range [][2]string{{"R_", "host"}, {"I_", "inner"}, {"G_", "switch"}, {"O_", "outer"}, {"OF_", "firewall"}} {
				add(pair[0]+suffix, pair[1], site, lev)
			}
			cable("R_"+suffix, "red", red+"10/24", "red", "I_"+suffix, "red", red+"1/24", "red")
			cable("I_"+suffix, "gray", gray+"2/24", "gray", "G_"+suffix, "inner", "", "gray")
			cable("O_"+suffix, "gray", gray+"1/24", "gray", "G_"+suffix, "outer", "", "gray")
			cable("GF_"+site, fmt.Sprintf("s%d", level), gray+"254/24", "gray", "G_"+suffix, "filter", "", "gray")
			cable("O_"+suffix, "black", wan+"1/30", "black", "OF_"+suffix, "inside", wan+"2/30", "black")
			cable("OF_"+suffix, "outside", black+"1/30", "black", "BLACK", fmt.Sprintf("p%d%d", idx, level), black+"2/30", "black")
			route("R_"+suffix, "0.0.0.0/0", red+"1")
			route("I_"+suffix, remRed+"0/24", gray+"1")
			route("I_"+suffix, remGray+"2/32", gray+"1")
			route("I_"+suffix, fmt.Sprintf("10.%d.%d.0/24", idx*100, 3-level), gray+"254")
			route("O_"+suffix, remGray+"2/32", wan+"2")
			route("O_"+suffix, remWan+"1/32", wan+"2")
			route("OF_"+suffix, "0.0.0.0/0", black+"2")
			route("BLACK", wan+"0/30", black+"1")
			s.Device("I_" + suffix).Tunnel = &Tunnel{Peer: "I_" + remote, Local: gray + "2", Remote: remGray + "2", LocalTS: red + "0/24", RemoteTS: remRed + "0/24", Trust: fmt.Sprintf("inner-s%d", level), ReqID: 100 + level, Inside: "red", Outside: "gray"}
			s.Device("O_" + suffix).Tunnel = &Tunnel{Peer: "O_" + remote, Local: wan + "1", Remote: remWan + "1", LocalTS: gray + "2/32", RemoteTS: remGray + "2/32", Trust: "outer", ReqID: 200 + level, Inside: "gray", Outside: "black"}
		}
		for _, domain := range []int{1, 2, 99} {
			group := fmt.Sprintf("%s%d", site, domain)
			net := fmt.Sprintf("172.30.%d.", idx*10+domain)
			sw, aw := "M_"+group, "AW_"+group
			add(sw, "switch", site, "management")
			add(aw, "admin", site, "management")
			cable(aw, "mgmt", net+"10/24", "management", sw, "admin", "", "management")
			targets := []string{fmt.Sprintf("I_%s%d", site, domain)}
			if domain == 99 {
				targets = []string{"GF_" + site, "O_" + site + "1", "O_" + site + "2", "OF_" + site + "1", "OF_" + site + "2"}
			}
			for j, id := range targets {
				cable(id, "mgmt", fmt.Sprintf("%s%d/24", net, j+20), "management", sw, fmt.Sprintf("d%d", j), "", "management")
				s.Device(id).Admin = net + "10"
			}
		}
	}
	return s
}
