package msc

import "fmt"

// Layout controls the generated two-site profile. The emitted device/link JSON
// remains editable, including different sharing choices at the two sites.
type Layout struct {
	Name           string `json:"name"`
	Levels         int    `json:"levels"`
	OuterFirewalls int    `json:"outer_firewalls"`
	GrayFirewalls  int    `json:"gray_firewalls"`
	SharedGray     bool   `json:"shared_gray"`
}

func DefaultLayout() Layout {
	return Layout{Name: "msc", Levels: 2, OuterFirewalls: 2, GrayFirewalls: 1}
}

func Example() *Spec {
	s, err := Generate(DefaultLayout())
	if err != nil {
		panic(err)
	}
	return s
}

// Generate places a Gray Firewall on every cross-level physical Gray path.
// SharedGray uses a common outer-side fabric with the inner encryptors behind
// one or more firewalls. It does not merge the inner ports into one L2 domain.
func Generate(o Layout) (*Spec, error) {
	if !identifier.MatchString(o.Name) || o.Levels < 1 || o.Levels > 8 || o.OuterFirewalls < 1 || o.OuterFirewalls > o.Levels || o.GrayFirewalls < 1 || o.GrayFirewalls > o.Levels {
		return nil, fmt.Errorf("name must be a safe identifier; levels=1..8; outer-firewalls and gray-firewalls=1..levels per site")
	}
	s := &Spec{Version: 2, RouterImage: "hyhe/twinet-msc-router@sha256:ea7ba8412a19340a843abe7e3b9ea12fafbc3ba966fb103290a8660e7d731920", SwitchImage: "hyhe/twinet-msc-switch@sha256:7d112ada3368efd46b649927bf09e38875a582fb575ef6c443b532a6c093b83d", Name: o.Name, Image: "hyhe/twinet-msc@sha256:6cfc920ac8df78b10746e78d730366781d3db2ab957dd13d9368cb7ca63264fa", MTU: 1400}
	add := func(id, role, site, level string) {
		s.Devices = append(s.Devices, Device{ID: id, Role: role, Site: site, Level: level})
	}
	cable := func(a, ai, aa, az, b, bi, ba, bz string) {
		s.Device(a).Interfaces = append(s.Device(a).Interfaces, Interface{Name: ai, Address: aa, Zone: az, Bridge: s.Device(a).Role == "switch"})
		s.Device(b).Interfaces = append(s.Device(b).Interfaces, Interface{Name: bi, Address: ba, Zone: bz, Bridge: s.Device(b).Role == "switch"})
		s.Links = append(s.Links, Link{Endpoint{a, ai}, Endpoint{b, bi}})
	}
	route := func(id, prefix, via string) { s.Device(id).Routes = append(s.Device(id).Routes, Route{prefix, via}) }
	gfID := func(site string, k int) string {
		if o.GrayFirewalls == 1 {
			return "GF_" + site
		}
		return fmt.Sprintf("GF_%s%d", site, k)
	}
	add("BLACK", "transport", "", "")
	for n, site := range []string{"A", "B"} {
		idx, other := n+1, 2-n
		peerSite := []string{"B", "A"}[n]
		fabric := fmt.Sprintf("10.%d.0.", idx*100+10)
		for k := 1; k <= o.GrayFirewalls; k++ {
			add(gfID(site, k), "gray-firewall", site, "")
		}
		if o.SharedGray {
			add("G_"+site, "switch", site, "shared-gray")
			for k := 1; k <= o.GrayFirewalls; k++ {
				cable(gfID(site, k), "fabric", fmt.Sprintf("%s%d/24", fabric, 240+k), "gray", "G_"+site, fmt.Sprintf("gf%d", k), "", "gray")
			}
		}
		for k := 1; k <= o.OuterFirewalls; k++ {
			id := fmt.Sprintf("OF_%s%d", site, k)
			add(id, "firewall", site, "")
			black := fmt.Sprintf("172.21.%d.", idx*10+k)
			cable(id, "outside", black+"1/30", "black", "BLACK", fmt.Sprintf("p%d%d", idx, k), black+"2/30", "black")
		}
		for level := 1; level <= o.Levels; level++ {
			suffix, remote, lev := fmt.Sprintf("%s%d", site, level), fmt.Sprintf("%s%d", peerSite, level), fmt.Sprintf("S%d", level)
			red, remRed := fmt.Sprintf("10.%d.%d.", idx, level), fmt.Sprintf("10.%d.%d.", other, level)
			gray, remGray := fmt.Sprintf("10.%d.%d.", idx*100, level), fmt.Sprintf("10.%d.%d.", other*100, level)
			wan, remWan := fmt.Sprintf("172.20.%d.", idx*10+level), fmt.Sprintf("172.20.%d.", other*10+level)
			for _, pair := range [][2]string{{"R_", "host"}, {"I_", "inner"}, {"O_", "outer"}} {
				add(pair[0]+suffix, pair[1], site, lev)
			}
			cable("R_"+suffix, "red", red+"10/24", "red", "I_"+suffix, "red", red+"1/24", "red")
			innerGW := gray + "1"
			if o.SharedGray {
				gf := gfID(site, (level-1)%o.GrayFirewalls+1)
				cable("I_"+suffix, "gray", gray+"2/24", "gray", gf, fmt.Sprintf("s%d", level), gray+"254/24", "gray")
				outerGray := fmt.Sprintf("%s%d", fabric, level)
				cable("O_"+suffix, "gray", outerGray+"/24", "gray", "G_"+site, fmt.Sprintf("outer%d", level), "", "gray")
				innerGW = gray + "254"
				route(gf, remGray+"2/32", outerGray)
				route("O_"+suffix, gray+"2/32", fmt.Sprintf("%s%d", fabric, 241+(level-1)%o.GrayFirewalls))
			} else {
				add("G_"+suffix, "switch", site, lev)
				cable("I_"+suffix, "gray", gray+"2/24", "gray", "G_"+suffix, "inner", "", "gray")
				cable("O_"+suffix, "gray", gray+"1/24", "gray", "G_"+suffix, "outer", "", "gray")
				for k := 1; k <= o.GrayFirewalls; k++ {
					port := "filter"
					if o.GrayFirewalls > 1 {
						port = fmt.Sprintf("filter%d", k)
					}
					cable(gfID(site, k), fmt.Sprintf("s%d", level), fmt.Sprintf("%s%d/24", gray, 255-k), "gray", "G_"+suffix, port, "", "gray")
				}
			}
			of := fmt.Sprintf("OF_%s%d", site, (level-1)%o.OuterFirewalls+1)
			inside := "inside"
			if o.OuterFirewalls < o.Levels {
				inside = fmt.Sprintf("in%d", level)
			}
			cable("O_"+suffix, "black", wan+"1/30", "black", of, inside, wan+"2/30", "black")
			route("R_"+suffix, "0.0.0.0/0", red+"1")
			route("I_"+suffix, remRed+"0/24", innerGW)
			route("I_"+suffix, remGray+"2/32", innerGW)
			for cross := 1; cross <= o.Levels; cross++ {
				if cross != level {
					route("I_"+suffix, fmt.Sprintf("10.%d.%d.0/24", idx*100, cross), gray+"254")
				}
			}
			route("O_"+suffix, remGray+"2/32", wan+"2")
			route("O_"+suffix, remWan+"1/32", wan+"2")
			s.Device("I_" + suffix).Tunnel = &Tunnel{Peer: "I_" + remote, Local: gray + "2", Remote: remGray + "2", LocalTS: red + "0/24", RemoteTS: remRed + "0/24", Trust: fmt.Sprintf("inner-s%d", level), ReqID: 100 + level, Inside: "red", Outside: "gray"}
			s.Device("O_" + suffix).Tunnel = &Tunnel{Peer: "O_" + remote, Local: wan + "1", Remote: remWan + "1", LocalTS: gray + "2/32", RemoteTS: remGray + "2/32", Trust: "outer", ReqID: 200 + level, Inside: "gray", Outside: "black"}
		}
		if o.SharedGray {
			for k := 1; k <= o.GrayFirewalls; k++ {
				for level := 1; level <= o.Levels; level++ {
					owner := (level-1)%o.GrayFirewalls + 1
					if owner != k {
						route(gfID(site, k), fmt.Sprintf("10.%d.%d.0/24", idx*100, level), fmt.Sprintf("%s%d", fabric, 240+owner))
					}
				}
			}
		}
		domains := []int{}
		for i := 1; i <= o.Levels; i++ {
			domains = append(domains, i)
		}
		domains = append(domains, 99)
		for _, domain := range domains {
			group := fmt.Sprintf("%s%d", site, domain)
			net := fmt.Sprintf("172.30.%d.", idx*10+domain)
			sw, aw := "M_"+group, "AW_"+group
			add(sw, "switch", site, "management")
			add(aw, "admin", site, "management")
			cable(aw, "mgmt", net+"10/24", "management", sw, "admin", "", "management")
			targets := []string{fmt.Sprintf("I_%s%d", site, domain)}
			if domain == 99 {
				targets = nil
				for k := 1; k <= o.GrayFirewalls; k++ {
					targets = append(targets, gfID(site, k))
				}
				for k := 1; k <= o.Levels; k++ {
					targets = append(targets, fmt.Sprintf("O_%s%d", site, k))
				}
				for k := 1; k <= o.OuterFirewalls; k++ {
					targets = append(targets, fmt.Sprintf("OF_%s%d", site, k))
				}
			}
			for j, id := range targets {
				cable(id, "mgmt", fmt.Sprintf("%s%d/24", net, j+20), "management", sw, fmt.Sprintf("d%d", j), "", "management")
				s.Device(id).Admin = net + "10"
			}
		}
	}
	return s, s.Validate()
}
