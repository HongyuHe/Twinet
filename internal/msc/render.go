package msc

import (
	"fmt"
	"strings"
)

func swanConfig(d *Device) string {
	t := d.Tunnel
	return fmt.Sprintf(`connections {
 msc {
  version = 2
  local_addrs = %s
  remote_addrs = %s
  proposals = aes256gcm16-prfsha384-ecp384
  reauth_time = 3h
  rekey_time = 0s
  over_time = 10m
  dpd_delay = 10s
  keyingtries = 0
  mobike = no
  local {
   auth = pubkey
   certs = cert.pem
   id = %s.msc.test
  }
  remote {
   auth = pubkey
   id = %s.msc.test
   cacerts = ca.pem
   revocation = strict
  }
  children {
   protected {
    local_ts = %s
    remote_ts = %s
    mode = tunnel
    reqid = %d
    esp_proposals = aes256gcm16-ecp384
    rekey_time = 50m
    life_time = 1h
    start_action = trap
    dpd_action = trap
    close_action = trap
   }
  }
 }
}
`, t.Local, t.Remote, d.ID, t.Peer, t.LocalTS, t.RemoteTS, t.ReqID)
}

// filterRules deliberately has no broad ESTABLISHED forwarding exemption.
// Every forwarded payload must still match its IPsec policy after SA loss.
func filterRules(s *Spec, d *Device) string {
	var b strings.Builder
	b.WriteString("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n")
	localDefaultDeny := d.Role == "inner" || d.Role == "outer" || d.Role == "firewall" || d.Role == "gray-firewall"
	if d.Role == "inner" || d.Role == "outer" {
		// PF-11 applies to every gateway. Keep loopback and locally generated
		// traffic inside the same IPv4 protocol set as forwarded payloads.
		// Data-facing OUTPUT allowances are bound to the tunnel peer below.
		b.WriteString(":OUTPUT DROP [0:0]\n")
		for _, proto := range []string{"tcp", "udp", "esp", "icmp"} {
			fmt.Fprintf(&b, "-A INPUT -i lo -p %s -j ACCEPT\n-A OUTPUT -o lo -p %s -j ACCEPT\n", proto, proto)
		}
	} else if localDefaultDeny {
		b.WriteString(":OUTPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\n-A OUTPUT -o lo -j ACCEPT\n")
	} else {
		b.WriteString(":OUTPUT ACCEPT [0:0]\n-A INPUT -i lo -j ACCEPT\n")
	}
	if d.Admin != "" {
		fmt.Fprintf(&b, "-A INPUT -i mgmt -s %s -p icmp -j ACCEPT\n-A INPUT -i mgmt -s %s -p tcp --dport 8443 -j ACCEPT\n", d.Admin, d.Admin)
		if localDefaultDeny {
			fmt.Fprintf(&b, "-A OUTPUT -o mgmt -d %s -p icmp -j ACCEPT\n-A OUTPUT -o mgmt -d %s -p tcp --sport 8443 -j ACCEPT\n", d.Admin, d.Admin)
		}
	}
	switch d.Role {
	case "host", "admin":
		b.WriteString("-A INPUT -p icmp -j ACCEPT\n-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	case "transport", "switch":
		if s.IsOSPF(d) {
			for _, port := range d.Interfaces {
				peer, pi := s.Peer(d.ID, port.Name)
				if peer != nil && s.IsOSPF(peer) {
					fmt.Fprintf(&b, "-A INPUT -i %s -s %s -p ospf -j ACCEPT\n", port.Name, strings.Split(pi.Address, "/")[0])
				}
			}
		}
		b.WriteString("-A INPUT -p icmp -j ACCEPT\n-A FORWARD -j ACCEPT\n")
	case "inner", "outer":
		t := d.Tunnel
		// Only the declared peer may receive gateway-local IKE or ESP on
		// the external data interface. Protected forwarding keeps its XFRM guard.
		fmt.Fprintf(&b, "-A OUTPUT -o %s -s %s -d %s -p udp -m multiport --dports 500,4500 -j ACCEPT\n-A OUTPUT -o %s -s %s -d %s -p esp -j ACCEPT\n", t.Outside, t.Local, t.Remote, t.Outside, t.Local, t.Remote)
		fmt.Fprintf(&b, "-A INPUT -i %s -s %s -d %s -p udp -m multiport --dports 500,4500 -j ACCEPT\n-A INPUT -i %s -s %s -d %s -p esp -j ACCEPT\n", t.Outside, t.Remote, t.Local, t.Outside, t.Remote, t.Local)
		protocols := []string{" -p tcp", " -p udp", " -p esp", " -p icmp"}
		if d.Role == "outer" {
			protocols = []string{" -p esp", " -p udp -m multiport --dports 500,4500"}
		}
		for _, proto := range protocols {
			fmt.Fprintf(&b, "-A FORWARD -i %s -o %s -s %s -d %s%s -m policy --dir out --pol ipsec --mode tunnel --reqid %d -j ACCEPT\n", t.Inside, t.Outside, t.LocalTS, t.RemoteTS, proto, t.ReqID)
			fmt.Fprintf(&b, "-A FORWARD -i %s -o %s -s %s -d %s%s -m policy --dir in --pol ipsec --mode tunnel --reqid %d -j ACCEPT\n", t.Outside, t.Inside, t.RemoteTS, t.LocalTS, proto, t.ReqID)
		}
	case "firewall":
		for _, port := range d.Interfaces {
			peer, pi := s.Peer(d.ID, port.Name)
			if peer == nil {
				continue
			}
			if s.IsOSPF(d) && s.IsOSPF(peer) {
				local := strings.Split(port.Address, "/")[0]
				remote := strings.Split(pi.Address, "/")[0]
				// Native OSPF adjacencies use numbered point-to-point links.
				// Bind both directions to that link and its actual neighbor.
				for _, destination := range []string{local, "224.0.0.5"} {
					fmt.Fprintf(&b, "-A INPUT -i %s -s %s -d %s -p ospf -j ACCEPT\n", port.Name, remote, destination)
				}
				for _, destination := range []string{remote, "224.0.0.5"} {
					fmt.Fprintf(&b, "-A OUTPUT -o %s -s %s -d %s -p ospf -j ACCEPT\n", port.Name, local, destination)
				}
			}
			if peer.Role != "outer" {
				continue
			}
			t := peer.Tunnel
			for _, r := range []struct{ in, out, src, dst string }{{port.Name, "outside", t.Local, t.Remote}, {"outside", port.Name, t.Remote, t.Local}} {
				writePeerFilter(&b, r.in, r.out, r.src, r.dst)
			}
		}
	case "gray-firewall":
		// Only inline shared-Gray paths carry authorized inner peer traffic.
		for _, port := range d.Interfaces {
			peer, _ := s.Peer(d.ID, port.Name)
			if peer == nil || peer.Role != "inner" || d.Interface("fabric") == nil {
				continue
			}
			t := peer.Tunnel
			writePeerFilter(&b, port.Name, "fabric", t.Local, t.Remote)
			writePeerFilter(&b, "fabric", port.Name, t.Remote, t.Local)
		}

	}
	b.WriteString("COMMIT\n")
	rules := b.String()
	if d.Role == "outer" {
		// The low nibble of the first IPv4 byte is the header length in words.
		// PF-10 selects IHL=5, excluding options on every ACCEPT path. Chain
		// defaults remain DROP, including OUTPUT, so no broad path bypasses it.
		rules = strings.ReplaceAll(rules, " -j ACCEPT", " -m u32 --u32 \"0>>0x18&0xf=0x5\" -j ACCEPT")
	}
	return rules
}
func canonicalFilter(in string) string {
	var out []string
	for _, l := range strings.Split(in, "\n") {
		if strings.HasPrefix(l, "*") || strings.HasPrefix(l, "-A ") || strings.HasPrefix(l, ":") || l == "COMMIT" {
			if strings.HasPrefix(l, ":") {
				f := strings.Fields(l)
				if len(f) > 1 {
					l = f[0] + " " + f[1]
				}
			}
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

const adminServer = `import http.server, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain('/run/msc-tls/x509/cert.pem', '/run/msc-tls/private/key.pem')
ctx.load_verify_locations('/run/msc-tls/x509ca/ca.pem')
ctx.verify_mode = ssl.CERT_REQUIRED
class Health(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'MSC management reachable\n')
server = http.server.HTTPServer(('0.0.0.0', 8443), Health)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
`

func writePeerFilter(b *strings.Builder, in, out, src, dst string) {
	fmt.Fprintf(b, "-A FORWARD -i %s -o %s -s %s -d %s -p esp -j ACCEPT\n", in, out, src, dst)
	fmt.Fprintf(b, "-A FORWARD -i %s -o %s -s %s -d %s -p udp -m multiport --dports 500,4500 -j ACCEPT\n", in, out, src, dst)
}
