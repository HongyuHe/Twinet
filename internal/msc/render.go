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
	b.WriteString("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -i lo -j ACCEPT\n")
	if d.Admin != "" {
		fmt.Fprintf(&b, "-A INPUT -i mgmt -s %s -p icmp -j ACCEPT\n-A INPUT -i mgmt -s %s -p tcp --dport 8443 -j ACCEPT\n", d.Admin, d.Admin)
	}
	switch d.Role {
	case "host", "admin":
		b.WriteString("-A INPUT -p icmp -j ACCEPT\n-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	case "transport", "switch":
		b.WriteString("-A INPUT -p icmp -j ACCEPT\n-A FORWARD -j ACCEPT\n")
	case "inner", "outer":
		t := d.Tunnel
		fmt.Fprintf(&b, "-A INPUT -i %s -s %s -d %s -p udp -m multiport --dports 500,4500 -j ACCEPT\n-A INPUT -i %s -s %s -d %s -p esp -j ACCEPT\n", t.Outside, t.Remote, t.Local, t.Outside, t.Remote, t.Local)
		protocols := []string{""}
		if d.Role == "outer" {
			protocols = []string{" -p esp", " -p udp -m multiport --dports 500,4500"}
		}
		for _, proto := range protocols {
			fmt.Fprintf(&b, "-A FORWARD -i %s -o %s -s %s -d %s%s -m policy --dir out --pol ipsec --mode tunnel --reqid %d -j ACCEPT\n", t.Inside, t.Outside, t.LocalTS, t.RemoteTS, proto, t.ReqID)
			fmt.Fprintf(&b, "-A FORWARD -i %s -o %s -s %s -d %s%s -m policy --dir in --pol ipsec --mode tunnel --reqid %d -j ACCEPT\n", t.Outside, t.Inside, t.RemoteTS, t.LocalTS, proto, t.ReqID)
		}
	case "firewall":
		outer := s.Device(strings.Replace(d.ID, "OF_", "O_", 1))
		if outer != nil && outer.Tunnel != nil {
			t := outer.Tunnel
			for _, r := range []struct{ in, out, src, dst string }{{"inside", "outside", t.Local, t.Remote}, {"outside", "inside", t.Remote, t.Local}} {
				fmt.Fprintf(&b, "-A FORWARD -i %s -o %s -s %s -d %s -p esp -j ACCEPT\n", r.in, r.out, r.src, r.dst)
				fmt.Fprintf(&b, "-A FORWARD -i %s -o %s -s %s -d %s -p udp -m multiport --dports 500,4500 -j ACCEPT\n", r.in, r.out, r.src, r.dst)
			}
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
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
