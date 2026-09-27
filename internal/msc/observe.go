package msc

import (
	"context"
	"encoding/json"
	"fmt"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Observation struct {
	Device string            `json:"device"`
	Role   string            `json:"role"`
	State  rt.State          `json:"state"`
	Image  string            `json:"image"`
	Facts  map[string]string `json:"facts"`
	Errors map[string]string `json:"errors,omitempty"`
}
type Status struct {
	Lab      string          `json:"lab"`
	SpecHash string          `json:"spec_sha256"`
	Started  time.Time       `json:"started"`
	Finished time.Time       `json:"finished"`
	Devices  []Observation   `json:"devices"`
	Fault    json.RawMessage `json:"fault,omitempty"`
}

// Status reads live facts. It deliberately never asks for XFRM key material.
func (e *Engine) Status(ctx context.Context) (Status, error) {
	out := Status{Lab: e.Spec.Name, SpecHash: e.Spec.Hash(), Started: time.Now().UTC()}
	if b, err := os.ReadFile(filepath.Join(e.Dir, "fault.json")); err == nil {
		out.Fault = b
	} else if !os.IsNotExist(err) {
		return out, err
	}
	for i := range e.Spec.Devices {
		d := &e.Spec.Devices[i]
		c, err := e.owned(ctx, d)
		if err != nil {
			return out, err
		}
		o := Observation{Device: d.ID, Role: d.Role, State: c.State, Image: c.ImageID, Facts: map[string]string{}, Errors: map[string]string{}}
		if c.State == rt.StateRunning {
			commands := map[string][]string{"interfaces": {"ip", "-j", "address", "show"}, "routes": {"ip", "-j", "route", "show", "table", "all"}, "rules": {"ip", "-j", "rule", "show"}, "filter": {"iptables-save", "-t", "filter"}, "forwarding": {"sysctl", "-n", "net.ipv4.ip_forward"}, "processes": {"ps", "-eo", "comm="}}
			if d.Tunnel != nil {
				commands["sas"] = []string{"swanctl", "--list-sas"}
				commands["certificates"] = []string{"swanctl", "--list-certs"}
				commands["policies"] = []string{"ip", "xfrm", "policy", "list"}
				commands["xfrm"] = []string{"ip", "-s", "xfrm", "state", "list", "nokeys"}
			}
			for k, args := range commands {
				v, er := e.exec(ctx, d.ID, args...)
				if er != nil {
					o.Errors[k] = er.Error()
				} else {
					o.Facts[k] = v
				}
			}
		}
		out.Devices = append(out.Devices, o)
	}
	out.Finished = time.Now().UTC()
	return out, nil
}

type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}
type Report struct {
	Lab      string    `json:"lab"`
	At       time.Time `json:"at"`
	SpecHash string    `json:"spec_sha256"`
	Passed   bool      `json:"passed"`
	Checks   []Check   `json:"checks"`
}

func (r *Report) add(name string, passed bool, detail string) {
	r.Checks = append(r.Checks, Check{name, passed, detail})
	if !passed {
		r.Passed = false
	}
}
func (e *Engine) ping(ctx context.Context, from, to string) (bool, string) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := e.exec(cctx, from, "ping", "-n", "-c", "2", "-W", "1", to)
	if err != nil {
		return false, err.Error()
	}
	return true, strings.TrimSpace(out)
}
func (e *Engine) Check(ctx context.Context) (Report, error) {
	r := Report{Lab: e.Spec.Name, At: time.Now().UTC(), SpecHash: e.Spec.Hash(), Passed: true}
	st, err := e.Status(ctx)
	if err != nil {
		return r, err
	}
	if len(st.Fault) > 0 {
		r.add("no-active-fault", false, string(st.Fault))
	}
	for _, o := range st.Devices {
		r.add("running/"+o.Device, o.State == rt.StateRunning, string(o.State))
		r.add("observations/"+o.Device, len(o.Errors) == 0, fmt.Sprint(o.Errors))
		if o.State != rt.StateRunning {
			continue
		}
		d := e.Spec.Device(o.Device)
		wantForward := "1"
		if d.Role == "host" || d.Role == "admin" || d.Role == "switch" {
			wantForward = "0"
		}
		r.add("forwarding/"+d.ID, strings.TrimSpace(o.Facts["forwarding"]) == wantForward, "expected "+wantForward)
		if d.Role == "outer" {
			routing := false
			for _, p := range strings.Fields(o.Facts["processes"]) {
				if p == "bgpd" || p == "ospfd" || p == "ospf6d" || p == "bird" {
					routing = true
				}
			}
			r.add("no-routing-daemon/"+d.ID, !routing, "outer encryption appliances use static crypto forwarding")
		}
		// iptables-save canonicalizes host selectors and module ordering. Compare
		// the kernel's normalization of the expected rules with the observed rules.
		expected, err := os.ReadFile(filepath.Join(e.Dir, "devices", d.ID, "filter.expected"))
		r.add("filter/"+d.ID, err == nil && canonicalFilter(string(expected)) == canonicalFilter(o.Facts["filter"]), "kernel-normalized baseline comparison")
		if d.Tunnel != nil {
			r.add("ipsec/"+d.ID, strings.Contains(o.Facts["sas"], "ESTABLISHED") && strings.Contains(o.Facts["sas"], "INSTALLED") && strings.Contains(o.Facts["sas"], "TUNNEL"), o.Facts["sas"])
		}
	}
	// Confirm source traffic and encrypted carriage with live, ready captures.
	if err = e.beginCapture(ctx, "BLACK", "black"); err != nil {
		return r, err
	}
	if err = e.beginCapture(ctx, "G_A1", "gray"); err != nil {
		return r, err
	}
	hosts := []*Device{}
	for i := range e.Spec.Devices {
		if e.Spec.Devices[i].Role == "host" {
			hosts = append(hosts, &e.Spec.Devices[i])
		}
	}
	for _, a := range hosts {
		for _, b := range hosts {
			if a.ID == b.ID {
				continue
			}
			ip := strings.Split(b.Interface("red").Address, "/")[0]
			ok, detail := e.ping(ctx, a.ID, ip)
			want := a.Level == b.Level
			r.add("reachability/"+a.ID+"/"+b.ID, ok == want, fmt.Sprintf("want delivery=%v; %s", want, detail))
		}
	}
	for _, p := range []struct{ device, name, peerFilter string }{{"BLACK", "black", "esp"}, {"G_A1", "gray", "esp"}} {
		if err = e.finishCapture(ctx, p.device, p.name); err != nil {
			return r, err
		}
		count, err := e.exec(ctx, p.device, "sh", "-ec", "tcpdump -Z root -nn -r /tmp/msc-"+p.name+".pcap '"+p.peerFilter+"' 2>/dev/null | wc -l")
		r.add("capture/"+p.name+"/esp", err == nil && strings.TrimSpace(count) != "0", strings.TrimSpace(count)+" ESP observations")
		plain, err := e.exec(ctx, p.device, "tcpdump", "-Z", "root", "-nn", "-r", "/tmp/msc-"+p.name+".pcap", "net 10.1.0.0/16 or net 10.2.0.0/16")
		r.add("capture/"+p.name+"/no-red-plaintext", err == nil && strings.TrimSpace(plain) == "", plain)
	}
	for _, site := range []string{"A", "B"} {
		r.add("gray-firewall-cut/"+site, graySeparated(e.Spec, "I_"+site+"1", "I_"+site+"2"), "all modeled Gray paths cross a Gray Firewall")

		// Give a local cross-level packet a real route to the Gray Firewall, then
		// require that its explicit default-deny forwarding policy blocks it.
		from := e.Spec.Device("I_" + site + "1")
		target := e.Spec.Device("I_" + site + "2")
		ip := strings.Split(target.Interface("gray").Address, "/")[0]
		before, er := e.exec(ctx, "GF_"+site, "iptables", "-nvx", "-L", "FORWARD")
		if er != nil {
			return r, er
		}
		ok, _ := e.ping(ctx, from.ID, ip)
		after, er := e.exec(ctx, "GF_"+site, "iptables", "-nvx", "-L", "FORWARD")
		r.add("gray-cross-level/"+site, !ok && er == nil && before != after, "probe blocked and firewall counters changed")
	}
	for _, d := range e.Spec.Devices {
		if d.Admin == "" {
			continue
		}
		var aw string
		for _, a := range e.Spec.Devices {
			if a.Role == "admin" && strings.Split(a.Interface("mgmt").Address, "/")[0] == d.Admin {
				aw = a.ID
			}
		}
		ip := strings.Split(d.Interface("mgmt").Address, "/")[0]
		_, err = e.exec(ctx, aw, "python3", "-c", `import ssl,urllib.request,sys;c=ssl.create_default_context(cafile='/run/msc-tls/x509ca/ca.pem');c.load_cert_chain('/run/msc-tls/x509/cert.pem','/run/msc-tls/private/key.pem');print(urllib.request.urlopen('https://'+sys.argv[1]+':8443',context=c,timeout=3).read().decode())`, ip)
		r.add("management/"+aw+"/"+d.ID, err == nil, fmt.Sprint(err))
		_, unauthErr := e.exec(ctx, aw, "python3", "-c", `import ssl,urllib.request,sys;c=ssl.create_default_context(cafile='/run/msc-tls/x509ca/ca.pem');urllib.request.urlopen('https://'+sys.argv[1]+':8443',context=c,timeout=3).read()`, ip)
		r.add("management-client-auth/"+d.ID, err == nil && unauthErr != nil, "reachable endpoint rejects a client without a certificate")
	}
	return r, nil
}
func (e *Engine) beginCapture(ctx context.Context, id, name string) error {
	prefix := "/tmp/msc-" + name
	body := "rm -f " + prefix + ".pcap " + prefix + ".log " + prefix + ".done; tcpdump -Z root -U -nn -i any -w " + prefix + ".pcap >/dev/null 2>" + prefix + ".log & cap_pid=$!; echo $cap_pid >" + prefix + ".pid; set +e; wait $cap_pid; echo $? >" + prefix + ".done"

	if err := e.background(ctx, id, body); err != nil {
		return err
	}
	for i := 0; i < 30; i++ {
		if v, er := e.exec(ctx, id, "cat", "/tmp/msc-"+name+".log"); er == nil && strings.Contains(v, "listening on") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("capture on %s never became ready", id)
}

func graySeparated(s *Spec, from, to string) bool {
	edges := map[string][]string{}
	for _, l := range s.Links {
		a, b := s.Device(l.A.Device), s.Device(l.B.Device)
		if a.Role == "gray-firewall" || b.Role == "gray-firewall" {
			continue
		}
		if a.Interface(l.A.Interface).Zone != "gray" || b.Interface(l.B.Interface).Zone != "gray" {
			continue
		}
		edges[a.ID] = append(edges[a.ID], b.ID)
		edges[b.ID] = append(edges[b.ID], a.ID)
	}
	seen := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		if v == to {
			return false
		}
		for _, n := range edges[v] {
			if !seen[n] {
				seen[n] = true
				queue = append(queue, n)
			}
		}
	}
	return true
}

func (e *Engine) finishCapture(ctx context.Context, id, name string) error {
	prefix := "/tmp/msc-" + name
	body := "cap_pid=$(cat " + prefix + ".pid); kill -0 $cap_pid; kill -INT $cap_pid; for attempt in $(seq 1 30); do if test -f " + prefix + ".done; then test $(cat " + prefix + ".done) = 0; grep -q '0 packets dropped by kernel' " + prefix + ".log; exit; fi; sleep 0.1; done; exit 1"
	if err := e.shell(ctx, id, body); err != nil {
		return fmt.Errorf("capture %s/%s did not finish cleanly: %w", id, name, err)
	}
	return nil
}
