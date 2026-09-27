package msc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/access"
	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/nos"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// nativeTopology feeds the existing deployment, NOS and access stack. FRR
// daemons retain the dev branch's private control sidecar; the interactive
// router container never receives its SYS_ADMIN capability.
func (e *Engine) nativeTopology() *model.Topology {
	top := &model.Topology{Name: e.Spec.Name, Hash: e.Spec.Hash(), Lab: &model.Lab{}, Devices: map[string]*model.Device{}, ASes: map[int]*model.AS{}}
	for _, d := range e.Spec.Devices {
		kind := model.KindHost
		if e.Spec.IsFRR(&d) {
			kind = model.KindRouter
		}
		if e.Spec.IsOVS(&d) {
			kind = model.KindSwitch
		}
		m := &model.Device{ID: d.ID, Name: d.ID, Kind: kind, Capabilities: []string{"NET_ADMIN", "NET_RAW"}, Image: e.Spec.ImageFor(&d), Container: e.Spec.Container(d.ID), CPUs: 2, Memory: "256Mi", Pids: 512, Command: []string{"sleep", "infinity"},
			Labels:  map[string]string{"twinet.msc.lab": e.Spec.Name, "twinet.msc.state": e.Dir, "twinet.msc.spec": e.Spec.Hash(), "twinet.msc.device": d.ID},
			Sysctls: map[string]string{"net.ipv4.ip_forward": "0", "net.ipv4.conf.all.rp_filter": "0", "net.ipv4.conf.default.rp_filter": "0", "net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.default.send_redirects": "0", "net.ipv6.conf.all.disable_ipv6": "1"}}
		if d.Interface("mgmt") != nil {
			m.Binds = append(m.Binds, e.tlsDir(&d)+":/run/msc-tls:ro")
		}
		for _, p := range d.Interfaces {
			m.Ifaces = append(m.Ifaces, &model.Iface{Name: p.Name, Addr4: p.Address, Device: m, Owner: model.OwnerPlatform})
		}
		top.Devices[d.ID] = m
	}
	for n, l := range e.Spec.Links {
		var ends [2]*model.Iface
		for k, ep := range []Endpoint{l.A, l.B} {
			for _, p := range top.Devices[ep.Device].Ifaces {
				if p.Name == ep.Interface {
					ends[k] = p
				}
			}
		}
		link := &model.Link{ID: fmt.Sprintf("msc-%d", n), A: ends[0], B: ends[1]}
		ends[0].Link = link
		ends[1].Link = link
		ends[0].Peer = ends[1]
		ends[1].Peer = ends[0]
		top.Links = append(top.Links, link)
	}
	return top
}
func (e *Engine) deployEngine() *deploy.Engine {
	return &deploy.Engine{Runtime: e.Runtime, FRRControlRoot: filepath.Join(e.Dir, "native", "frr"), WritableRoot: filepath.Join(e.Dir, "native", "writable")}
}
func (e *Engine) nativeRuntimeSpec(ctx context.Context, d *Device, imageID string) (*rt.Spec, error) {
	top := e.nativeTopology()
	m := top.Devices[d.ID]
	m.ImageID = imageID
	m.Labels["twinet.msc.image"] = imageID
	de := e.deployEngine()
	if err := de.PrepareRuntimeSpec(top, m); err != nil {
		return nil, err
	}
	return de.RuntimeSpec(ctx, top, m)
}
func (e *Engine) ownedControl(ctx context.Context, d *Device) (rt.Container, error) {
	c, err := e.Runtime.Inspect(ctx, e.Spec.Container(d.ID)+"-frr")
	if err != nil {
		return c, err
	}
	if c.State != rt.StateAbsent && (c.Labels["twinet.msc.lab"] != e.Spec.Name || c.Labels["twinet.msc.state"] != e.Dir) {
		return c, fmt.Errorf("refuse foreign FRR control container %s", c.Name)
	}
	return c, nil
}
func (e *Engine) removeNativeControls(ctx context.Context) error {
	for _, d := range e.Spec.Devices {
		if !e.Spec.IsFRR(&d) {
			continue
		}
		c, err := e.ownedControl(ctx, &d)
		if err != nil {
			return err
		}
		if c.State != rt.StateAbsent {
			if err = e.Runtime.Remove(ctx, e.Spec.Container(d.ID)+"-frr", true); err != nil {
				return err
			}
		}
	}
	return nil
}
func frrConfig(s *Spec, d *Device) string {
	var b strings.Builder
	fmt.Fprintf(&b, "frr defaults traditional\nhostname %s\nservice integrated-vtysh-config\n!\n", d.ID)
	routerID := ""
	for _, p := range d.Interfaces {
		fmt.Fprintf(&b, "interface %s\n", p.Name)
		if p.Address != "" {
			fmt.Fprintf(&b, " ip address %s\n", p.Address)
		}
		if s.IsOSPF(d) && p.Zone == "black" {
			if routerID == "" {
				routerID = strings.Split(p.Address, "/")[0]
			}
			b.WriteString(" ip ospf area 0\n")
			peer, _ := s.Peer(d.ID, p.Name)
			if peer != nil && s.IsOSPF(peer) {
				b.WriteString(" ip ospf network point-to-point\n ip ospf hello-interval 1\n ip ospf dead-interval 4\n")
			}
		}
		b.WriteString("exit\n!\n")
	}
	for _, r := range d.Routes {
		fmt.Fprintf(&b, "ip route %s %s\n", r.Prefix, r.Via)
	}
	if s.IsOSPF(d) {
		fmt.Fprintf(&b, "router ospf\n ospf router-id %s\n passive-interface default\n", routerID)
		for _, p := range d.Interfaces {
			peer, _ := s.Peer(d.ID, p.Name)
			if p.Zone == "black" && peer != nil && s.IsOSPF(peer) {
				fmt.Fprintf(&b, " no passive-interface %s\n", p.Name)
			}
		}
		b.WriteString("exit\n!\n")
	}
	b.WriteString("line vty\n!\n")
	return b.String()
}
func (e *Engine) configureFRR(ctx context.Context, d *Device, imageID string) error {
	if _, err := e.ownedControl(ctx, d); err != nil {
		return err
	}
	top := e.nativeTopology()
	m := top.Devices[d.ID]
	m.ImageID = imageID
	m.Labels["twinet.msc.image"] = imageID
	de := e.deployEngine()
	if err := de.RecreateRuntimeSupport(ctx, top, m); err != nil {
		return err
	}
	daemons := strings.ReplaceAll(render.FRRDaemons, "bgpd=yes", "bgpd=no")
	if !e.Spec.IsOSPF(d) {
		daemons = strings.ReplaceAll(daemons, "ospfd=yes", "ospfd=no")
	}
	provider, err := nos.Resolve(m)
	if err != nil {
		return err
	}
	request := nos.RenderRequest{Topology: top, Device: m, Mode: nos.ModePlatform, Platform: frrConfig(e.Spec, d), Daemons: daemons}
	files, err := provider.Render(request)
	if err != nil {
		return err
	}
	control := deploy.FRRControlContainer(m)
	for path, file := range files.Files {
		if err = e.copyFile(ctx, control, path, file.Mode, file.Content); err != nil {
			return err
		}
	}
	run := func(args []string) error {
		r, er := e.Runtime.Exec(ctx, control, rt.ExecCmd{Cmd: args})
		if er != nil {
			return er
		}
		return r.Err()
	}
	if err = run([]string{"sh", "-ec", "chown frr:frr /etc/frr/frr.conf /etc/frr/daemons; rm -f /run/frr/*.pid /run/frr/*.vty"}); err != nil {
		return err
	}
	commands, err := provider.Apply(request)
	if err != nil {
		return err
	}
	for _, c := range commands {
		if err = run(c.Args); err != nil {
			return err
		}
	}
	probe := "vtysh -d zebra -c 'show version' >/dev/null && vtysh -d staticd -c 'show version' >/dev/null"
	if e.Spec.IsOSPF(d) {
		probe += " && vtysh -d ospfd -c 'show version' >/dev/null"
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err = e.shell(ctx, d.ID, probe); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("FRR on %s did not start: %w", d.ID, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	config, err := e.exec(ctx, d.ID, "vtysh", "-c", "show running-config")
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(e.Dir, "devices", d.ID, "frr.expected"), []byte(canonicalFRR(config)))
}

// Forwarding is checked separately against the live namespace sysctl. FRR
// displays that kernel setting even when it was not a user configuration edit.
func canonicalFRR(config string) string {
	var lines []string
	for _, line := range strings.Split(config, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "ip forwarding" || trim == "no ip forwarding" || trim == "" || strings.HasPrefix(trim, "Building configuration") || strings.HasPrefix(trim, "Current configuration") || strings.HasPrefix(trim, "! Last") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
func (e *Engine) configureOVS(ctx context.Context, d *Device) error {
	// Reset only this owned switch's database, then use the ordinary renderer.
	if err := e.shell(ctx, d.ID, "for br in $(ovs-vsctl --timeout=5 list-br); do ovs-vsctl del-br \"$br\"; done"); err != nil {
		return err
	}
	top := e.nativeTopology()
	renderer := render.New(top, render.ModePlatform)
	commands, err := renderer.Commands(top.Devices[d.ID])
	if err != nil {
		return err
	}
	for _, c := range commands {
		if _, err := e.exec(ctx, d.ID, c.Args...); err != nil {
			return err
		}
	}
	if err := e.shell(ctx, d.ID, "ovs-vsctl set-fail-mode br0 secure; ovs-ofctl del-flows br0; ovs-ofctl add-flow br0 'priority=0,actions=NORMAL'"); err != nil {
		return err
	}
	state, err := e.ovsState(ctx, d)
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(e.Dir, "devices", d.ID, "ovs.expected"), []byte(state))
}
func (e *Engine) ovsState(ctx context.Context, d *Device) (string, error) {
	// IDs and counters vary at runtime; forwarding policy and port membership do not.
	ports, err := e.exec(ctx, d.ID, "ovs-vsctl", "--format=json", "--columns=name,tag,trunks,vlan_mode", "list", "Port")
	if err != nil {
		return "", err
	}
	var rows struct {
		Data []json.RawMessage `json:"data"`
	}
	if err = json.Unmarshal([]byte(ports), &rows); err != nil {
		return "", err
	}
	out := []string{}
	for _, row := range rows.Data {
		var value any
		if err = json.Unmarshal(row, &value); err != nil {
			return "", err
		}
		b, _ := json.Marshal(value)
		out = append(out, string(b))
	}
	sort.Strings(out)
	membership, err := e.exec(ctx, d.ID, "ovs-vsctl", "list-ports", "br0")
	if err != nil {
		return "", err
	}
	members := strings.Fields(membership)
	sort.Strings(members)
	out = append(out, strings.Join(members, ","))
	flows, err := e.exec(ctx, d.ID, "ovs-ofctl", "dump-flows", "br0")
	if err != nil {
		return "", err
	}
	var policy []string
	for _, line := range strings.Split(flows, "\n") {
		if pos := strings.Index(line, "priority="); pos >= 0 {
			policy = append(policy, line[pos:])
		}
	}
	sort.Strings(policy)
	out = append(out, policy...)
	mode, err := e.exec(ctx, d.ID, "ovs-vsctl", "get-fail-mode", "br0")
	if err != nil {
		return "", err
	}
	out = append(out, strings.TrimSpace(mode))
	controller, err := e.exec(ctx, d.ID, "ovs-vsctl", "get-controller", "br0")
	if err != nil {
		return "", err
	}
	out = append(out, strings.TrimSpace(controller))
	return strings.Join(out, "\n"), nil
}
func (s *Spec) ospfNeighbors(d *Device) int {
	count := 0
	for _, p := range d.Interfaces {
		peer, _ := s.Peer(d.ID, p.Name)
		if p.Zone == "black" && peer != nil && s.IsOSPF(peer) {
			count++
		}
	}
	return count
}
func fullNeighbors(raw string) int {
	var value any
	if json.Unmarshal([]byte(raw), &value) != nil {
		return -1
	}
	count := 0
	var visit func(any)
	visit = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, n := range x {
				if k == "nbrState" {
					if state, ok := n.(string); ok && strings.HasPrefix(state, "Full") {
						count++
					}
				} else {
					visit(n)
				}
			}
		case []any:
			for _, n := range x {
				visit(n)
			}
		}
	}
	visit(value)
	return count
}
func (e *Engine) waitOSPF(ctx context.Context) error {
	deadline := time.Now().Add(45 * time.Second)
	for {
		ready := true
		var pending []string
		for _, d := range e.Spec.Devices {
			if !e.Spec.IsOSPF(&d) {
				continue
			}
			raw, err := e.exec(ctx, d.ID, "vtysh", "-c", "show ip ospf neighbor json")
			if err != nil || fullNeighbors(raw) != e.Spec.ospfNeighbors(&d) {
				ready = false
				pending = append(pending, d.ID)
			}
		}
		if ready {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("OSPF did not converge on %s", strings.Join(pending, ","))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
func (e *Engine) checkNative(ctx context.Context, r *Report, d *Device, o Observation) {
	if e.Spec.IsFRR(d) {
		expected, err := os.ReadFile(filepath.Join(e.Dir, "devices", d.ID, "frr.expected"))
		r.add("frr-config/"+d.ID, err == nil && canonicalFRR(o.Facts["frr-config"]) == canonicalFRR(string(expected)), "running configuration matches declared baseline")
		if e.Spec.IsOSPF(d) {
			r.add("ospf-neighbors/"+d.ID, fullNeighbors(o.Facts["ospf"]) == e.Spec.ospfNeighbors(d), fmt.Sprintf("expected %d Full adjacencies", e.Spec.ospfNeighbors(d)))
			var routes map[string]json.RawMessage
			err = json.Unmarshal([]byte(o.Facts["ospf-routes"]), &routes)
			for _, outer := range e.Spec.Role("outer") {
				prefix, _ := netip.ParsePrefix(outer.Interface(outer.Tunnel.Outside).Address)
				p := prefix.Masked().String()
				connected := false
				for _, i := range d.Interfaces {
					q, er := netip.ParsePrefix(i.Address)
					if er == nil && q.Masked() == prefix.Masked() {
						connected = true
					}
				}
				if !connected {
					_, found := routes[p]
					r.add("ospf-route/"+d.ID+"/"+outer.ID, err == nil && found, p)
				}
			}
		}
	}
	if e.Spec.IsOVS(d) {
		actual, err := e.ovsState(ctx, d)
		expected, er := os.ReadFile(filepath.Join(e.Dir, "devices", d.ID, "ovs.expected"))
		r.add("ovs-config/"+d.ID, err == nil && er == nil && actual == string(expected), "OVS ports, VLANs, OpenFlow rules and control mode match baseline")
	}
}

// Console streams through the same local access implementation as dev routers.
func (e *Engine) Console(ctx context.Context, id string, args []string, stdin io.Reader, stdout, stderr io.Writer, tty bool) error {
	d := e.Spec.Device(id)
	if d == nil {
		return fmt.Errorf("unknown device %s", id)
	}
	c, err := e.owned(ctx, d)
	if err != nil {
		return err
	}
	if c.State != rt.StateRunning {
		return fmt.Errorf("device %s is not running", id)
	}
	if len(args) == 0 {
		args = []string{"bash"}
		if e.Spec.IsFRR(d) {
			args = []string{"vtysh"}
		}
	}
	local := &access.LocalExec{Topology: e.nativeTopology(), Runtime: e.Runtime}
	code, err := local.Shell(ctx, id, args, stdin, stdout, stderr, tty, 24, 80)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("console exited %d", code)
	}
	return nil
}
