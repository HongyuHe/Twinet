package msc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/netx"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"golang.org/x/sys/unix"
)

type Engine struct {
	Spec    *Spec
	Dir     string
	Runtime rt.Runtime
	Log     io.Writer
}

func (e *Engine) Lock() (func(), error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return nil, fmt.Errorf("MSC runtime commands require root on the Linux worker; use sudo")
	}
	abs, err := filepath.Abs(e.Dir)
	if err != nil {
		return nil, err
	}
	e.Dir = abs
	if err = os.MkdirAll(e.Dir, 0700); err != nil {
		return nil, err
	}
	if err = os.Chmod(e.Dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(e.Dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another MSC operation holds %s", e.Dir)
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
func (e *Engine) log(format string, a ...any) {
	if e.Log != nil {
		fmt.Fprintf(e.Log, format+"\n", a...)
	}
}
func (e *Engine) exec(ctx context.Context, id string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ctx = cctx
	r, err := e.Runtime.Exec(ctx, e.Spec.Container(id), rt.ExecCmd{Cmd: append([]string{"timeout", "15"}, args...)})
	if err != nil {
		return "", fmt.Errorf("%s: %w", id, err)
	}
	if err = r.Err(); err != nil {
		return r.Stdout, fmt.Errorf("%s: %w", id, err)
	}
	return r.Stdout, nil
}
func (e *Engine) shell(ctx context.Context, id, body string) error {
	_, err := e.exec(ctx, id, "sh", "-ec", body)
	return err
}
func (e *Engine) background(ctx context.Context, id, body string) error {
	r, err := e.Runtime.Exec(ctx, e.Spec.Container(id), rt.ExecCmd{Cmd: []string{"sh", "-ec", body}, Detach: true})
	if err != nil {
		return err
	}
	return r.Err()
}
func (e *Engine) owned(ctx context.Context, d *Device) (rt.Container, error) {
	c, err := e.Runtime.Inspect(ctx, e.Spec.Container(d.ID))
	if err != nil {
		return c, err
	}
	if c.State != rt.StateAbsent && (c.Labels["twinet.msc.lab"] != e.Spec.Name || c.Labels["twinet.msc.state"] != e.Dir) {
		return c, fmt.Errorf("refuse foreign container %s", c.Name)
	}
	return c, nil
}
func (e *Engine) tunnelDir(d *Device) string { return filepath.Join(e.Dir, "devices", d.ID, "swanctl") }
func (e *Engine) tlsDir(d *Device) string    { return filepath.Join(e.Dir, "devices", d.ID, "tls") }
func (e *Engine) prepare(d *Device, renew bool) error {
	if d.Tunnel != nil {
		dir := e.tunnelDir(d)
		if err := e.leaf(d, d.Tunnel.Trust, dir, "", renew); err != nil {
			return err
		}
		if err := writePrivate(filepath.Join(dir, "swanctl.conf"), []byte(swanConfig(d))); err != nil {
			return err
		}
	}
	if i := d.Interface("mgmt"); i != nil {
		ip := strings.Split(i.Address, "/")[0]
		domain := ip[:strings.LastIndex(ip, ".")]
		if err := e.leaf(d, "management-"+strings.ReplaceAll(domain, ".", "-"), e.tlsDir(d), ip, renew); err != nil {
			return err
		}
	}
	return nil
}
func (e *Engine) Up(ctx context.Context, recoverFault bool) error {
	if err := e.Spec.Validate(); err != nil {
		return err
	}
	if _, err := e.Runtime.Ping(ctx); err != nil {
		return err
	}
	faultPath := filepath.Join(e.Dir, "fault.json")
	if _, err := os.Stat(faultPath); err == nil && !recoverFault {
		return fmt.Errorf("a fault is active; use msc recover to restore the baseline")
	}
	hash := e.Spec.Hash()
	for i := range e.Spec.Devices {
		d := &e.Spec.Devices[i]
		c, err := e.owned(ctx, d)
		if err != nil {
			return err
		}
		if c.State != rt.StateAbsent && c.Labels["twinet.msc.spec"] != hash {
			return fmt.Errorf("specification changed; run msc down using the old spec before deploying the new one")
		}
	}
	exists, err := e.Runtime.ImageExists(ctx, e.Spec.Image)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("build image %s first (images/msc/Dockerfile)", e.Spec.Image)
	}
	imageID, err := e.Runtime.ImageDigest(ctx, e.Spec.Image)
	if err != nil {
		return err
	}
	for i := range e.Spec.Devices {
		d := &e.Spec.Devices[i]
		if err = e.prepare(d, recoverFault); err != nil {
			return err
		}
		c, err := e.owned(ctx, d)
		if err != nil {
			return err
		}
		if c.State != rt.StateAbsent && c.Labels["twinet.msc.image"] != imageID {
			return fmt.Errorf("image changed; down/up is required to replace existing containers")
		}
		if c.State == rt.StateAbsent {
			caps := []string{"NET_ADMIN", "NET_RAW", "NET_BIND_SERVICE"}
			if d.Tunnel != nil {
				caps = append(caps, "SETUID", "SETGID", "CHOWN")
			}
			spec := &rt.Spec{Name: e.Spec.Container(d.ID), Hostname: strings.ToLower(d.ID), Image: e.Spec.Image, Command: []string{"sleep", "infinity"}, NetworkMode: "none", Capabilities: caps, CapDrop: []string{"ALL"}, CPUs: 2, Memory: "256Mi", PidsLimit: 128, Labels: map[string]string{"twinet.msc.lab": e.Spec.Name, "twinet.msc.state": e.Dir, "twinet.msc.spec": hash, "twinet.msc.image": imageID, "twinet.msc.device": d.ID}, Sysctls: map[string]string{"net.ipv4.ip_forward": "0", "net.ipv4.conf.all.rp_filter": "0", "net.ipv4.conf.default.rp_filter": "0", "net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.default.send_redirects": "0", "net.ipv6.conf.all.disable_ipv6": "1"}}
			if d.Tunnel != nil {
				spec.Binds = append(spec.Binds, rt.Bind{Source: e.tunnelDir(d), Target: "/etc/swanctl", ReadOnly: true})
			}
			if d.Interface("mgmt") != nil {
				spec.Binds = append(spec.Binds, rt.Bind{Source: e.tlsDir(d), Target: "/run/msc-tls", ReadOnly: true})
			}
			if _, err = e.Runtime.Create(ctx, spec); err != nil {
				return err
			}
		}
		if c.State == rt.StatePaused {
			if err = e.Runtime.Unpause(ctx, e.Spec.Container(d.ID)); err != nil {
				return err
			}
		} else if c.State != rt.StateRunning {
			if err = e.Runtime.Start(ctx, e.Spec.Container(d.ID)); err != nil {
				return err
			}
		}
		if err = e.forwarding(ctx, d.ID, false); err != nil {
			return err
		}
	}
	// Filters are installed before new links or forwarding can carry data.
	for i := range e.Spec.Devices {
		d := &e.Spec.Devices[i]
		if err = e.Runtime.CopyTo(ctx, e.Spec.Container(d.ID), "/tmp/msc-filter.rules", 0600, []byte(filterRules(e.Spec, d))); err != nil {
			return err
		}
		if err = e.shell(ctx, d.ID, "iptables-restore < /tmp/msc-filter.rules"); err != nil {
			return err
		}
		expected, er := e.exec(ctx, d.ID, "iptables-save", "-t", "filter")
		if er != nil {
			return er
		}
		if err = writePrivate(filepath.Join(e.Dir, "devices", d.ID, "filter.expected"), []byte(expected)); err != nil {
			return err
		}
	}
	for n, l := range e.Spec.Links {
		endpoints := []netx.EndpointSpec{}
		for _, ep := range []Endpoint{l.A, l.B} {
			d := e.Spec.Device(ep.Device)
			i := d.Interface(ep.Interface)
			ns, err := e.Runtime.NSPath(ctx, e.Spec.Container(d.ID))
			if err != nil {
				return err
			}
			p := netx.EndpointSpec{NSPath: ns, Name: i.Name, MTU: e.Spec.MTU, OwnAddrs: true, Up: true, Altname: fmt.Sprintf("msc-%s-%d-%s", e.Spec.Name, n, d.ID)}
			if i.Address != "" {
				p.Addrs = []string{i.Address}
			}
			endpoints = append(endpoints, p)
		}
		h := sha256.Sum256([]byte(e.Dir + fmt.Sprint(n)))
		tag := hex.EncodeToString(h[:])[:10]
		if err = netx.CreateVeth(netx.VethSpec{TempA: "ma" + tag, TempB: "mb" + tag, MTU: e.Spec.MTU, A: endpoints[0], B: endpoints[1]}); err != nil {
			return fmt.Errorf("wire %v: %w", l, err)
		}
	}
	for i := range e.Spec.Devices {
		d := &e.Spec.Devices[i]
		if d.Role == "switch" {
			if err = e.shell(ctx, d.ID, "ip link show br0 >/dev/null 2>&1 || ip link add br0 type bridge; ip link set br0 up"); err != nil {
				return err
			}
			for _, p := range d.Interfaces {
				if err = e.shell(ctx, d.ID, "ip link set "+p.Name+" master br0; ip link set "+p.Name+" up"); err != nil {
					return err
				}
			}
		}
		for _, r := range d.Routes {
			if _, err = e.exec(ctx, d.ID, "ip", "route", "replace", r.Prefix, "via", r.Via, "proto", "static"); err != nil {
				return err
			}
		}
		if d.Admin != "" {
			if err = e.Runtime.CopyTo(ctx, e.Spec.Container(d.ID), "/tmp/msc-admin.py", 0600, []byte(adminServer)); err != nil {
				return err
			}
			if err = e.background(ctx, d.ID, "pkill -f '^python3 /tmp/msc-admin.py$' || true; exec python3 /tmp/msc-admin.py >/tmp/msc-admin.log 2>&1"); err != nil {
				return err
			}
		}
	}
	if recoverFault {
		for _, d := range e.Spec.Devices {
			if d.Tunnel != nil {
				if err = e.stopIPsec(ctx, d.ID); err != nil {
					return err
				}
			}
		}
	}
	for _, role := range []string{"outer", "inner"} {
		for i := range e.Spec.Devices {
			d := &e.Spec.Devices[i]
			if d.Role != role {
				continue
			}
			if err = e.startIPsec(ctx, d); err != nil {
				return err
			}
		}
	}
	for _, d := range e.Spec.Devices {
		if d.Role != "host" && d.Role != "admin" && d.Role != "switch" {
			if err = e.forwarding(ctx, d.ID, true); err != nil {
				return err
			}
		}
	}
	// Outer tunnels must exist before their payload can carry inner IKE.
	for _, role := range []string{"outer", "inner"} {
		for _, d := range e.Spec.Devices {
			if d.Role != role || d.Site != "A" {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, 40*time.Second)
			_, err = e.exec(cctx, d.ID, "swanctl", "--initiate", "--child", "protected")
			cancel()
			if err != nil {
				return fmt.Errorf("initiate %s: %w", d.ID, err)
			}
			e.log("ready %s <-> %s", d.ID, d.Tunnel.Peer)
		}
	}
	if recoverFault {
		if err = os.Remove(faultPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	body, _ := json.MarshalIndent(e.Spec, "", "  ")
	if err = writePrivate(filepath.Join(e.Dir, "spec.json"), body); err != nil {
		return err
	}
	e.log("MSC lab %s: %d devices, %d links, image %s", e.Spec.Name, len(e.Spec.Devices), len(e.Spec.Links), imageID)
	return nil
}
func (e *Engine) startIPsec(ctx context.Context, d *Device) error {
	if err := e.background(ctx, d.ID, "pgrep -x charon >/dev/null || exec stdbuf -oL /usr/lib/ipsec/charon >/tmp/charon.log 2>&1"); err != nil {
		return err
	}
	for n := 0; n < 40; n++ {
		if _, err := e.exec(ctx, d.ID, "swanctl", "--load-all", "--clear"); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("%s: strongSwan not ready; inspect /tmp/charon.log", d.ID)
}
func (e *Engine) Down(ctx context.Context) error {
	var failures []string
	for i := range e.Spec.Devices {
		d := &e.Spec.Devices[i]
		c, err := e.owned(ctx, d)
		if err != nil {
			return err
		}
		if c.State != rt.StateAbsent {
			if err = e.Runtime.Remove(ctx, e.Spec.Container(d.ID), true); err != nil {
				failures = append(failures, err.Error())
			}
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("cleanup: %s", strings.Join(failures, "; "))
	}
	return nil
}
func (e *Engine) Exec(ctx context.Context, id string, args []string) (rt.ExecResult, error) {
	d := e.Spec.Device(id)
	if d == nil {
		return rt.ExecResult{}, fmt.Errorf("unknown device %s", id)
	}
	if _, err := e.owned(ctx, d); err != nil {
		return rt.ExecResult{}, err
	}
	return e.Runtime.Exec(ctx, e.Spec.Container(id), rt.ExecCmd{Cmd: args})
}
func (e *Engine) Restart(ctx context.Context, id string) error {
	d := e.Spec.Device(id)
	if d == nil {
		return fmt.Errorf("unknown device %s", id)
	}
	if _, err := e.owned(ctx, d); err != nil {
		return err
	}
	if err := e.Runtime.Stop(ctx, e.Spec.Container(id), 3*time.Second); err != nil {
		return err
	}
	return e.Up(ctx, false)
}

// forwarding writes namespace-local sysctls from the worker's writable procfs.
// Container procfs is read-only; some sysctl versions misleadingly exit zero
// after printing that the write was ignored, so every setting is read back.
func (e *Engine) forwarding(ctx context.Context, id string, on bool) error {
	path, err := e.Runtime.NSPath(ctx, e.Spec.Container(id))
	if err != nil {
		return err
	}
	ns, err := netx.OpenNS(path)
	if err != nil {
		return err
	}
	defer ns.Close()
	value := "0"
	if on {
		value = "1"
	}
	return ns.Do(func() error {
		values := [][2]string{{"ip_forward", value}, {"conf/all/rp_filter", "0"}, {"conf/default/rp_filter", "0"}, {"conf/all/send_redirects", "0"}, {"conf/default/send_redirects", "0"}}
		for _, kv := range values {
			file := "/proc/sys/net/ipv4/" + kv[0]
			if err := os.WriteFile(file, []byte(kv[1]), 0600); err != nil {
				return err
			}
			got, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(got)) != kv[1] {
				return fmt.Errorf("%s: sysctl %s did not converge", id, kv[0])
			}
		}
		return nil
	})
}
