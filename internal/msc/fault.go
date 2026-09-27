package msc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Fault struct {
	Kind      string    `json:"kind"`
	Device    string    `json:"device"`
	Interface string    `json:"interface,omitempty"`
	At        time.Time `json:"at"`
}

func (e *Engine) stopIPsec(ctx context.Context, id string) error {
	return e.shell(ctx, id, "pkill -TERM -x charon || true; for n in $(seq 1 30); do pgrep -x charon >/dev/null || break; sleep 0.1; done; pkill -KILL -x charon || true; ip xfrm state flush; ip xfrm policy flush")
}
func (e *Engine) Fault(ctx context.Context, kind, id, iface string) error {
	d := e.Spec.Device(id)
	if d == nil {
		return fmt.Errorf("unknown device %s", id)
	}
	if _, err := e.owned(ctx, d); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(e.Dir, "fault.json")); err == nil {
		return fmt.Errorf("recover the active fault first")
	}
	switch kind {
	case "ipsec-down", "revoke", "wrong-peer":
		if d.Tunnel == nil {
			return fmt.Errorf("%s is not an encryptor", id)
		}
	case "link-down":
		if d.Interface(iface) == nil {
			return fmt.Errorf("unknown interface %s/%s", id, iface)
		}
	case "firewall-open":
		if d.Role != "gray-firewall" && d.Role != "firewall" {
			return fmt.Errorf("target must be a firewall")
		}
	default:
		return fmt.Errorf("unknown fault %q; use ipsec-down, revoke, wrong-peer, link-down, firewall-open", kind)
	}
	f := Fault{kind, id, iface, time.Now().UTC()}
	b, _ := json.MarshalIndent(f, "", "  ")
	if err := writePrivate(filepath.Join(e.Dir, "fault.json"), b); err != nil {
		return err
	}
	switch kind {
	case "ipsec-down":
		return e.stopIPsec(ctx, id)
	case "link-down":
		_, err := e.exec(ctx, id, "ip", "link", "set", iface, "down")
		return err
	case "firewall-open":
		_, err := e.exec(ctx, id, "iptables", "-P", "FORWARD", "ACCEPT")
		return err
	case "wrong-peer":
		body := strings.Replace(swanConfig(d), "id = "+d.Tunnel.Peer+".msc.test", "id = unintended-peer.msc.test", 1)
		if err := writePrivate(filepath.Join(e.tunnelDir(d), "swanctl.conf"), []byte(body)); err != nil {
			return err
		}
	case "revoke":
		cert, err := readCert(filepath.Join(e.tunnelDir(d), "x509", "cert.pem"))
		if err != nil {
			return err
		}
		for i := range e.Spec.Devices {
			other := &e.Spec.Devices[i]
			if other.Tunnel != nil && other.Tunnel.Trust == d.Tunnel.Trust {
				if err = e.crl(d.Tunnel.Trust, e.tunnelDir(other), []*x509.Certificate{cert}); err != nil {
					return err
				}
			}
		}
	}
	peer := e.Spec.Device(d.Tunnel.Peer)
	for _, v := range []*Device{d, peer} {
		if err := e.stopIPsec(ctx, v.ID); err != nil {
			return err
		}
		if err := e.startIPsec(ctx, v); err != nil {
			return err
		}
	}
	return nil
}

// TestFailures removes both SAs and policies, so passing cannot depend on a
// stale protection policy surviving the daemon. Recovery is attempted even if
// an observation fails, and a failed recovery is returned to the operator.
func (e *Engine) TestFailures(ctx context.Context) (Report, error) {
	r := Report{Lab: e.Spec.Name, At: time.Now().UTC(), SpecHash: e.Spec.Hash(), Passed: true}
	for _, test := range []struct{ kind, id string }{{"ipsec-down", "I_A1"}, {"ipsec-down", "O_A1"}, {"wrong-peer", "I_A1"}, {"revoke", "I_A1"}} {
		if err := e.Fault(ctx, test.kind, test.id, ""); err != nil {
			return r, err
		}
		observeErr := func() error {
			if err := e.beginCapture(ctx, "BLACK", "failure"); err != nil {
				return err
			}
			defer e.shell(ctx, "BLACK", "kill -INT $(cat /tmp/msc-failure.pid) 2>/dev/null || true")
			if err := e.beginCapture(ctx, "G_A1", "failure"); err != nil {
				return err
			}
			defer e.shell(ctx, "G_A1", "kill -INT $(cat /tmp/msc-failure.pid) 2>/dev/null || true")
			ok, detail := e.ping(ctx, "R_A1", "10.2.1.10")
			r.add(test.kind+"/"+test.id+"/blocks-S1", !ok, detail)
			ok, detail = e.ping(ctx, "R_A2", "10.2.2.10")
			r.add(test.kind+"/"+test.id+"/S2-unaffected", ok, detail)
			if test.kind == "ipsec-down" {
				states, er := e.exec(ctx, test.id, "ip", "xfrm", "state", "list", "nokeys")
				policies, pe := e.exec(ctx, test.id, "ip", "xfrm", "policy", "list")
				r.add(test.kind+"/"+test.id+"/no-stale-protection", er == nil && pe == nil && strings.TrimSpace(states) == "" && strings.TrimSpace(policies) == "", "SAs and policies were removed")
			} else {
				own, er := e.exec(ctx, test.id, "cat", "/tmp/charon.log")
				peer, pe := e.exec(ctx, e.Spec.Device(test.id).Tunnel.Peer, "cat", "/tmp/charon.log")
				logs := strings.ToLower(own + peer)
				reason := "unintended-peer.msc.test"
				if test.kind == "revoke" {
					reason = "revoked"
				}
				r.add(test.kind+"/"+test.id+"/authentication-rejection", er == nil && pe == nil && strings.Contains(logs, reason), "fresh IKE logs contain "+reason)
			}
			for _, id := range []string{"BLACK", "G_A1"} {
				if err := e.finishCapture(ctx, id, "failure"); err != nil {
					return err
				}
				plain, err := e.exec(ctx, id, "tcpdump", "-Z", "root", "-nn", "-r", "/tmp/msc-failure.pcap", "net 10.1.0.0/16 or net 10.2.0.0/16")
				r.add(test.kind+"/"+test.id+"/no-plaintext/"+id, err == nil && strings.TrimSpace(plain) == "", plain)
			}
			return nil
		}()
		if err := e.Up(ctx, true); err != nil {
			return r, fmt.Errorf("recovery after %s: %w", test.kind, err)
		}
		if observeErr != nil {
			return r, observeErr
		}
		ok, detail := e.ping(ctx, "R_A1", "10.2.1.10")
		r.add(test.kind+"/"+test.id+"/recovered", ok, detail)
	}
	for _, id := range []string{"I_A1", "O_B2"} {
		if err := e.Restart(ctx, id); err != nil {
			return r, err
		}
		for _, level := range []int{1, 2} {
			ok, detail := e.ping(ctx, fmt.Sprintf("R_A%d", level), fmt.Sprintf("10.2.%d.10", level))
			r.add("restart/"+id+fmt.Sprintf("/S%d", level), ok, detail)
		}
	}
	return r, nil
}
