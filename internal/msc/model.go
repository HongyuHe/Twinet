// Package msc implements a single-worker, explicit-appliance MSC research lab.
// It reuses Twinet's runtime and virtual-link primitives without introducing
// routing protocols into encryption appliances.
package msc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

type Spec struct {
	Version     int      `json:"version"`
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	RouterImage string   `json:"router_image,omitempty"`
	SwitchImage string   `json:"switch_image,omitempty"`
	MTU         int      `json:"mtu"`
	Devices     []Device `json:"devices"`
	Links       []Link   `json:"links"`
}
type Device struct {
	ID         string      `json:"id"`
	Role       string      `json:"role"`
	Site       string      `json:"site,omitempty"`
	Level      string      `json:"level,omitempty"`
	Interfaces []Interface `json:"interfaces"`
	Routes     []Route     `json:"routes,omitempty"`
	Tunnel     *Tunnel     `json:"tunnel,omitempty"`
	Admin      string      `json:"admin,omitempty"`
}
type Interface struct {
	Name    string `json:"name"`
	Address string `json:"address,omitempty"`
	Zone    string `json:"zone"`
	Bridge  bool   `json:"bridge,omitempty"`
}
type Route struct {
	Prefix string `json:"prefix"`
	Via    string `json:"via"`
}
type Tunnel struct {
	Peer     string `json:"peer"`
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	LocalTS  string `json:"local_ts"`
	RemoteTS string `json:"remote_ts"`
	Trust    string `json:"trust"`
	ReqID    int    `json:"reqid"`
	Inside   string `json:"inside"`
	Outside  string `json:"outside"`
}
type Endpoint struct {
	Device    string `json:"device"`
	Interface string `json:"interface"`
}
type Link struct {
	A Endpoint `json:"a"`
	B Endpoint `json:"b"`
}

var identifier = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,23}$`)
var ifaceName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`)

func Load(path string) (*Spec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var s Spec
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err = dec.Decode(&s); err != nil {
		return nil, err
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing JSON")
	}
	return &s, s.Validate()
}
func (s *Spec) Device(id string) *Device {
	for i := range s.Devices {
		if s.Devices[i].ID == id {
			return &s.Devices[i]
		}
	}
	return nil
}
func (d *Device) Interface(name string) *Interface {
	for i := range d.Interfaces {
		if d.Interfaces[i].Name == name {
			return &d.Interfaces[i]
		}
	}
	return nil
}
func (s *Spec) Hash() string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s *Spec) Container(id string) string {
	if s.Version == 2 {
		return id
	}
	return "twinet-" + s.Name + "-" + strings.ToLower(id)
}
func (s *Spec) Validate() error {
	if (s.Version != 1 && s.Version != 2) || !identifier.MatchString(s.Name) || s.Image == "" || s.MTU < 1280 || s.MTU > 9000 {
		return fmt.Errorf("version=1 or 2, a safe name, image, and MTU 1280..9000 are required")
	}
	if s.Version == 2 && (s.RouterImage == "" || s.SwitchImage == "") {
		return fmt.Errorf("MSC v2 requires router_image and switch_image")
	}
	ids := map[string]bool{}
	endpoints := map[string]bool{}
	addresses := map[string]bool{}
	roles := map[string]bool{"host": true, "inner": true, "outer": true, "firewall": true, "gray-firewall": true, "switch": true, "transport": true, "admin": true}
	for _, d := range s.Devices {
		if s.IsOSPF(&d) && len(d.Routes) > 0 {
			return fmt.Errorf("%s uses OSPF; static underlay routes are not allowed", d.ID)
		}
		key := strings.ToLower(d.ID)
		if !identifier.MatchString(d.ID) || ids[key] || !roles[d.Role] {
			return fmt.Errorf("invalid/duplicate device or role: %s", d.ID)
		}
		ids[key] = true
		for _, i := range d.Interfaces {
			k := d.ID + ":" + i.Name
			if !ifaceName.MatchString(i.Name) || endpoints[k] || i.Name == "lo" || i.Name == "br0" {
				return fmt.Errorf("invalid/duplicate interface %s", k)
			}
			endpoints[k] = true
			if i.Address != "" {
				p, e := netip.ParsePrefix(i.Address)
				if e != nil || !p.Addr().Is4() || addresses[p.Addr().String()] {
					return fmt.Errorf("invalid/duplicate IPv4 address %s", i.Address)
				}
				addresses[p.Addr().String()] = true
			}
			if i.Name == "mgmt" && i.Address == "" {
				return fmt.Errorf("management interface requires an address on %s", d.ID)
			}
			if i.Bridge && d.Role != "switch" {
				return fmt.Errorf("bridge port on non-switch %s", d.ID)
			}
		}
		for _, r := range d.Routes {
			p, e := netip.ParsePrefix(r.Prefix)
			if e != nil || !p.Addr().Is4() {
				return fmt.Errorf("bad route on %s", d.ID)
			}
			a, e := netip.ParseAddr(r.Via)
			if e != nil || !a.Is4() {
				return fmt.Errorf("bad gateway on %s", d.ID)
			}
		}
		if (d.Role == "inner" || d.Role == "outer") != (d.Tunnel != nil) {
			return fmt.Errorf("encryptor %s must have exactly one tunnel", d.ID)
		}
		if d.Admin != "" {
			if d.Interface("mgmt") == nil {
				return fmt.Errorf("managed device %s requires a management interface", d.ID)
			}
			if a, e := netip.ParseAddr(d.Admin); e != nil || !a.Is4() {
				return fmt.Errorf("bad admin on %s", d.ID)
			}
		}
	}
	for _, d := range s.Devices {
		if s.IsFRR(&d) && ids[strings.ToLower(d.ID)+"-frr"] {
			return fmt.Errorf("device ID conflicts with FRR control container for %s", d.ID)
		}
		if s.IsFRR(&d) {
			for _, port := range d.Interfaces {
				if port.Address == "" {
					return fmt.Errorf("FRR interface %s/%s requires an IPv4 address", d.ID, port.Name)
				}
			}
		}
	}

	for _, d := range s.Devices {
		if t := d.Tunnel; t != nil {
			p := s.Device(t.Peer)
			if p == nil || p.Tunnel == nil || p.Tunnel.Peer != d.ID || p.Role != d.Role || p.Level != d.Level || p.Site == d.Site {
				return fmt.Errorf("invalid peer for %s", d.ID)
			}
			if !identifier.MatchString(t.Trust) || t.Trust != p.Tunnel.Trust || t.Local != p.Tunnel.Remote || t.Remote != p.Tunnel.Local || t.LocalTS != p.Tunnel.RemoteTS || t.RemoteTS != p.Tunnel.LocalTS || t.ReqID < 1 {
				return fmt.Errorf("inconsistent tunnel %s", d.ID)
			}
			if d.Interface(t.Inside) == nil || d.Interface(t.Outside) == nil || t.Inside == t.Outside {
				return fmt.Errorf("invalid tunnel ports on %s", d.ID)
			}
			for _, a := range []string{t.Local, t.Remote} {
				if ip, e := netip.ParseAddr(a); e != nil || !ip.Is4() {
					return fmt.Errorf("bad tunnel endpoint %s", a)
				}
			}
			for _, a := range []string{t.LocalTS, t.RemoteTS} {
				if ip, e := netip.ParsePrefix(a); e != nil || !ip.Addr().Is4() {
					return fmt.Errorf("bad selector %s", a)
				}
			}
			own := strings.Split(d.Interface(t.Outside).Address, "/")[0]
			if own != t.Local {
				return fmt.Errorf("tunnel local must be outside address on %s", d.ID)
			}
		}
	}
	for _, l := range s.Links {
		for _, e := range []Endpoint{l.A, l.B} {
			k := e.Device + ":" + e.Interface
			if !endpoints[k] {
				return fmt.Errorf("unbound or repeated endpoint %s", k)
			}
			delete(endpoints, k)
		}
		if l.A.Device == l.B.Device {
			return fmt.Errorf("self link")
		}
	}
	if len(endpoints) > 0 {
		return fmt.Errorf("interfaces without links: %v", endpoints)
	}

	for _, d := range s.Devices {
		if d.Admin != "" {
			found := false
			for _, admin := range s.Devices {
				if admin.Role == "admin" && admin.Interface("mgmt") != nil && strings.Split(admin.Interface("mgmt").Address, "/")[0] == d.Admin {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("no administrative workstation for %s", d.ID)
			}
		}
		if d.Role == "host" && (d.Interface("red") == nil || d.Interface("red").Address == "") {
			return fmt.Errorf("host requires addressed red interface")
		}
		if d.Role == "admin" && (d.Interface("mgmt") == nil || d.Interface("mgmt").Address == "") {
			return fmt.Errorf("admin requires addressed management interface")
		}
	}
	if len(s.Devices) == 0 {
		return fmt.Errorf("empty topology")
	}
	return nil
}

func (s *Spec) IsFRR(d *Device) bool {
	return s.Version == 2 && (d.Role == "transport" || d.Role == "firewall" || d.Role == "gray-firewall")
}
func (s *Spec) IsOVS(d *Device) bool { return s.Version == 2 && d.Role == "switch" }
func (s *Spec) ImageFor(d *Device) string {
	if s.IsFRR(d) {
		return s.RouterImage
	}
	if s.IsOVS(d) {
		return s.SwitchImage
	}
	return s.Image
}

func (s *Spec) IsOSPF(d *Device) bool {
	return s.Version == 2 && (d.Role == "transport" || d.Role == "firewall")
}

func (s *Spec) Peer(id, iface string) (*Device, *Interface) {
	for _, l := range s.Links {
		for _, pair := range [][2]Endpoint{{l.A, l.B}, {l.B, l.A}} {
			if pair[0].Device == id && pair[0].Interface == iface {
				d := s.Device(pair[1].Device)
				return d, d.Interface(pair[1].Interface)
			}
		}
	}
	return nil, nil
}
func (s *Spec) Role(role string) []*Device {
	var out []*Device
	for i := range s.Devices {
		if s.Devices[i].Role == role {
			out = append(out, &s.Devices[i])
		}
	}
	return out
}
