package netstate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// ReadKernel reads Linux-owned facts. It is intentionally shared by every NOS:
// switching BGP implementations must not change what an interface or kernel
// forwarding route means.
func ReadKernel(ctx context.Context, d *model.Device, exec Executor, query Query) (State, error) {
	if d == nil {
		return State{}, fmt.Errorf("read kernel state for nil device")
	}
	if exec == nil {
		return State{}, fmt.Errorf("read kernel state for %s: no executor", d.ID)
	}
	var out State
	if query.Has(QueryInterfaces) {
		res, err := exec.Exec(ctx, d.ID, []string{"ip", "-j", "address", "show"})
		if err != nil {
			return State{}, fmt.Errorf("read interfaces on %s: %w", d.ID, err)
		}
		if res.ExitCode != 0 {
			return State{}, commandError(d.ID, "ip -j address show", res.ExitCode, res.Stderr)
		}
		if err := json.Unmarshal([]byte(res.Stdout), &out.Interfaces); err != nil {
			return State{}, fmt.Errorf("parse interfaces on %s: %w", d.ID, err)
		}
	}
	if query.Has(QueryKernel) {
		res, err := exec.Exec(ctx, d.ID, []string{"ip", "-j", "route", "show", "table", "all"})
		if err != nil {
			return State{}, fmt.Errorf("read kernel routes on %s: %w", d.ID, err)
		}
		if res.ExitCode != 0 {
			return State{}, commandError(d.ID, "ip -j route show table all", res.ExitCode, res.Stderr)
		}
		routes, err := parseRoutes([]byte(res.Stdout))
		if err != nil {
			return State{}, fmt.Errorf("parse kernel routes on %s: %w", d.ID, err)
		}
		out.Kernel.Routes = routes
		v4, err := forwarding(ctx, d, exec, "net.ipv4.ip_forward")
		if err != nil {
			return State{}, err
		}
		v6, err := forwarding(ctx, d, exec, "net.ipv6.conf.all.forwarding")
		if err != nil {
			return State{}, err
		}
		out.Kernel.Forwarding = Forwarding{IPv4: v4, IPv6: v6}
	}
	out.Sort()
	return out, nil
}

// UnmarshalJSON translates iproute2's interface document without leaking its
// changing field names into callers.
func (i *Interface) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Name      string   `json:"ifname"`
		OperState string   `json:"operstate"`
		Flags     []string `json:"flags"`
		MTU       int      `json:"mtu"`
		Addresses []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
			Scope     string `json:"scope"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	i.Name, i.MTU = wire.Name, wire.MTU
	i.OperUp = strings.EqualFold(wire.OperState, "UP")
	for _, flag := range wire.Flags {
		if strings.EqualFold(flag, "UP") {
			i.AdminUp = true
			break
		}
	}
	for _, addr := range wire.Addresses {
		if addr.Local == "" || (addr.Family != "inet" && addr.Family != "inet6") {
			continue
		}
		prefix, err := netip.ParsePrefix(addr.Local + "/" + strconv.Itoa(addr.PrefixLen))
		if err != nil {
			return fmt.Errorf("address %s/%d: %w", addr.Local, addr.PrefixLen, err)
		}
		family := "ipv4"
		if addr.Family == "inet6" {
			family = "ipv6"
		}
		i.Addresses = append(i.Addresses, Address{Prefix: prefix.String(), Family: family, Scope: addr.Scope})
	}
	return nil
}

func forwarding(ctx context.Context, d *model.Device, exec Executor, key string) (bool, error) {
	res, err := exec.Exec(ctx, d.ID, []string{"sysctl", "-n", key})
	if err != nil {
		return false, fmt.Errorf("read %s on %s: %w", key, d.ID, err)
	}
	if res.ExitCode != 0 {
		return false, commandError(d.ID, "sysctl -n "+key, res.ExitCode, res.Stderr)
	}
	value := strings.TrimSpace(res.Stdout)
	switch value {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("read %s on %s: expected 0 or 1, got %q", key, d.ID, value)
	}
}

type ipRoute struct {
	Destination string          `json:"dst"`
	Gateway     string          `json:"gateway"`
	Device      string          `json:"dev"`
	Protocol    string          `json:"protocol"`
	Type        string          `json:"type"`
	Table       json.RawMessage `json:"table"`
	Metric      int             `json:"metric"`
	Flags       []string        `json:"flags"`
	NextHops    []struct {
		Gateway string `json:"gateway"`
		Device  string `json:"dev"`
		Weight  int    `json:"weight"`
	} `json:"nexthops"`
}

func parseRoutes(raw []byte) ([]Route, error) {
	var wire []ipRoute
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, err
	}
	out := make([]Route, 0, len(wire))
	for _, item := range wire {
		prefix := item.Destination
		if prefix == "" {
			prefix = "default"
		}
		family := "ipv4"
		if strings.Contains(prefix, ":") || strings.Contains(item.Gateway, ":") {
			family = "ipv6"
		}
		r := Route{
			Prefix: prefix, Family: family, Table: rawString(item.Table),
			Protocol: item.Protocol, Type: item.Type, Metric: item.Metric,
			Device: item.Device, Selected: true, Installed: true,
		}
		if item.Gateway != "" || item.Device != "" {
			r.NextHops = append(r.NextHops, NextHop{Address: item.Gateway, Device: item.Device})
		}
		for _, nh := range item.NextHops {
			r.NextHops = append(r.NextHops, NextHop{Address: nh.Gateway, Device: nh.Device, Weight: nh.Weight})
		}
		out = append(out, r)
	}
	return out, nil
}

func rawString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var number int
	if json.Unmarshal(raw, &number) == nil {
		return strconv.Itoa(number)
	}
	return strings.Trim(string(raw), `"`)
}

func commandError(device, command string, code int, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return fmt.Errorf("%s on %s exited %d", command, device, code)
	}
	return fmt.Errorf("%s on %s exited %d: %s", command, device, code, stderr)
}
