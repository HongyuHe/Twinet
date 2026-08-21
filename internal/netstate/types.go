// Package netstate defines vendor-neutral operational network state.
//
// Providers translate their native control-plane output into these facts.
// Kernel interfaces, routes, and forwarding remain collected from ip(8) and
// sysctl because those facts are already vendor-neutral.
package netstate

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/runtime"
)

// Query selects operational state families. A provider must return an
// UnsupportedError rather than silently omitting an explicitly requested
// family.
type Query uint32

const (
	QueryInterfaces Query = 1 << iota
	QueryKernel
	QueryBGPSessions
	QueryBGPRIB
	QueryOSPF
	QueryPolicy
)

// QueryBGP selects both BGP sessions and RIB paths. Callers interested in one
// bounded observation can select QueryBGPSessions or QueryBGPRIB directly.
const QueryBGP = QueryBGPSessions | QueryBGPRIB

// All is every state family.
const All = QueryInterfaces | QueryKernel | QueryBGP | QueryOSPF | QueryPolicy

// Has reports whether q selects a state family.
func (q Query) Has(part Query) bool { return q&part != 0 }

// String names selected state families deterministically.
func (q Query) String() string {
	parts := make([]string, 0, 5)
	for _, item := range []struct {
		flag Query
		name string
	}{
		{QueryInterfaces, "interfaces"},
		{QueryKernel, "kernel"},
		{QueryBGP, "bgp"},
		{QueryOSPF, "ospf"},
		{QueryPolicy, "policy"},
	} {
		if q.Has(item.flag) {
			parts = append(parts, item.name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

// UnsupportedError says a NOS cannot answer a requested operational query.
// It is infrastructure unsupported, never evidence of a student's mistake.
type UnsupportedError struct {
	Device string
	NOS    string
	Query  Query
	Reason string
}

func (e *UnsupportedError) Error() string {
	where := e.Device
	if where == "" {
		where = "device"
	}
	if e.Reason != "" {
		return fmt.Sprintf("%s uses NOS %q, which does not support state query %s: %s",
			where, e.NOS, e.Query, e.Reason)
	}
	return fmt.Sprintf("%s uses NOS %q, which does not support state query %s",
		where, e.NOS, e.Query)
}

// IsUnsupported reports whether err means the required provider capability is
// absent rather than the device returning a negative operational fact.
func IsUnsupported(err error) bool {
	var unsupported *UnsupportedError
	return errors.As(err, &unsupported)
}

// Executor runs commands in a device. It intentionally matches the existing
// runtime interface without making netstate depend on a controller or agent.
type Executor interface {
	Exec(context.Context, string, []string) (runtime.ExecResult, error)
}

// ExecFunc adapts a strongly typed function to Executor.
type ExecFunc func(context.Context, string, []string) (runtime.ExecResult, error)

// Exec implements Executor.
func (f ExecFunc) Exec(ctx context.Context, deviceID string, command []string) (runtime.ExecResult, error) {
	return f(ctx, deviceID, command)
}

// Reader provides state for an expanded device.
type Reader interface {
	ReadState(context.Context, *model.Device, Executor, Query) (State, error)
}

// State is a normalized operational snapshot. A zero-valued family is only
// meaningful when that family was not requested; providers return an error
// rather than presenting unsupported state as an empty table.
type State struct {
	Interfaces []Interface  `json:"interfaces,omitempty"`
	Kernel     Kernel       `json:"kernel,omitempty"`
	BGP        BGP          `json:"bgp,omitempty"`
	OSPF       []OSPFPeer   `json:"ospf_neighbors,omitempty"`
	Policy     []PolicyFact `json:"policy,omitempty"`
}

// Interface is an observed kernel network interface.
type Interface struct {
	Name      string    `json:"name"`
	AdminUp   bool      `json:"admin_up"`
	OperUp    bool      `json:"oper_up"`
	MTU       int       `json:"mtu,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`
}

// Address is an address attached to a kernel interface.
type Address struct {
	Prefix string `json:"prefix"`
	Family string `json:"family"` // ipv4 or ipv6
	Scope  string `json:"scope,omitempty"`
}

// Kernel is the vendor-neutral forwarding state installed in Linux.
type Kernel struct {
	Forwarding Forwarding `json:"forwarding"`
	Routes     []Route    `json:"routes,omitempty"`
}

// Forwarding records whether the kernel accepts forwarding for each family.
type Forwarding struct {
	IPv4 bool `json:"ipv4"`
	IPv6 bool `json:"ipv6"`
}

// Route is one kernel route. Protocol is the kernel protocol label (for
// example bgp, ospf, static, or kernel), not a vendor CLI spelling.
type Route struct {
	Prefix    string    `json:"prefix"`
	Family    string    `json:"family"`
	Table     string    `json:"table,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	Type      string    `json:"type,omitempty"`
	Metric    int       `json:"metric,omitempty"`
	Device    string    `json:"device,omitempty"`
	NextHops  []NextHop `json:"next_hops,omitempty"`
	Selected  bool      `json:"selected"`
	Installed bool      `json:"installed"`
}

// NextHop is one route next hop.
type NextHop struct {
	Address string `json:"address,omitempty"`
	Device  string `json:"device,omitempty"`
	Weight  int    `json:"weight,omitempty"`
}

// BGP is the provider-normalized BGP operational state.
type BGP struct {
	Sessions []BGPSession `json:"sessions,omitempty"`
	Paths    []BGPPath    `json:"paths,omitempty"`
}

// BGPSession is one BGP peer session.
type BGPSession struct {
	Neighbor        string `json:"neighbor"`
	RemoteAS        uint32 `json:"remote_as,omitempty"`
	State           string `json:"state"`
	PrefixesIn      int    `json:"prefixes_in,omitempty"`
	PrefixesOut     int    `json:"prefixes_out,omitempty"`
	UpdatesReceived int    `json:"updates_received,omitempty"`
	UpdatesSent     int    `json:"updates_sent,omitempty"`
}

// RPKIState is an origin-validation result.
type RPKIState string

const (
	RPKIUnknown  RPKIState = ""
	RPKIValid    RPKIState = "valid"
	RPKIInvalid  RPKIState = "invalid"
	RPKINotFound RPKIState = "notfound"
)

// BGPPath is one path in a BGP RIB. ASPath is retained as both a normalized
// string and parsed ASN sequence because the former preserves confederation
// spelling while the latter supports portable policy checks.
type BGPPath struct {
	Prefix      string    `json:"prefix"`
	ASPath      string    `json:"as_path,omitempty"`
	ASNs        []uint32  `json:"asns,omitempty"`
	NextHops    []NextHop `json:"next_hops,omitempty"`
	Best        bool      `json:"best"`
	Valid       bool      `json:"valid"`
	LocalPref   int       `json:"local_pref,omitempty"`
	Origin      string    `json:"origin,omitempty"`
	Peer        string    `json:"peer,omitempty"`
	PeerAS      uint32    `json:"peer_as,omitempty"`
	Source      string    `json:"source,omitempty"` // internal, external, local
	Communities []string  `json:"communities,omitempty"`
	RPKI        RPKIState `json:"rpki,omitempty"`
}

// OSPFPeer is one OSPF adjacency.
type OSPFPeer struct {
	RouterID  string `json:"router_id,omitempty"`
	Address   string `json:"address,omitempty"`
	Interface string `json:"interface,omitempty"`
	State     string `json:"state"`
}

// PolicyFact is a provider-confirmed policy fact. It intentionally captures
// observable semantics rather than a vendor configuration stanza.
type PolicyFact struct {
	Name        string   `json:"name"`
	Direction   string   `json:"direction,omitempty"` // import or export
	Peer        string   `json:"peer,omitempty"`
	Action      string   `json:"action,omitempty"` // accept, reject, prefer
	Match       string   `json:"match,omitempty"`
	Communities []string `json:"communities,omitempty"`
}

// Sort normalizes all state slices for stable reports and golden tests.
func (s *State) Sort() {
	sort.Slice(s.Interfaces, func(i, j int) bool { return s.Interfaces[i].Name < s.Interfaces[j].Name })
	for i := range s.Interfaces {
		sort.Slice(s.Interfaces[i].Addresses, func(a, b int) bool {
			return s.Interfaces[i].Addresses[a].Prefix < s.Interfaces[i].Addresses[b].Prefix
		})
	}
	sort.Slice(s.Kernel.Routes, func(i, j int) bool {
		return s.Kernel.Routes[i].Prefix+s.Kernel.Routes[i].Table <
			s.Kernel.Routes[j].Prefix+s.Kernel.Routes[j].Table
	})
	sort.Slice(s.BGP.Sessions, func(i, j int) bool {
		return s.BGP.Sessions[i].Neighbor < s.BGP.Sessions[j].Neighbor
	})
	sort.Slice(s.BGP.Paths, func(i, j int) bool {
		if s.BGP.Paths[i].Prefix != s.BGP.Paths[j].Prefix {
			return s.BGP.Paths[i].Prefix < s.BGP.Paths[j].Prefix
		}
		return s.BGP.Paths[i].ASPath < s.BGP.Paths[j].ASPath
	})
	sort.Slice(s.OSPF, func(i, j int) bool {
		return s.OSPF[i].RouterID+s.OSPF[i].Address < s.OSPF[j].RouterID+s.OSPF[j].Address
	})
	sort.Slice(s.Policy, func(i, j int) bool {
		return s.Policy[i].Name+s.Policy[i].Peer < s.Policy[j].Name+s.Policy[j].Peer
	})
}
