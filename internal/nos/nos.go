// Package nos registers network operating system providers.
//
// A provider owns the vendor-specific parts of a router's lifecycle. The
// topology, Linux interfaces, and kernel forwarding remain common Twinet
// concerns; configuration syntax and control-plane state do not.
package nos

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// Feature is a network feature a NOS may explicitly support.
type Feature string

const (
	FeatureIPv4 Feature = "ipv4"
	FeatureIPv6 Feature = "ipv6"
	// FeatureForwarding says the provider is able to install and operate
	// kernel forwarding state. A topology may still declare a control-only
	// route server, in which case the agent intentionally does not require
	// end-to-end forwarding from that device.
	FeatureForwarding Feature = "forwarding"
	FeatureOSPF       Feature = "ospf"
	FeatureBGP        Feature = "bgp"
	FeaturePolicy     Feature = "policy"
	FeatureCommunity  Feature = "community"
	FeatureRPKI       Feature = "rpki"
	FeatureVLAN       Feature = "vlan"
	FeatureTunnels    Feature = "tunnels"
	FeatureMPLS       Feature = "mpls"
	FeatureLDP        Feature = "ldp"
	FeatureVRF        Feature = "vrf"
	FeatureMulticast  Feature = "multicast"
	FeatureDHCP       Feature = "dhcp"
)

// Features returns every known feature in stable order.
func Features() []Feature {
	return []Feature{
		FeatureIPv4, FeatureIPv6, FeatureForwarding, FeatureOSPF, FeatureBGP, FeaturePolicy,
		FeatureCommunity, FeatureRPKI, FeatureVLAN, FeatureTunnels,
		FeatureMPLS, FeatureLDP, FeatureVRF, FeatureMulticast, FeatureDHCP,
	}
}

// Capabilities declares the features an implementation supports.
//
// The map is private so a caller cannot mutate provider capabilities after
// registration. Use Supports or Features to inspect it.
type Capabilities struct {
	features map[Feature]bool
}

// NewCapabilities creates a capability declaration.
func NewCapabilities(features ...Feature) Capabilities {
	out := Capabilities{features: make(map[Feature]bool, len(features))}
	for _, feature := range features {
		out.features[feature] = true
	}
	return out
}

// Supports reports whether a declared feature is available.
func (c Capabilities) Supports(feature Feature) bool { return c.features[feature] }

// Features lists declared features in stable order.
func (c Capabilities) Features() []Feature {
	out := make([]Feature, 0, len(c.features))
	for feature := range c.features {
		out = append(out, feature)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Mode selects whether platform-only or reference configuration is rendered.
type Mode string

const (
	ModePlatform Mode = "platform"
	ModeSolve    Mode = "solve"
)

// RenderRequest carries the routing intent compiled by the common renderer.
// Platform and Expected are provider syntax, while the provider owns the
// paths, daemon lifecycle, and readiness semantics that apply the result.
type RenderRequest struct {
	Topology *model.Topology
	Device   *model.Device
	Mode     Mode
	Platform string
	Expected string
	Daemons  string
}

// Rendered is the provider-specific configuration file set.
type Rendered struct {
	Files map[string]FileSpec
}

// FileSpec is a provider-owned file that the existing deployment renderer
// copies into the device.
type FileSpec struct {
	Content []byte
	Mode    int64
}

// Command is provider-specific lifecycle work. The common renderer converts it
// to its existing deployment command interface.
type Command struct {
	Args        []string
	IgnoreError bool
	Describe    string
}

// Provider owns one NOS implementation.
type Provider interface {
	Name() string
	Capabilities() Capabilities
	Render(RenderRequest) (Rendered, error)
	Apply(RenderRequest) ([]Command, error)
	Ready(*model.Device, runtime.Runtime) *plan.Waiter
	ReadState(context.Context, *model.Device, netstate.Executor, netstate.Query) (netstate.State, error)
	StateKind() state.Kind
	Save(context.Context, *model.Device, netstate.Executor, string, string) ([]state.Snapshot, error)
	Restore(context.Context, *model.Device, runtime.Runtime, state.Snapshot) error
}

// UnknownError identifies a manifest or runtime reference to an unregistered
// NOS implementation.
type UnknownError struct{ Name string }

func (e *UnknownError) Error() string {
	return fmt.Sprintf("NOS %q is not registered", e.Name)
}

// UnsupportedFeatureError identifies a device/feature pair that cannot be
// deployed. Validation emits it before any runtime mutation.
type UnsupportedFeatureError struct {
	Device  string
	NOS     string
	Feature Feature
}

func (e *UnsupportedFeatureError) Error() string {
	return fmt.Sprintf("device %s uses NOS %q, which does not support feature %q",
		e.Device, e.NOS, e.Feature)
}

type registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

var providers = registry{providers: map[string]Provider{}}

// Register adds a NOS implementation. Duplicate registrations are a
// programming error because the same manifest must never select behavior by
// import order.
func Register(provider Provider) {
	if provider == nil || strings.TrimSpace(provider.Name()) == "" {
		panic("nos: register a provider with no name")
	}
	name := strings.ToLower(strings.TrimSpace(provider.Name()))
	providers.mu.Lock()
	defer providers.mu.Unlock()
	if _, exists := providers.providers[name]; exists {
		panic("nos: duplicate provider " + name)
	}
	providers.providers[name] = provider
}

// Lookup returns a registered provider by name.
func Lookup(name string) (Provider, bool) {
	providers.mu.RLock()
	defer providers.mu.RUnlock()
	provider, ok := providers.providers[strings.ToLower(strings.TrimSpace(name))]
	return provider, ok
}

// Resolve returns the provider selected for d, retaining the model's explicit
// legacy FRR default for routers whose manifests do not name a NOS.
func Resolve(d *model.Device) (Provider, error) {
	if d == nil {
		return nil, fmt.Errorf("resolve NOS for nil device")
	}
	if !d.IsRouter() {
		return nil, fmt.Errorf("device %s is %s, not a router with a NOS", d.ID, d.Kind)
	}
	name := d.EffectiveNOS()
	provider, ok := Lookup(name)
	if !ok {
		return nil, &UnknownError{Name: name}
	}
	return provider, nil
}

// Names lists registered implementations.
func Names() []string {
	providers.mu.RLock()
	defer providers.mu.RUnlock()
	out := make([]string, 0, len(providers.providers))
	for name := range providers.providers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// FeatureSet validates a provider declaration for a named device.
func FeatureSet(provider Provider, device string, required []Feature) error {
	for _, feature := range required {
		if !provider.Capabilities().Supports(feature) {
			return &UnsupportedFeatureError{Device: device, NOS: provider.Name(), Feature: feature}
		}
	}
	return nil
}

// ValidateStateQuery converts a missing control-plane capability into the
// explicit infrastructure-unsupported result used by graders and observers.
// Kernel facts are deliberately omitted: they are collected from Linux for
// every container regardless of its routing NOS.
func ValidateStateQuery(provider Provider, device string, query netstate.Query) error {
	if provider == nil {
		return &netstate.UnsupportedError{Device: device, Query: query, Reason: "no NOS provider"}
	}
	for _, required := range []struct {
		query   netstate.Query
		feature Feature
	}{
		{netstate.QueryBGP, FeatureBGP},
		{netstate.QueryOSPF, FeatureOSPF},
		{netstate.QueryPolicy, FeaturePolicy},
	} {
		if query.Has(required.query) && !provider.Capabilities().Supports(required.feature) {
			return &netstate.UnsupportedError{
				Device: device, NOS: provider.Name(), Query: required.query,
				Reason: fmt.Sprintf("the provider does not declare %s", required.feature),
			}
		}
	}
	return nil
}
