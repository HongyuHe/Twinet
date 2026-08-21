package runtime

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Factory constructs one runtime backend. The registry deliberately exposes
// the existing Runtime interface rather than a Docker-specific option type so
// a Podman, containerd, or test backend can be selected without changing
// deployment planning.
type Factory func() Runtime

// BackendCapabilities declares which operations a runtime can provide. The
// deployment engine needs every listed capability for a normal routed lab;
// callers can reject an incomplete backend before creating containers.
type BackendCapabilities struct {
	Lifecycle         bool
	Exec              bool
	Copy              bool
	NetworkNamespaces bool
	Events            bool
}

// SupportsRoutedLab reports whether a backend can run the complete Twinet
// substrate. A backend with only lifecycle support is useful for a narrow unit
// test, but it must never get far enough into a deployment to create half a
// lab and discover that it cannot wire or configure it.
func (c BackendCapabilities) SupportsRoutedLab() bool {
	return c.Lifecycle && c.Exec && c.Copy && c.NetworkNamespaces && c.Events
}

var runtimeRegistry = struct {
	sync.RWMutex
	backends map[string]runtimeBackend
}{backends: map[string]runtimeBackend{}}

type runtimeBackend struct {
	factory      Factory
	capabilities BackendCapabilities
}

// Register adds a runtime backend. Duplicate names are rejected because a
// deployment must never select an engine based on package initialization order.
func Register(name string, capabilities BackendCapabilities, factory Factory) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || factory == nil {
		panic("runtime: register needs a name and factory")
	}
	runtimeRegistry.Lock()
	defer runtimeRegistry.Unlock()
	if _, exists := runtimeRegistry.backends[name]; exists {
		panic("runtime: duplicate backend " + name)
	}
	runtimeRegistry.backends[name] = runtimeBackend{factory: factory, capabilities: capabilities}
}

// NewRuntime creates a named backend.
func NewRuntime(name string) (Runtime, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	runtimeRegistry.RLock()
	backend, ok := runtimeRegistry.backends[name]
	runtimeRegistry.RUnlock()
	if !ok {
		return nil, fmt.Errorf("runtime backend %q is not registered (available: %s)",
			name, strings.Join(RuntimeNames(), ", "))
	}
	return backend.factory(), nil
}

// RuntimeNames lists registered runtime backends.
func RuntimeNames() []string {
	runtimeRegistry.RLock()
	defer runtimeRegistry.RUnlock()
	out := make([]string, 0, len(runtimeRegistry.backends))
	for name := range runtimeRegistry.backends {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// CapabilitiesFor returns the declared capabilities of a registered backend.
func CapabilitiesFor(name string) (BackendCapabilities, bool) {
	runtimeRegistry.RLock()
	defer runtimeRegistry.RUnlock()
	backend, ok := runtimeRegistry.backends[strings.ToLower(strings.TrimSpace(name))]
	return backend.capabilities, ok
}

// RequireRoutedLabCapabilities validates a runtime selection before a caller
// mutates containers or host networking.
func RequireRoutedLabCapabilities(name string) error {
	capabilities, ok := CapabilitiesFor(name)
	if !ok {
		return fmt.Errorf("runtime backend %q is not registered (available: %s)",
			name, strings.Join(RuntimeNames(), ", "))
	}
	if capabilities.SupportsRoutedLab() {
		return nil
	}
	var missing []string
	if !capabilities.Lifecycle {
		missing = append(missing, "lifecycle")
	}
	if !capabilities.Exec {
		missing = append(missing, "exec")
	}
	if !capabilities.Copy {
		missing = append(missing, "copy")
	}
	if !capabilities.NetworkNamespaces {
		missing = append(missing, "network namespaces")
	}
	if !capabilities.Events {
		missing = append(missing, "events")
	}
	return fmt.Errorf("runtime backend %q cannot run a routed Twinet lab; missing %s",
		name, strings.Join(missing, ", "))
}

// EndpointRuntime is implemented by backends that can be bound to one
// explicit API socket. Agent configuration uses it instead of changing
// process-global environment variables, which would let two agents in one
// process accidentally select each other's engine.
type EndpointRuntime interface {
	Runtime
	SetRuntimeEndpoint(string) error
	RuntimeEndpoint() string
}

// ConfigureEndpoint binds a selected runtime to an explicit Unix socket or
// TCP endpoint. An empty endpoint retains the backend's ordinary default.
func ConfigureEndpoint(r Runtime, endpoint string) error {
	if strings.TrimSpace(endpoint) == "" {
		return nil
	}
	configurable, ok := r.(EndpointRuntime)
	if !ok {
		return fmt.Errorf("runtime backend %q does not support an explicit socket", r.Name())
	}
	return configurable.SetRuntimeEndpoint(endpoint)
}

// ValidateSelection checks both a registered routed-lab backend and its
// optional endpoint without opening a daemon connection or mutating anything.
// Manifest validation and bootstrap generation use it before they produce work
// that would otherwise fail halfway through a deployment.
func ValidateSelection(name, endpoint string) error {
	if err := RequireRoutedLabCapabilities(name); err != nil {
		return err
	}
	r, err := NewRuntime(name)
	if err != nil {
		return err
	}
	return ConfigureEndpoint(r, endpoint)
}

// Endpoint returns the API socket or endpoint a backend reports. It is kept
// separate from Name so status can prove which daemon an agent actually uses.
func Endpoint(r Runtime) string {
	if configurable, ok := r.(EndpointRuntime); ok {
		return configurable.RuntimeEndpoint()
	}
	return ""
}

func init() {
	Register("docker", BackendCapabilities{
		Lifecycle: true, Exec: true, Copy: true, NetworkNamespaces: true, Events: true,
	}, func() Runtime { return NewDocker() })
	Register("podman", BackendCapabilities{
		Lifecycle: true, Exec: true, Copy: true, NetworkNamespaces: true, Events: true,
	}, func() Runtime { return NewPodman() })
}
