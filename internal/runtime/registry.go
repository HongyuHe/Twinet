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

func init() {
	Register("docker", BackendCapabilities{
		Lifecycle: true, Exec: true, Copy: true, NetworkNamespaces: true, Events: true,
	}, func() Runtime { return NewDocker() })
	Register("podman", BackendCapabilities{
		Lifecycle: true, Exec: true, Copy: true, NetworkNamespaces: true, Events: true,
	}, func() Runtime { return NewPodman() })
}
