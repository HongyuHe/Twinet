package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// identityRuntime is a Runtime whose namespace answers are scripted. The
// embedded interface is nil on purpose: anything these tests do not use must
// fail loudly rather than return a plausible zero value.
type identityRuntime struct {
	Runtime
	name       string
	observed   []Container
	path       string
	inspectErr error
	pathErr    error
	inspects   int
}

func (r *identityRuntime) Name() string { return r.name }

func (r *identityRuntime) Inspect(_ context.Context, _ string) (Container, error) {
	if r.inspectErr != nil {
		return Container{}, r.inspectErr
	}
	index := r.inspects
	if index >= len(r.observed) {
		index = len(r.observed) - 1
	}
	r.inspects++
	return r.observed[index], nil
}

func (r *identityRuntime) NSPath(_ context.Context, _ string) (string, error) {
	if r.pathErr != nil {
		return "", r.pathErr
	}
	return r.path, nil
}

type plainRuntime struct{ Runtime }

func (plainRuntime) Name() string { return "unit" }

func TestNetnsIdentityOfPathReadsTheKernelNamespaceIdentity(t *testing.T) {
	identity, err := NetnsIdentityOfPath("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("reading this process's own namespace: %v", err)
	}
	if !identity.Known() {
		t.Fatal("a readable namespace produced an unknown identity")
	}
	self, err := SelfNetnsIdentity()
	if err != nil || !self.SameAs(identity) {
		t.Fatalf("SelfNetnsIdentity = %v, %v; want %v", self, err, identity)
	}
	if identity.String() == "unknown" {
		t.Fatalf("identity rendered as unknown: %+v", identity)
	}
}

func TestUnknownIdentitiesAreNeverEqual(t *testing.T) {
	var a, b NetnsIdentity
	if a.SameAs(b) {
		t.Fatal("two unproven identities were reported as the same namespace")
	}
	if a.String() != "unknown" {
		t.Fatalf("unproven identity rendered as %q", a.String())
	}
	known := NetnsIdentity{Dev: 4, Inode: 4026552127}
	if known.SameAs(a) || a.SameAs(known) {
		t.Fatal("a proven identity matched an unproven one")
	}
	if !known.SameAs(NetnsIdentity{Dev: 4, Inode: 4026552127}) {
		t.Fatal("identical identities were reported as different namespaces")
	}
	if known.SameAs(NetnsIdentity{Dev: 5, Inode: 4026552127}) {
		t.Fatal("identities on different namespace filesystems were merged")
	}
	if known.String() != "net:[4026552127]" {
		t.Fatalf("identity rendered as %q", known.String())
	}
}

func TestUnreadableNamespaceFailsClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no", "such", "ns")
	if _, err := NetnsIdentityOfPath(missing); !errors.Is(err, ErrNamespaceIdentityUnknown) {
		t.Fatalf("unreadable namespace path error = %v", err)
	}
	if _, err := NetnsIdentityOfPath(""); !errors.Is(err, ErrNamespaceIdentityUnknown) {
		t.Fatalf("empty namespace path error = %v", err)
	}
	backend := &identityRuntime{
		name:     "containerd",
		observed: []Container{{Name: "tw-r1", State: StateRunning, PID: 4242}},
		pathErr:  errors.New("task not found"),
	}
	if _, err := netnsIdentityViaTask(context.Background(), backend, "tw-r1"); !errors.Is(
		err, ErrNamespaceIdentityUnknown) {
		t.Fatalf("unreadable namespace path error = %v", err)
	}
}

// A pid that changed between the two inspections is either a container that
// restarted underneath the read or a number the kernel has handed to something
// else. Both make the identity just read describe a namespace that is not this
// container's, and returning it would be worse than returning nothing.
func TestRecycledPIDIsRejectedRatherThanReported(t *testing.T) {
	backend := &identityRuntime{
		name: "containerd",
		observed: []Container{
			{Name: "tw-r1", State: StateRunning, PID: 4242},
			{Name: "tw-r1", State: StateRunning, PID: 5150},
		},
		path: "/proc/self/ns/net",
	}
	_, err := netnsIdentityViaTask(context.Background(), backend, "tw-r1")
	if !errors.Is(err, ErrNamespaceIdentityUnknown) {
		t.Fatalf("a task replaced mid-read produced %v", err)
	}
	if got := err.Error(); got == "" ||
		!strings.Contains(got, "pid 4242") || !strings.Contains(got, "pid 5150") {
		t.Fatalf("the diagnostic did not name both pids: %s", got)
	}
}

func TestStoppedContainerHasNoProvableNamespace(t *testing.T) {
	for _, tc := range []struct {
		name      string
		container Container
	}{
		{name: "exited", container: Container{Name: "tw-r1", State: StateExited, PID: 4242}},
		{name: "no-pid", container: Container{Name: "tw-r1", State: StateRunning}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &identityRuntime{
				name: "containerd", observed: []Container{tc.container}, path: "/proc/self/ns/net",
			}
			if _, err := netnsIdentityViaTask(context.Background(), backend, "tw-r1"); !errors.Is(
				err, ErrNamespaceIdentityUnknown) {
				t.Fatalf("identity of a %s container = %v", tc.name, err)
			}
			if _, err := observedNetnsIdentityViaTask(tc.container); !errors.Is(
				err, ErrNamespaceIdentityUnknown) {
				t.Fatalf("observed identity of a %s container = %v", tc.name, err)
			}
		})
	}
}

func TestNetnsIdentityIsCapabilityGated(t *testing.T) {
	plain := plainRuntime{}
	if SupportsNetnsIdentity(plain) {
		t.Fatal("a backend with no namespace capability claimed to have one")
	}
	_, err := NetnsIdentityOf(context.Background(), plain, "tw-r1")
	if !errors.Is(err, ErrNamespaceIdentityUnsupported) {
		t.Fatalf("unsupported backend error = %v", err)
	}
	if got := err.Error(); !strings.Contains(got, "unit") {
		t.Fatalf("unsupported backend error did not name the backend: %s", got)
	}
	_, err = ObservedNetnsIdentityOf(context.Background(), plain, Container{Name: "tw-r1"})
	if !errors.Is(err, ErrNamespaceIdentityUnsupported) {
		t.Fatalf("unsupported backend observed error = %v", err)
	}
	for _, backend := range []Runtime{NewContainerd(), NewDocker(), NewPodman()} {
		if !SupportsNetnsIdentity(backend) {
			t.Fatalf("%s cannot prove namespace identity", backend.Name())
		}
	}
}

func TestObservedNetnsIdentityMatchesTheProvenOne(t *testing.T) {
	self, err := SelfNetnsIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pid := os.Getpid()
	backend := &identityRuntime{
		name:     "containerd",
		observed: []Container{{Name: "tw-r1", State: StateRunning, PID: pid}},
		path:     fmt.Sprintf("/proc/%d/ns/net", pid),
	}
	proven, err := netnsIdentityViaTask(context.Background(), backend, "tw-r1")
	if err != nil {
		t.Fatal(err)
	}
	observed, err := observedNetnsIdentityViaTask(Container{Name: "tw-r1", State: StateRunning, PID: pid})
	if err != nil {
		t.Fatal(err)
	}
	if !proven.SameAs(observed) || !proven.SameAs(self) {
		t.Fatalf("proven %v, observed %v, self %v disagree", proven, observed, self)
	}
}

// opaqueDecorator is how every runtime decorator is written: it satisfies
// Runtime by embedding one, which hides every capability of the backend behind
// it. It is here because that shape, wrapped around containerd, is what let a
// live deployment find no namespace proof and report a no-op over an orphaned
// control sidecar.
type opaqueDecorator struct{ Runtime }

type forwardingDecorator struct{ Runtime }

func (d *forwardingDecorator) Unwrap() Runtime { return d.Runtime }

// selfWrappingDecorator is malformed on purpose: capability resolution must
// terminate on it rather than follow the chain for ever.
type selfWrappingDecorator struct{ Runtime }

func (d *selfWrappingDecorator) Unwrap() Runtime { return d }

func TestADecoratorDoesNotSilentlyEraseTheIdentityCapability(t *testing.T) {
	pid := os.Getpid()
	self, err := SelfNetnsIdentity()
	if err != nil {
		t.Fatal(err)
	}
	backend := &identityBackend{path: fmt.Sprintf("/proc/%d/ns/net", pid)}
	observation := Container{Name: "tw-r1", State: StateRunning, PID: pid}

	if !SupportsNetnsIdentity(backend) {
		t.Fatal("the backend cannot prove namespace identity")
	}

	opaque := &opaqueDecorator{Runtime: backend}
	if SupportsNetnsIdentity(opaque) {
		t.Fatal("a decorator that hides the backend claimed the capability")
	}
	if _, err := NetnsIdentityOf(context.Background(), opaque, "tw-r1"); !errors.Is(
		err, ErrNamespaceIdentityUnsupported) {
		t.Fatalf("hidden capability error = %v", err)
	}

	forwarding := &forwardingDecorator{Runtime: backend}
	if !SupportsNetnsIdentity(forwarding) {
		t.Fatal("a decorator that exposes its backend lost the capability")
	}
	proven, err := NetnsIdentityOf(context.Background(), forwarding, "tw-r1")
	if err != nil || !proven.SameAs(self) {
		t.Fatalf("proof through a decorator = %s, %v", proven, err)
	}
	observed, err := ObservedNetnsIdentityOf(context.Background(), forwarding, observation)
	if err != nil || !observed.SameAs(self) {
		t.Fatalf("observation through a decorator = %s, %v", observed, err)
	}

	// Two layers, and the outermost is the one an agent adds for metrics.
	nested := &forwardingDecorator{Runtime: &forwardingDecorator{Runtime: backend}}
	if !SupportsNetnsIdentity(nested) {
		t.Fatal("a two-layer decorator chain lost the capability")
	}

	if SupportsNetnsIdentity(&selfWrappingDecorator{}) {
		t.Fatal("a self-wrapping decorator claimed the capability")
	}
}

// identityBackend is a capable backend: it answers namespace identity the way
// containerd, Docker, and Podman do.
type identityBackend struct {
	Runtime
	path string
}

func (b *identityBackend) Name() string { return "containerd" }

func (b *identityBackend) Inspect(_ context.Context, name string) (Container, error) {
	return Container{Name: name, State: StateRunning, PID: os.Getpid()}, nil
}

func (b *identityBackend) NSPath(context.Context, string) (string, error) { return b.path, nil }

func (b *identityBackend) NetnsIdentity(ctx context.Context, name string) (NetnsIdentity, error) {
	return netnsIdentityViaTask(ctx, b, name)
}

func (b *identityBackend) ObservedNetnsIdentity(_ context.Context, c Container) (NetnsIdentity, error) {
	return observedNetnsIdentityViaTask(c)
}
