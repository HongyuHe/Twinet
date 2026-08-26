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
