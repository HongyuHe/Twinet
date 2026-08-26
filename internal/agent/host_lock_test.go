package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// namespaceHandle stands in for /proc/<pid>/ns/net. What the derivation reads
// is the inode, so two distinct files are two namespaces and one file used
// twice is one namespace -- which is the property under test, and needs no
// privilege to arrange.
func namespaceHandle(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// acquireIsolated takes a lease as an agent that is not in PID 1's namespace,
// so the legacy fixed-path guard does not decide the outcome of a test about
// namespace identity.
func acquireIsolated(t *testing.T, dir, nsPath, node, listen, runtimeNamespace string,
) (*hostLease, error) {
	t.Helper()
	return acquireHostAgentLockIn(dir, nsPath, namespaceHandle(t, "init-net"),
		node, listen, runtimeNamespace)
}

func TestOnlyOneAgentMayOwnAHostNetworkNamespace(t *testing.T) {
	dir := t.TempDir()
	netns := namespaceHandle(t, "net")
	first, err := acquireIsolated(t, dir, netns, "node-0", "10.0.1.1:7200", "twinet-node-0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()

	// A different API port and a different runtime metadata namespace isolate
	// nothing: both processes still rewire the same root namespace.
	if _, err := acquireIsolated(t, dir, netns, "node-shadow", "10.0.1.1:7300",
		"twinet-shadow"); err == nil {
		t.Fatal("a second agent acquired the same host-network lock")
	} else {
		for _, want := range []string{"another Twinet agent", "node-0", "10.0.1.1:7200"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("lock refusal does not contain %q: %v", want, err)
			}
		}
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireIsolated(t, dir, netns, "node-0", "10.0.1.1:7200", "twinet-node-0")
	if err != nil {
		t.Fatalf("lock was not released with the first agent: %v", err)
	}
	_ = second.Close()
}

// The point of deriving ownership from the namespace is that an operator
// cannot choose it. Two agents in one namespace contend however their lock
// directories are arranged, because the claim is scoped by the kernel and not
// by the filesystem. The removed -host-lock override made exactly this
// succeed.
func TestAgentsInOneNamespaceContendAcrossLockDirectories(t *testing.T) {
	netns := namespaceHandle(t, "net")
	first, err := acquireIsolated(t, t.TempDir(), netns, "node-0", "10.0.1.1:7200", "twinet-node-0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()

	_, err = acquireIsolated(t, t.TempDir(), netns, "node-shadow", "10.0.1.1:7300", "twinet-shadow")
	if err == nil {
		t.Fatal("a second agent in the same network namespace acquired its own lock")
	}
	if !strings.Contains(err.Error(), "node=node-0") {
		t.Errorf("refusal does not name the agent that actually owns the namespace: %v", err)
	}
	if !strings.Contains(err.Error(), "separate lock directory") {
		t.Errorf("refusal does not explain that a private lock directory is not isolation: %v", err)
	}
}

// And two agents in genuinely separate namespaces must not contend, or the
// refusal would stop the isolated agent the operator guide describes.
func TestAgentsInSeparateNamespacesDoNotContend(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireIsolated(t, dir, namespaceHandle(t, "net"),
		"node-0", "10.0.1.1:7200", "twinet-node-0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()

	second, err := acquireIsolated(t, dir, namespaceHandle(t, "net"),
		"node-isolated", "10.0.1.1:7300", "twinet-isolated")
	if err != nil {
		t.Fatalf("an agent in a separate network namespace was refused: %v", err)
	}
	_ = second.Close()
}

// An agent in the host's root namespace also takes the fixed path older builds
// used, so a stale agent from before this change is still refused rather than
// left running beside a new one in the namespace they both rewire.
func TestRootNamespaceAgentAlsoHoldsTheLegacyLock(t *testing.T) {
	dir := t.TempDir()
	netns := namespaceHandle(t, "net")
	lease, err := acquireHostAgentLockIn(dir, netns, netns, "node-0", "10.0.1.1:7200", "twinet-node-0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.Close() }()

	legacy := filepath.Join(dir, legacyHostLockName)
	recorded, err := os.ReadFile(legacy)
	if err != nil {
		t.Fatalf("root-namespace agent did not take %s: %v", legacy, err)
	}
	if !strings.Contains(string(recorded), "node=node-0") {
		t.Errorf("legacy lock does not record its owner: %s", recorded)
	}
	if _, err := lockHostFile(legacy, "intruder"); err == nil {
		t.Fatal("an older agent could still take the fixed-path lock")
	}
}

// An isolated agent has only its own links to protect. Refusing it because it
// shares a /run with the host agent would defeat the isolation its namespace
// already gives it.
func TestIsolatedNamespaceAgentDoesNotTakeTheLegacyLock(t *testing.T) {
	dir := t.TempDir()
	lease, err := acquireIsolated(t, dir, namespaceHandle(t, "net"),
		"node-isolated", "10.0.1.1:7300", "twinet-isolated")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.Close() }()

	if _, err := os.Stat(filepath.Join(dir, legacyHostLockName)); !os.IsNotExist(err) {
		t.Fatalf("an isolated agent took the host's fixed-path lock: %v", err)
	}
}

// The refusal has to say which namespace and which owner, or an operator
// cannot act on it.
func TestHostLockRecordsTheNamespaceAndItsOwner(t *testing.T) {
	dir := t.TempDir()
	netns := namespaceHandle(t, "net")
	identity, err := hostNetnsIdentity(netns)
	if err != nil {
		t.Fatal(err)
	}
	path := namespaceLockPath(dir, identity)
	if !strings.Contains(filepath.Base(path), identity) {
		t.Fatalf("lock path %q is not named after namespace %q", path, identity)
	}

	lease, err := acquireIsolated(t, dir, netns, "node-0", "10.0.1.1:7200", "twinet-node-0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.Close() }()

	recorded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"node=node-0", "listen=10.0.1.1:7200", "netns=" + identity} {
		if !strings.Contains(string(recorded), want) {
			t.Errorf("lock owner record does not contain %q: %s", want, recorded)
		}
	}

	if _, err := acquireIsolated(t, dir, netns, "node-shadow", "10.0.1.1:7300",
		"twinet-shadow"); err == nil {
		t.Fatal("a second agent acquired the lock")
	} else if !strings.Contains(err.Error(), identity) {
		t.Errorf("refusal does not name the contended namespace %q: %v", identity, err)
	}
}

// A host whose namespace cannot be identified is refused rather than given a
// default name two agents could share.
func TestHostLockFailsClosedWhenTheNamespaceCannotBeIdentified(t *testing.T) {
	_, err := acquireIsolated(t, t.TempDir(), filepath.Join(t.TempDir(), "absent"),
		"node-0", "10.0.1.1:7200", "twinet-node-0")
	if err == nil {
		t.Fatal("an agent started without knowing which network namespace it is in")
	}
	if !strings.Contains(err.Error(), "network namespace") {
		t.Errorf("refusal does not explain what could not be identified: %v", err)
	}
}

// The real kernel handles must work, or every agent on a real host fails to
// start for want of an identity. A live agent on this machine already owns the
// namespace, and being refused by name is the same proof.
func TestHostLockUsesTheRunningProcessNamespace(t *testing.T) {
	if _, err := os.Stat(hostNetnsPath); err != nil {
		t.Skipf("no network namespace handle at %s: %v", hostNetnsPath, err)
	}
	identity, err := hostNetnsIdentity(hostNetnsPath)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := acquireHostAgentLock(t.TempDir(), "node-0", "10.0.1.1:7200", "twinet-node-0")
	if err != nil {
		if !strings.Contains(err.Error(), identity) {
			t.Fatalf("refusal on the real namespace does not name it: %v", err)
		}
		t.Skipf("an agent already owns this machine's network namespace: %v", err)
	}
	if lease.namespace != identity {
		t.Errorf("lease namespace %q, want %q", lease.namespace, identity)
	}
	_ = lease.Close()
}
