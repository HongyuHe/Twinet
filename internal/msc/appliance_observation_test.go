package msc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNamespaceProcessesIncludesSeparatePIDNamespaces(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "netns")
	if err := os.WriteFile(target, []byte("namespace"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, pid := range []string{"11", "29"} {
		base := filepath.Join(root, pid)
		if err := os.MkdirAll(filepath.Join(base, "ns"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(target, filepath.Join(base, "ns/net")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "comm"), []byte("ospfd\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/usr/lib/frr/ospfd", filepath.Join(base, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(root, "31")
	if err := os.MkdirAll(filepath.Join(other, "ns"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "ns/net"), []byte("different"), 0600); err != nil {
		t.Fatal(err)
	}
	processes, err := namespaceProcesses(root, target)
	if err != nil || len(processes) != 2 || processes[0].PID != 11 || processes[1].PID != 29 {
		t.Fatalf("namespace-wide process observation: %+v, %v", processes, err)
	}
	if processes[0].Executable != "/usr/lib/frr/ospfd" || processes[0].Name != "ospfd" {
		t.Fatal(processes)
	}
	if _, err := namespaceProcesses(root, filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing namespace must remain an observation error")
	}
}
