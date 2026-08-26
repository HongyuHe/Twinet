package cli

import (
	"fmt"
	"strings"
	"testing"
)

// destroyRun executes the real command tree and returns what a person would
// see: standard output, standard error, and the process result.
func destroyRun(t *testing.T, args ...string) (out, errOut string, err error) {
	t.Helper()
	// The persistent flags take their defaults from the environment, and a
	// developer with TWINET_RUNTIME set would otherwise satisfy a requirement
	// the test is asserting.
	t.Setenv("TWINET_RUNTIME", "")
	t.Setenv("TWINET_RUNTIME_SOCKET", "")
	root := Root()
	var stdout, stderr strings.Builder
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err = root.Execute()
	return stdout.String(), stderr.String(), err
}

// The finding, in one test.
//
// `twinet destroy --lab cos461 --yes` with no loadable manifest selected the
// default Docker backend, found none of the containerd cluster's containers,
// deleted the overlay objects this machine held for the lab, printed "removed",
// and exited zero -- while a 212-container lab kept running on three nodes with
// its cross-node cables cut. The name of a lab is not evidence about where it
// is running, so the command now refuses before touching anything.
func TestDestroyWithoutAManifestRefusesAClusteredLabName(t *testing.T) {
	empty := t.TempDir()
	out, errOut, err := destroyRun(t, "-m", empty, "destroy", "--lab", "cos461", "--yes")
	if err == nil {
		t.Fatalf("destroying a lab nobody has the manifest for succeeded:\nstdout %q\nstderr %q",
			out, errOut)
	}
	if out != "" {
		t.Errorf("a refusal that mutates nothing printed to standard output: %q", out)
	}
	message := err.Error()
	for _, want := range []string{
		"refusing to remove lab \"cos461\"",
		empty,
		"twinet -m PATH destroy --lab cos461 --yes",
		"node sweep --remove",
		"--this-node-only",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, message)
		}
	}
	for _, forbidden := range []string{"removed", "nothing to remove"} {
		if strings.Contains(strings.ToLower(out+message), forbidden) {
			t.Errorf("the refusal claims %q:\nstdout %q\nerror %s", forbidden, out, message)
		}
	}
}

// The explicit local path exists, and its scope is unmistakable: it needs the
// lab's name, the acknowledgement that only this machine is being cleaned, and
// the engine to ask -- because an empty answer from the wrong daemon reads
// exactly like an empty machine.
func TestThisNodeOnlyRequiresAnExplicitScope(t *testing.T) {
	empty := t.TempDir()
	t.Run("needs a lab", func(t *testing.T) {
		out, _, err := destroyRun(t, "-m", empty, "destroy", "--this-node-only", "--yes")
		if err == nil {
			t.Fatalf("a scope with no lab was accepted: %q", out)
		}
		if !strings.Contains(err.Error(), "--lab NAME") {
			t.Errorf("the refusal does not say what is missing: %v", err)
		}
		if out != "" {
			t.Errorf("a refusal printed to standard output: %q", out)
		}
	})
	t.Run("needs a runtime", func(t *testing.T) {
		out, _, err := destroyRun(t, "-m", empty, "destroy",
			"--lab", "cos461", "--this-node-only", "--yes")
		if err == nil {
			t.Fatalf("a manifest-less local cleanup ran against a guessed engine: %q", out)
		}
		if !strings.Contains(err.Error(), "--runtime") ||
			!strings.Contains(err.Error(), "containerd") {
			t.Errorf("the refusal does not name the engines it would accept: %v", err)
		}
		if out != "" {
			t.Errorf("a refusal printed to standard output: %q", out)
		}
	})
}

// A manifest that describes the named lab is used even when the lab is on one
// node: it carries the engine, the node the devices are placed on, and the
// overlay identifiers, none of which a container label can supply. Naming such
// a lab must not be treated as naming a lab nobody has a manifest for.
func TestDestroyUsesASingleNodeManifestForItsOwnLab(t *testing.T) {
	out, _, err := destroyRun(t, "-m", "../../examples/demo", "destroy", "--lab", "demo")
	if err != nil && strings.Contains(err.Error(), "refusing to remove lab") {
		t.Fatalf("a lab with its own manifest was treated as manifest-less: %v", err)
	}
	if strings.Contains(out, "removed") {
		t.Fatalf("a destroy without --yes removed something: %q", out)
	}
}

// The overlay rule, without a host to build overlays on.
//
// An overlay whose bridge still has an interface attached is carrying a cable
// for something. Removing it is not cleanup; it is an outage in whatever is
// still using it, and the count of removals is what makes the report look fine.
func TestOverlaysStillCarryingACableAreNeverRemoved(t *testing.T) {
	original := overlayPortsOfLab
	t.Cleanup(func() { overlayPortsOfLab = original })
	overlayPortsOfLab = func(lab string) (map[uint32]int, error) {
		if lab != "cos461" {
			t.Errorf("asked about lab %q", lab)
		}
		return map[uint32]int{4001: 2, 4002: 0, 4003: 1}, nil
	}

	var asked [][]uint32
	remove := func(vnis []uint32) error {
		asked = append(asked, append([]uint32(nil), vnis...))
		return nil
	}
	removed, kept, err := removeIdleOverlays(remove, "cos461", []uint32{4003, 4002, 4001, 4002})
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || len(asked[0]) != 1 || asked[0][0] != 4002 {
		t.Fatalf("removal was asked for %v; only the overlay with nothing attached may be removed", asked)
	}
	if len(removed) != 1 || removed[0] != 4002 {
		t.Errorf("removed = %v", removed)
	}
	if fmt.Sprint(kept) != "[4001 4003]" {
		t.Errorf("kept = %v, want the two that still have an interface attached", kept)
	}

	var report strings.Builder
	reportKeptOverlays(&report, kept)
	if !strings.Contains(report.String(), "4001") || !strings.Contains(report.String(), "4003") ||
		!strings.Contains(report.String(), "not removed") {
		t.Errorf("what was left behind is not reported honestly: %q", report.String())
	}
}

// Not knowing which overlays are in use is a reason to remove none of them.
// An identifier still held is recoverable; a live link cut by a cleanup that
// could not see it is not.
func TestOverlaysAreKeptWhenTheirUseCannotBeDetermined(t *testing.T) {
	original := overlayPortsOfLab
	t.Cleanup(func() { overlayPortsOfLab = original })
	overlayPortsOfLab = func(string) (map[uint32]int, error) {
		return nil, fmt.Errorf("netlink dump interrupted")
	}
	removed, kept, err := removeIdleOverlays(func([]uint32) error {
		t.Fatal("an overlay was removed without knowing whether anything was attached to it")
		return nil
	}, "cos461", []uint32{7, 8})
	if err == nil {
		t.Fatal("a failed check was treated as an empty answer")
	}
	if len(removed) != 0 || len(kept) != 2 {
		t.Fatalf("removed = %v, kept = %v", removed, kept)
	}
}

// The help is part of the fix: it used to tell a reader that naming a lab
// cleans up a deployment whose manifest is gone, which is the operation that
// cut a live cluster's overlays and reported success.
func TestDestroyHelpDescribesTheScopeItCanActuallyProve(t *testing.T) {
	root := Root()
	var destroy = child(root, "destroy")
	if destroy == nil {
		t.Fatal("there is no destroy command")
	}
	long := destroy.Long
	for _, want := range []string{"--this-node-only", "--lab NAME on its own refuses"} {
		if !strings.Contains(long, want) {
			t.Errorf("the help does not mention %q:\n%s", want, long)
		}
	}
	if strings.Contains(long, "even\nif the manifest that created it is no longer available") {
		t.Errorf("the help still promises manifest-less cleanup:\n%s", long)
	}
	flag := destroy.Flags().Lookup("lab")
	if flag == nil {
		t.Fatal("destroy has no --lab flag")
	}
	if !strings.Contains(flag.Usage, "manifest") {
		t.Errorf("--lab still reads as an alternative to having a manifest: %q", flag.Usage)
	}
	if destroy.Flags().Lookup("this-node-only") == nil {
		t.Error("the explicit local-cleanup path has no flag")
	}
}

// The messages are half of the defect: what a cleanup says it did is the only
// thing an operator can check afterwards. "nothing to remove for lab cos461"
// and "removed lab cos461" were printed by a command that had inspected one
// machine of three, and neither line said so.
func TestDestroyMessagesNameTheScopeTheyCanSpeakFor(t *testing.T) {
	t.Run("one machine", func(t *testing.T) {
		noop := destroyNoOpMessage("cos461", true)
		if !strings.Contains(noop, `lab "cos461" on this machine`) ||
			!strings.Contains(noop, "no other machine was inspected, and none was changed") {
			t.Errorf("a machine-scoped no-op reads as though it spoke for the lab: %q", noop)
		}
		removed := destroyRemovedMessage(12, "cos461", true)
		if !strings.Contains(removed, `removed 12 containers of lab "cos461" on this machine`) ||
			!strings.Contains(removed, "no other machine was contacted, and none was changed") {
			t.Errorf("a machine-scoped removal reads as though the lab were gone: %q", removed)
		}
	})
	t.Run("the whole lab", func(t *testing.T) {
		noop := destroyNoOpMessage("cos461", false)
		if strings.Contains(noop, "this machine") {
			t.Errorf("a manifest-scoped no-op understates itself: %q", noop)
		}
		removed := destroyRemovedMessage(212, "cos461", false)
		if strings.Contains(removed, "this machine") ||
			!strings.Contains(removed, `removed 212 containers of lab "cos461"`) {
			t.Errorf("a manifest-scoped removal = %q", removed)
		}
	})
}
