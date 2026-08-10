package fault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// Every registered fault must satisfy the contract, because a fault that
// cannot be verified might never have taken effect and one that cannot be
// resolved contaminates every episode after it.
func TestRegistryContract(t *testing.T) {
	if len(All()) == 0 {
		t.Fatal("no faults registered")
	}
	for _, f := range All() {
		if !f.Category.Valid() {
			t.Errorf("%s: unknown category %q", f.Name, f.Category)
		}
		if f.Inject == nil || f.Verify == nil || f.Resolve == nil {
			t.Errorf("%s: must implement inject, verify and resolve", f.Name)
		}
		if strings.TrimSpace(f.Symptom) == "" {
			t.Errorf("%s: has no reported symptom, so an agent has nothing to go on", f.Name)
		}
		if strings.TrimSpace(f.Describe) == "" {
			t.Errorf("%s: has no description, so its ground truth would be empty", f.Name)
		}
		if len(f.Needs) == 0 {
			t.Errorf("%s: declares no capabilities, so it cannot be refused on a backend that lacks them", f.Name)
		}
	}
}

// The symptom is what an agent is told. If it names the mechanism, the task is
// no longer a diagnosis.
func TestSymptomDoesNotGiveTheAnswerAway(t *testing.T) {
	giveaways := []string{
		"ospf network statement", "route-map", "iptables", "tc qdisc",
		"was removed", "was changed to", "blackhole route was",
	}
	for _, f := range All() {
		low := strings.ToLower(f.Symptom)
		for _, g := range giveaways {
			if strings.Contains(low, g) {
				t.Errorf("%s: the reported symptom names the mechanism (%q): %q", f.Name, g, f.Symptom)
			}
		}
		// The fault's own identifier must not appear either.
		if strings.Contains(low, strings.ReplaceAll(f.Name, "_", " ")) {
			t.Errorf("%s: the symptom repeats the fault name", f.Name)
		}
	}
}

// Ground truth must serialise into the shape NIKA's scoring expects.
func TestGroundTruthShape(t *testing.T) {
	f, ok := Lookup("link_down")
	if !ok {
		t.Fatal("link_down is not registered")
	}
	gt := f.Truth(Target{AS: 12, Device: "ATL"}, "")
	raw, err := json.Marshal(gt)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"is_anomaly", "faulty_devices", "root_cause_category",
		"root_cause_name", "detailed_cause"} {
		if _, ok := decoded[k]; !ok {
			t.Errorf("ground truth is missing the %q field NIKA expects", k)
		}
	}
	if decoded["is_anomaly"] != true {
		t.Error("an injected fault must report is_anomaly")
	}
	if gt.FaultyDevices[0] != "as12/ATL" {
		t.Errorf("faulty device = %q, want as12/ATL", gt.FaultyDevices[0])
	}
}

// The categories must be exactly NIKA's, or the taxonomies cannot be compared.
func TestCategoriesMatchNIKA(t *testing.T) {
	want := map[Category]bool{
		CatEndHost: true, CatLink: true, CatMisconfig: true,
		CatNodeError: true, CatAttack: true, CatContention: true, CatMultiple: true,
	}
	for c := range want {
		if !c.Valid() {
			t.Errorf("%q should be a valid category", c)
		}
	}
	if Category("made_up").Valid() {
		t.Error("an unknown category must not validate")
	}
	// Every registered fault should sit in one of the six real categories.
	for _, f := range All() {
		if f.Category == CatMultiple {
			t.Errorf("%s: multiple_faults is a composition, not a fault type", f.Name)
		}
	}
}

// A failed injection must be rolled back, never left half-applied: a lab in an
// unknown state produces a meaningless measurement.
func TestFailedVerificationRollsBack(t *testing.T) {
	const name = "test_rollback_only"
	resolved := false
	Register(&Fault{
		Name: name, Category: CatLink, Symptom: "something is wrong",
		Describe: "a test fault", Needs: []Capability{CapExec},
		Inject: func(context.Context, *Env, Target) (State, error) {
			return State{"k": "v"}, nil
		},
		Verify: func(context.Context, *Env, Target, State) (Evidence, error) {
			return Evidence{Verified: false, Detail: "it never took effect"}, nil
		},
		Resolve: func(context.Context, *Env, Target, State) error {
			resolved = true
			return nil
		},
	})
	defer delete(registry, name)

	env := &Env{Exec: func(context.Context, string, []string) (rt.ExecResult, error) {
		return rt.ExecResult{}, nil
	}}
	if _, err := Inject(context.Background(), env, name, Target{}); err == nil {
		t.Fatal("expected injection to fail when verification says it did not take effect")
	}
	if !resolved {
		t.Error("a failed injection must be rolled back, or the lab is left in an unknown state")
	}
}

// A resolve that silently half-worked is the most damaging failure, because the
// contamination it leaves is invisible. It must be reported.
func TestResolveThatDidNotWorkIsReported(t *testing.T) {
	const name = "test_stubborn"
	Register(&Fault{
		Name: name, Category: CatLink, Symptom: "something is wrong",
		Describe: "a test fault", Needs: []Capability{CapExec},
		Inject:  func(context.Context, *Env, Target) (State, error) { return State{}, nil },
		Verify:  func(context.Context, *Env, Target, State) (Evidence, error) { return Evidence{Verified: true}, nil },
		Resolve: func(context.Context, *Env, Target, State) error { return nil },
	})
	defer delete(registry, name)

	env := &Env{Exec: func(context.Context, string, []string) (rt.ExecResult, error) {
		return rt.ExecResult{}, nil
	}}
	err := Resolve(context.Background(), env, &Injection{Fault: name})
	if err == nil {
		t.Fatal("expected an error when the fault is still present after resolving")
	}
	if !strings.Contains(err.Error(), "still present") {
		t.Errorf("the error should say the fault survived, got: %v", err)
	}
}

func TestUnknownFaultIsRejected(t *testing.T) {
	env := &Env{}
	_, err := Inject(context.Background(), env, "no_such_fault", Target{})
	if err == nil || !strings.Contains(err.Error(), "no fault named") {
		t.Fatalf("expected a clear error for an unknown fault, got %v", err)
	}
}

func TestTargetDeviceID(t *testing.T) {
	cases := map[string]Target{
		"as12/ATL": {AS: 12, Device: "ATL"},
		"svc/dns":  {Device: "svc/dns"},
		"":         {},
	}
	for want, tgt := range cases {
		if got := tgt.DeviceID(); got != want {
			t.Errorf("DeviceID(%+v) = %q, want %q", tgt, got, want)
		}
	}
}

// killMatching must not kill the shell running it: `pkill -f /usr/lib/frr/`
// matches its own command line, which made a fault kill itself half-way.
func TestKillMatchingExcludesItsOwnShell(t *testing.T) {
	script := killMatching("/usr/lib/frr/")
	if !strings.Contains(script, `"$p" != "$$"`) {
		t.Errorf("killMatching must exclude the current shell:\n%s", script)
	}
	if strings.Contains(script, "pkill") {
		t.Errorf("killMatching must not use pkill -f, which self-matches:\n%s", script)
	}
}

// busybox pgrep does not implement -x the way procps does: it silently matches
// nothing, so a running daemon was reported as stopped.
func TestProcRunningDoesNotUsePgrepDashX(t *testing.T) {
	script := procRunning("/bgpd")
	if strings.Contains(script, "pgrep -x") {
		t.Errorf("procRunning must not rely on pgrep -x, which busybox does not honour:\n%s", script)
	}
	if !strings.Contains(script, "grep -v grep") {
		t.Errorf("procRunning must exclude its own grep:\n%s", script)
	}
}
