package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func deviceWithPlatformAddress() *model.Device {
	d := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter}
	d.Ifaces = []*model.Iface{
		{Name: "port_BOS", Owner: model.OwnerPlatform, Addr4: "3.0.1.1/24", Link: &model.Link{}},
		{Name: "host", Owner: model.OwnerStudent, Link: &model.Link{}},
	}
	return d
}

func probeReply(sections map[string][]string) string {
	var b strings.Builder
	for _, name := range []string{"tunnels", "routes", "routes6", "addrs", "vlans"} {
		b.WriteString("--" + name + "\n")
		for _, l := range sections[name] {
			b.WriteString(l + "\n")
		}
	}
	b.WriteString("--done\n")
	return b.String()
}

// Absence is the answer this probe is looking for, and an absence probe must
// not report failure by finding nothing.
//
// The first version ended in a `grep` for stale routes. grep exits 1 when it
// matches nothing, which is the desired state, so a device that had been reset
// perfectly reported "the reset could not be checked" -- and a real class run
// quarantined all eight submissions with it.
func TestACleanDevicePassesVerification(t *testing.T) {
	exec := func(_ context.Context, _ string, _ []string) (rt.ExecResult, error) {
		return rt.ExecResult{
			// Non-zero, as a trailing grep that matched nothing would leave it.
			ExitCode: 1,
			Stdout: probeReply(map[string][]string{
				"addrs": {"port_BOS 3.0.1.1/24"},
			}),
		}, nil
	}
	if err := verifyWiped(context.Background(), exec, deviceWithPlatformAddress()); err != nil {
		t.Fatalf("a device that was reset perfectly was reported as still dirty: %v", err)
	}
}

// The reset suppresses every individual error so that removing something twice
// does not stop it. That makes its exit status worthless as evidence of the one
// thing it exists to establish.
func TestWhatTheResetFailedToRemoveIsReported(t *testing.T) {
	exec := func(_ context.Context, _ string, _ []string) (rt.ExecResult, error) {
		return rt.ExecResult{Stdout: probeReply(map[string][]string{
			"tunnels": {"tun6"},
			"routes":  {"9.0.0.0/8 via 3.0.1.9 dev port_BOS"},
			"addrs":   {"port_BOS 3.0.1.1/24", "port_BOS 10.9.9.9/32"},
			"vlans":   {"eth1 tag=20"},
		})}, nil
	}
	err := verifyWiped(context.Background(), exec, deviceWithPlatformAddress())
	if err == nil {
		t.Fatal("a device still carrying the last submission's tunnels, routes, " +
			"addresses and VLAN assignments passed verification. The next student " +
			"would be marked on somebody else's work.")
	}
	for _, want := range []string{"tun6", "9.0.0.0/8", "10.9.9.9/32", "tag=20"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not mention %s: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "3.0.1.1/24") {
		t.Error("the platform's own address was reported as leftover work, which would " +
			"stop grading on a device that is exactly as it should be")
	}
}

// A probe that never completed is not a clean device.
func TestADeviceThatCouldNotBeReadIsNotReportedAsClean(t *testing.T) {
	exec := func(_ context.Context, _ string, _ []string) (rt.ExecResult, error) {
		return rt.ExecResult{Stdout: "--tunnels\n", Stderr: "container is not running"}, nil
	}
	err := verifyWiped(context.Background(), exec, deviceWithPlatformAddress())
	if err == nil {
		t.Fatal("a device whose probe never finished was reported as reset")
	}
	if !strings.Contains(err.Error(), "did not finish") {
		t.Errorf("the failure does not say the check itself did not run: %v", err)
	}
}

// Two archives for one group wrote to the same report filename, so whichever
// was graded second overwrote the first; two for one AS were silently dropped
// to one by the wave planner. Both lost work with nothing said.
func TestAnAmbiguousSubmissionSetIsRefused(t *testing.T) {
	err := refuseDuplicates([]submission{
		{Group: "group3", AS: 3},
		{Group: "Group3", AS: 3},
	})
	if err == nil {
		t.Fatal("two submissions claiming to be the same group were accepted; one of " +
			"them will silently overwrite the other's report")
	}
	if !strings.Contains(err.Error(), "group3") {
		t.Errorf("the refusal does not name the group: %v", err)
	}

	err = refuseDuplicates([]submission{
		{Group: "alice", AS: 3},
		{Group: "bob", AS: 3},
	})
	if err == nil {
		t.Fatal("two submissions for the same autonomous system were accepted; only " +
			"one can be loaded, and the other disappears without a word")
	}
	for _, want := range []string{"alice", "bob", "AS 3"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %s: %v", want, err)
		}
	}
}

func TestAnOrdinarySubmissionSetIsAccepted(t *testing.T) {
	if err := refuseDuplicates([]submission{
		{Group: "group3", AS: 3},
		{Group: "group4", AS: 4},
		{Group: "group5", AS: 5},
	}); err != nil {
		t.Fatalf("a perfectly ordinary set of submissions was refused: %v", err)
	}
}
