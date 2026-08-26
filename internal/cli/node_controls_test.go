package cli

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
)

// The audit's namespace column has to make the fault legible at a glance: a
// sidecar that is running, has every daemon, answers on its vty, and is not in
// its router's network namespace is the one line an operator must act on.
func TestControlNamespaceSummaryNamesTheSplit(t *testing.T) {
	for _, tc := range []struct {
		name string
		ns   *agent.ControlNamespace
		want string
	}{
		{name: "absent", ns: nil, want: "-"},
		{
			name: "bound",
			ns:   &agent.ControlNamespace{Supported: true, Proven: true, Match: true, Interfaces: true},
			want: "same",
		},
		{
			name: "orphaned",
			ns: &agent.ControlNamespace{
				Supported: true, Proven: true, Primary: "net:[4026552127]", Control: "net:[4026535379]",
			},
			want: "SPLIT",
		},
		{
			name: "unreadable",
			ns:   &agent.ControlNamespace{Supported: true},
			want: "UNKNOWN",
		},
		{
			name: "no-capability-but-wired",
			ns:   &agent.ControlNamespace{Interfaces: true},
			want: "wired",
		},
		{
			name: "no-capability-and-unproven",
			ns:   &agent.ControlNamespace{},
			want: "unproven",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := controlNamespaceSummary(tc.ns); got != tc.want {
				t.Fatalf("namespace column = %q, want %q", got, tc.want)
			}
		})
	}
}

// A degraded sidecar must never be printed as ok, whatever its daemon counts.
func TestControlAuditRowIsDegradedWhenTheSidecarIsOrphaned(t *testing.T) {
	control := agent.ControlStatus{
		Node: "node-0", Device: "as3/PHY", Container: "twinet-cos461-as3-phy-frr",
		Daemons: map[string]int{"bgpd": 1, "ospfd": 1, "zebra": 1}, VTY: true,
		Namespace: &agent.ControlNamespace{Supported: true, Proven: true},
		Reason:    "its FRR control sidecar is attached to a different network namespace: ...",
	}
	if control.Healthy {
		t.Fatal("the audit contract lets a sidecar be healthy with a namespace split")
	}
	if got := controlNamespaceSummary(control.Namespace); got != "SPLIT" {
		t.Fatalf("namespace column = %q for an orphaned sidecar", got)
	}
	if summary := controlDaemonSummary(control.Daemons); summary != "bgpd=1,ospfd=1,zebra=1" {
		t.Fatalf("daemon column = %q", summary)
	}
}
