package grade

import (
	"context"
	"strings"
	"testing"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func TestSustainedECMPLossNeedsRepeatedPopulationEvidence(t *testing.T) {
	tests := []struct {
		name   string
		losses []int
		want   bool
	}{
		{name: "clean", losses: []int{0, 0, 0, 0}},
		{name: "one transient burst", losses: []int{6, 0, 0, 0}},
		{name: "isolated losses", losses: []int{1, 1, 1, 1}},
		{name: "too few affected sweeps", losses: []int{3, 3, 0, 0}},
		{name: "persistent path loss", losses: []int{3, 2, 4, 0}, want: true},
		{name: "persistent protocol loss", losses: []int{8, 7, 9, 6}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sustainedECMPLoss(tc.losses); got != tc.want {
				t.Fatalf("sustainedECMPLoss(%v) = %v, want %v", tc.losses, got, tc.want)
			}
		})
	}
}

func TestECMPNextHopWeightsMustBeEqual(t *testing.T) {
	equal := []installedHop{
		{iface: "port_BOS", ip: "3.0.10.1", weight: 0},
		{iface: "port_PHY", ip: "3.0.8.1", weight: 1},
	}
	if got := unequalNextHopWeights(equal); got != "" {
		t.Fatalf("default and explicit unit weights differ: %q", got)
	}
	unequal := append([]installedHop(nil), equal...)
	unequal[1].weight = 9
	got := unequalNextHopWeights(unequal)
	if !strings.Contains(got, "port_BOS (3.0.10.1) weight 1") ||
		!strings.Contains(got, "port_PHY (3.0.8.1) weight 9") {
		t.Fatalf("unequal weights were not explained: %q", got)
	}
}

func TestECMPLostFlowsRequireSourceDepartureAndDestinationSilence(t *testing.T) {
	tapReads := 0
	var sendCommand string
	env := &Env{Exec: func(_ context.Context, _ string, cmd []string) (rt.ExecResult, error) {
		joined := strings.Join(cmd, " ")
		switch {
		case strings.Contains(joined, "tcpdump -i any"):
			return rt.ExecResult{}, nil
		case strings.Contains(joined, "EARLY="):
			tapReads++
			body := ecmpTestFrame("Out", "20000", false) +
				ecmpTestFrame("Out", "20001", true)
			if tapReads%2 == 0 {
				body = ecmpTestFrame("In", "20000", false)
			}
			return rt.ExecResult{Stdout: stillRunning(tapBanner) + "---\n" + body}, nil
		case strings.Contains(joined, "nc -w 1"):
			sendCommand = joined
			return rt.ExecResult{Stdout: "20000\n20001\n"}, nil
		default:
			return rt.ExecResult{}, nil
		}
	}}
	flows := []sweepFlow{{sourcePort: "20000"}, {sourcePort: "20001", udp: true}}
	lost, ok, diagnostic := lostFlows(
		t.Context(), env, "as3/ATL", "as3/BOS",
		"3.156.0.1", "3.153.0.1", "33456", flows,
	)
	if !ok || diagnostic != "" {
		t.Fatalf("attribution: ok=%v diagnostic=%q", ok, diagnostic)
	}
	if len(lost) != 1 || lost[0] != flows[1] {
		t.Fatalf("lost=%+v, want only %+v", lost, flows[1])
	}
	if !strings.Contains(sendCommand,
		"nc -u -w 1 -s 3.156.0.1 -p 20001 3.153.0.1 33456") {
		t.Fatalf("UDP tuple changed:\n%s", sendCommand)
	}
}

func TestECMPLostFlowsRejectIncompleteSourceEvidence(t *testing.T) {
	tapReads := 0
	env := &Env{Exec: func(_ context.Context, _ string, cmd []string) (rt.ExecResult, error) {
		joined := strings.Join(cmd, " ")
		switch {
		case strings.Contains(joined, "tcpdump -i any"):
			return rt.ExecResult{}, nil
		case strings.Contains(joined, "EARLY="):
			tapReads++
			body := ""
			if tapReads%2 == 1 {
				body = ecmpTestFrame("Out", "20000", false)
			}
			return rt.ExecResult{Stdout: stillRunning(tapBanner) + "---\n" + body}, nil
		case strings.Contains(joined, "nc -w 1"):
			return rt.ExecResult{Stdout: "20000\n"}, nil
		default:
			return rt.ExecResult{}, nil
		}
	}}
	flows := []sweepFlow{{sourcePort: "20000"}, {sourcePort: "20001", udp: true}}
	lost, ok, diagnostic := lostFlows(
		t.Context(), env, "as3/ATL", "as3/BOS",
		"3.156.0.1", "3.153.0.1", "33456", flows,
	)
	if ok || len(lost) != 1 || lost[0] != flows[0] {
		t.Fatalf("lost=%+v attributable=%v", lost, ok)
	}
	if !strings.Contains(diagnostic, "udp/20001->33456 sent=0/1 departed=0/1") {
		t.Fatalf("diagnostic=%q", diagnostic)
	}
}

func TestECMPSweepUsesBoundedParallelBatches(t *testing.T) {
	flows := make([]sweepFlow, 2*ecmpSweepSendParallelism+1)
	for i := range flows {
		flows[i] = sweepFlow{sourcePort: itoa(20000 + i), udp: i%2 != 0}
	}
	command := sweepSendCommand("3.156.0.1", "3.153.0.1", "33456", flows)
	batches := strings.Split(command, "wait; ")
	if len(batches) != 3 {
		t.Fatalf("got %d batches, want 3:\n%s", len(batches), command)
	}
	for i, want := range []int{ecmpSweepSendParallelism, ecmpSweepSendParallelism, 1} {
		if got := strings.Count(batches[i], ") &"); got != want {
			t.Fatalf("batch %d starts %d jobs, want %d:\n%s", i+1, got, want, command)
		}
	}
	if !strings.HasSuffix(command, "wait") {
		t.Fatalf("sender does not wait for its final batch:\n%s", command)
	}
}

func ecmpTestFrame(direction, port string, udp bool) string {
	ending := "Flags [S], length 0\n"
	if udp {
		ending = "UDP, length 7\n"
	}
	return "22:00:00.000000 port_X " + direction +
		" IP 3.156.0.1." + port + " > 3.153.0.1.33456: " + ending
}
