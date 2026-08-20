package grade

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// ldpLab builds a two-router AS whose routers face each other on an interior
// link, which is the shape interiorPeers reads.
func ldpLab() *model.Topology {
	mk := func(name, lo string) *model.Device {
		return &model.Device{
			Name: name, ASN: 1, Kind: model.KindRouter,
			Ifaces: []*model.Iface{{Name: "lo", Addr4: lo + "/32"}},
		}
	}
	r1, r2 := mk("R1", "1.151.0.1"), mk("R2", "1.152.0.1")

	link := &model.Link{}
	i1 := &model.Iface{Name: "port_R2", Link: link}
	i2 := &model.Iface{Name: "port_R1", Link: link}
	i1.Peer, i2.Peer = i2, i1
	i1.Device, i2.Device = r1, r2
	r1.Ifaces = append(r1.Ifaces, i1)
	r2.Ifaces = append(r2.Ifaces, i2)

	as := &model.AS{ASN: 1, Devices: []*model.Device{r1, r2}, Routers: []*model.Device{r1, r2}}
	return &model.Topology{ASes: map[int]*model.AS{1: as}}
}

// ldpExec answers the two commands the wait asks: what the router is
// configured to run, and which sessions it has. sessionsUp decides the second,
// and is read afresh on every poll so a test can bring LDP up mid-wait.
func ldpExec(configured bool, sessionsUp *atomic.Bool, polls *atomic.Int64) func(context.Context, string, []string) (rt.ExecResult, error) {
	return func(_ context.Context, id string, cmd []string) (rt.ExecResult, error) {
		joined := strings.Join(cmd, " ")
		switch {
		case strings.Contains(joined, "show running-config"):
			if configured {
				return rt.ExecResult{Stdout: "router ospf\n mpls ldp\n  address-family ipv4\n"}, nil
			}
			return rt.ExecResult{Stdout: "router ospf\n network 1.0.0.0/8 area 0\n"}, nil
		case strings.Contains(joined, "mpls ldp neighbor"):
			polls.Add(1)
			if !sessionsUp.Load() {
				return rt.ExecResult{Stdout: "AF   ID              State       Remote Address    Uptime\n"}, nil
			}
			peer := "1.152.0.1"
			if strings.Contains(id, "R2") {
				peer = "1.151.0.1"
			}
			return rt.ExecResult{Stdout: fmt.Sprintf(
				"AF   ID              State       Remote Address    Uptime\n"+
					"ipv4 %s       OPERATIONAL %s       00:00:15\n", peer, peer)}, nil
		}
		return rt.ExecResult{}, nil
	}
}

// The wait watched OSPF, then BGP, then the RIB, and never label distribution
// -- so a lab whose whole subject is MPLS was marked the moment the RIB stopped
// moving, while LDP was still bringing its sessions up. Grading in place hides
// it, because a lab running for minutes converged long ago. It appears the
// moment grading follows a reset, which is what a class run does to every
// submission: the same advnet submission scored 6.00 in place and 5.20 through
// `grade class`, losing mpls.ldp_adjacencies to sessions that were up fifteen
// seconds later.
func TestTheWaitIncludesLabelDistribution(t *testing.T) {
	var up atomic.Bool
	var polls atomic.Int64
	env := &Env{Topology: ldpLab(), AS: 1, Exec: ldpExec(true, &up, &polls)}

	// Comes up shortly after the wait starts, as it does on a real reset.
	go func() {
		time.Sleep(700 * time.Millisecond)
		up.Store(true)
	}()

	start := time.Now()
	if err := WaitLDP(context.Background(), env, 20*time.Second); err != nil {
		t.Fatalf("the wait gave up on sessions that came up: %v", err)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Error("returned before the sessions were operational, which is the defect itself")
	}
}

// A submission that has not configured LDP has nothing to converge, and making
// every lab in the collection sit through an MPLS timeout would take the marks
// of students whose course has no MPLS in it.
func TestTheWaitDoesNotStallOnALabWithoutLDP(t *testing.T) {
	var up atomic.Bool
	var polls atomic.Int64
	env := &Env{Topology: ldpLab(), AS: 1, Exec: ldpExec(false, &up, &polls)}

	start := time.Now()
	if err := WaitLDP(context.Background(), env, 20*time.Second); err != nil {
		t.Fatalf("a lab that does not run LDP was reported as not converging: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("waited %v for label distribution nobody configured", d)
	}
	if polls.Load() != 0 {
		t.Errorf("asked for LDP sessions %d time(s) on a lab that runs no LDP", polls.Load())
	}
}

// A submission whose LDP never comes up must still be marked. The wait reports
// what it was waiting for; the report records it as a warning and the check
// fails on its own evidence, which is the student's mark to lose.
func TestTheWaitReportsWhatItWasWaitingFor(t *testing.T) {
	var up atomic.Bool
	var polls atomic.Int64
	env := &Env{Topology: ldpLab(), AS: 1, Exec: ldpExec(true, &up, &polls)}

	err := WaitLDP(context.Background(), env, 2*time.Second)
	if err == nil {
		t.Fatal("declared LDP settled when no session was operational")
	}
	if !strings.Contains(err.Error(), "R1->R2") && !strings.Contains(err.Error(), "R2->R1") {
		t.Errorf("did not name the sessions it was waiting for: %v", err)
	}
}
