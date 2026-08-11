package grade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/plan"
)

// Convergence predicates.
//
// This is where the grading speed-up comes from. The platform this replaces
// used a fixed twenty-second sleep after anything that might change routing,
// invoked more than eight times per submission, so a class took hours of
// wall-clock time in which nothing was happening. A predicate finishes as soon
// as the network has actually settled, which is usually two to six seconds, and
// it reports what it was still waiting for when it gives up.

// WaitOSPF waits until every OSPF adjacency in the AS is Full.
func WaitOSPF(ctx context.Context, env *Env, timeout time.Duration) error {
	return plan.Wait(ctx, plan.Waiter{
		Describe:  fmt.Sprintf("OSPF in AS %d to reach full adjacency", env.AS),
		Interval:  500 * time.Millisecond,
		Timeout:   timeout,
		StableFor: 2,
		Check: func(ctx context.Context) (bool, error) {
			var notFull []string
			seen, queried := 0, 0
			for _, r := range env.Routers() {
				var out ospfNeighborJSON
				if err := env.VtyshJSON(ctx, r.Name, "show ip ospf neighbor json", &out); err != nil {
					continue
				}
				queried++
				for id, ns := range out.Neighbors {
					for _, n := range ns {
						seen++
						if !strings.HasPrefix(n.NbrState, "Full") {
							notFull = append(notFull, fmt.Sprintf("%s->%s %s", r.Name, id, n.NbrState))
						}
					}
				}
			}
			// Zero observed adjacencies is not convergence, it is an OSPF that
			// has not started. Treating it as settled would let every later
			// check run against a network that is still empty.
			if queried == 0 {
				return false, fmt.Errorf("no router answered an OSPF query")
			}
			if seen == 0 {
				return false, fmt.Errorf("no OSPF adjacencies exist yet")
			}
			if len(notFull) == 0 {
				return true, nil
			}
			sort.Strings(notFull)
			return false, fmt.Errorf("%d of %d adjacencies not Full: %s",
				len(notFull), seen, strings.Join(truncate(notFull, 3), ", "))
		},
	})
}

// WaitBGPSessions waits until every configured BGP session is Established.
func WaitBGPSessions(ctx context.Context, env *Env, timeout time.Duration) error {
	return plan.Wait(ctx, plan.Waiter{
		Describe:  fmt.Sprintf("BGP sessions in AS %d to establish", env.AS),
		Interval:  500 * time.Millisecond,
		Timeout:   timeout,
		StableFor: 2,
		Check: func(ctx context.Context) (bool, error) {
			var down []string
			seen := 0
			for _, r := range env.Routers() {
				sum, err := bgpSummary(ctx, env, r.Name)
				if err != nil {
					continue
				}
				for addr, p := range sum.IPv4Unicast.Peers {
					seen++
					if !strings.EqualFold(p.State, "Established") {
						down = append(down, fmt.Sprintf("%s->%s %s", r.Name, addr, p.State))
					}
				}
			}
			if seen == 0 {
				return false, fmt.Errorf("no BGP peers are configured yet")
			}
			if len(down) == 0 {
				return true, nil
			}
			sort.Strings(down)
			return false, fmt.Errorf("%d of %d sessions not established: %s",
				len(down), seen, strings.Join(truncate(down, 3), ", "))
		},
	})
}

// WaitRIBStable waits until the BGP routing table stops changing.
//
// This is the predicate that replaces "sleep twenty seconds and hope". It
// fingerprints the table and requires the fingerprint to hold still for several
// consecutive polls, which distinguishes a converged network from one that is
// merely between updates.
func WaitRIBStable(ctx context.Context, env *Env, timeout time.Duration) error {
	var last string
	return plan.Wait(ctx, plan.Waiter{
		Describe:  fmt.Sprintf("the BGP table of AS %d to stop changing", env.AS),
		Interval:  700 * time.Millisecond,
		Timeout:   timeout,
		StableFor: 3,
		Check: func(ctx context.Context) (bool, error) {
			fp, n, err := ribFingerprint(ctx, env)
			if err != nil {
				return false, err
			}
			if n == 0 {
				return false, fmt.Errorf("the BGP table is still empty")
			}
			stable := fp == last
			last = fp
			if !stable {
				return false, fmt.Errorf("the table is still changing (%d prefixes)", n)
			}
			return true, nil
		},
	})
}

// ribFingerprint hashes the AS's BGP tables into a single value.
func ribFingerprint(ctx context.Context, env *Env) (string, int, error) {
	h := sha256.New()
	total := 0
	var lastErr error
	for _, r := range env.Routers() {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			lastErr = err
			continue
		}
		table := tbl.Table()
		prefixes := make([]string, 0, len(table))
		for p := range table {
			prefixes = append(prefixes, p)
		}
		sort.Strings(prefixes)
		fmt.Fprintf(h, "%s|", r.Name)
		for _, p := range prefixes {
			total++
			fmt.Fprintf(h, "%s:", p)
			// Include the chosen path and preference: a table with the same
			// prefixes but a different best path has not converged.
			for _, e := range table[p] {
				if e.BestPath {
					fmt.Fprintf(h, "%s/%d;", strings.TrimSpace(e.Path), e.LocalPref)
				}
			}
			h.Write([]byte("|"))
		}
	}
	if total == 0 && lastErr != nil {
		return "", 0, lastErr
	}
	return hex.EncodeToString(h.Sum(nil))[:16], total, nil
}

// waitForScope waits for whichever part of the control plane a question is
// about.
//
// Waiting for more than the question needs is not conservative, it is wrong: a
// question about the interior that waits for external sessions reports a
// student whose OSPF is perfect as ungradeable because their BGP is not written
// yet, and an ungradeable report is a mark nobody receives.
func waitForScope(ctx context.Context, env *Env, scope string, timeout time.Duration) error {
	switch scope {
	case "ospf":
		return WaitOSPF(ctx, env, timeout)
	case "bgp":
		deadline := time.Now().Add(timeout)
		if err := WaitBGPSessions(ctx, env, timeout); err != nil {
			return err
		}
		return WaitRIBStable(ctx, env, time.Until(deadline))
	default:
		return WaitConverged(ctx, env, timeout)
	}
}

// WaitConverged waits for the whole control plane of the AS to settle.
func WaitConverged(ctx context.Context, env *Env, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	remaining := func() time.Duration {
		d := time.Until(deadline)
		if d < 15*time.Second {
			// A phase given a second or two cannot finish, and its probe is
			// cancelled mid-flight, so the report blames whichever router was
			// being asked rather than saying the lab did not converge. A floor
			// large enough to complete one poll keeps the message honest.
			return 15 * time.Second
		}
		return d
	}
	// OSPF first: BGP next hops cannot resolve until the interior is up, so
	// waiting on BGP before OSPF would just time out with a confusing message.
	if err := WaitOSPF(ctx, env, remaining()); err != nil {
		return err
	}
	if err := WaitBGPSessions(ctx, env, remaining()); err != nil {
		return err
	}
	return WaitRIBStable(ctx, env, remaining())
}

func truncate(v []string, n int) []string {
	if len(v) <= n {
		return v
	}
	out := append([]string{}, v[:n]...)
	return append(out, fmt.Sprintf("and %d more", len(v)-n))
}
