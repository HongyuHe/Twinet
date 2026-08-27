package grade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/netstate"
	"github.com/HongyuHe/twinet/internal/plan"
	rt "github.com/HongyuHe/twinet/internal/runtime"
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
				state, err := env.RouterState(ctx, r.Name, netstate.QueryOSPF)
				if err != nil {
					continue
				}
				queried++
				for _, peer := range state.OSPF {
					seen++
					if !strings.HasPrefix(peer.State, "Full") {
						notFull = append(notFull, fmt.Sprintf("%s->%s %s", r.Name, peer.RouterID, peer.State))
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
		StableFor: 8,
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
	for _, r := range env.Routers() {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			return "", 0, fmt.Errorf("%s BGP table: %w", r.Name, err)
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
	return hex.EncodeToString(h.Sum(nil))[:16], total, nil
}

// ldpConfigured returns the routers whose configuration runs LDP.
//
// Read from the configuration rather than from the sessions, because "no
// session yet" and "this lab does not use LDP" are the same output from
// `show mpls ldp neighbor`. Telling them apart by what is currently up is how
// a wait for something still starting returns instantly and declares it
// settled.
func ldpConfigured(ctx context.Context, env *Env) map[string]bool {
	out := map[string]bool{}
	for _, r := range env.Routers() {
		cfg, err := env.Vtysh(ctx, r.Name, "show running-config")
		if err != nil {
			continue
		}
		if strings.Contains(cfg, "mpls ldp") {
			out[r.Name] = true
		}
	}
	return out
}

// WaitLDP waits until every interior link between LDP routers has an
// operational session.
//
// Nothing waited for label distribution. The wait watched OSPF, then BGP, then
// the RIB, and a lab whose entire subject is MPLS was marked the moment the
// RIB stopped moving -- while LDP was still bringing its sessions up. Grading
// in place hid it, because a lab that has been running for minutes converged
// long ago; it appears the moment grading follows a reset, which is what every
// class and batch run does to every submission.
//
// Measured on advnet: the same submission scores 6.00 graded in place and 5.20
// through `grade class`, losing mpls.ldp_adjacencies with "R2 has no LDP
// session with R5". Read back afterwards, R2's sessions were up with fifteen
// seconds of uptime -- they had come up after the mark was recorded.
//
// A submission that has not configured LDP at all is not waited for: there is
// nothing to converge, and the check will say so.
func WaitLDP(ctx context.Context, env *Env, timeout time.Duration) error {
	running := ldpConfigured(ctx, env)
	if len(running) == 0 {
		return nil
	}
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return nil
	}
	return plan.Wait(ctx, plan.Waiter{
		Describe:  fmt.Sprintf("LDP sessions in AS %d to become operational", env.AS),
		Interval:  500 * time.Millisecond,
		Timeout:   timeout,
		StableFor: 2,
		Check: func(ctx context.Context) (bool, error) {
			var down []string
			seen := 0
			for _, d := range as.Routers {
				if !running[d.Name] {
					continue
				}
				peers := interiorPeers(as, d)
				if len(peers) == 0 {
					continue
				}
				out, err := env.Vtysh(ctx, d.Name, "show mpls ldp neighbor")
				if err != nil {
					continue
				}
				for _, p := range peers {
					// Only peers that run LDP themselves. A session cannot
					// come up with a router that is not speaking, and waiting
					// for one would spend the whole budget before the checks
					// that can be answered.
					if !running[p.name] {
						continue
					}
					seen++
					if !operationalWith(out, p.addr) {
						down = append(down, fmt.Sprintf("%s->%s", d.Name, p.name))
					}
				}
			}
			if seen == 0 {
				return true, nil
			}
			if len(down) == 0 {
				return true, nil
			}
			sort.Strings(down)
			return false, fmt.Errorf("%d of %d LDP session(s) not operational: %s",
				len(down), seen, strings.Join(truncate(down, 3), ", "))
		},
	})
}

// waitForScope waits for whichever part of the control plane a rubric's
// questions are about.
//
// Waiting for more than they need is not conservative, it is wrong: a rubric
// about the interior that waits for external sessions reports a student whose
// OSPF is perfect as ungradeable because their BGP is not written yet, and an
// ungradeable report is a mark nobody receives.
func waitForScope(ctx context.Context, env *Env, scope string, timeout time.Duration) error {
	switch scope {
	case convergeScopeOSPF:
		return WaitOSPF(ctx, env, timeout)
	case convergeScopeBGP:
		deadline := time.Now().Add(timeout)
		if err := WaitBGPSessions(ctx, env, timeout); err != nil {
			return err
		}
		return WaitRIBStable(ctx, env, time.Until(deadline))
	default:
		return WaitConverged(ctx, env, timeout)
	}
}

// The scopes a rubric question may name. Anything else means the whole
// control plane, which is also what an undeclared scope means.
const (
	convergeScopeOSPF = "ospf"
	convergeScopeBGP  = "bgp"
	convergeScopeAll  = ""
)

// rubricConvergeScope is the narrowest wait that satisfies every question of a
// rubric that asks for one.
//
// A rubric that asks for nothing still gets the whole control plane, because
// the caller asking for a wait at all is the one who knows the lab was just
// deployed. Two questions asking for different parts get both.
func rubricConvergeScope(r *Rubric) string {
	if r == nil {
		return convergeScopeAll
	}
	seen := map[string]bool{}
	for _, q := range r.Questions {
		if !q.Converge {
			continue
		}
		seen[strings.ToLower(strings.TrimSpace(q.ConvergeScope))] = true
	}
	if len(seen) != 1 {
		return convergeScopeAll
	}
	for scope := range seen {
		switch scope {
		case convergeScopeOSPF, convergeScopeBGP:
			return scope
		}
	}
	return convergeScopeAll
}

// convergenceOutcome says why a bounded convergence wait ended. The four cases
// are deliberately distinct, because only one of them is about the submission
// and none of them is a zero.
type convergenceOutcome string

const (
	// convergenceSettled: the control plane held still, and what the checks
	// read afterwards is the network the student configured.
	convergenceSettled convergenceOutcome = "settled"
	// convergenceUnsettled: the budget ran out with the network still moving.
	// A correct submission can simply be slower than the budget, so this is
	// evidence that the marks below are provisional, not evidence of a
	// mistake.
	convergenceUnsettled convergenceOutcome = "unsettled"
	// convergenceUnobservable: the machinery could not ask. A node that
	// cannot be reached is never a student's zero.
	convergenceUnobservable convergenceOutcome = "unobservable"
	// convergenceCancelled: the caller gave up, or its own deadline expired.
	convergenceCancelled convergenceOutcome = "cancelled"
)

// convergenceResult is what one bounded wait established.
type convergenceResult struct {
	Outcome convergenceOutcome
	Scope   string
	Waited  time.Duration
	// Err is why the wait ended, for every outcome but settled.
	Err error
	// Transport is the first failure to reach a device during the wait. It is
	// what separates "this lab has not settled" from "this grader cannot see".
	Transport error
}

// Where names the part of the control plane that was waited for, in the words
// a report a person reads uses.
func (c convergenceResult) Where() string {
	where := "the control plane"
	switch c.Scope {
	case convergeScopeOSPF:
		where = "the interior"
	case convergeScopeBGP:
		where = "BGP"
	}
	return where
}

// waitBeforeChecks performs the bounded convergence wait a caller asked for
// and classifies why it ended.
//
// The wait deliberately reads the lab rather than the grade's frozen
// observation snapshot: the snapshot is taken afterwards, and a wait that
// re-read its own first answer would declare every lab settled instantly.
func waitBeforeChecks(ctx context.Context, env *Env, scope string,
	timeout time.Duration,
) convergenceResult {
	out := convergenceResult{Outcome: convergenceSettled, Scope: scope}
	if env == nil || timeout <= 0 {
		return out
	}
	if err := ctx.Err(); err != nil {
		return convergenceResult{Outcome: convergenceCancelled, Scope: scope, Err: err}
	}

	watch := &transportWatch{}
	waitEnv := *env
	waitEnv.snapshot = nil
	waitEnv.observationBatcher = nil
	waitEnv.infraSeen = nil
	waitEnv.trace = nil
	if waitEnv.Exec != nil {
		waitEnv.Exec = watch.wrap(waitEnv.Exec)
	}

	// The budget is a budget. WaitConverged floors each of its phases at
	// fifteen seconds so a phase given a second cannot cancel its own probe
	// and blame the router it was asking, which is right for the phase and
	// wrong for the total: four floors are a minute, and a caller that asked
	// for thirty seconds must not wait two.
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	err := waitForScope(waitCtx, &waitEnv, scope, timeout)
	out.Waited = time.Since(start)
	out.Transport = watch.failure()
	switch {
	// The parent, not the derived context: a wait that spent its own budget
	// is a lab that did not settle, and only the caller giving up is a
	// cancellation.
	case ctx.Err() != nil:
		out.Outcome, out.Err = convergenceCancelled, ctx.Err()
	case err == nil:
	case out.Transport != nil:
		out.Outcome, out.Err = convergenceUnobservable, err
	default:
		out.Outcome, out.Err = convergenceUnsettled, err
	}
	return out
}

// transportWatch remembers whether a device could not be reached at all, as
// opposed to answering something the wait did not want to hear.
//
// A command that exits non-zero is an answer: OSPF is not up yet, BGP has no
// peers yet. A command that could not be delivered is not, and the difference
// decides whether a report says the lab was slow or says the grader was blind.
type transportWatch struct {
	mu    sync.Mutex
	first error
}

func (w *transportWatch) wrap(inner func(context.Context, string, []string) (rt.ExecResult, error),
) func(context.Context, string, []string) (rt.ExecResult, error) {
	return func(ctx context.Context, device string, command []string) (rt.ExecResult, error) {
		res, err := inner(ctx, device, command)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			w.record(fmt.Errorf("%s: %w", device, err))
		}
		return res, err
	}
}

func (w *transportWatch) record(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.first == nil {
		w.first = err
	}
}

func (w *transportWatch) failure() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.first
}

// WaitControlPlaneStable waits for the observable OSPF/BGP state to stop
// changing, whether the settled answer is healthy or wrong. Requiring every
// session to become healthy makes an intentionally broken submission spend the
// whole timeout before the checks can grade it. A stable wrong state is a mark;
// a changing state is not.
func WaitControlPlaneStable(ctx context.Context, env *Env, timeout time.Duration) error {
	var last string
	return plan.Wait(ctx, plan.Waiter{
		Describe:  fmt.Sprintf("the control plane of AS %d to stop changing", env.AS),
		Interval:  700 * time.Millisecond,
		Timeout:   timeout,
		StableFor: 30,
		Check: func(ctx context.Context) (bool, error) {
			fingerprint, routers, err := controlPlaneFingerprint(ctx, env)
			if err != nil {
				return false, err
			}
			if routers == 0 {
				return true, nil
			}
			stable := fingerprint == last
			last = fingerprint
			if !stable {
				return false, fmt.Errorf("the control plane is still changing across %d router(s)", routers)
			}
			return true, nil
		},
	})
}

func controlPlaneFingerprint(ctx context.Context, env *Env) (string, int, error) {
	h := sha256.New()
	routers := env.Routers()
	for _, router := range routers {
		state, err := env.RouterState(ctx, router.Name,
			netstate.QueryOSPF|netstate.QueryBGPSessions|netstate.QueryBGPRIB)
		if err != nil {
			return "", 0, fmt.Errorf("%s control-plane state: %w", router.ID, err)
		}
		state.Sort()
		fmt.Fprintf(h, "%s|", router.ID)
		var facts []string
		for _, peer := range state.OSPF {
			facts = append(facts, fmt.Sprintf("o:%s:%s:%s:%s",
				peer.RouterID, peer.Address, peer.Interface, peer.State))
		}
		for _, session := range state.BGP.Sessions {
			facts = append(facts, fmt.Sprintf("s:%s:%d:%s:%d:%d",
				session.Neighbor, session.RemoteAS, session.State,
				session.PrefixesIn, session.PrefixesOut))
		}
		for _, path := range state.BGP.Paths {
			var fact strings.Builder
			fmt.Fprintf(&fact, "p:%s:%s:%t:%t:%d:%s:%s:%s",
				path.Prefix, path.ASPath, path.Best, path.Valid, path.LocalPref,
				path.Origin, path.Peer, path.RPKI)
			var nextHops []string
			for _, nextHop := range path.NextHops {
				nextHops = append(nextHops,
					fmt.Sprintf("%s:%s:%d", nextHop.Address, nextHop.Device, nextHop.Weight))
			}
			sort.Strings(nextHops)
			fmt.Fprintf(&fact, ":n=%s", strings.Join(nextHops, ","))
			communities := append([]string(nil), path.Communities...)
			sort.Strings(communities)
			fmt.Fprintf(&fact, ":c=%s", strings.Join(communities, ","))
			facts = append(facts, fact.String())
		}
		sort.Strings(facts)
		for _, fact := range facts {
			fmt.Fprintf(h, "%s|", fact)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16], len(routers), nil
}

// WaitConverged waits for the whole control plane of the AS to settle.
func WaitConverged(ctx context.Context, env *Env, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if err := WaitControlPlaneStable(ctx, env, timeout); err != nil {
		return err
	}
	// Label distribution is not represented by the routing protocol snapshot.
	// Labs without MPLS pass straight through; MPLS labs retain their explicit
	// operational adjacency gate.
	remaining := time.Until(deadline)
	if remaining < 15*time.Second {
		remaining = 15 * time.Second
	}
	return WaitLDP(ctx, env, remaining)
}

func truncate(v []string, n int) []string {
	if len(v) <= n {
		return v
	}
	out := append([]string{}, v[:n]...)
	return append(out, fmt.Sprintf("and %d more", len(v)-n))
}
