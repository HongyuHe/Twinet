package grade

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	"github.com/HongyuHe/twinet/internal/plan"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// WaitReferenceBaseline verifies the solved portion of an ungraded harness
// after asynchronous control-plane convergence and before any submission is
// loaded. The target AS is deliberately excluded: it is the student's blank
// platform baseline. Every surrounding solved AS must establish its
// non-target BGP control sessions and route to representative solved hosts.
//
// This is the compensating fail-closed gate for deployment transactions that
// cannot synchronously wait for cross-node BGP/forwarding while they hold a
// mutation fence. It is not a student check: failure means infrastructure and
// callers must produce NeedsReview rather than a mark.
func WaitReferenceBaseline(ctx context.Context, top *model.Topology, target int,
	exec func(context.Context, string, []string) (rt.ExecResult, error),
	stateReader netstate.Reader, timeout time.Duration,
) error {
	if top == nil || exec == nil {
		return fmt.Errorf("reference baseline needs topology and executor")
	}
	if _, ok := top.ASes[target]; !ok {
		return fmt.Errorf("reference baseline target AS %d is absent", target)
	}
	targets := referenceBaselineTargets(top, target)
	return plan.Wait(ctx, plan.Waiter{
		Describe:  fmt.Sprintf("solved reference baseline around ungraded AS %d", target),
		Interval:  750 * time.Millisecond,
		Timeout:   timeout,
		StableFor: 2,
		Check: func(ctx context.Context) (bool, error) {
			if err := checkReferenceBaseline(ctx, top, target, targets, exec, stateReader); err != nil {
				return false, err
			}
			return true, nil
		},
	})
}

func checkReferenceBaseline(ctx context.Context, top *model.Topology, target int, targets []string,
	exec func(context.Context, string, []string) (rt.ExecResult, error), stateReader netstate.Reader,
) error {
	type routerCheck struct {
		asn    int
		router *model.Device
	}
	var checks []routerCheck
	for _, asn := range top.SortedASNs() {
		if asn == target {
			continue
		}
		as := top.ASes[asn]
		if as == nil {
			continue
		}
		routers := append([]*model.Device(nil), as.Routers...)
		sort.Slice(routers, func(i, j int) bool { return routers[i].ID < routers[j].ID })
		for _, router := range routers {
			if router == nil {
				continue
			}
			checks = append(checks, routerCheck{asn: asn, router: router})
		}
	}
	if len(checks) == 0 {
		return nil
	}

	const maxWorkers = 32
	workers := min(maxWorkers, len(checks))
	jobs := make(chan int, len(checks))
	for i := range checks {
		jobs <- i
	}
	close(jobs)
	errs := make([]error, len(checks))
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				item := checks[index]
				router := item.router
				if ctx.Err() != nil {
					errs[index] = ctx.Err()
					continue
				}
				caps := top.SemanticHealthCapabilities(router)
				env := &Env{Topology: top, AS: item.asn, Exec: exec, StateReader: stateReader}
				if caps.BGPControl && routerHasReferenceBGPPeer(router, target) {
					state, err := env.LiveDeviceState(ctx, router.ID, netstate.QueryBGPSessions)
					if err != nil {
						errs[index] = fmt.Errorf("%s read solved BGP control state: %w", router.ID, err)
						continue
					}
					seen := 0
					for _, session := range state.BGP.Sessions {
						if session.RemoteAS == uint32(target) {
							continue
						}
						seen++
						if !strings.EqualFold(session.State, "Established") {
							errs[index] = fmt.Errorf(
								"%s solved BGP session to %s is %q, want Established",
								router.ID, session.Neighbor, session.State)
							break
						}
					}
					if errs[index] != nil {
						continue
					}
					if seen == 0 {
						errs[index] = fmt.Errorf("%s has no solved non-target BGP session", router.ID)
						continue
					}
				}
				if caps.Forwarding && len(targets) > 0 {
					errs[index] = verifyReferenceForwarding(ctx, exec, router.ID, targets)
				}
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func routerHasReferenceBGPPeer(router *model.Device, target int) bool {
	for _, iface := range router.Ifaces {
		if iface == nil || iface.Peer == nil || iface.Peer.Device == nil {
			continue
		}
		if iface.Peer.Device.Kind != model.KindRouter || iface.Peer.Device.ASN == target {
			continue
		}
		switch iface.Role {
		case model.RoleInterAS, model.RoleIXPLink:
			return true
		}
	}
	return false
}

func referenceBaselineTargets(top *model.Topology, target int) []string {
	seen := map[string]bool{}
	var out []string
	for _, asn := range top.SortedASNs() {
		if asn == target {
			continue
		}
		as := top.ASes[asn]
		if as == nil {
			continue
		}
		devices := append([]*model.Device(nil), as.Devices...)
		sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
		found := false
		for _, device := range devices {
			if device == nil || device.Kind != model.KindHost {
				continue
			}
			for _, iface := range device.Ifaces {
				if iface == nil || iface.Addr4 == "" {
					continue
				}
				prefix, err := netip.ParsePrefix(iface.Addr4)
				if err != nil || prefix.Addr().IsLoopback() {
					continue
				}
				address := prefix.Addr().String()
				if !seen[address] {
					seen[address] = true
					out = append(out, address)
				}
				found = true
				break
			}
			if found {
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func verifyReferenceForwarding(ctx context.Context,
	exec func(context.Context, string, []string) (rt.ExecResult, error),
	device string, targets []string,
) error {
	script := "failed=''; "
	for _, target := range targets {
		script += "ip route get " + target + " >/dev/null 2>&1 || failed=\"$failed " + target + "\"; "
	}
	script += `printf '%s\n' "$failed"`
	result, err := exec(ctx, device, []string{"sh", "-c", script})
	if err != nil {
		return fmt.Errorf("%s probe solved forwarding: %w", device, err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("%s probe solved forwarding exited %d", device, result.ExitCode)
	}
	if missing := strings.Fields(result.Stdout); len(missing) > 0 {
		return fmt.Errorf("%s has no route to solved reference host address(es) %s",
			device, strings.Join(missing, ", "))
	}
	return nil
}
