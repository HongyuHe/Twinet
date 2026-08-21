package fault

import (
	"context"
	"fmt"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// AvailabilityFor reports whether f can run against target now. A nil Env or
// topology is the list-command view: native implementation is present but a
// concrete target has not been selected yet.
func AvailabilityFor(ctx context.Context, f *Fault, env *Env, target Target) []Availability {
	if f == nil {
		return nil
	}
	if len(f.Requires) == 0 {
		return []Availability{{
			Mode: SupportNative, Implemented: true, Available: true,
			Reason: "uses the standard Twinet device runtime",
		}}
	}
	out := make([]Availability, 0, len(f.Requires))
	for _, req := range f.Requires {
		row := Availability{Substrate: req.Substrate, Mode: req.Mode, Implemented: true}
		switch req.Substrate {
		case SubstrateP4BMv2:
			if env == nil || env.Topology == nil || target.DeviceID() == "" {
				row.Available, row.Reason = true, "requires a typed P4/BMv2 device target"
				break
			}
			d, ok := env.Topology.Device(target.DeviceID())
			switch {
			case !ok:
				row.Reason = fmt.Sprintf("target %q is not in this topology", target.DeviceID())
			case d.Kind != model.KindP4 || d.P4 == nil:
				row.Reason = fmt.Sprintf("target %s is %s, not a typed P4/BMv2 device", d.ID, d.Kind)
			case env.Exec == nil:
				row.Reason = "runtime cannot execute BMv2 control-plane probes"
			default:
				row.Available, row.Reason = true, "typed BMv2 program and control-plane contract are present"
			}
		case SubstrateOpenFlow:
			if env == nil || env.Topology == nil || target.DeviceID() == "" {
				row.Available, row.Reason = true, "requires an OpenFlow controller or its managed OVS switch"
				break
			}
			d, ok := env.Topology.Device(target.DeviceID())
			switch {
			case !ok:
				row.Reason = fmt.Sprintf("target %q is not in this topology", target.DeviceID())
			case d.Kind == model.KindController && d.OpenFlow != nil:
				row.Available, row.Reason = true, "typed OpenFlow controller is present"
			case d.Kind == model.KindSwitch && d.OpenFlowController != "":
				row.Available, row.Reason = true, "OVS switch has a declared controller contract"
			default:
				row.Reason = fmt.Sprintf("target %s has no declared OpenFlow control plane", d.ID)
			}
		case SubstrateLoadBalancer:
			if env == nil || env.Topology == nil {
				row.Available, row.Reason = true, "requires typed load-balancer and traffic-generator services"
				break
			}
			lb, traffic := false, false
			for _, d := range env.Topology.Devices {
				lb = lb || d.Kind == model.KindService && d.ServiceKind == "builtin.load-balancer"
				traffic = traffic || d.Kind == model.KindService && d.ServiceKind == "builtin.traffic-generator"
			}
			switch {
			case !lb:
				row.Reason = "no builtin.load-balancer service is declared"
			case !traffic:
				row.Reason = "no builtin.traffic-generator service is declared"
			case env.Exec == nil:
				row.Reason = "runtime cannot collect traffic and metrics"
			default:
				row.Available, row.Reason = true, "measured load-balancer and deterministic traffic generator are present"
			}
		case SubstrateMPLSLabels:
			if env == nil || env.Topology == nil || target.DeviceID() == "" {
				row.Available, row.Reason = true, "requires an MPLS router and node-side label allocator"
				break
			}
			d, ok := env.Topology.Device(target.DeviceID())
			if !ok {
				row.Reason = fmt.Sprintf("target %q is not in this topology", target.DeviceID())
			} else if d.Kind != model.KindRouter || env.Topology.ASes[d.ASN] == nil || !env.Topology.ASes[d.ASN].MPLS.Enabled {
				row.Reason = fmt.Sprintf("target %s is not in an MPLS-enabled router AS", d.ID)
			} else if env.LabelSpace == nil {
				row.Reason = "no privileged node-side MPLS label allocator is configured"
			} else {
				row.Available, row.Reason = true, "fenced node-side MPLS label allocator is present"
			}
		case SubstrateKubernetes:
			row.Mode = SupportDelegated
			if env == nil || env.Kubernetes == nil {
				row.Reason = "no NIKA Kubernetes endpoint/context is configured"
				break
			}
			ok, reason, err := env.Kubernetes.Available(ctx)
			if err != nil {
				row.Reason = fmt.Sprintf("Kubernetes capability discovery failed: %v", err)
			} else {
				row.Available, row.Reason = ok, reason
				if row.Reason == "" && !ok {
					row.Reason = "NIKA Kubernetes backend is unavailable"
				}
			}
		}
		out = append(out, row)
	}
	return out
}

// RequireAvailable refuses before an injector can mutate anything. It is used
// by direct faults and incident scenarios alike; keeping this boundary inside
// the engine prevents a future CLI path from bypassing capability discovery.
func RequireAvailable(ctx context.Context, f *Fault, env *Env, target Target) error {
	for _, got := range AvailabilityFor(ctx, f, env, target) {
		if !got.Available {
			substrate := string(got.Substrate)
			if substrate == "" {
				substrate = "standard runtime"
			}
			return fmt.Errorf("%s is unavailable for %s: %s", substrate, f.Name, got.Reason)
		}
	}
	return nil
}

// RequirementsFor returns canonical requirements for a fault name. The copy
// prevents a caller from mutating the registry through a scenario parser.
func RequirementsFor(name string) []Requirement {
	f, ok := Lookup(name)
	if !ok {
		return nil
	}
	return append([]Requirement(nil), f.Requires...)
}

// ValidateScenarioRequirements proves that a scenario explicitly declares
// every substrate its selected fault requires. The separate declaration makes
// a scenario portable: its manifest can be refused before target draw or
// injection instead of discovering mid-episode that a backend is absent.
func ValidateScenarioRequirements(names []string, declared []Substrate) error {
	have := map[Substrate]bool{}
	for _, s := range declared {
		if !s.Valid() {
			return fmt.Errorf("unknown substrate requirement %q", s)
		}
		have[s] = true
	}
	var missing []string
	for _, name := range names {
		for _, req := range RequirementsFor(name) {
			if !have[req.Substrate] {
				missing = append(missing, fmt.Sprintf("%s (needed by %s)", req.Substrate, name))
			}
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("scenario does not declare required substrates: %s",
			strings.Join(uniqueSorted(missing), ", "))
	}
	return nil
}

func uniqueSorted(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	// Avoid importing a whole capability package just to sort diagnostic text.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
