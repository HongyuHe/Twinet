package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// This file is the single source of the semantic health a node publishes.
//
// Status, the read-only plan preflight, and the apply response all answer from
// the same audited observations. They used to disagree: `node status` reported
// a hundred devices with semantic or runtime drift while `deploy` accepted a
// zero-change no-op against the same node in the same second, because the
// deployment path only compared rendered hashes and container labels. A
// deployment that reports success must not be able to contradict the node it
// deployed to.

// noopRefusalReason is why a node must not answer a zero-change witness. It is
// the one place the "no work" and "degraded" answers are reconciled, so a
// deployment cannot report success against health the node itself publishes.
func noopRefusalReason(health SemanticHealth) string {
	degraded := health.Degraded()
	if degraded == 0 {
		return ""
	}
	reason := fmt.Sprintf("%d device(s) have semantic/runtime drift", degraded)
	if drift := health.Drift(); drift != "" {
		reason += ": " + drift
	}
	return reason
}

// auditedDriftError turns an audited drift reason into the error a deployment
// diff understands, so the device is planned for repair rather than reported
// as converged.
func auditedDriftError(reason string) error {
	if reason == "" {
		return nil
	}
	return errors.New(reason)
}

// semanticHealthLocked summarises audited device observations per lab. The
// caller holds s.mu. An empty lab selects every lab this node knows about.
//
// Observations are filtered against the committed topology. A device that has
// been removed from a lab, or moved to another node, leaves its last
// observation behind in the audit map, and publishing that as live drift
// would make every future deployment refuse a no-op it cannot repair.
func semanticHealthLocked(health map[string]deviceObservation, terminal map[string]string,
	current map[string]*model.Topology, node, lab string,
) map[string]SemanticHealth {
	out := map[string]SemanticHealth{}
	for key, observation := range health {
		name, device, _ := strings.Cut(key, "|")
		if lab != "" && name != lab {
			continue
		}
		top := current[name]
		if top == nil {
			continue
		}
		if declared := top.Devices[device]; declared == nil || declared.Node != node {
			continue
		}
		summary := out[name]
		switch observation.Health {
		case healthHealthy:
			summary.Healthy++
		case healthBroken:
			summary.Broken++
		case healthUnknown:
			summary.Unknown++
		case healthPartial:
			summary.Partial++
		}
		reason := observation.Reason
		if why, abandoned := terminal[key]; abandoned {
			summary.Terminal++
			reason = terminalReasonPrefix + why
		}
		if observation.Health != healthHealthy && reason != "" {
			if summary.Reasons == nil {
				summary.Reasons = map[string]string{}
			}
			summary.Reasons[device] = reason
		}
		out[name] = summary
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// convergenceCounts flattens published per-lab health into the node-wide
// classification counts status and metrics report.
func convergenceCounts(health map[string]SemanticHealth) map[string]int {
	out := map[string]int{
		string(healthHealthy): 0, string(healthBroken): 0,
		string(healthUnknown): 0, string(healthPartial): 0,
	}
	for _, summary := range health {
		out[string(healthHealthy)] += summary.Healthy
		out[string(healthBroken)] += summary.Broken
		out[string(healthUnknown)] += summary.Unknown
		out[string(healthPartial)] += summary.Partial
	}
	return out
}

// labSemanticHealth is the authoritative audited health of one lab on this
// node, as published by status.
func (s *Server) labSemanticHealth(lab string) SemanticHealth {
	s.mu.Lock()
	defer s.mu.Unlock()
	return semanticHealthLocked(s.health, s.repairTerminal, s.current, s.cfg.Node, lab)[lab]
}

// auditedDriftReason re-observes a device the audit last saw as drifted.
//
// It is the join between the deployment's desired/observed diff and the
// node's own convergence audit. The diff cannot see a device that lost its
// cables or its routing daemons -- its container labels and rendered file
// hashes are all still correct -- so a lab in exactly that state was reported
// as converged by every deploy while the agent published it as degraded.
//
// Only devices the audit already distrusts are re-observed, so a healthy lab
// pays nothing, and the fresh observation replaces the cached one: a device
// repaired by this very deployment stops being reported as drifted instead of
// blocking the next no-op for ever.
func (s *Server) auditedDriftReason(ctx context.Context, lab string, device *model.Device) string {
	if device == nil {
		return ""
	}
	s.mu.Lock()
	observation, known := s.health[repairKey(lab, device.ID)]
	s.mu.Unlock()
	if !known || observation.Health == healthHealthy {
		return ""
	}
	if s.isExempt(lab, device.ID) {
		return ""
	}
	fresh := s.observeDevice(ctx, lab, device, false)
	s.rememberHealth(lab, device.ID, fresh)
	switch fresh.Health {
	case healthBroken, healthPartial:
		reason := fresh.Reason
		if reason == "" {
			reason = string(fresh.Health)
		}
		return reason
	default:
		return ""
	}
}

// refreshRepairedHealth re-observes the devices a deployment put back together
// after finding their network namespace, or the interfaces in it, replaced.
//
// Those devices have their semantic probe turned off for the pass that repairs
// them: there is no point auditing addressing that the same pass is about to
// replay, and the probe is what would otherwise refresh the cached verdict.
// Without this the deployment that fixed a router answers, and publishes, the
// verdict from before it ran -- so an operator who has just repaired a lab is
// told it is still degraded, with nothing to distinguish that from a repair
// that did not work.
//
// The set is bounded by what actually moved, so a node with two hundred healthy
// routers pays nothing for it.
func (s *Server) refreshRepairedHealth(ctx context.Context, top *model.Topology, ids []string) {
	if top == nil || len(ids) == 0 {
		return
	}
	for _, id := range ids {
		device, ok := top.Device(id)
		if !ok || device.Node != s.cfg.Node {
			continue
		}
		s.rememberHealth(top.Name, device.ID, s.observeDevice(ctx, top.Name, device, false))
	}
}
