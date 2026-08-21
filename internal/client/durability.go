package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
)

// DurabilityOptions supplies the previous committed placement and the sole
// explicit escape hatch for a state migration that cannot prove freshness.
type DurabilityOptions struct {
	Previous        *place.Record
	AllowStaleState bool
	AllowDataLoss   bool
}

// DurabilityReport is surfaced verbatim by the CLI and logged by the
// controller. Audit entries are deliberately conspicuous: a request to accept
// possible data loss must not be indistinguishable from a healthy migration.
type DurabilityReport struct {
	Moved int
	Audit []string
}

type migrationPlan struct {
	proofs map[string][]agent.StateProof
	report DurabilityReport
}

// ApplyDurable executes state migration and deployment under one cluster
// mutation lease. It captures source state freshly, waits for the source
// agent's durable peer quorum, imports it at the destination, verifies restore
// before commit, and only then permits pruning the old placement.
func (c *Cluster) ApplyDurable(ctx context.Context, top *model.Topology,
	req agent.ApplyRequest, options DurabilityOptions,
) ([]NodeResult[agent.ApplyResponse], DurabilityReport) {
	nodes := c.sortedNodes()
	if top == nil || top.Lab == nil {
		return transactionFailure(nodes, nil, errors.New("durable apply needs a topology with a lab")), DurabilityReport{}
	}
	top.Lab.Normalize()
	if err := c.VersionSkew(ctx); err != nil && os.Getenv("TWINET_ALLOW_VERSION_SKEW") == "" {
		return transactionFailure(nodes, nil, err), DurabilityReport{}
	}
	if req.StrictAdmission {
		if err := c.Admit(ctx, top, true, req.Overcommit); err != nil {
			return transactionFailure(nodes, nil, err), DurabilityReport{}
		}
	}
	c.stampImageIDs(ctx, top)
	if req.DryRun || len(nodes) == 0 {
		return c.coordinatedApply(ctx, top, req), DurabilityReport{}
	}

	lease, err := c.AcquireMutationLease(ctx, top.Name)
	if err != nil {
		return transactionFailure(nodes, nil, err), DurabilityReport{}
	}
	defer lease.Release()
	plan, err := c.prepareMigration(lease.Context(), top, lease, options)
	if err != nil {
		return transactionFailure(nodes, nil, err), plan.report
	}
	if plan.report.Moved > 0 {
		if len(req.OnlySteps) > 0 {
			return transactionFailure(nodes, nil, errors.New(
					"refusing a scoped apply that moves state; source pruning requires a complete fenced topology")),
				plan.report
		}
		// A caller must not be able to import and verify state, then forget
		// to remove the old live placement. That would leave two ASes
		// announcing the same prefixes, so movement itself implies prune.
		req.Prune = true
	}
	results := c.coordinatedApplyWithLease(lease.Context(), top, req, lease, plan.proofs)
	for _, audit := range plan.report.Audit {
		slog.Error("AUDIT: durable migration exception", "lab", top.Name, "detail", audit)
	}
	return results, plan.report
}

func (c *Cluster) prepareMigration(ctx context.Context, top *model.Topology,
	lease *MutationLease, options DurabilityOptions,
) (migrationPlan, error) {
	plan := migrationPlan{proofs: map[string][]agent.StateProof{}}
	previous, err := c.runningPlacement(ctx, top, options.Previous)
	if err != nil {
		return plan, err
	}

	from := map[string][]*model.Device{}
	for _, device := range top.SortedDevices() {
		source := previous[device.ID]
		if source == "" || source == device.Node {
			continue
		}
		from[source] = append(from[source], device)
	}
	if len(from) == 0 {
		return plan, nil
	}
	sources := sortedStringKeys(from)
	for _, source := range sources {
		devices := from[source]
		sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
		ids := make([]string, len(devices))
		for i, device := range devices {
			ids[i] = device.ID
		}

		export, fresh, err := c.freshOrReplicaState(ctx, top, source, ids,
			options.AllowStaleState, options.AllowDataLoss, &plan.report)
		if err != nil {
			return plan, err
		}
		if fresh && export.FreshAt.IsZero() {
			return plan, fmt.Errorf("%s returned state without a fresh-capture acknowledgement", source)
		}

		byDestination := map[string][]agent.WireSnapshot{}
		for _, snapshot := range export.Snapshots {
			device, ok := top.Device(snapshot.Device)
			if !ok {
				return plan, fmt.Errorf("%s returned state for unknown device %q", source, snapshot.Device)
			}
			if device.Node == source {
				continue
			}
			byDestination[device.Node] = append(byDestination[device.Node], snapshot)
		}

		// A freshly captured empty student device has no snapshot and therefore
		// no restore proof; it is safe to move as empty. A non-fresh path may
		// only do the same under the explicit audit escape hatch.
		if len(export.Snapshots) == 0 && !fresh && !options.AllowDataLoss {
			return plan, fmt.Errorf("source %s is unavailable and no verified replica exists for %s",
				source, strings.Join(ids, ", "))
		}
		destinations := sortedWireDestinations(byDestination, devices)
		for _, destination := range destinations {
			target := c.node(destination)
			if target == nil {
				return plan, fmt.Errorf("migration destination %q is not an available cluster node", destination)
			}
			fence, ok := lease.Fence(destination)
			if !ok {
				return plan, fmt.Errorf("migration destination %q has no mutation fence", destination)
			}
			snapshots := byDestination[destination]
			records := export.Records
			if len(snapshots) == 0 && len(records) == 0 {
				continue
			}
			response, err := target.ImportStateDetailed(ctx, agent.StateImportRequest{
				Lab: top.Name, Fence: fence, Snapshots: snapshots, Records: records,
			})
			if err != nil {
				return plan, fmt.Errorf("import durable state on %s: %w", destination, err)
			}
			if err := verifyImportAcks(response.Acks, snapshots, records); err != nil {
				return plan, fmt.Errorf("import durable state on %s: %w", destination, err)
			}
			for _, proof := range proofsForDestination(snapshots) {
				plan.proofs[destination] = append(plan.proofs[destination], proof)
			}
		}
		plan.report.Moved += len(devices)
	}
	for destination := range plan.proofs {
		sort.Slice(plan.proofs[destination], func(i, j int) bool {
			return plan.proofs[destination][i].Device < plan.proofs[destination][j].Device
		})
	}
	sort.Strings(plan.report.Audit)
	return plan, nil
}

// runningPlacement reads a persisted placement first and only queries live
// containers for objects absent from it. A record remains useful precisely
// when a source node is gone and cannot answer the container query.
func (c *Cluster) runningPlacement(ctx context.Context, top *model.Topology,
	record *place.Record,
) (map[string]string, error) {
	out := map[string]string{}
	if record != nil {
		for _, device := range top.SortedDevices() {
			if device.ASN != 0 {
				if device.PlacementGroup != "" && record.ByGroup != nil {
					out[device.ID] = record.ByGroup[device.PlacementGroup]
				}
				if out[device.ID] == "" {
					out[device.ID] = record.ByAS[device.ASN]
				}
				continue
			}
			for name, service := range top.Services {
				if service != nil && service.Device == device {
					out[device.ID] = record.ByService[name]
					break
				}
			}
		}
	}
	containers, errs := c.Containers(ctx, top.Name)
	if len(errs) > 0 {
		// A complete record is enough to safely identify missing sources. If
		// it lacks an object, guessing from a partial live survey would be
		// stale-placement substitution, so fail closed.
		for _, device := range top.SortedDevices() {
			if _, ok := out[device.ID]; !ok {
				return nil, fmt.Errorf("could not read running placement from every node and placement record has no %s (%v)",
					device.ID, errs[0])
			}
		}
		return out, nil
	}
	for _, container := range containers {
		id := container.Label(deploy.LabelDeviceID)
		node := container.Label(deploy.LabelNode)
		if id != "" && node != "" {
			out[id] = node
		}
	}
	return out, nil
}

func (c *Cluster) freshOrReplicaState(ctx context.Context, top *model.Topology, source string,
	devices []string, allowStale, allowDataLoss bool, report *DurabilityReport,
) (agent.StateExportResponse, bool, error) {
	if node := c.node(source); node != nil {
		export, err := node.ExportState(ctx, top.Name, devices)
		if err == nil {
			return export, true, nil
		}
		// If the source still answers status, the error is a failed fresh
		// capture, not a node loss. Never silently replace it with an older
		// replica: that is the stale-snapshot migration bug this protocol fixes.
		if _, statusErr := node.Status(ctx); statusErr == nil && !stateSourceUnavailable(err) {
			if !allowStale && !allowDataLoss {
				return agent.StateExportResponse{}, false, fmt.Errorf(
					"fresh capture on source %s failed: %w; refusing to substitute stale state",
					source, err)
			}
			stored, storedErr := node.ExportStoredState(ctx, top.Name, devices)
			if storedErr == nil {
				flag := "--allow-stale-state"
				if !allowStale {
					flag = "--allow-data-loss"
				}
				report.Audit = append(report.Audit, fmt.Sprintf(
					"%s accepted stored state from reachable source %s after fresh capture failed: %v",
					flag, source, err))
				return stored, false, nil
			}
		}
	}

	replica, err := c.findReplicaState(ctx, top.Name, source, devices)
	if err == nil {
		report.Audit = append(report.Audit, fmt.Sprintf(
			"source %s is unavailable; restoring verified replica state from a surviving node", source))
		return replica, false, nil
	}
	if allowDataLoss {
		report.Audit = append(report.Audit, fmt.Sprintf(
			"--allow-data-loss accepted migration from %s without verified state: %v", source, err))
		return agent.StateExportResponse{Lab: top.Name}, false, nil
	}
	return agent.StateExportResponse{}, false, fmt.Errorf(
		"source %s is unavailable and no verified replica can be located: %w", source, err)
}

// stateSourceUnavailable separates a live source whose container could not be
// freshly captured (fail closed) from a live agent whose state disk/store is
// gone (recover from a surviving verified replica). Node.do preserves the HTTP
// status in its error text, so this remains compatible with older agents.
func stateSourceUnavailable(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "503") ||
		strings.Contains(message, "service unavailable") ||
		strings.Contains(message, "no state store") ||
		strings.Contains(message, "state store is unavailable")
}

func (c *Cluster) findReplicaState(ctx context.Context, lab, source string,
	devices []string,
) (agent.StateExportResponse, error) {
	var exports []agent.StateExportResponse
	var problems []string
	for _, node := range c.sortedNodes() {
		if node.Name == source {
			continue
		}
		export, err := node.ExportStoredState(ctx, lab, devices)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", node.Name, err))
			continue
		}
		if len(export.Snapshots) > 0 || len(export.Records) > 0 {
			exports = append(exports, export)
		}
	}
	if len(exports) == 0 {
		sort.Strings(problems)
		return agent.StateExportResponse{}, fmt.Errorf("no surviving replica responded (%s)", strings.Join(problems, "; "))
	}
	combined := agent.StateExportResponse{Lab: lab}
	snapshots := map[string]agent.WireSnapshot{}
	records := map[string]agent.WireRecord{}
	for _, export := range exports {
		for _, snapshot := range export.Snapshots {
			key := snapshot.Device + "/" + string(snapshot.Kind)
			if old, ok := snapshots[key]; ok {
				if old.Digest != snapshot.Digest && old.TakenAt.Equal(snapshot.TakenAt) {
					return agent.StateExportResponse{}, fmt.Errorf("replicas disagree about current %s at %s",
						key, snapshot.TakenAt.UTC().Format(time.RFC3339Nano))
				}
				if !snapshot.TakenAt.After(old.TakenAt) {
					continue
				}
			}
			snapshots[key] = snapshot
		}
		for _, record := range export.Records {
			key := string(record.Kind)
			if old, ok := records[key]; ok {
				if old.Digest != record.Digest && old.TakenAt.Equal(record.TakenAt) {
					return agent.StateExportResponse{}, fmt.Errorf("replicas disagree about current %s record", key)
				}
				if !record.TakenAt.After(old.TakenAt) {
					continue
				}
			}
			records[key] = record
		}
	}
	for _, key := range sortedStringKeys(snapshots) {
		combined.Snapshots = append(combined.Snapshots, snapshots[key])
	}
	for _, key := range sortedStringKeys(records) {
		combined.Records = append(combined.Records, records[key])
	}
	return combined, nil
}

func sortedWireDestinations(byDestination map[string][]agent.WireSnapshot,
	devices []*model.Device,
) []string {
	seen := map[string]bool{}
	for destination := range byDestination {
		seen[destination] = true
	}
	// Copying durable records to a destination with an empty student device is
	// still needed for mode/topology repair, and gives that device a valid
	// transaction path even though it has no restore proof.
	for _, device := range devices {
		seen[device.Node] = true
	}
	return sortedStringKeys(seen)
}

func proofsForDestination(snapshots []agent.WireSnapshot) []agent.StateProof {
	byDevice := map[string][]agent.WireSnapshot{}
	for _, snapshot := range snapshots {
		byDevice[snapshot.Device] = append(byDevice[snapshot.Device], snapshot)
	}
	var out []agent.StateProof
	for _, device := range sortedStringKeys(byDevice) {
		snaps := byDevice[device]
		sort.Slice(snaps, func(i, j int) bool { return snaps[i].Kind < snaps[j].Kind })
		out = append(out, agent.StateProof{Device: device, Snapshots: snaps})
	}
	return out
}

func verifyImportAcks(acks []agent.StateAck, snapshots []agent.WireSnapshot, records []agent.WireRecord) error {
	got := map[string]string{}
	for _, ack := range acks {
		got[ack.Key] = ack.Digest
	}
	for _, snapshot := range snapshots {
		key := "snapshot/" + snapshot.Device + "/" + string(snapshot.Kind)
		if got[key] != snapshot.Digest {
			return fmt.Errorf("destination did not acknowledge %s digest %s", key, snapshot.Digest)
		}
	}
	for _, record := range records {
		key := "record/" + string(record.Kind)
		if got[key] != record.Digest {
			return fmt.Errorf("destination did not acknowledge %s digest %s", key, record.Digest)
		}
	}
	return nil
}

func sortedStringKeys[V any](values map[string]V) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
