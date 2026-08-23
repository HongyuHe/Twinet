package agent

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	"github.com/HongyuHe/twinet/internal/nos"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// verifyCommittedSemantics is the proof boundary that inventory alone cannot
// provide. A joinable container with the right labels can still be an empty
// host namespace, a router with no usable configuration, or a service with
// stale files. Commit therefore verifies exact rendered artifacts and local
// network semantics for every touched device. Distributed BGP reachability is
// asynchronous and belongs to the controller's post-commit convergence gate.
func (s *Server) verifyCommittedSemantics(ctx context.Context, top *model.Topology,
	mode render.Mode, ungraded int, touched []string,
) error {
	return s.verifyTopologySemantics(ctx, top, mode, ungraded, touched, nil)
}

func (s *Server) verifyKnownStudentState(ctx context.Context, top *model.Topology,
	previousMode render.Mode, previousUngraded int, desiredMode render.Mode, desiredUngraded int,
) error {
	// Snapshot replay is a solve->platform operation only. A solve no-change
	// transaction must never enter this path: doing so would treat a reference
	// lab as if it had transitioned back to teaching and restore stale work.
	if s.store == nil || previousMode != render.ModeSolve || desiredMode == render.ModeSolve {
		return nil
	}
	for _, device := range top.DevicesOnNode(s.cfg.Node) {
		// Only devices that were reference-owned before the transition need
		// a reset/restore proof. The ungraded harness AS was already teaching
		// mode and must not be treated as a reference answer.
		if renderModeForDevice(previousMode, previousUngraded, device) != render.ModeSolve ||
			renderModeForDevice(desiredMode, desiredUngraded, device) == render.ModeSolve ||
			!deployStudentOwned(top, device) {
			continue
		}
		var expected []state.Snapshot
		for _, kind := range state.AllKinds {
			snapshot, err := s.store.Current(top.Name, device.ID, kind)
			if err == nil {
				expected = append(expected, snapshot)
			}
		}
		if len(expected) == 0 {
			continue // intentional blank student start
		}
		if _, err := verifyRestoredState(ctx, s.rt, device, top.Name, top.Hash, expected); err != nil {
			return fmt.Errorf("verify restored solve->platform student state for %s: %w", device.ID, err)
		}
	}
	return nil
}

func semanticTouchedDevices(tx applyTransaction) []string {
	seen := map[string]bool{}
	for _, id := range tx.Touched {
		seen[id] = true
	}
	for _, id := range tx.DirtyCapture {
		seen[id] = true
	}
	for _, id := range tx.Semantic {
		seen[id] = true
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// semanticCommitDevices expands a mode/harness transition to the entire local
// lab. Mode is not represented by an OCI spec hash: a host that was not
// otherwise dirty can still be missing its solve/reference address or retain
// an answer while returning to teaching mode.
func semanticCommitDevices(top *model.Topology, node string, tx applyTransaction, desired render.Mode) []string {
	seen := map[string]bool{}
	for _, id := range semanticTouchedDevices(tx) {
		seen[id] = true
	}
	modeChanged := canonicalMode(tx.PreviousMode) != canonicalMode(string(desired)) ||
		tx.PreviousUngraded != tx.Ungraded
	if modeChanged && top != nil {
		for _, device := range top.DevicesOnNode(node) {
			seen[device.ID] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// verifyRecoveredSemantics validates a rollback against the persisted
// pre-transaction artifacts. Unlike the desired forward path, these bytes are
// the exact historic renderer contract and must not be reinterpreted through a
// newer build.
func (s *Server) verifyRecoveredSemantics(ctx context.Context, top *model.Topology,
	mode render.Mode, ungraded int, specs []transactionRuntimeSpec,
) error {
	artifacts := make(map[string][]transactionArtifact, len(specs))
	ids := make([]string, 0, len(specs))
	for _, spec := range specs {
		artifacts[spec.DeviceID] = append([]transactionArtifact(nil), spec.Artifacts...)
		ids = append(ids, spec.DeviceID)
	}
	if len(ids) == 0 {
		// Legacy transactions lack exact per-device contracts, but recovery
		// may still not declare an inventory-only success. Render the whole
		// recovered local topology and verify its observable semantics.
		for _, device := range top.DevicesOnNode(s.cfg.Node) {
			ids = append(ids, device.ID)
		}
	}
	// Rollback is a local durability boundary. Exact artifacts, local
	// addresses/routes, and daemon readiness must be restored before commit;
	// remote BGP convergence is asynchronous and cannot safely hold a
	// transaction open or turn one temporarily Active peer into a permanent
	// rollback failure.
	return s.verifyTopologyRecoveryContracts(ctx, top, mode, ungraded, ids, artifacts)
}

func (s *Server) verifyTopologySemantics(ctx context.Context, top *model.Topology,
	mode render.Mode, ungraded int, ids []string, artifacts map[string][]transactionArtifact,
) error {
	return s.verifyTopologyChecks(ctx, top, mode, ungraded, ids, artifacts, true)
}

func (s *Server) verifyTopologyRecoveryContracts(ctx context.Context, top *model.Topology,
	mode render.Mode, ungraded int, ids []string, artifacts map[string][]transactionArtifact,
) error {
	return s.verifyTopologyChecks(ctx, top, mode, ungraded, ids, artifacts, false)
}

func (s *Server) verifyTopologyChecks(ctx context.Context, top *model.Topology,
	mode render.Mode, ungraded int, ids []string, artifacts map[string][]transactionArtifact,
	repairSolve bool,
) error {
	if top == nil {
		return fmt.Errorf("semantic verification needs a topology")
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	if len(want) == 0 {
		return nil
	}
	r := renderer(top, mode, ungraded)
	var devices []*model.Device
	for _, device := range top.DevicesOnNode(s.cfg.Node) {
		if !want[device.ID] {
			continue
		}
		devices = append(devices, device)
	}
	workers := s.recoveryWorkerCount()
	if repairSolve {
		// Normal commit follows a successful apply and has the full exec
		// pressure budget available. Reusing the conservative eight-worker
		// rollback pool serialized thousands of already-ready device proofs.
		workers = s.semanticWorkerCount()
	}
	return runBoundedDeviceChecks(ctx, workers,
		devices, s.recoveryArtifactLimit(),
		func(device *model.Device) string { return "semantic verification " + device.ID },
		func(verifyCtx context.Context, device *model.Device) error {
			if s.isExempt(top.Name, device.ID) {
				return nil
			}
			expected := artifacts[device.ID]
			if expected == nil {
				var err error
				expected, err = renderedSemanticArtifacts(r, device)
				if err != nil {
					return fmt.Errorf("render semantic artifacts for %s: %w", device.ID, err)
				}
			}
			deviceMode := renderModeForDevice(mode, ungraded, device)
			verify := func() error {
				if err := s.verifyRenderedArtifacts(verifyCtx, top, device, deviceMode, expected); err != nil {
					return err
				}
				// Commit proves only local contracts. Cross-node BGP routes
				// form after every node commits and are proven by the
				// controller's convergence-aware grade gate.
				if err := s.verifyNetworkSemantics(verifyCtx, top, device, deviceMode); err != nil {
					return err
				}
				if waiter := r.Ready(device, s.rt); waiter != nil {
					ready, err := waiter.Check(verifyCtx)
					if err != nil {
						return fmt.Errorf("semantic readiness of %s: %w", device.ID, err)
					}
					if !ready {
						return fmt.Errorf("semantic readiness of %s is false", device.ID)
					}
				}
				return nil
			}
			firstErr := verify()
			if firstErr == nil || !repairSolve || deviceMode != render.ModeSolve {
				return firstErr
			}
			repair := &deploy.Engine{
				Runtime: s.rt, Node: s.cfg.Node, State: s.store, Limiter: s.workLimiter(),
				Renderer: r, Authoritative: true, WritesReference: true,
				UnderlayIP: s.cfg.UnderlayIP, UnderlayDev: s.cfg.UnderlayDev,
				PeerUnderlay: s.peerUnderlay(top.Name),
			}
			if err := repair.ReconfigureDevice(verifyCtx, device); err != nil {
				return fmt.Errorf("%w; solved-reference reconfiguration also failed: %v", firstErr, err)
			}
			if err := verify(); err != nil {
				return fmt.Errorf("%w; solved-reference reconfiguration did not repair it: %v",
					firstErr, err)
			}
			return nil
		})
}

func renderedSemanticArtifacts(r *render.Renderer, device *model.Device) ([]transactionArtifact, error) {
	files, err := r.Files(device)
	if err != nil {
		return nil, err
	}
	commands, err := r.Commands(device)
	if err != nil {
		return nil, err
	}
	var out []transactionArtifact
	for _, path := range sortedStringMapKeys(files) {
		file := files[path]
		out = append(out, transactionArtifact{
			Path: path, Content: append([]byte(nil), file.Content...), Mode: file.Mode,
			Digest: artifactDigest(file.Content),
		})
	}
	for i := range commands {
		command := commands[i]
		out = append(out, transactionArtifact{
			Path: fmt.Sprintf("command/%04d", i), Command: &command,
		})
	}
	return out, nil
}

func (s *Server) verifyRenderedArtifacts(ctx context.Context, top *model.Topology,
	device *model.Device, mode render.Mode, artifacts []transactionArtifact,
) error {
	for _, artifact := range artifacts {
		if artifact.Command != nil || skipMutableArtifact(top, device, mode, artifact.Path) {
			continue
		}
		if artifact.Digest != artifactDigest(artifact.Content) {
			return fmt.Errorf("persisted artifact %s for %s has an invalid digest", artifact.Path, device.ID)
		}
		result, err := s.probeExec(ctx, device.Container, rt.ExecCmd{Cmd: []string{"cat", artifact.Path}})
		if err != nil {
			return fmt.Errorf("read rendered artifact %s on %s: %w", artifact.Path, device.ID, err)
		}
		if result.ExitCode != 0 {
			return fmt.Errorf("read rendered artifact %s on %s exited %d", artifact.Path, device.ID, result.ExitCode)
		}
		if artifactDigest([]byte(result.Stdout)) != artifact.Digest {
			return fmt.Errorf("rendered artifact %s on %s does not match its persisted digest",
				artifact.Path, device.ID)
		}
	}
	return nil
}

func skipMutableArtifact(top *model.Topology, device *model.Device, mode render.Mode, path string) bool {
	if mode == render.ModeSolve || !deployStudentOwned(top, device) || device.Kind != model.KindRouter {
		return false
	}
	// These are deliberately student-owned in teaching mode. Exact artifact
	// comparison here would reject the configuration preservation O7 exists
	// to protect; readiness and platform-owned interface semantics are still
	// checked below.
	return path == "/etc/frr/frr.conf" || path == "/etc/bird/bird.conf"
}

func (s *Server) verifyNetworkSemantics(ctx context.Context, top *model.Topology,
	device *model.Device, mode render.Mode,
) error {
	if err := s.verifyExpectedAddresses(ctx, device, mode); err != nil {
		return err
	}

	if err := s.verifyExpectedDefaultRoute(ctx, top, device, mode); err != nil {
		return err
	}
	if device.Kind == model.KindSwitch {
		if err := s.verifySwitchSemantics(ctx, device, mode); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) semanticProbe(ctx context.Context, top *model.Topology,
	mode render.Mode, ungraded int, device *model.Device,
) error {
	deviceMode := renderModeForDevice(mode, ungraded, device)
	if err := s.verifyNetworkSemantics(ctx, top, device, deviceMode); err != nil {
		return err
	}
	if deviceMode != render.ModeSolve || s.labHasExemptions(top.Name) {
		return nil
	}
	requirements, err := semanticHealthRequirements(top, device)
	if err != nil {
		return err
	}
	// Reference peering forms concurrently with the rest of a harness. It is
	// verified by the harness convergence and grading witnesses after commit;
	// holding a fenced deployment open for it produces a rollback loop before
	// the remote side has even finished its own transaction.
	if requirements.BGPControl && verifyReferenceBGPAtCommit(ungraded) {
		if err := s.verifyReferenceBGPControl(ctx, device); err != nil {
			return err
		}
	}
	// A harness leaves one target AS in platform mode. Its surrounding
	// reference ASes are configured correctly, but their remote BGP routes
	// converge asynchronously after the transaction commits. Requiring every
	// reference router to forward to every remote host while the transaction
	// is still open turns a correct private harness into a rollback loop.
	// Grade convergence and delivery checks remain the witness for that
	// asynchronous path; ordinary solved labs retain this deployment check.
	if requirements.Forwarding && verifyReferenceForwardingAtCommit(ungraded) {
		if err := s.verifyReferenceReachability(ctx, top, device); err != nil {
			return err
		}
	}
	return nil
}

func verifyReferenceForwardingAtCommit(ungraded int) bool {
	return ungraded == 0
}

func verifyReferenceBGPAtCommit(ungraded int) bool {
	return ungraded == 0
}

type semanticHealthPlan struct {
	Forwarding bool
	BGPControl bool
}

// semanticHealthRequirements combines the topology's declared operational
// role with the selected NOS implementation. An IXP route server therefore
// proves its BGP control plane and RIB but is never treated as a transit
// router merely because it happens to run FRR or BIRD.
func semanticHealthRequirements(top *model.Topology, device *model.Device) (semanticHealthPlan, error) {
	declared := top.SemanticHealthCapabilities(device)
	if !declared.Forwarding && !declared.BGPControl {
		return semanticHealthPlan{}, nil
	}
	provider, err := nos.Resolve(device)
	if err != nil {
		return semanticHealthPlan{}, err
	}
	caps := provider.Capabilities()
	if declared.Forwarding && !caps.Supports(nos.FeatureForwarding) {
		return semanticHealthPlan{}, fmt.Errorf("%s uses NOS %q without forwarding capability",
			device.ID, provider.Name())
	}
	if declared.BGPControl && !caps.Supports(nos.FeatureBGP) {
		return semanticHealthPlan{}, fmt.Errorf("%s uses NOS %q without BGP control capability",
			device.ID, provider.Name())
	}
	return semanticHealthPlan{
		Forwarding: declared.Forwarding && caps.Supports(nos.FeatureForwarding),
		BGPControl: declared.BGPControl && caps.Supports(nos.FeatureBGP),
	}, nil
}

func (s *Server) labHasExemptions(lab string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ex := s.exempt[lab]
	return ex != nil && len(ex.Devices) > 0
}

// verifyReferenceReachability checks one representative host address from
// every other AS in a single namespace exec. BGP sessions alone can be
// Established while a leaked/missing prefix leaves forwarding "Network
// unreachable"; this catches the AS3-to-AS5/AS10 failure without issuing one
// controller probe per destination.
func (s *Server) verifyReferenceReachability(ctx context.Context, top *model.Topology, device *model.Device) error {
	targets := referenceReachabilityTargets(top, device.ASN)
	if len(targets) == 0 {
		return nil
	}
	script := "failed=''; "
	for _, target := range targets {
		script += "ip route get " + target + " >/dev/null 2>&1 || failed=\"$failed " + target + "\"; "
	}
	script += `printf '%s\n' "$failed"`
	result, err := s.probeExec(ctx, device.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", script}})
	if err != nil {
		return fmt.Errorf("probe reference forwarding from %s: %w", device.ID, err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("probe reference forwarding from %s exited %d", device.ID, result.ExitCode)
	}
	if missing := strings.Fields(result.Stdout); len(missing) > 0 {
		return fmt.Errorf("%s has no route to reference host address(es) %s",
			device.ID, strings.Join(missing, ", "))
	}
	return nil
}

func referenceReachabilityTargets(top *model.Topology, sourceASN int) []string {
	if top == nil {
		return nil
	}
	var targets []string
	for _, asn := range top.SortedASNs() {
		if asn == sourceASN {
			continue
		}
		as := top.ASes[asn]
		if as == nil {
			continue
		}
		found := ""
		for _, device := range as.Devices {
			if device.Kind != model.KindHost {
				continue
			}
			for _, iface := range device.Ifaces {
				if iface.Addr4 == "" {
					continue
				}
				candidate := cidrAddress(iface.Addr4)
				if candidate != "" && !strings.HasPrefix(candidate, "127.") {
					found = candidate
					break
				}
			}
			if found != "" {
				break
			}
		}
		if found != "" {
			targets = append(targets, found)
		}
	}
	sort.Strings(targets)
	return targets
}

func referenceBGPPeers(device *model.Device) []string {
	var peers []string
	for _, iface := range device.Ifaces {
		if iface.Peer == nil || iface.Peer.Device == nil || iface.Peer.Device.Kind != model.KindRouter ||
			iface.Peer.Addr4 == "" {
			continue
		}
		switch iface.Role {
		case model.RoleInterAS, model.RoleIXPLink:
			peers = append(peers, cidrAddress(iface.Peer.Addr4))
		}
	}
	if len(peers) == 0 {
		return nil
	}
	sort.Strings(peers)
	return peers
}

// verifyReferenceBGPControl reads normalized NOS state rather than assuming
// FRR's vtysh spelling. It checks the declared sessions and requires a
// non-empty BGP RIB, which is meaningful for both a transit router and an IXP
// route server without asking the latter to forward packets to every host.
func (s *Server) verifyReferenceBGPControl(ctx context.Context, device *model.Device) error {
	peers := referenceBGPPeers(device)
	if len(peers) == 0 {
		return nil
	}
	provider, err := nos.Resolve(device)
	if err != nil {
		return err
	}
	if err := nos.ValidateStateQuery(provider, device.ID, netstate.QueryBGP); err != nil {
		return err
	}
	exec := netstate.ExecFunc(func(execCtx context.Context, deviceID string, command []string) (rt.ExecResult, error) {
		if deviceID != device.ID {
			return rt.ExecResult{}, fmt.Errorf("state query for %s was sent to %s", deviceID, device.ID)
		}
		container := device.Container
		if device.EffectiveNOS() == model.DefaultNOS {
			container = s.frrContainer(execCtx, device)
		}
		return s.probeExec(execCtx, container, rt.ExecCmd{Cmd: command})
	})
	state, err := provider.ReadState(ctx, device, exec, netstate.QueryBGP)
	if err != nil {
		return fmt.Errorf("read BGP state of %s: %w", device.ID, err)
	}
	for _, peer := range peers {
		found := ""
		for _, session := range state.BGP.Sessions {
			if session.Neighbor == peer {
				found = session.State
				break
			}
		}
		if !strings.EqualFold(found, "Established") {
			return fmt.Errorf("%s BGP session to %s is %q, want Established", device.ID, peer, found)
		}
	}
	if len(state.BGP.Paths) == 0 {
		return fmt.Errorf("%s has established BGP session(s) but no BGP RIB paths", device.ID)
	}
	return nil
}

func bgpPeerState(value any, peer string) string {
	switch current := value.(type) {
	case map[string]any:
		if child, ok := current[peer]; ok {
			if fields, ok := child.(map[string]any); ok {
				for _, key := range []string{"state", "bgpState", "connectionState"} {
					if state, ok := fields[key].(string); ok {
						return state
					}
				}
			}
		}
		for _, child := range current {
			if state := bgpPeerState(child, peer); state != "" {
				return state
			}
		}
	case []any:
		for _, child := range current {
			if state := bgpPeerState(child, peer); state != "" {
				return state
			}
		}
	}
	return ""
}

func (s *Server) verifyExpectedAddresses(ctx context.Context, device *model.Device, mode render.Mode) error {
	expected := map[string]map[string]bool{}
	for _, iface := range device.Ifaces {
		if iface.Owner != model.OwnerPlatform && mode != render.ModeSolve {
			continue
		}
		for _, address := range []string{iface.Addr4, iface.Addr6} {
			if address == "" {
				continue
			}
			if expected[iface.Name] == nil {
				expected[iface.Name] = map[string]bool{}
			}
			expected[iface.Name][address] = true
		}
	}
	if len(expected) == 0 {
		return nil
	}
	result, err := s.probeExec(ctx, device.Container, rt.ExecCmd{Cmd: []string{"ip", "-o", "addr", "show"}})
	if err != nil {
		return fmt.Errorf("read addresses of %s: %w", device.ID, err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("read addresses of %s exited %d", device.ID, result.ExitCode)
	}
	have := parseInterfaceAddresses(result.Stdout)
	for iface, addresses := range expected {
		for address := range addresses {
			if !have[iface][address] {
				return fmt.Errorf("%s is missing expected address %s on %s", device.ID, address, iface)
			}
		}
	}
	return nil
}

func parseInterfaceAddresses(raw string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 {
			continue
		}
		iface := strings.TrimSuffix(fields[1], ":")
		iface, _, _ = strings.Cut(iface, "@")
		for i := 2; i+1 < len(fields); i++ {
			if fields[i] != "inet" && fields[i] != "inet6" {
				continue
			}
			if out[iface] == nil {
				out[iface] = map[string]bool{}
			}
			out[iface][fields[i+1]] = true
		}
	}
	return out
}

func (s *Server) verifyExpectedDefaultRoute(ctx context.Context, top *model.Topology,
	device *model.Device, mode render.Mode,
) error {
	gateway4, gateway6, dev := expectedDefaultGateway(top, device, mode)
	if gateway4 == "" && gateway6 == "" {
		return nil
	}
	if gateway4 != "" {
		result, err := s.probeExec(ctx, device.Container, rt.ExecCmd{Cmd: []string{"ip", "-o", "route", "show"}})
		if err != nil {
			return fmt.Errorf("read IPv4 routes of %s: %w", device.ID, err)
		}
		if result.ExitCode != 0 || !hasDefaultRoute(result.Stdout, gateway4, dev) {
			return fmt.Errorf("%s is missing expected IPv4 default route via %s", device.ID, gateway4)
		}
	}
	if gateway6 != "" {
		result, err := s.probeExec(ctx, device.Container, rt.ExecCmd{Cmd: []string{"ip", "-o", "-6", "route", "show"}})
		if err != nil {
			return fmt.Errorf("read IPv6 routes of %s: %w", device.ID, err)
		}
		if result.ExitCode != 0 || !hasDefaultRoute(result.Stdout, gateway6, dev) {
			return fmt.Errorf("%s is missing expected IPv6 default route via %s", device.ID, gateway6)
		}
	}
	return nil
}

func expectedDefaultGateway(top *model.Topology, device *model.Device, mode render.Mode) (string, string, string) {
	if device.Kind != model.KindHost && device.Kind != model.KindService && device.Kind != model.KindController {
		return "", "", ""
	}
	if mode != render.ModeSolve && device.Kind != model.KindService {
		return "", "", ""
	}
	if device.L2Domain != "" && mode == render.ModeSolve {
		vlan := 0
		for _, iface := range device.Ifaces {
			if iface.VLAN > 0 {
				vlan = iface.VLAN
			}
		}
		if as := top.ASes[device.ASN]; as != nil {
			for _, router := range as.Routers {
				if router.L2Gateway != device.L2Domain {
					continue
				}
				for _, iface := range router.Ifaces {
					if iface.Role == model.RoleL2SubIface && iface.VLAN == vlan {
						return cidrAddress(iface.Addr4), cidrAddress(iface.Addr6), ""
					}
				}
			}
		}
	}
	for _, iface := range device.Ifaces {
		if iface.Peer == nil || iface.Peer.Addr4 == "" {
			continue
		}
		if iface.Role == model.RoleHostLink || iface.Role == model.RoleService {
			return cidrAddress(iface.Peer.Addr4), cidrAddress(iface.Peer.Addr6), iface.Name
		}
	}
	return "", "", ""
}

func cidrAddress(cidr string) string {
	if before, _, ok := strings.Cut(cidr, "/"); ok {
		return before
	}
	return cidr
}

func hasDefaultRoute(raw, gateway, dev string) bool {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 || fields[0] != "default" {
			continue
		}
		foundGateway, foundDev := false, dev == ""
		for i := range fields {
			if fields[i] == "via" && i+1 < len(fields) && fields[i+1] == gateway {
				foundGateway = true
			}
			if fields[i] == "dev" && i+1 < len(fields) && fields[i+1] == dev {
				foundDev = true
			}
		}
		if foundGateway && foundDev {
			return true
		}
	}
	return false
}

func (s *Server) verifySwitchSemantics(ctx context.Context, device *model.Device, mode render.Mode) error {
	result, err := s.probeExec(ctx, device.Container, rt.ExecCmd{Cmd: []string{"ovs-vsctl", "list-br"}})
	if err != nil {
		return fmt.Errorf("read OVS bridges of %s: %w", device.ID, err)
	}
	if result.ExitCode != 0 || strings.TrimSpace(result.Stdout) == "" {
		return fmt.Errorf("%s has no usable OVS bridge", device.ID)
	}
	for _, iface := range device.Ifaces {
		if iface.Owner != model.OwnerPlatform && mode != render.ModeSolve {
			continue
		}
		if iface.VLAN <= 0 && !iface.Trunk {
			continue
		}
		if iface.VLAN > 0 {
			tag, err := s.probeExec(ctx, device.Container,
				rt.ExecCmd{Cmd: []string{"ovs-vsctl", "get", "port", iface.Name, "tag"}})
			if err != nil || tag.ExitCode != 0 || strings.Trim(strings.TrimSpace(tag.Stdout), "\"") != strconv.Itoa(iface.VLAN) {
				return fmt.Errorf("%s VLAN port %s is not tagged %d", device.ID, iface.Name, iface.VLAN)
			}
		}
		if iface.Trunk {
			trunks, err := s.probeExec(ctx, device.Container,
				rt.ExecCmd{Cmd: []string{"ovs-vsctl", "get", "port", iface.Name, "trunks"}})
			if err != nil || trunks.ExitCode != 0 {
				return fmt.Errorf("%s cannot read trunk state of %s", device.ID, iface.Name)
			}
			for _, vlan := range device.VLANs {
				if !strings.Contains(trunks.Stdout, strconv.Itoa(vlan)) {
					return fmt.Errorf("%s trunk %s is missing VLAN %d", device.ID, iface.Name, vlan)
				}
			}
		}
	}
	return nil
}

// semanticReason is deliberately narrow enough for sampled repair. It detects
// a host whose wires survived but whose expected addresses/default route did
// not, while leaving a teaching-mode student interface intentionally blank.
func (s *Server) semanticReason(ctx context.Context, lab string, device *model.Device) string {
	s.mu.Lock()
	top := s.current[lab]
	mode := render.Mode(s.modes[lab])
	ungraded := s.ungraded[lab]
	s.mu.Unlock()
	if top == nil {
		return ""
	}
	if err := s.semanticProbe(ctx, top, mode, ungraded, device); err != nil {
		return err.Error()
	}
	return ""
}
