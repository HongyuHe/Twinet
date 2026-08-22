package agent

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// verifyCommittedSemantics is the proof boundary that inventory alone cannot
// provide. A joinable container with the right labels can still be an empty
// host namespace, a router with no usable configuration, or a service with
// stale files. Commit therefore verifies the exact rendered artifacts and the
// observable network semantics for every device the transaction touched.
func (s *Server) verifyCommittedSemantics(ctx context.Context, top *model.Topology,
	mode render.Mode, ungraded int, touched []string,
) error {
	return s.verifyTopologySemantics(ctx, top, mode, ungraded, touched, nil)
}

func semanticTouchedDevices(tx applyTransaction) []string {
	seen := map[string]bool{}
	for _, id := range tx.Touched {
		seen[id] = true
	}
	for _, id := range tx.DirtyCapture {
		seen[id] = true
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
	return s.verifyTopologySemantics(ctx, top, mode, ungraded, ids, artifacts)
}

func (s *Server) verifyTopologySemantics(ctx context.Context, top *model.Topology,
	mode render.Mode, ungraded int, ids []string, artifacts map[string][]transactionArtifact,
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
	for _, device := range top.DevicesOnNode(s.cfg.Node) {
		if !want[device.ID] {
			continue
		}
		expected := artifacts[device.ID]
		if expected == nil {
			var err error
			expected, err = renderedSemanticArtifacts(r, device)
			if err != nil {
				return fmt.Errorf("render semantic artifacts for %s: %w", device.ID, err)
			}
		}
		if err := s.verifyRenderedArtifacts(ctx, top, device,
			renderModeForDevice(mode, ungraded, device), expected); err != nil {
			return err
		}
		if err := s.verifyNetworkSemantics(ctx, top, device,
			renderModeForDevice(mode, ungraded, device)); err != nil {
			return err
		}
		if waiter := r.Ready(device, s.rt); waiter != nil {
			ready, err := waiter.Check(ctx)
			if err != nil {
				return fmt.Errorf("semantic readiness of %s: %w", device.ID, err)
			}
			if !ready {
				return fmt.Errorf("semantic readiness of %s is false", device.ID)
			}
		}
	}
	return nil
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
	if err := s.verifyNetworkSemantics(ctx, top, device, renderModeForDevice(mode, ungraded, device)); err != nil {
		return err.Error()
	}
	return ""
}
