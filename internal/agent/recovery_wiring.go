package agent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// rollbackCanKeepWiring proves that a failed no-change transaction did not
// disturb the prior runtime or network namespaces. Exact recovery otherwise
// rewires every link, but doing that for an already intact class lab creates
// needless cross-node netlink work precisely while all nodes are recovering.
func (s *Server) rollbackCanKeepWiring(ctx context.Context, tx applyTransaction,
	top *model.Topology,
) (bool, error) {
	var previous, requested Wire
	if err := json.Unmarshal(tx.Previous, &previous); err != nil {
		return false, err
	}
	if err := json.Unmarshal(tx.Requested, &requested); err != nil {
		return false, err
	}
	if previous.Hash == "" || previous.Hash != requested.Hash ||
		canonicalMode(tx.PreviousMode) != canonicalMode(tx.Mode) ||
		tx.PreviousUngraded != tx.Ungraded {
		return false, nil
	}
	for _, entry := range tx.Prestate.RuntimeSpecs {
		current, err := s.rt.Inspect(ctx, entry.Spec.Name)
		if err != nil || !current.State.Joinable() ||
			current.Label(deploy.LabelSpec) != entry.Spec.Labels[deploy.LabelSpec] {
			return false, nil //nolint:nilerr // uncertainty requires a full rewire, not failed recovery
		}
		// A missing FRR sidecar does not remove a primary namespace interface.
		// Exact rollback restores controls after the optional rewire phase, so
		// do not force an otherwise no-change topology through cross-node
		// netlink just because that later local lifecycle step is pending.
	}
	for _, device := range top.DevicesOnNode(s.cfg.Node) {
		want := map[string]bool{}
		for _, iface := range device.Ifaces {
			if iface.Link != nil || iface.VLAN > 0 {
				want[iface.Name] = true
			}
		}
		if len(want) == 0 {
			continue
		}
		result, err := s.probeExec(ctx, device.Container, rt.ExecCmd{
			Cmd: []string{"sh", "-c", `ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1`},
		})
		if err != nil {
			return false, nil //nolint:nilerr // inability to prove intact wiring selects full rewire
		}
		if result.ExitCode != 0 {
			return false, nil
		}
		have := map[string]bool{}
		for _, name := range strings.Fields(result.Stdout) {
			have[name] = true
		}
		for name := range want {
			if !have[name] {
				return false, nil
			}
		}
	}
	return true, nil
}
