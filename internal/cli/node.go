package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/alloc"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/contract"
	"github.com/HongyuHe/twinet/internal/limiter"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
	"github.com/HongyuHe/twinet/internal/runtime"
)

// tokenFor resolves the shared secret the control plane presents to agents.
func tokenFor(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if v := os.Getenv("TWINET_TOKEN"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no agent token: set TWINET_TOKEN from a protected credential file")
}

// clustered reports whether the lab should be driven through node agents.
//
// A single-node lab is driven directly by the CLI: requiring an agent to run a
// lab on your laptop would be pointless ceremony. The moment a lab names more
// than one node, agents are the only way to reach the other machines.
func clustered(top *model.Topology) bool {
	if top.Lab.Placement.Strategy == "single-node" {
		return false
	}
	return len(top.Lab.Placement.Nodes) > 1
}

func newNodeCmd(opts *Options) *cobra.Command {
	var (
		token              string
		bootstrapPKI       string
		bootstrapTokenFile string
	)
	cmd := &cobra.Command{
		Use:   "node",
		Short: "Inspect and manage the cluster's node agents",
	}
	cmd.PersistentFlags().StringVar(&token, "token", "", "agent token (or set TWINET_TOKEN)")

	status := &cobra.Command{
		Use:   "status",
		Short: "Show every node agent's health and capacity",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			tok, err := tokenFor(token)
			if err != nil {
				return err
			}
			c := client.NewCluster(top.Lab, tok)
			results := c.Status(cmd.Context())

			// --json is a global flag, and this command took it and printed a
			// table anyway. A flag that is accepted and ignored is worse than
			// one that is rejected: whatever was parsing the output got a table
			// and no error.
			if opts.JSON {
				out := make([]map[string]any, 0, len(results))
				for _, r := range results {
					row := map[string]any{"node": r.Node}
					if r.Err != nil {
						row["error"] = r.Err.Error()
					} else {
						row["status"] = r.Value
					}
					out = append(out, row)
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
			}

			// "ok" used to mean "answered", and nothing else.
			//
			// A cluster whose agents were a build behind the controller -- which
			// makes them render different configuration from the same manifest
			// -- reported every node ok, in the one command an operator runs to
			// ask whether the cluster is healthy. So did a cluster with a
			// grading hold on it, and one with a node busy applying. Each of
			// those is something the next command will refuse to do, and being
			// told afterwards is not the same as being told.
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NODE\tSTATE\tSOURCE\tRUNTIME\tCONTRACTS\tSOCKET\tALLOCATABLE\tRESERVED\tLOAD\tPRESSURE\tIMAGES\tUNDERLAY\tPEER\tCONTAINERS\tLAB\tRECOVERY")
			bad, degraded := 0, 0
			for _, r := range results {
				if r.Err != nil {
					bad++
					fmt.Fprintf(w, "%s\tUNREACHABLE\t-\t-\t-\t-\t-\t%s\n", r.Node, firstLine(r.Err.Error()))
					continue
				}
				v := r.Value
				state, why := nodeState(v, agent.Compatibility())
				if state != "ok" {
					degraded++
				}
				lab := dash(v.Lab)
				if why != "" {
					lab = why
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					r.Node, state, v.Version, v.Runtime, v.RuntimeVer, contractSummary(v.Compatibility),
					dash(v.RuntimeSocket),
					inventorySummary(v.Inventory.Allocatable), inventorySummary(v.Inventory.Reserved),
					loadSummary(v.Inventory.Load), limiterPressureSummary(v.Backpressure),
					imageCacheSummary(v.Inventory.ImageCache),
					dash(v.UnderlayIP), peerReplicationSummary(v.PeerReplication), containerSummary(v), lab,
					recoverySummary(v.Recoveries))
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if bad > 0 {
				return fmt.Errorf("%d of %d node(s) are unreachable", bad, len(results))
			}
			if degraded > 0 {
				return fmt.Errorf("%d of %d node(s) are not in a state this controller can "+
					"safely act on; see the last column", degraded, len(results))
			}
			return nil
		},
	}

	check := &cobra.Command{
		Use:   "check",
		Short: "Verify the underlay can carry the lab's link MTU",
		Long: `Every cross-node link is carried in a VXLAN tunnel, which adds 50 bytes.
If the underlay MTU is too small, large packets disappear inside a student's
network for no reason they could ever discover. This checks it up front.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			tok, err := tokenFor(token)
			if err != nil {
				return err
			}
			c := client.NewCluster(top.Lab, tok)
			problems := c.CheckUnderlay(cmd.Context(), top)
			if len(problems) == 0 {
				want := 1500
				if top.Lab.LinkDefaults.MTU != nil {
					want = *top.Lab.LinkDefaults.MTU
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"underlay is sufficient for a %d byte lab MTU across %d node(s)\n",
					want, len(top.Lab.Placement.Nodes))
				return nil
			}
			for _, p := range problems {
				fmt.Fprintln(cmd.ErrOrStderr(), "  "+p)
			}
			return fmt.Errorf("%d underlay problem(s)", len(problems))
		},
	}

	bootstrap := &cobra.Command{
		Use:   "bootstrap [node...]",
		Short: "Print the commands that install the agent on a node",
		Long: `Emits an idempotent shell script that installs twinetd and a systemd unit
on each node. It is printed rather than executed so an operator can read exactly
what will run with root on their machines before it does.

The script requires node-specific mutual-TLS material from "twinet node pki".
It refuses to generate a remotely reachable bearer-token-only agent.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if bootstrapPKI == "" {
				bootstrapPKI = filepath.Join(top.Lab.Dir, ".twinet", "pki")
			}
			for _, name := range []string{
				"ca_cert.pem", "controller_cert.pem", "controller_key.pem",
			} {
				if _, err := os.Stat(filepath.Join(bootstrapPKI, name)); err != nil {
					return fmt.Errorf("secure bootstrap needs %s: %w; run `twinet node pki` first",
						filepath.Join(bootstrapPKI, name), err)
				}
			}
			nodes := args
			if len(nodes) == 0 {
				for _, n := range top.Lab.Placement.Nodes {
					nodes = append(nodes, n.Name)
				}
			}
			for _, name := range nodes {
				n, ok := top.Lab.NodeByName(name)
				if !ok {
					return fmt.Errorf("node %q is not declared in placement.nodes", name)
				}
				for _, suffix := range []string{
					"_server_cert.pem", "_server_key.pem", "_peer_cert.pem", "_peer_key.pem",
				} {
					path := filepath.Join(bootstrapPKI, name+suffix)
					if _, err := os.Stat(path); err != nil {
						return fmt.Errorf("secure bootstrap needs %s: %w; rerun `twinet node pki`",
							path, err)
					}
				}
				selectedRuntime := top.Lab.RuntimeForNode(name)
				socket := top.Lab.RuntimeSocketForNode(name)
				if err := runtime.ValidateSelection(selectedRuntime, socket); err != nil {
					return fmt.Errorf("cannot bootstrap node %q: %w", name, err)
				}
				var peers []string
				for _, peer := range top.Lab.Placement.Nodes {
					if peer.Name != name && peer.UnderlayIP != "" {
						peers = append(peers, peer.UnderlayIP)
					}
				}
				fmt.Fprint(cmd.OutOrStdout(),
					bootstrapScriptForRuntime(n, selectedRuntime, socket, bootstrapPKI, bootstrapTokenFile, peers))
			}
			return nil
		},
	}
	bootstrap.Flags().StringVar(&bootstrapPKI, "pki", "",
		"directory produced by `twinet node pki`")
	bootstrap.Flags().StringVar(&bootstrapTokenFile, "token-file", "",
		"root-readable environment file containing TWINET_TOKEN (default $TWINET_TOKEN_FILE)")

	cmd.AddCommand(status, check, bootstrap, newNodePKICmd(opts), newNodeSweepCmd(opts),
		newNodeControlsCmd(opts, &token), newNodeReconcileCmd(opts, &token), newNodeDrainCmd(opts, &token))
	return cmd
}

func newNodeControlsCmd(opts *Options, token *string) *cobra.Command {
	var (
		lab    string
		repair bool
	)
	cmd := &cobra.Command{
		Use:   "controls",
		Short: "Audit private FRR control sidecars",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if lab == "" {
				lab = top.Name
			}
			tok, err := tokenFor(*token)
			if err != nil {
				return err
			}
			cluster := client.NewCluster(top.Lab, tok)
			results := cluster.Controls(cmd.Context(), lab)
			if opts.JSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(results)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NODE\tDEVICE\tCONTROL\tSTATE\tDAEMONS\tVTY\tSTATUS\tREASON")
			problems := 0
			for _, result := range results {
				if result.Err != nil {
					problems++
					fmt.Fprintf(w, "%s\t-\t-\t-\t-\t-\tERROR\t%s\n", result.Node, firstLine(result.Err.Error()))
					continue
				}
				for _, control := range result.Value.Controls {
					status := "ok"
					if !control.Healthy {
						problems++
						status = "DEGRADED"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%t\t%s\t%s\n",
						result.Node, control.Device, control.Container, control.State,
						controlDaemonSummary(control.Daemons), control.VTY, status, firstLine(control.Reason))
				}
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if repair {
				for _, result := range cluster.ReconcileControls(cmd.Context(), lab) {
					if result.Err != nil {
						problems++
						fmt.Fprintf(cmd.ErrOrStderr(), "%s: cannot schedule control repair: %v\n", result.Node, result.Err)
						continue
					}
					if len(result.Value) > 0 {
						fmt.Fprintf(cmd.OutOrStdout(), "%s: queued control repair for %s\n",
							result.Node, strings.Join(result.Value, ", "))
					}
				}
			}
			if problems > 0 && !repair {
				return fmt.Errorf("%d control sidecar(s) are degraded; rerun with --repair to queue bounded platform repair", problems)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&lab, "lab", "", "lab to audit (default: manifest lab)")
	cmd.Flags().BoolVar(&repair, "repair", false, "queue bounded platform repair for unhealthy controls")
	return cmd
}

func controlDaemonSummary(counts map[string]int) string {
	if len(counts) == 0 {
		return "-"
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s=%d", name, counts[name]))
	}
	return strings.Join(parts, ",")
}

func newNodeReconcileCmd(opts *Options, token *string) *cobra.Command {
	var (
		lab     string
		devices []string
		force   bool
		overlay bool
	)
	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Queue bounded desired/observed reconciliation",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if lab == "" {
				lab = top.Name
			}
			tok, err := tokenFor(*token)
			if err != nil {
				return err
			}
			results := client.NewCluster(top.Lab, tok).ReconcileWithOverlay(cmd.Context(), lab, devices, force, overlay)
			if opts.JSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(results)
			}
			var problems []string
			for _, result := range results {
				if result.Err != nil {
					problems = append(problems, result.Node+": "+result.Err.Error())
					continue
				}
				if len(result.Value.Scheduled) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "%s: queued %s\n",
						result.Node, strings.Join(result.Value.Scheduled, ", "))
				}
				if len(result.Value.OverlayRepaired) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "%s: repaired overlay bindings %s\n",
						result.Node, strings.Join(result.Value.OverlayRepaired, ", "))
				}
				if len(result.Value.OverlayExtra) > 0 {
					problems = append(problems, result.Node+": extra overlay bindings require explicit prune: "+
						strings.Join(result.Value.OverlayExtra, ", "))
				}
				for binding, failure := range result.Value.OverlayFailed {
					problems = append(problems, result.Node+": overlay "+binding+": "+failure)
				}
			}
			if len(problems) > 0 {
				sort.Strings(problems)
				return fmt.Errorf("could not queue reconciliation: %s", strings.Join(problems, "; "))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&lab, "lab", "", "lab to reconcile (default: manifest lab)")
	cmd.Flags().StringSliceVar(&devices, "device", nil, "device ID to reconcile (repeatable; default all local devices)")
	cmd.Flags().BoolVar(&force, "force", false, "clear automatic repair backoff before queuing")
	cmd.Flags().BoolVar(&overlay, "overlay", false, "repair logical VNI/VLAN bindings too (implicit when no --device is given)")
	return cmd
}

// newNodeDrainCmd moves placement groups away from a healthy node. The source
// remains in the fenced cluster until fresh capture, replica quorum,
// destination restore, and verification finish; it is not a best-effort
// "delete then hope the next deploy fixes it" operation.
func newNodeDrainCmd(opts *Options, token *string) *cobra.Command {
	var (
		allowStale bool
		allowLoss  bool
		dryRun     bool
	)
	cmd := &cobra.Command{
		Use:   "drain <node>",
		Short: "Fenced-migrate placement groups off a healthy node",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			source := args[0]
			top, err := load(opts)
			if err != nil {
				return err
			}
			if !clustered(top) {
				return fmt.Errorf("node drain requires clustered placement")
			}
			if _, ok := top.Lab.NodeByName(source); !ok {
				return fmt.Errorf("node %q is not declared in placement.nodes", source)
			}
			record, err := place.LoadRecord(labPrivateDir(top), top.Name)
			if err != nil {
				return err
			}
			if record == nil {
				return fmt.Errorf("node drain requires a committed placement record; deploy the lab before draining it")
			}
			tok, err := tokenFor(*token)
			if err != nil {
				return err
			}
			cluster := client.NewCluster(top.Lab, tok)
			if err := cluster.HealthCheck(cmd.Context()); err != nil {
				return fmt.Errorf("refusing to drain %s because every source and destination must be healthy: %w", source, err)
			}
			survivors := cluster.Without(source)
			if len(survivors.Nodes) == 0 {
				return fmt.Errorf("cannot drain the only node")
			}
			inventory, err := survivors.Inventories(cmd.Context())
			if err != nil {
				return fmt.Errorf("cannot place drained groups without survivor inventory: %w", err)
			}
			assignment, err := place.Place(top, place.Options{
				Fixed:       record,
				Inventory:   inventory,
				Strict:      true,
				Unavailable: map[string]bool{source: true},
			})
			if err != nil {
				return fmt.Errorf("cannot drain %s: %w", source, err)
			}
			next := assignment.Record(top.Name, top.Lab.Placement.Strategy+" (drained "+source+")")
			if !placementRecordMoved(record, next) {
				fmt.Fprintf(cmd.OutOrStdout(), "%s hosts no movable placement groups for %s\n", source, top.Name)
				return nil
			}
			if !dryRun {
				if err := place.StageRecord(labPrivateDir(top), next); err != nil {
					return fmt.Errorf("stage drained placement: %w", err)
				}
			}
			deployErr := deployCluster(cmd.Context(), top, tok, agent.ApplyRequest{
				Mode:            "platform",
				PullPolicy:      "if-missing",
				Workers:         0,
				DryRun:          dryRun,
				StrictAdmission: true,
				Prune:           true,
				Generation:      time.Now().UTC().Format("20060102T150405.000"),
			}, client.DurabilityOptions{
				Previous: record, AllowStaleState: allowStale, AllowDataLoss: allowLoss,
			}, cmd.OutOrStdout(), cmd.ErrOrStderr())
			if deployErr != nil {
				if !dryRun {
					_ = place.DiscardStagedRecord(labPrivateDir(top))
				}
				return deployErr
			}
			if !dryRun {
				if err := place.CommitStagedRecord(labPrivateDir(top)); err != nil {
					return fmt.Errorf("drain committed but placement record was not committed: %w", err)
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "drained %s from %s under a verified durable migration\n", source, top.Name)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "plan the drain without mutation")
	cmd.Flags().BoolVar(&allowStale, "allow-stale-state", false,
		"AUDIT: permit non-fresh state only when recovery is otherwise impossible")
	cmd.Flags().BoolVar(&allowLoss, "allow-data-loss", false,
		"AUDIT: permit drain without a verified durable replica")
	return cmd
}

// bootstrapScript keeps direct unit callers on the Docker-compatible default.
// The CLI resolves the lab default and node override through the runtime
// registry before it calls bootstrapScriptForRuntime.
func bootstrapScript(n model.NodeSpec, _ string, pkiDir string) string {
	selected := n.Runtime
	if selected == "" {
		selected = model.DefaultRuntime
	}
	return bootstrapScriptForRuntime(n, selected, n.RuntimeSocket, pkiDir, "", nil)
}

func bootstrapScriptForRuntime(n model.NodeSpec, selectedRuntime, socket, pkiDir, tokenFile string,
	peers []string,
) string {
	port := "7200"
	if n.Addr != "" {
		if i := strings.LastIndex(n.Addr, ":"); i > 0 {
			port = n.Addr[i+1:]
		}
	}
	host := n.UnderlayIP
	if host == "" && n.Addr != "" {
		if i := strings.LastIndex(n.Addr, ":"); i > 0 {
			host = n.Addr[:i]
		}
	}
	if host == "" {
		host = "127.0.0.1"
	}
	listen := host + ":" + port
	selectedRuntime = strings.ToLower(strings.TrimSpace(selectedRuntime))
	if selectedRuntime == "" {
		selectedRuntime = model.DefaultRuntime
	}
	if socket == "" {
		switch selectedRuntime {
		case "podman":
			socket = "unix:///run/podman/podman.sock"
		case "containerd":
			socket = "unix:///run/containerd/containerd.sock"
		default:
			socket = "unix:///var/run/docker.sock"
		}
	}

	serverCert := filepath.Join(pkiDir, n.Name+"_server_cert.pem")
	serverKey := filepath.Join(pkiDir, n.Name+"_server_key.pem")
	peerCert := filepath.Join(pkiDir, n.Name+"_peer_cert.pem")
	peerKey := filepath.Join(pkiDir, n.Name+"_peer_key.pem")
	caCert := filepath.Join(pkiDir, "ca_cert.pem")
	controllerCert := filepath.Join(pkiDir, "controller_cert.pem")
	controllerKey := filepath.Join(pkiDir, "controller_key.pem")

	var b strings.Builder
	b.WriteString("set -euo pipefail\n")
	fmt.Fprintf(&b, "# ---- %s ----\n", n.Name)
	b.WriteString("command -v curl >/dev/null 2>&1 || { echo 'bootstrap needs curl on the controller' >&2; exit 1; }\n")
	b.WriteString("command -v python3 >/dev/null 2>&1 || { echo 'bootstrap needs python3 on the controller' >&2; exit 1; }\n")
	if tokenFile != "" {
		fmt.Fprintf(&b, "export TWINET_TOKEN_FILE=%q\n", tokenFile)
	}
	b.WriteString(": \"${TWINET_TOKEN_FILE:?set TWINET_TOKEN_FILE to a file containing TWINET_TOKEN=...}\"\n")
	b.WriteString("test -f \"$TWINET_TOKEN_FILE\" || { echo 'token file does not exist' >&2; exit 1; }\n")
	b.WriteString("grep -Eq '^TWINET_TOKEN=[^[:space:]]+' \"$TWINET_TOKEN_FILE\" || { echo 'token file must contain TWINET_TOKEN=...' >&2; exit 1; }\n")
	fmt.Fprintf(&b, "ssh root@%s 'install -d -m 0700 /etc/twinet/pki /var/lib/twinet/state'\n", n.Name)
	fmt.Fprintf(&b, "scp bin/twinetd root@%s:/usr/local/bin/twinetd\n", n.Name)
	if selectedRuntime == "containerd" {
		fmt.Fprintf(&b, "scp bin/twinet-init root@%s:/usr/local/bin/twinet-init\n", n.Name)
	}
	fmt.Fprintf(&b, "scp %q root@%s:/etc/twinet/pki/server_cert.pem\n", serverCert, n.Name)
	fmt.Fprintf(&b, "scp %q root@%s:/etc/twinet/pki/server_key.pem\n", serverKey, n.Name)
	fmt.Fprintf(&b, "scp %q root@%s:/etc/twinet/pki/peer_cert.pem\n", peerCert, n.Name)
	fmt.Fprintf(&b, "scp %q root@%s:/etc/twinet/pki/peer_key.pem\n", peerKey, n.Name)
	fmt.Fprintf(&b, "scp %q root@%s:/etc/twinet/pki/ca_cert.pem\n", caCert, n.Name)
	// The token is copied from a root-readable environment file. It is never
	// embedded in the script or in the world-readable systemd unit.
	fmt.Fprintf(&b, "scp \"$TWINET_TOKEN_FILE\" root@%s:/etc/twinet/agent.env\n", n.Name)
	fmt.Fprintf(&b, "ssh root@%s 'bash -s' <<'TWINET_REMOTE'\n", n.Name)
	b.WriteString("set -euo pipefail\n")
	b.WriteString("install_package() {\n")
	b.WriteString("  command -v \"$1\" >/dev/null 2>&1 && return 0\n")
	b.WriteString("  command -v apt-get >/dev/null 2>&1 || { echo \"missing $1; automatic install needs apt-get\" >&2; exit 1; }\n")
	b.WriteString("  export DEBIAN_FRONTEND=noninteractive\n  apt-get update\n  apt-get install -y \"$2\"\n}\n")
	switch selectedRuntime {
	case "podman":
		b.WriteString("install_package podman podman\nsystemctl enable --now podman.socket\npodman info >/dev/null\n")
		if socketPath := strings.TrimPrefix(socket, "unix://"); strings.HasPrefix(socket, "unix://") || strings.HasPrefix(socket, "/") {
			fmt.Fprintf(&b, "test -S %q || { echo 'Podman API socket is unavailable' >&2; exit 1; }\n", socketPath)
		}
	case "containerd":
		b.WriteString("install_package containerd containerd\nsystemctl enable --now containerd.service\n")
		if socketPath := strings.TrimPrefix(socket, "unix://"); strings.HasPrefix(socket, "unix://") || strings.HasPrefix(socket, "/") {
			fmt.Fprintf(&b, "test -S %q || { echo 'containerd socket is unavailable' >&2; exit 1; }\n", socketPath)
		}
	default:
		b.WriteString("install_package docker docker.io\nsystemctl enable --now docker.service\ndocker info >/dev/null\n")
	}
	b.WriteString("install -d -m 0700 /etc/twinet /var/lib/twinet/state\n")
	b.WriteString("chmod 0755 /usr/local/bin/twinetd\n")
	if selectedRuntime == "containerd" {
		b.WriteString("chmod 0755 /usr/local/bin/twinet-init\n")
	}
	b.WriteString("chmod 0600 /etc/twinet/agent.env /etc/twinet/pki/server_key.pem /etc/twinet/pki/peer_key.pem\n")
	b.WriteString("chmod 0644 /etc/twinet/pki/server_cert.pem /etc/twinet/pki/peer_cert.pem /etc/twinet/pki/ca_cert.pem\n")
	b.WriteString("cat > /etc/systemd/system/twinetd.service <<'UNIT'\n[Unit]\nDescription=Twinet node agent\n")
	switch selectedRuntime {
	case "podman":
		b.WriteString("After=podman.socket\nRequires=podman.socket\n\n")
	case "containerd":
		b.WriteString("After=containerd.service\nRequires=containerd.service\n\n")
	default:
		b.WriteString("After=docker.service\nRequires=docker.service\n\n")
	}
	b.WriteString("[Service]\nType=simple\nEnvironmentFile=/etc/twinet/agent.env\n")
	fmt.Fprintf(&b, "ExecStart=/usr/local/bin/twinetd -node %s -listen %s -runtime %s -runtime-socket %s",
		n.Name, listen, selectedRuntime, socket)
	if n.UnderlayIP != "" {
		fmt.Fprintf(&b, " -underlay-ip %s", n.UnderlayIP)
	}
	if n.UnderlayDev != "" {
		fmt.Fprintf(&b, " -underlay-dev %s", n.UnderlayDev)
	}
	b.WriteString(" -tls-cert /etc/twinet/pki/server_cert.pem -tls-key /etc/twinet/pki/server_key.pem")
	b.WriteString(" -client-ca /etc/twinet/pki/ca_cert.pem -peer-tls-cert /etc/twinet/pki/peer_cert.pem -peer-tls-key /etc/twinet/pki/peer_key.pem\n")
	b.WriteString("Restart=always\nRestartSec=2\n")
	b.WriteString("AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_NET_RAW\n")
	b.WriteString("CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_NET_RAW CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER CAP_SETUID CAP_SETGID\n")
	b.WriteString("NoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nLimitNOFILE=1048576\nTasksMax=infinity\n\n")
	b.WriteString("[Install]\nWantedBy=multi-user.target\nUNIT\n")
	b.WriteString("systemctl daemon-reload && systemctl enable --now twinetd\n")
	b.WriteString("systemctl is-active --quiet twinetd || { journalctl -u twinetd -n 50 --no-pager >&2; exit 1; }\n")
	for _, peer := range peers {
		fmt.Fprintf(&b, "ping -c 1 -W 2 %s >/dev/null || { echo 'underlay peer unreachable: %s' >&2; exit 1; }\n", peer, peer)
	}
	b.WriteString("TWINET_REMOTE\n")
	b.WriteString("TWINET_TOKEN=$(sed -n 's/^TWINET_TOKEN=//p' \"$TWINET_TOKEN_FILE\" | head -n 1)\n")
	b.WriteString("test -n \"$TWINET_TOKEN\" || { echo 'token file did not yield TWINET_TOKEN' >&2; exit 1; }\n")
	fmt.Fprintf(&b, "status_json=$(curl --fail --silent --show-error --cacert %q --cert %q --key %q --header @<(printf 'Authorization: Bearer %%s\\n' \"$TWINET_TOKEN\") https://%s/v1/status)\n",
		caCert, controllerCert, controllerKey, listen)
	underlay := n.UnderlayIP
	if underlay == "" {
		underlay = "-"
	}
	b.WriteString("printf '%s' \"$status_json\" | python3 -c 'import json,sys; s=json.load(sys.stdin); runtime,socket,underlay=sys.argv[1:]; ")
	b.WriteString("assert s.get(\"runtime\")==runtime, s; assert s.get(\"runtime_version\"), s; assert s.get(\"runtime_socket\")==socket, s; ")
	b.WriteString("c=s.get(\"compatibility\",{}); assert c.get(\"protocol\",{}).get(\"current\"), s; assert c.get(\"renderer\",{}).get(\"current\"), s; assert c.get(\"state\",{}).get(\"current\"), s; ")
	b.WriteString("assert \"image_cache\" in s.get(\"inventory\",{}), s; assert s.get(\"state_store_healthy\") is True, s; ")
	b.WriteString("assert underlay==\"-\" or (s.get(\"underlay_ip\")==underlay and s.get(\"underlay_mtu\",0)>0), s' ")
	fmt.Fprintf(&b, "%q %q %q\n", selectedRuntime, socket, underlay)
	fmt.Fprintf(&b, "echo '%s: secure %s agent is healthy at https://%s'\n\n", n.Name, selectedRuntime, listen)
	return b.String()
}

// deployCluster fans the deployment out across node agents.
// deconflictOverlays reassigns VXLAN identifiers that another lab already owns.
func deconflictOverlays(ctx context.Context, c *client.Cluster, top *model.Topology) int {
	inUse := c.OverlaysInUse(ctx)
	if len(inUse) == 0 {
		return 0
	}
	assigned := make(map[string]uint32, len(top.Links))
	for _, l := range top.Links {
		if l.VNI != 0 {
			assigned[l.ID] = l.VNI
		}
	}
	updated, moved := alloc.Deconflict(top.Name, assigned, inUse)
	if moved == 0 {
		return 0
	}
	for _, l := range top.Links {
		if v, ok := updated[l.ID]; ok {
			l.VNI = v
		}
	}
	return moved
}

// checkVersionSkew refuses an incompatible protocol, renderer, or state
// contract before any deployment work. Exact source versions remain in status
// and audit events but compatible bug-fix builds may roll one node at a time.
func checkVersionSkew(ctx context.Context, c *client.Cluster) error {
	// The check itself lives on the cluster, where Apply can enforce it for
	// every caller. This wrapper remains so the deploy path can report it
	// before doing any other work.
	return c.VersionSkew(ctx)
}

// redeployScopes re-applies the reference solution to specific autonomous
// systems, which is how a submission is cleared once it has been graded.
//
// Returning a system to the state a *student* starts from is a different job,
// done per device by resetToStudentStart: it must not touch anything outside
// the one system, because everything else in the lab is the reference the next
// submission will be graded against.
func redeployScopes(ctx context.Context, top *model.Topology, token string, scopes []string) error {
	tok, err := tokenFor(token)
	if err != nil {
		return err
	}
	if len(scopes) == 0 {
		return fmt.Errorf("no scopes were given to restore")
	}
	c := client.NewCluster(top.Lab, tok)

	// The apply is restricted to the systems being restored, plus the peering
	// and service scopes.
	//
	// It used to discard its argument and run an authoritative solve over the
	// whole topology. That reinstalled the reference solution on every
	// autonomous system in the lab, including submissions that had loaded
	// successfully and were about to be graded. A student whose neighbour
	// failed to load had their work replaced by the model answer and was then
	// marked on it -- ten out of ten for a submission nobody had read, with
	// nothing flagged for review. That is the most damaging thing a grading
	// system can do, and it is invisible in the report.
	//
	// The peering scope is included because an inter-AS link belongs to
	// neither system: leaving it out rebuilds a router without rewiring its
	// external links, and the router comes back with almost no interfaces
	// while its neighbours see sessions that never establish. Including it
	// rewires links without touching any other system's configuration, because
	// only the create and configure stages carry an AS scope.
	only := restoreScopes(scopes)
	results := c.Apply(ctx, top, agent.ApplyRequest{
		Mode:            "solve",
		PullPolicy:      "if-missing",
		Workers:         8,
		OnlySteps:       only,
		StrictAdmission: true,
		Generation:      time.Now().UTC().Format("20060102T150405.000"),
		// Grading holds the lab, and this is grading putting a system back.
		Hold: currentHoldToken(),
	})
	for _, r := range results {
		if r.Err != nil {
			return r.Err
		}
		for scope, msgs := range r.Value.Failures {
			if len(msgs) > 0 {
				return fmt.Errorf("%s: %s", scope, firstLine(msgs[0]))
			}
		}
	}
	return nil
}

func deployCluster(ctx context.Context, top *model.Topology, tok string, req agent.ApplyRequest,
	durability client.DurabilityOptions, out, errOut interface {
		Write([]byte) (int, error)
	}) error {
	c := client.NewCluster(top.Lab, tok)
	controllerPhases := map[string]time.Duration{}
	measure := func(name string, fn func() error) error {
		start := time.Now()
		err := fn()
		controllerPhases[name] += time.Since(start)
		return err
	}

	// The runtime is part of the substrate contract. Check it before admission
	// reads, VNI deconfliction, state migration, or any fenced request so a
	// Docker agent cannot mutate a lab that explicitly requested Podman.
	if err := measure("runtime_compatibility", func() error { return c.RuntimeCompatibility(ctx) }); err != nil {
		return err
	}

	// Admission must precede overlay deconfliction, state migration, record
	// writes by callers, and every node mutation. A capacity refusal after
	// any of those has already changed the cluster it was meant to protect.
	if req.StrictAdmission {
		if err := measure("admission", func() error {
			return c.Admit(ctx, top, true, req.Overcommit)
		}); err != nil {
			return fmt.Errorf("strict admission refused deployment before mutation: %w", err)
		}
	}

	// Move any overlay identifier another lab is already using, before the
	// topology is sent anywhere. Doing it here means both ends of every link
	// receive the same value without the nodes having to agree on anything.
	moved := 0
	if err := measure("overlay_deconfliction", func() error {
		moved = deconflictOverlays(ctx, c, top)
		return nil
	}); err != nil {
		return err
	}
	if moved > 0 {
		fmt.Fprintf(errOut, "  moved %d overlay identifier(s) that another lab was using\n", moved)
	}

	// Refuse to build a lab whose links cannot fit through the fabric.
	var underlayProblems []string
	if err := measure("underlay", func() error {
		underlayProblems = c.CheckUnderlay(ctx, top)
		return nil
	}); err != nil {
		return err
	}
	if len(underlayProblems) > 0 {
		for _, p := range underlayProblems {
			fmt.Fprintln(errOut, "  "+p)
		}
		return fmt.Errorf("the underlay cannot carry this lab; fix the above or lower link_defaults.mtu")
	}

	// Source builds may differ during a safe rolling upgrade. The independent
	// protocol, renderer, and state contracts are what determine whether the
	// nodes can render and persist one lab safely.
	if err := measure("version_skew", func() error { return checkVersionSkew(ctx, c) }); err != nil {
		return err
	}

	start := time.Now()
	var (
		results []client.NodeResult[agent.ApplyResponse]
		durable client.DurabilityReport
	)
	if err := measure("cluster_transaction", func() error {
		results, durable = c.ApplyDurable(ctx, top, req, durability)
		return nil
	}); err != nil {
		return err
	}
	if durable.Moved > 0 {
		fmt.Fprintf(errOut, "  moved %d device(s) through fresh durable state transfer\n", durable.Moved)
	}
	for _, audit := range durable.Audit {
		fmt.Fprintln(errOut, "  AUDIT: "+audit)
	}
	printControllerPhases(errOut, controllerPhases, durable.Phases)

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NODE\tSTEPS\tDURATION\tSTATUS")
	failed := 0
	devices, links, crossEndpoints, wantDev, wantLink, wantCrossEndpoints := 0, 0, 0, 0, 0, 0
	reached, steps := 0, 0
	for _, r := range results {
		if r.Err != nil {
			failed++
			fmt.Fprintf(w, "%s\t-\t-\t%s\n", r.Node, firstLine(r.Err.Error()))
			continue
		}
		reached++
		steps += r.Value.Steps
		devices += r.Value.Devices
		links += r.Value.Links
		crossEndpoints += r.Value.CrossLinkEndpoints
		wantDev += r.Value.WantDevice
		wantLink += r.Value.WantLinks
		wantCrossEndpoints += r.Value.WantCrossLinkEndpoints
		status := "ok"
		if len(r.Value.Failures) > 0 {
			failed++
			status = fmt.Sprintf("%d scope(s) degraded", len(r.Value.Failures))
		}
		steps := fmt.Sprintf("%d", r.Value.Steps)
		if r.Value.Planned > r.Value.Steps {
			steps = fmt.Sprintf("%d/%d", r.Value.Steps, r.Value.Planned)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Node, steps,
			time.Duration(r.Value.DurationMS)*time.Millisecond, status)
	}
	_ = w.Flush()

	for _, r := range results {
		for scope, msgs := range r.Value.Failures {
			for _, m := range msgs {
				fmt.Fprintf(errOut, "  %s/%s: %s\n", r.Node, scope, firstLine(m))
			}
		}
	}

	// Summed from actual per-node wire results, not the manifest. A cross-node
	// link reports two completed endpoints, so only the reported cross-endpoint
	// count is divided by two. This keeps a zero-work deploy at zero rather
	// than subtracting every cross-node link in the topology.
	whole := failed == 0 && reached == len(c.Nodes) && len(req.OnlySteps) == 0
	if req.DryRun {
		if whole {
			logicalWantLinks := logicalLinks(wantLink, wantCrossEndpoints)
			fmt.Fprintf(out, "\ndry run: %d devices and %d links would be deployed "+
				"across %d nodes; nothing was changed\n",
				wantDev, logicalWantLinks, len(c.Nodes))
		} else {
			fmt.Fprintf(out, "\ndry run: %d devices and %d link endpoints would be "+
				"deployed across the %d node(s) that answered; nothing was changed\n",
				wantDev, wantLink, reached)
		}
		if failed > 0 {
			return fmt.Errorf("%d node(s) reported problems; re-run deploy to converge", failed)
		}
		return nil
	}
	if whole {
		completedLinks := logicalLinks(links, crossEndpoints)
		fmt.Fprintf(out, "\n%d devices, %d links (%d cross-node) across %d nodes in %s\n",
			devices, completedLinks, crossEndpoints/2, len(c.Nodes),
			time.Since(start).Round(time.Millisecond))
	} else {
		fmt.Fprintf(out, "\n%d of %d devices and %d of %d link endpoints deployed "+
			"across the %d node(s) that answered, in %s\n",
			devices, wantDev, links, wantLink, reached,
			time.Since(start).Round(time.Millisecond))
	}

	if failed > 0 {
		return fmt.Errorf("%d node(s) reported problems; re-run deploy to converge", failed)
	}
	// A deployment that changed nothing is only a success if the nodes agree
	// that there was nothing to change. They publish the same audited health
	// `node status` shows, so a zero-change run against a node reporting
	// drifted devices is a contradiction, and it used to be reported as
	// success with an exit status of zero.
	if drift := clusterSemanticDrift(results); drift != "" {
		if err := zeroChangeDriftError(steps, drift); err != nil {
			return err
		}
		fmt.Fprintf(errOut,
			"AUDIT: the deployment made %d change(s) and the cluster is still degraded: %s\n",
			steps, drift)
	}
	return nil
}

// zeroChangeDriftError enforces the one invariant a deployment summary must
// never break: zero changes and degraded semantic health cannot both be true
// and still be a success. A run that did change something has reported that
// work, and its remaining drift is audited rather than fatal.
func zeroChangeDriftError(steps int, drift string) error {
	if drift == "" || steps > 0 {
		return nil
	}
	return fmt.Errorf("deployment made no changes while %s; "+
		"the cluster is not converged, so this is not a successful no-op", drift)
}

// clusterSemanticDrift names the degraded nodes and one device that proves it.
func clusterSemanticDrift(results []client.NodeResult[agent.ApplyResponse]) string {
	var degraded []string
	detail := ""
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		count := r.Value.SemanticHealth.Degraded()
		if count == 0 {
			continue
		}
		degraded = append(degraded, fmt.Sprintf("%s reports %d device(s) with semantic/runtime drift",
			r.Node, count))
		if detail == "" {
			if drift := r.Value.SemanticHealth.Drift(); drift != "" {
				detail = drift
			}
		}
	}
	if len(degraded) == 0 {
		return ""
	}
	sort.Strings(degraded)
	out := strings.Join(degraded, "; ")
	if detail != "" {
		out += " (" + firstLine(detail) + ")"
	}
	return out
}

func logicalLinks(endpoints, crossEndpoints int) int {
	if endpoints <= 0 {
		return 0
	}
	if crossEndpoints < 0 {
		crossEndpoints = 0
	}
	if crossEndpoints > endpoints {
		crossEndpoints = endpoints
	}
	return endpoints - crossEndpoints/2
}

func printControllerPhases(out interface{ Write([]byte) (int, error) }, outer map[string]time.Duration, inner client.PhaseTimings) {
	all := map[string]time.Duration{}
	for name, elapsed := range outer {
		all[name] += elapsed
	}
	for name, elapsed := range inner {
		all[name] += elapsed
	}
	if len(all) == 0 {
		return
	}
	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprint(out, "  controller phases:")
	for _, name := range names {
		fmt.Fprintf(out, " %s=%s", name, all[name].Round(time.Millisecond))
	}
	fmt.Fprintln(out)
}

// restoreScopes is the set of deployment scopes a restore must cover: the
// systems named, and the scopes that hold what connects them.
//
// Nothing else may appear here. Every extra scope is another student's work
// overwritten with the reference solution.
func restoreScopes(scopes []string) []string {
	out := append([]string{}, scopes...)
	return append(out, "peering", "services")
}

// nodeState says what an agent's status means, rather than that it answered.
//
// Three things make a node one the controller should not act on without saying
// so first: a build that differs from this one, because the node renders the
// device configuration and a different build renders it differently; a lab
// with an operation already in flight, because the next command will be
// refused; and an agent that reports no runtime at all.
func nodeState(v agent.StatusResponse, controller contract.Set) (state, why string) {
	if v.RuntimeVer == "" {
		return "no-runtime", "the container runtime did not answer"
	}
	if statusUnknown(v.Unknown, "containers") {
		why := "managed container inventory could not be read"
		if v.ContainerListError != "" {
			why += ": " + firstLine(v.ContainerListError)
		}
		return "unknown", why
	}
	if v.Compatibility.Empty() {
		return "incompatible", "agent does not advertise protocol, renderer, and state contracts"
	}
	if !controller.Empty() {
		if err := controller.Compatible(v.Compatibility); err != nil {
			return "incompatible", err.Error()
		}
	}
	if len(v.Busy) > 0 {
		return "busy", "operation in flight: " + strings.Join(v.Busy, ", ")
	}
	if v.StateStoreHealthy != nil && !*v.StateStoreHealthy {
		return "state-unhealthy", "durable state store is unavailable"
	}
	if v.Convergence["broken"] > 0 {
		why := fmt.Sprintf("%d device(s) have semantic/runtime drift", v.Convergence["broken"])
		if detail := semanticStatusReason(v.SemanticHealth); detail != "" {
			why += ": " + detail
		}
		return "degraded", why
	}
	if v.Convergence["unknown"] > 0 {
		return "semantic-unknown", fmt.Sprintf("%d device(s) could not be semantically observed", v.Convergence["unknown"])
	}
	for _, peer := range v.PeerReplication {
		if !peer.Healthy {
			return "peer-unhealthy", fmt.Sprintf("durability peer %s is not acknowledged: %s",
				peer.Peer, peer.Error)
		}
	}
	return "ok", ""
}

func semanticStatusReason(values map[string]agent.SemanticHealth) string {
	labs := make([]string, 0, len(values))
	for lab := range values {
		labs = append(labs, lab)
	}
	sort.Strings(labs)
	for _, lab := range labs {
		if drift := values[lab].Drift(); drift != "" {
			device, reason, _ := strings.Cut(drift, ": ")
			return device + ": " + firstLine(reason)
		}
	}
	return ""
}

func peerReplicationSummary(values map[string]agent.PeerReplicationStatus) string {
	if len(values) == 0 {
		return "-"
	}

	healthy, failed := 0, 0
	for _, status := range values {
		if status.Healthy {
			healthy++
		} else {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Sprintf("%d ok/%d failed", healthy, failed)
	}
	return fmt.Sprintf("%d ok", healthy)
}

func recoverySummary(values map[string]agent.RecoveryStatus) string {
	if len(values) == 0 {
		return "-"
	}
	labs := make([]string, 0, len(values))
	for lab := range values {
		labs = append(labs, lab)
	}
	sort.Strings(labs)
	var out []string
	for _, lab := range labs {
		status := values[lab]
		if status.Phase == "committed" || status.Phase == "idle" {
			continue
		}
		target := status.CurrentTarget
		if target == "" {
			target = status.Error
		}
		out = append(out, fmt.Sprintf("%s:%s owner=%s strategy=%s target=%s progress=%s deadline=%s retries=%d",
			lab, status.Phase, dash(status.Owner), dash(status.Strategy), dash(target),
			dash(status.LastProgressAt.Format(time.RFC3339)), dash(status.Deadline.Format(time.RFC3339)),
			status.RetryCount))
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, "; ")
}

func containerSummary(v agent.StatusResponse) string {
	if v.ManagedContainers > 0 || v.ControlContainers > 0 {
		return fmt.Sprintf("%d primary + %d control (%d managed)",
			v.PrimaryContainers, v.ControlContainers, v.ManagedContainers)
	}
	return fmt.Sprintf("%d", v.Containers)
}

func contractSummary(value contract.Set) string {
	return fmt.Sprintf("p%s/r%s/s%s",
		dash(value.Protocol.Current), dash(value.Renderer.Current), dash(value.State.Current))
}

func statusUnknown(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func inventorySummary(v agent.ResourceInventory) string {
	if v.CPUs == nil || v.MemoryBytes == nil || v.DiskBytes == nil || v.Pids == nil ||
		v.FileDescriptors == nil || v.NetDevices == nil {
		return "unknown"
	}
	return fmt.Sprintf("%.1fc/%s/%s/%dp/%dfd/%dnd",
		*v.CPUs, inventoryBytes(*v.MemoryBytes), inventoryBytes(*v.DiskBytes),
		*v.Pids, *v.FileDescriptors, *v.NetDevices)
}

func inventoryBytes(v int64) string {
	switch {
	case v >= 1<<30:
		return fmt.Sprintf("%.1fGi", float64(v)/(1<<30))
	case v >= 1<<20:
		return fmt.Sprintf("%dMi", v>>20)
	default:
		return fmt.Sprintf("%dB", v)
	}
}

func loadSummary(v agent.LoadAverage) string {
	if v.One == nil {
		return "unknown"
	}
	return fmt.Sprintf("%.2f", *v.One)
}

func imageCacheSummary(v agent.ImageCacheInventory) string {
	if v.Count == nil {
		return "unknown"
	}
	return fmt.Sprintf("%d", *v.Count)
}

func limiterPressureSummary(values map[string]limiter.Stats) string {
	if len(values) == 0 {
		return "unknown"
	}
	active, queued := 0, 0
	for _, value := range values {
		active += value.InFlight
		queued += value.QueueDepth
	}
	if active == 0 && queued == 0 {
		return "idle"
	}
	return fmt.Sprintf("%d active/%d queued", active, queued)
}

// newNodeSweepCmd finds and removes the overlays a node is carrying for nobody.
func newNodeSweepCmd(opts *Options) *cobra.Command {
	var (
		token  string
		remove bool
	)
	cmd := &cobra.Command{
		Use:   "sweep",
		Short: "Find, and optionally remove, overlay devices left behind by removed labs",
		Long: "A lab whose teardown was interrupted leaves its tunnels and bridges on the " +
			"nodes. They cost a network identifier each out of a finite space, and the " +
			"deconfliction that stops two labs choosing the same one reads exactly the " +
			"ownership record they are missing. A hundred were found on one node of this " +
			"cluster against forty-four in use.\n\n" +
			"Reports by default. An overlay whose bridge still has something attached is " +
			"never removed, whatever its ownership record says: it is carrying a cable for " +
			"something.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			tok, err := tokenFor(token)
			if err != nil {
				return err
			}
			c := client.NewCluster(top.Lab, tok)
			results := c.Sweep(cmd.Context(), remove)

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NODE\tLOGICAL\tTRUNKS\tORPHANS\tREMOVED\tIN USE\tNOTE")
			bad, total := 0, 0
			for _, r := range results {
				if r.Err != nil {
					bad++
					fmt.Fprintf(w, "%s\t-\t-\t-\t-\t-\t%s\n", r.Node, firstLine(r.Err.Error()))
					continue
				}
				v := r.Value
				total += len(v.Orphans)
				note := ""
				if len(v.Errs) > 0 {
					note = strings.Join(v.Errs, "; ")
				}
				fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\t%s\n",
					r.Node, v.LogicalBindings, v.PhysicalTrunks,
					len(v.Orphans), len(v.Removed), len(v.InUse), note)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if !remove && total > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"\n%d overlay(s) belong to no lab these nodes host; remove them with "+
						"--remove\n", total)
			}
			if bad > 0 {
				return fmt.Errorf("%d of %d node(s) could not be swept", bad, len(results))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "agent token (or set TWINET_TOKEN)")
	cmd.Flags().BoolVar(&remove, "remove", false, "actually remove them")
	return cmd
}
