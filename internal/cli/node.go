package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/alloc"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/model"
)

// tokenFor resolves the shared secret the control plane presents to agents.
func tokenFor(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if v := os.Getenv("TWINET_TOKEN"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no agent token: pass --token or set TWINET_TOKEN")
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
	var token string
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

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NODE\tSTATE\tVERSION\tRUNTIME\tCPUS\tUNDERLAY\tCONTAINERS\tLAB")
			bad := 0
			for _, r := range results {
				if r.Err != nil {
					bad++
					fmt.Fprintf(w, "%s\tUNREACHABLE\t-\t-\t-\t-\t-\t%s\n", r.Node, firstLine(r.Err.Error()))
					continue
				}
				v := r.Value
				fmt.Fprintf(w, "%s\tok\t%s\t%s %s\t%d\t%s\t%d\t%s\n",
					r.Node, v.Version, v.Runtime, v.RuntimeVer, v.CPUs,
					dash(v.UnderlayIP), v.Containers, dash(v.Lab))
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if bad > 0 {
				return fmt.Errorf("%d of %d node(s) are unreachable", bad, len(results))
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
what will run with root on their machines before it does.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			tok, _ := tokenFor(token)
			if tok == "" {
				tok = "REPLACE_WITH_A_SHARED_SECRET"
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
				fmt.Fprint(cmd.OutOrStdout(), bootstrapScript(n, tok))
			}
			return nil
		},
	}

	cmd.AddCommand(status, check, bootstrap, newNodePKICmd(opts))
	return cmd
}

func bootstrapScript(n model.NodeSpec, token string) string {
	listen := ":7200"
	if n.Addr != "" {
		if i := strings.LastIndex(n.Addr, ":"); i > 0 {
			listen = n.Addr[i:]
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# ---- %s ----\n", n.Name)
	fmt.Fprintf(&b, "scp bin/twinetd root@%s:/usr/local/bin/twinetd\n", n.Name)
	fmt.Fprintf(&b, "ssh root@%s 'cat > /etc/systemd/system/twinetd.service <<UNIT\n", n.Name)
	b.WriteString("[Unit]\nDescription=Twinet node agent\nAfter=docker.service\nRequires=docker.service\n\n")
	b.WriteString("[Service]\nType=simple\n")
	fmt.Fprintf(&b, "Environment=TWINET_TOKEN=%s\n", token)
	fmt.Fprintf(&b, "ExecStart=/usr/local/bin/twinetd -node %s -listen %s", n.Name, listen)
	if n.UnderlayIP != "" {
		fmt.Fprintf(&b, " -underlay-ip %s", n.UnderlayIP)
	}
	b.WriteString("\nRestart=always\nRestartSec=2\n")
	// The agent creates namespaces and rewires the host, so it needs the
	// capabilities; it does not need the rest of root's authority.
	b.WriteString("AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_RAW\n")
	b.WriteString("LimitNOFILE=1048576\nTasksMax=infinity\n\n")
	b.WriteString("[Install]\nWantedBy=multi-user.target\nUNIT\n")
	b.WriteString("systemctl daemon-reload && systemctl enable --now twinetd'\n\n")
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

// warnVersionSkew reports nodes whose agent differs from this controller.
func warnVersionSkew(ctx context.Context, c *client.Cluster, errOut interface {
	Write([]byte) (int, error)
}) {
	want := Version
	var odd []string
	for _, r := range c.Status(ctx) {
		if r.Err != nil {
			continue
		}
		if v := r.Value.Version; v != "" && v != want {
			odd = append(odd, fmt.Sprintf("%s runs %s", r.Node, v))
		}
	}
	if len(odd) > 0 {
		sort.Strings(odd)
		fmt.Fprintf(errOut, "  warning: this controller is %s but %s; "+
			"re-run scripts/deploy_agents.sh before trusting the result\n",
			want, strings.Join(odd, ", "))
	}
}

// redeployScopes re-applies the reference solution to specific autonomous
// systems, which is how a wave's submissions are cleared before the next wave.
func redeployScopes(ctx context.Context, top *model.Topology, token string, scopes []string) error {
	tok, err := tokenFor(token)
	if err != nil {
		return err
	}
	c := client.NewCluster(top.Lab, tok)
	// A full apply, not one restricted to the systems being restored.
	//
	// Restricting it looks like the efficient choice and is wrong: an inter-AS
	// link belongs to the peering scope rather than to either system, so a
	// restricted apply rebuilds a router without rewiring its external links.
	// The router comes back with almost no interfaces, its neighbours see
	// sessions that never establish, and the cause is three steps removed from
	// the symptom. The apply is idempotent and takes about half a minute when
	// nothing has changed, which is a small price for not having to reason
	// about which scopes a change can reach.
	_ = scopes
	results := c.Apply(ctx, top, agent.ApplyRequest{
		Mode:       "solve",
		PullPolicy: "if-missing",
		Workers:    8,
		Generation: time.Now().UTC().Format("20060102T150405.000"),
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

func deployCluster(ctx context.Context, top *model.Topology, tok string, req agent.ApplyRequest, out, errOut interface {
	Write([]byte) (int, error)
}) error {
	c := client.NewCluster(top.Lab, tok)

	// Move any overlay identifier another lab is already using, before the
	// topology is sent anywhere. Doing it here means both ends of every link
	// receive the same value without the nodes having to agree on anything.
	if moved := deconflictOverlays(ctx, c, top); moved > 0 {
		fmt.Fprintf(errOut, "  moved %d overlay identifier(s) that another lab was using\n", moved)
	}

	// Refuse to build a lab whose links cannot fit through the fabric.
	if problems := c.CheckUnderlay(ctx, top); len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(errOut, "  "+p)
		}
		return fmt.Errorf("the underlay cannot carry this lab; fix the above or lower link_defaults.mtu")
	}

	// A cluster running mixed binaries produces results that cannot be
	// attributed to any one version, and the mismatch is otherwise invisible:
	// every node reports success while behaving differently.
	warnVersionSkew(ctx, c, errOut)

	start := time.Now()
	results := c.Apply(ctx, top, req)

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NODE\tSTEPS\tDURATION\tSTATUS")
	failed := 0
	for _, r := range results {
		if r.Err != nil {
			failed++
			fmt.Fprintf(w, "%s\t-\t-\t%s\n", r.Node, firstLine(r.Err.Error()))
			continue
		}
		status := "ok"
		if len(r.Value.Failures) > 0 {
			failed++
			status = fmt.Sprintf("%d scope(s) degraded", len(r.Value.Failures))
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", r.Node, r.Value.Steps,
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

	s := top.Stats()
	fmt.Fprintf(out, "\n%d devices, %d links (%d cross-node) across %d nodes in %s\n",
		s.Devices, s.Links, s.CrossNode, len(c.Nodes), time.Since(start).Round(time.Millisecond))

	if failed > 0 {
		return fmt.Errorf("%d node(s) reported problems; re-run deploy to converge", failed)
	}
	return nil
}
