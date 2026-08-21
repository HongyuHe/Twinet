package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/alloc"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
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
	var (
		token        string
		bootstrapPKI string
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
			fmt.Fprintln(w, "NODE\tSTATE\tVERSION\tRUNTIME\tALLOCATABLE\tRESERVED\tLOAD\tIMAGES\tUNDERLAY\tCONTAINERS\tLAB")
			bad, degraded := 0, 0
			for _, r := range results {
				if r.Err != nil {
					bad++
					fmt.Fprintf(w, "%s\tUNREACHABLE\t-\t-\t-\t-\t-\t%s\n", r.Node, firstLine(r.Err.Error()))
					continue
				}
				v := r.Value
				state, why := nodeState(v, Version)
				if state != "ok" {
					degraded++
				}
				lab := dash(v.Lab)
				if why != "" {
					lab = why
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s %s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
					r.Node, state, v.Version, v.Runtime, v.RuntimeVer,
					inventorySummary(v.Inventory.Allocatable), inventorySummary(v.Inventory.Reserved),
					loadSummary(v.Inventory.Load), imageCacheSummary(v.Inventory.ImageCache),
					dash(v.UnderlayIP), v.Containers, lab)
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
			tok, err := tokenFor(token)
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
				for _, suffix := range []string{"_server_cert.pem", "_server_key.pem"} {
					path := filepath.Join(bootstrapPKI, name+suffix)
					if _, err := os.Stat(path); err != nil {
						return fmt.Errorf("secure bootstrap needs %s: %w; rerun `twinet node pki`",
							path, err)
					}
				}
				fmt.Fprint(cmd.OutOrStdout(), bootstrapScript(n, tok, bootstrapPKI))
			}
			return nil
		},
	}
	bootstrap.Flags().StringVar(&bootstrapPKI, "pki", "",
		"directory produced by `twinet node pki`")

	cmd.AddCommand(status, check, bootstrap, newNodePKICmd(opts), newNodeSweepCmd(opts), newNodeDrainCmd(opts, &token))
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

func bootstrapScript(n model.NodeSpec, token, pkiDir string) string {
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
	serverCert := filepath.Join(pkiDir, n.Name+"_server_cert.pem")
	serverKey := filepath.Join(pkiDir, n.Name+"_server_key.pem")
	caCert := filepath.Join(pkiDir, "ca_cert.pem")
	controllerCert := filepath.Join(pkiDir, "controller_cert.pem")
	controllerKey := filepath.Join(pkiDir, "controller_key.pem")
	encodedToken := base64.StdEncoding.EncodeToString([]byte("TWINET_TOKEN=" + token))

	var b strings.Builder
	b.WriteString("set -euo pipefail\n")
	fmt.Fprintf(&b, "# ---- %s ----\n", n.Name)
	fmt.Fprintf(&b, "scp bin/twinetd root@%s:/usr/local/bin/twinetd\n", n.Name)
	fmt.Fprintf(&b, "ssh root@%s 'install -d -m 0700 /etc/twinet/pki'\n", n.Name)
	fmt.Fprintf(&b, "scp %q root@%s:/etc/twinet/pki/server_cert.pem\n", serverCert, n.Name)
	fmt.Fprintf(&b, "scp %q root@%s:/etc/twinet/pki/server_key.pem\n", serverKey, n.Name)
	fmt.Fprintf(&b, "scp %q root@%s:/etc/twinet/pki/ca_cert.pem\n", caCert, n.Name)
	// The token goes in a file only root can read, not in the unit.
	//
	// A systemd unit is world-readable by default and `Environment=` puts the
	// value in plain sight -- so the cluster secret was legible to every
	// account on the node, including the unprivileged one an evaluated RCA
	// agent runs as. That agent could read it, discard its own read-only
	// credential, and act as the controller across every lab on the cluster.
	fmt.Fprintf(&b, "ssh root@%s 'set -e\n", n.Name)
	b.WriteString("command -v docker >/dev/null 2>&1 || { echo \"Docker is required on this node\" >&2; exit 1; }\n")
	b.WriteString("docker version >/dev/null\n")
	b.WriteString("install -d -m 0700 /etc/twinet /var/lib/twinet/state\n")
	fmt.Fprintf(&b, "umask 077; printf %%s %s | base64 -d > /etc/twinet/agent.env\n",
		encodedToken)
	b.WriteString("chmod 0600 /etc/twinet/agent.env\n")
	b.WriteString("chmod 0600 /etc/twinet/pki/server_key.pem\n")
	b.WriteString("chmod 0644 /etc/twinet/pki/server_cert.pem /etc/twinet/pki/ca_cert.pem\n")
	b.WriteString("cat > /etc/systemd/system/twinetd.service <<UNIT\n")
	b.WriteString("[Unit]\nDescription=Twinet node agent\nAfter=docker.service\nRequires=docker.service\n\n")
	b.WriteString("[Service]\nType=simple\n")
	b.WriteString("EnvironmentFile=/etc/twinet/agent.env\n")
	fmt.Fprintf(&b, "ExecStart=/usr/local/bin/twinetd -node %s -listen %s", n.Name, listen)
	if n.UnderlayIP != "" {
		fmt.Fprintf(&b, " -underlay-ip %s", n.UnderlayIP)
	}
	b.WriteString(" -tls-cert /etc/twinet/pki/server_cert.pem")
	b.WriteString(" -tls-key /etc/twinet/pki/server_key.pem")
	b.WriteString(" -client-ca /etc/twinet/pki/ca_cert.pem")
	b.WriteString("\nRestart=always\nRestartSec=2\n")
	// The agent creates namespaces and rewires the host, so it needs the
	// capabilities; it does not need the rest of root's authority.
	b.WriteString("AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_RAW\n")
	b.WriteString("CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER CAP_SETUID CAP_SETGID\n")
	b.WriteString("NoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\n")
	b.WriteString("LimitNOFILE=1048576\nTasksMax=infinity\n\n")
	b.WriteString("[Install]\nWantedBy=multi-user.target\nUNIT\n")
	b.WriteString("systemctl daemon-reload && systemctl enable --now twinetd\n")
	b.WriteString("systemctl is-active --quiet twinetd || { journalctl -u twinetd -n 50 --no-pager >&2; exit 1; }'\n")
	fmt.Fprintf(&b, "twinet_token=$(printf %%s %s | base64 -d); twinet_token=${twinet_token#TWINET_TOKEN=}\n",
		encodedToken)
	fmt.Fprintf(&b, "curl --fail --silent --show-error --cacert %q --cert %q --key %q "+
		"-H \"Authorization: Bearer $twinet_token\" https://%s/v1/status >/dev/null\n",
		caCert, controllerCert, controllerKey, listen)
	fmt.Fprintf(&b, "echo '%s: secure agent is healthy at https://%s'\n\n", n.Name, listen)
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

// checkVersionSkew refuses to deploy when a node's agent is not this build.
//
// It used to print a warning and carry on, on the reasonable-sounding grounds
// that a version difference is usually harmless. It is not harmless here,
// because the agent renders the device configuration. A controller that has
// learned to emit a route distinguisher, or a VRF, or a label-switching stanza
// hands the node a topology, and the node's older renderer produces the
// configuration it already knew how to produce. Both halves report success.
// The deploy says it converged, the manifest is right, the controller's own
// tests pass, and the routers are configured differently from what anybody
// asked for.
//
// That is not hypothetical: it cost an afternoon during the MPLS work, where
// the controller emitted the right distinguisher and every router came up with
// none, because the agents were four commits behind.
//
// A warning is the wrong shape for this. It appears in a stream of ordinary
// output, everything downstream still reports success, and the person reading
// it has no reason to think the result is invalid. Refusing is the only
// response that cannot be missed.
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

	// Admission must precede overlay deconfliction, state migration, record
	// writes by callers, and every node mutation. A capacity refusal after
	// any of those has already changed the cluster it was meant to protect.
	if req.StrictAdmission {
		if err := c.Admit(ctx, top, true, req.Overcommit); err != nil {
			return fmt.Errorf("strict admission refused deployment before mutation: %w", err)
		}
	}

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
	if err := checkVersionSkew(ctx, c); err != nil {
		if os.Getenv("TWINET_ALLOW_VERSION_SKEW") == "" {
			return err
		}
		fmt.Fprintf(errOut, "  warning (skew allowed): %v\n", err)
	}

	start := time.Now()
	results, durable := c.ApplyDurable(ctx, top, req, durability)
	if durable.Moved > 0 {
		fmt.Fprintf(errOut, "  moved %d device(s) through fresh durable state transfer\n", durable.Moved)
	}
	for _, audit := range durable.Audit {
		fmt.Fprintln(errOut, "  AUDIT: "+audit)
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NODE\tSTEPS\tDURATION\tSTATUS")
	failed := 0
	devices, links, wantDev, wantLink := 0, 0, 0, 0
	reached := 0
	for _, r := range results {
		if r.Err != nil {
			failed++
			fmt.Fprintf(w, "%s\t-\t-\t%s\n", r.Node, firstLine(r.Err.Error()))
			continue
		}
		reached++
		devices += r.Value.Devices
		links += r.Value.Links
		wantDev += r.Value.WantDevice
		wantLink += r.Value.WantLinks
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

	// Summed from what the nodes reported doing, not from the manifest. A
	// cross-node link is wired from both ends, so the per-node totals count it
	// twice. Subtracting the topology's cross-node count undoes that, but only
	// for a run that covered the whole topology: with --only, or a node that
	// did not answer, the endpoints summed here are a subset the manifest's
	// figure says nothing about. Those cases report endpoints and say so
	// rather than printing a link count they cannot support.
	s := top.Stats()
	whole := failed == 0 && reached == len(c.Nodes) && len(req.OnlySteps) == 0
	if req.DryRun {
		if whole {
			fmt.Fprintf(out, "\ndry run: %d devices and %d links would be deployed "+
				"across %d nodes; nothing was changed\n",
				wantDev, wantLink-s.CrossNode, len(c.Nodes))
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
		fmt.Fprintf(out, "\n%d devices, %d links (%d cross-node) across %d nodes in %s\n",
			devices, links-s.CrossNode, s.CrossNode, len(c.Nodes),
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
	return nil
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
func nodeState(v agent.StatusResponse, controller string) (state, why string) {
	switch {
	case v.RuntimeVer == "":
		return "no-runtime", "the container runtime did not answer"
	case controller != "" && v.Version != "" && v.Version != controller:
		return "skewed", fmt.Sprintf("agent %s, controller %s: they render configuration "+
			"differently", v.Version, controller)
	case len(v.Busy) > 0:
		return "busy", "operation in flight: " + strings.Join(v.Busy, ", ")
	}
	return "ok", ""
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
			fmt.Fprintln(w, "NODE\tORPHANS\tREMOVED\tIN USE\tNOTE")
			bad, total := 0, 0
			for _, r := range results {
				if r.Err != nil {
					bad++
					fmt.Fprintf(w, "%s\t-\t-\t-\t%s\n", r.Node, firstLine(r.Err.Error()))
					continue
				}
				v := r.Value
				total += len(v.Orphans)
				note := ""
				if len(v.Errs) > 0 {
					note = strings.Join(v.Errs, "; ")
				}
				fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%s\n",
					r.Node, len(v.Orphans), len(v.Removed), len(v.InUse), note)
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
