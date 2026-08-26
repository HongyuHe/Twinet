package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/images"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
	"github.com/HongyuHe/twinet/internal/place"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/render"
	"github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

func newDeployCmd(opts *Options) *cobra.Command {
	var (
		solve      bool
		dryRun     bool
		workers    int
		pull       string
		only       string
		quiet      bool
		token      string
		prune      bool
		rebalance  bool
		overcommit bool
		allowStale bool
		allowLoss  bool
	)
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy the lab, converging whatever is already running",
		Long: `Deploy is idempotent. It compares what the manifest describes against what
is actually running and creates only what is missing, so it is safe to re-run
after a partial failure, a reboot, or a topology edit.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			phases := deployPhaseTimings{}
			// Rebalancing moves systems between machines, and pruning is what
			// removes them from the machine they left. A scope switches
			// pruning off, because a scoped deploy has not looked at the
			// devices outside it and must not delete them -- so asking for
			// both is asking for a move whose old copy is left running,
			// announcing the same prefix from two places. Both halves then
			// look correct, which is why nobody would think to look.
			if rebalance && only != "" {
				return fmt.Errorf("--rebalance moves autonomous systems between " +
					"machines and --only stops the deployment from removing them " +
					"from the machine they left, so the moved system would run in " +
					"both places and announce its prefix from both. Rebalance the " +
					"whole lab, or move nothing")
			}
			var top *model.Topology
			err := phases.measure("topology", func() error {
				var loadErr error
				top, loadErr = load(opts)
				return loadErr
			})
			if err != nil {
				return err
			}
			warnSingleNodeDurability(cmd.ErrOrStderr(), top)
			var rec *place.Record
			err = phases.measure("placement_record", func() error {
				var recordErr error
				rec, recordErr = place.LoadRecord(labPrivateDir(top), top.Name)
				return recordErr
			})
			if err != nil {
				return err
			}
			adopted := false
			if rec == nil && !rebalance {
				// No record, but the lab may still be running -- deployed by
				// an earlier version, or the record lost. What is running is
				// the authority.
				err = phases.measure("placement_adoption", func() error {
					var adoptErr error
					rec, adoptErr = adoptRunningPlacement(cmd.Context(), top, token)
					return adoptErr
				})
				if err != nil {
					return err
				}
				if rec != nil {
					adopted = true
					fmt.Fprintf(cmd.ErrOrStderr(),
						"adopted the placement of the %d autonomous systems already running\n",
						len(rec.ByAS))
				}
			}
			// A completed placement record lets the controller ask every
			// agent for one read-only desired/observed witness before it pays
			// for inventory, image resolution, leases, and a transaction
			// journal. Any dirty/semantic/contract drift falls through to the
			// ordinary fenced path below.
			if clustered(top) && !dryRun && !rebalance && !prune && !overcommit && only == "" && rec != nil {
				if _, err := place.Place(top, place.Options{Fixed: rec}); err != nil {
					return err
				}
				tok, err := tokenFor(token)
				if err != nil {
					return err
				}
				var noop bool
				if err := phases.measure("noop_preflight", func() error {
					var preflightErr error
					noop, preflightErr = tryClusterNoop(cmd.Context(), top, tok, modeName(solve), 0,
						opts.Verbose, opts.JSON,
						cmd.OutOrStdout(), cmd.ErrOrStderr())
					return preflightErr
				}); err != nil {
					return err
				}
				if noop {
					phases.print(cmd.ErrOrStderr())
					return nil
				}
			}
			var inventory []place.NodeInventory
			if clustered(top) {
				tok, err := tokenFor(token)
				if err != nil {
					return err
				}
				cluster := client.NewCluster(top.Lab, tok)
				var lost []string
				err = phases.measure("cluster_status", func() error {
					lost = unavailableClusterNodes(cluster.Status(cmd.Context()))
					return nil
				})
				if err != nil {
					return err
				}
				if len(lost) > 0 {
					if top.Lab.Placement.OnNodeLoss != "reschedule" {
						return fmt.Errorf("cluster health check failed before placement; %s is unavailable and placement.on_node_loss is %q",
							strings.Join(lost, ", "), effectiveNodeLossPolicy(top.Lab))
					}
					if rec == nil {
						return fmt.Errorf("cannot reschedule unavailable node(s) %s without a committed placement record; "+
							"refusing to guess which student state must be recovered", strings.Join(lost, ", "))
					}
					if err := removeUnavailableNodes(top.Lab, lost); err != nil {
						return err
					}
					if err := ensureSurvivingDurability(top.Lab); err != nil {
						return err
					}
					fmt.Fprintf(cmd.ErrOrStderr(),
						"AUDIT: placement.on_node_loss=reschedule removes unavailable node(s) %s; restoring only verified replicas\n",
						strings.Join(lost, ", "))
					cluster = client.NewCluster(top.Lab, tok)
				}
				if err := phases.measure("cluster_health", func() error { return cluster.HealthCheck(cmd.Context()) }); err != nil {
					return err
				}
				err = phases.measure("inventory", func() error {
					var inventoryErr error
					inventory, inventoryErr = cluster.Inventories(cmd.Context())
					return inventoryErr
				})
				if err != nil {
					if !overcommit {
						return fmt.Errorf("strict admission requires live inventory before placement: %w", err)
					}
					fmt.Fprintf(cmd.ErrOrStderr(),
						"AUDIT: --overcommit bypasses unavailable live inventory for lab %q: %v\n",
						top.Name, err)
					inventory = nil
				}
			}
			var a *place.Assignment
			err = phases.measure("placement", func() error {
				var placementErr error
				a, placementErr = place.Place(top, place.Options{
					Fixed: rec, Rebalance: rebalance, Inventory: inventory,
					Strict: clustered(top), Overcommit: overcommit,
				})
				return placementErr
			})
			if err != nil {
				return err
			}
			// Re-read inventory after placement and before saving its record.
			// The first read informed placement; this one makes the strict
			// refusal boundary explicit even if another lab changed while the
			// graph was being partitioned.
			if clustered(top) {
				tok, err := tokenFor(token)
				if err != nil {
					return err
				}
				if err := phases.measure("admission_record", func() error {
					return client.NewCluster(top.Lab, tok).Admit(cmd.Context(), top, true, overcommit)
				}); err != nil {
					return fmt.Errorf("strict admission refused deployment before placement record write: %w", err)
				}
			}
			warnAboutMoves(cmd.ErrOrStderr(), a, rebalance)
			// A node asked for more than it declares is refused rather than
			// warned about, for the same reason a mixed-version cluster is: a
			// warning arrives in a stream of ordinary output, everything after
			// it reports success, and the person reading has no reason to
			// think the result is wrong. The failure it predicts arrives an
			// hour later as containers killed under load, which reads as a
			// broken lab rather than as a placement that never fitted.
			//
			// The budgets are written by hand, so a stale one must not be able
			// to stop a class: --overcommit is the way past, and saying so in
			// the refusal is what keeps the check from being deleted instead.
			if len(a.Overloaded) > 0 && !overcommit {
				return fmt.Errorf("this lab does not fit the cluster it is placed on:\n  %s\n"+
					"Raise the node budgets in the manifest, add a node, or pass "+
					"--overcommit to deploy anyway", strings.Join(a.Overloaded, "\n  "))
			}
			if overcommit {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"AUDIT: --overcommit accepted placement for lab %q; requests may exceed live allocatable capacity\n",
					top.Name)
			}
			if err := phases.measure("image_resolution", func() error {
				return resolveImageIDs(cmd.Context(), top, token)
			}); err != nil {
				return err
			}
			record := a.Record(top.Name, strategyOf(top, rebalance, adopted))
			record.Overcommit = overcommit
			if !dryRun && !clustered(top) {
				if err := place.SaveRecord(labPrivateDir(top), record); err != nil {
					return fmt.Errorf("recording where the lab was placed: %w", err)
				}
			}
			scope, err := parseScope(only)
			if err != nil {
				return err
			}

			if clustered(top) {
				tok, err := tokenFor(token)
				if err != nil {
					return err
				}
				// Stage immediately before the fenced operation, after every
				// local validation that can still fail without touching a node.
				if !dryRun {
					if err := place.StageRecord(labPrivateDir(top), record); err != nil {
						return fmt.Errorf("staging where the lab will be placed: %w", err)
					}
				}
				moved := placementRecordMoved(rec, record)
				var deployErr error
				_ = phases.measure("deploy_transaction", func() error {
					deployErr = deployCluster(cmd.Context(), top, tok, agent.ApplyRequest{
						Mode:            modeName(solve),
						PullPolicy:      pull,
						Workers:         workers,
						DryRun:          dryRun,
						StrictAdmission: true,
						Overcommit:      overcommit,
						// A deployment that moves an autonomous system to a
						// different machine must remove it from the old one.
						//
						// Pruning was opt-in, and the engine's own comment says
						// what that costs: the moved system runs on both nodes and
						// announces the same prefix from two places, which is a
						// fault nobody would think to look for because both halves
						// look correct. A move is exactly when it matters, so a
						// move now prunes whether it was asked for or not.
						Prune:      (prune || rebalance || moved) && only == "",
						Generation: time.Now().UTC().Format("20060102T150405"),
						OnlySteps:  scope,
					}, client.DurabilityOptions{
						Previous: rec, AllowStaleState: allowStale, AllowDataLoss: allowLoss,
					}, cmd.OutOrStdout(), cmd.ErrOrStderr())
					return deployErr
				})
				if deployErr != nil {
					if !dryRun {
						if discardErr := place.DiscardStagedRecord(labPrivateDir(top)); discardErr != nil {
							return fmt.Errorf("%w; also could not discard uncommitted placement: %v", deployErr, discardErr)
						}
					}
					return deployErr
				}
				if !dryRun {
					if err := place.CommitStagedRecord(labPrivateDir(top)); err != nil {
						return fmt.Errorf("deployment committed but placement record could not be committed: %w", err)
					}
				}
				phases.print(cmd.ErrOrStderr())
				return nil
			}

			rt, err := localRuntime(top)
			if err != nil {
				return err
			}
			ver, err := rt.Ping(cmd.Context())
			if err != nil {
				return fmt.Errorf("cannot reach the container engine: %w", err)
			}
			if !quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "twinet: %s %s, lab %s (topology %s)\n",
					rt.Name(), ver, top.Name, top.Hash)
			}

			mode := render.ModePlatform
			if solve {
				mode = render.ModeSolve
			}
			node := localNode(top)
			// Without a state store the engine's preservation path is dead
			// code: a container replaced by a redeploy comes back with the
			// image's configuration and the student's work is gone. The local
			// path used to run exactly that way, so the guarantee documented
			// for the cluster silently did not hold for a single node.
			store, err := localStore(top)
			if err != nil {
				return err
			}
			// Remembered so that a later destroy of a solved lab does not file
			// the reference as each student's saved configuration.
			if !dryRun {
				recordLabMode(top, string(mode))
			}
			eng := &deploy.Engine{
				Runtime:                rt,
				Node:                   node,
				State:                  store,
				PullPolicy:             runtime.PullPolicy(pull),
				Renderer:               render.New(top, mode),
				Authoritative:          mode == render.ModeSolve,
				WritesReference:        mode == render.ModeSolve,
				UnderlayIP:             underlayOf(top, node),
				PeerUnderlay:           peerUnderlays(top),
				RequireImmutableImages: top.Lab.Images.RequiresImmutableImages(),
			}

			p, err := eng.Build(top)
			if err != nil {
				return err
			}
			if len(scope) > 0 {
				want := map[string]bool{}
				for _, s := range scope {
					want[s] = true
				}
				p = p.Restrict(func(st *plan.Step) bool { return want[st.Scope] })
			}
			if p.Len() == 0 {
				if len(scope) > 0 {
					return fmt.Errorf("nothing is placed on node %q; check placement.nodes", node)
				}
				if !quiet {
					fmt.Fprintln(cmd.OutOrStdout(), "no changes; lab is already converged")
				}
				return nil
			}

			obs := newProgress(cmd.OutOrStdout(), p.Len(), quiet)
			start := time.Now()
			rep, err := p.Execute(cmd.Context(), plan.Options{
				Workers:         workers,
				Observer:        obs,
				ContinueOnError: true,
				DryRun:          dryRun,
			})
			obs.done()
			if err != nil {
				return err
			}

			// Counted from what the run actually did, not from the manifest.
			// top.Stats() is the lab as written, which is the same number for a
			// --dry-run that touched nothing, for an --only that built one AS,
			// and for a deploy that fell over half way.
			devices := rep.Completed(plan.StageCreate)
			links := rep.Completed(plan.StageWire)
			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(),
					"\ndry run: %d devices and %d links would be deployed; nothing was changed\n",
					rep.Planned(plan.StageCreate), rep.Planned(plan.StageWire))
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"\ndeployed %d devices and %d links in %s\n",
				devices, links, rep.Duration.Round(time.Millisecond))
			if rep.Failed() {
				fmt.Fprintln(cmd.ErrOrStderr())
				printScopeFailures(cmd.ErrOrStderr(), rep)
				return fmt.Errorf("%d scope(s) degraded; re-run deploy to converge them",
					len(rep.FailedScopes()))
			}
			_ = start
			return nil
		},
	}
	cmd.Flags().BoolVar(&solve, "solve", false,
		"also apply the reference solution, for smoke-testing the platform")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would happen without doing it")
	cmd.Flags().IntVar(&workers, "workers", 0, "concurrency (default: 4x CPU count)")
	cmd.Flags().StringVar(&pull, "pull", "if-missing", "image pull policy: if-missing, always, never")
	cmd.Flags().StringVar(&only, "only", "",
		"restrict the work to a scope, e.g. as=12, peering or services; the topology stays whole")
	cmd.Flags().BoolVar(&prune, "prune", false,
		"also remove containers and overlays this topology no longer wants")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress per-step progress")
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster deployments (or set TWINET_TOKEN)")
	cmd.Flags().BoolVar(&overcommit, "overcommit", false,
		"audited escape hatch: deploy despite strict live-capacity admission")
	cmd.Flags().BoolVar(&rebalance, "rebalance", false,
		"recompute placement from scratch; every AS that moves has its containers rebuilt "+
			"and removed from the node it left")
	cmd.Flags().BoolVar(&allowStale, "allow-stale-state", false,
		"AUDIT: permit migration from stored state after fresh capture cannot be proved")
	cmd.Flags().BoolVar(&allowLoss, "allow-data-loss", false,
		"AUDIT: permit migration when no verified durable replica can be found")
	return cmd
}

// modeName maps the --solve flag onto the renderer's mode.
func modeName(solve bool) string {
	if solve {
		return string(render.ModeSolve)
	}
	return string(render.ModePlatform)
}

func newDestroyCmd(opts *Options) *cobra.Command {
	var (
		yes       bool
		lab       string
		keep      bool
		force     bool
		token     string
		localOnly bool
	)
	cmd := &cobra.Command{
		Use:   "destroy",
		Short: "Remove every container and overlay object belonging to the lab",
		Long: `Destroy removes a lab from every machine its manifest places it on.

Container labels say what belongs to the lab, so a deployment whose manifest has
been edited since can still be removed. The manifest is what says which machines
to reach. Without one there is nothing that can prove the lab is not still
running on another node, so --lab NAME on its own refuses to remove anything
rather than cleaning up this machine and reporting the lab gone.

--this-node-only is the explicit exception, and its scope is exactly its name:
the containers lab NAME has on this machine, and the overlay objects it owns
here that no longer carry a cable. No other node is contacted or changed, and
the removal is reported as this machine's alone. It needs --runtime as well,
because without a manifest nothing says which container engine created the lab,
and asking the wrong one reports an empty machine.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var top *model.Topology
			name := lab
			var vnis []uint32
			if name == "" {
				if localOnly {
					return fmt.Errorf("--this-node-only limits the scope of a named lab; " +
						"pass --lab NAME, or drop it to destroy the manifest's own lab")
				}
				t, err := loadAndPlace(opts)
				if err != nil {
					return fmt.Errorf("%w\n(pass --lab NAME with the lab's manifest to destroy "+
						"a lab whose name you know)", err)
				}
				top = t
				name = top.Name
				for _, l := range top.Links {
					vnis = append(vnis, l.VNI)
				}
			} else if !localOnly {
				// A name and a manifest together: the name says which lab, the
				// manifest says which machines. Without this, naming a lab fell
				// straight through to the local container runtime and tried to
				// clean a cluster's lab up on this machine alone -- which is
				// also the instruction this code prints when a grading harness
				// fails to come down, so the documented recovery did not work.
				// Three abandoned harnesses were found on this cluster and
				// could not be removed with the command that names them.
				//
				// A manifest describing this very lab is used whether or not it
				// is clustered: it carries the runtime, the node the devices
				// are placed on, and the identifiers of the overlays to remove,
				// none of which a container label can supply.
				if t, err := load(opts); err == nil && (t.Name == name || clustered(t)) {
					top = t
					if t.Name == name {
						for _, l := range top.Links {
							vnis = append(vnis, l.VNI)
						}
					}
				}
			}

			if top != nil && clustered(top) {
				tok, err := tokenFor(token)
				if err != nil {
					return err
				}
				if !yes {
					fmt.Fprintf(cmd.OutOrStdout(),
						"about to remove lab %q from %d nodes; pass --yes to proceed\n",
						name, len(top.Lab.Placement.Nodes))
					return nil
				}
				c := client.NewCluster(top.Lab, tok)
				destroy := c.Destroy
				if force {
					destroy = c.DestroyForce
				}
				var bad int
				for _, r := range destroy(cmd.Context(), name, vnis) {
					if r.Err != nil {
						bad++
						fmt.Fprintf(cmd.ErrOrStderr(), "  %s: %v\n", r.Node, r.Err)
					}
				}
				if bad > 0 {
					return fmt.Errorf("%d node(s) failed to clean up", bad)
				}
				// The record describes containers that no longer exist.
				// Leaving it pinned the next deployment to an arrangement
				// chosen for a lab that is gone -- the single-node path
				// removed it and this one returned first.
				//
				// Only when the lab being destroyed is the manifest's own.
				// Destroying a grading harness by name uses the class manifest
				// to say which machines to reach, and this then deleted the
				// *class's* record: the next deployment placed a running lab
				// again from scratch, `inspect --placement` disagreed with
				// what was actually running, and exec against three systems
				// answered 404 from the wrong nodes. Observed on this cluster.
				if name != top.Name {
					fmt.Fprintf(cmd.OutOrStdout(), "removed lab %q from %d nodes\n",
						name, len(c.Nodes))
					return nil
				}
				if err := os.Remove(filepath.Join(labPrivateDir(top), place.RecordName)); err != nil &&
					!errors.Is(err, os.ErrNotExist) {
					fmt.Fprintf(cmd.ErrOrStderr(), "note: the placement record could not be "+
						"cleared (%v); the next deployment will be pinned to the arrangement "+
						"chosen for the lab that has just been removed\n", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "removed lab %q from %d nodes\n",
					name, len(c.Nodes))
				return nil
			}

			// Everything below this point acts on this machine alone.
			//
			// With a manifest that is the whole lab, because the manifest is
			// what says which machines the lab is on. Without one it is a claim
			// nothing can check: `destroy --lab NAME` selected the default
			// Docker backend, found none of a containerd cluster's containers,
			// deleted the overlay objects this machine held for the lab,
			// printed a success, and left the lab running on three nodes with
			// its cross-node cables cut. A cleanup that cannot see the lab must
			// not report having removed it, so it refuses instead.
			if top == nil {
				if !localOnly {
					return fmt.Errorf("refusing to remove lab %q from a name alone: no manifest "+
						"was loaded from %q, so nothing here can tell whether the lab is running "+
						"on other machines, which engine created it, or which overlay objects are "+
						"still carrying its traffic.\n"+
						"  - to remove the whole lab, run this with its manifest: "+
						"twinet -m PATH destroy --lab %s --yes\n"+
						"  - to clean up abandoned objects across a cluster you can still reach, "+
						"use: twinet -m PATH node sweep --remove\n"+
						"  - to remove only what this one machine holds, say so explicitly: "+
						"twinet --runtime ENGINE destroy --lab %s --this-node-only --yes",
						name, opts.Manifest, name, name)
				}
				if strings.TrimSpace(opts.Runtime) == "" {
					return fmt.Errorf("--this-node-only has no manifest to read the container "+
						"engine from, and a lab is invisible to the wrong one: pass --runtime "+
						"(%s) so that an empty answer means the machine is empty rather than "+
						"that the wrong daemon was asked",
						strings.Join(runtime.RuntimeNames(), ", "))
				}
			}

			var rt runtime.Runtime
			if top != nil {
				local, err := localRuntime(top)
				if err != nil {
					return err
				}
				rt = local
			} else {
				local, err := localRuntimeNamed(opts.Runtime, opts.RuntimeSocket)
				if err != nil {
					return err
				}
				rt = local
			}
			// What this invocation can honestly speak for, named in every
			// message it prints. "nothing to remove for lab x" and "removed lab
			// x" mean different things on one machine and on a cluster, and the
			// reader cannot tell which they got unless it is said.
			machineOnly := top == nil
			scope := destroyScope(name, machineOnly)
			cs, err := rt.List(cmd.Context(), runtime.Filter{
				All: true, Labels: map[string]string{deploy.LabelLab: name}})
			if err != nil {
				return err
			}
			// The overlays are looked for before concluding there is nothing
			// here. A lab can have no containers left and still own hundreds of
			// VXLAN devices -- that is exactly the state an earlier destroy
			// left behind -- and "nothing to remove" was then untrue in the
			// most expensive way, because the identifiers stayed in use and the
			// next lab deriving the same ones would have joined its traffic to
			// a lab that no longer exists.
			//
			// They carry the owning lab's name on the device itself, which is
			// exactly so that this is possible without consulting anything.
			var owned []uint32
			var ownedErr error
			if !keep {
				owned, ownedErr = netx.ListOverlaysOfLab(name)
				if ownedErr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"note: this machine's overlay objects could not be listed (%v)\n", ownedErr)
				}
			}
			if len(cs) == 0 && len(owned) == 0 {
				if ownedErr != nil {
					// "Nothing to remove" would be a conclusion drawn from a
					// question that failed, which is the same mistake in a
					// smaller font.
					return fmt.Errorf("%s has no containers, but its overlay objects could not "+
						"be listed, so nothing here can say the lab is gone: %w", scope, ownedErr)
				}
				fmt.Fprint(cmd.OutOrStdout(), destroyNoOpMessage(name, machineOnly))
				return nil
			}
			if len(cs) == 0 {
				if !yes {
					fmt.Fprintf(cmd.OutOrStdout(),
						"%s has no containers left and %d overlay object(s) it still owns; "+
							"pass --yes to remove them\n", scope, len(owned))
					return nil
				}
				eng := &deploy.Engine{Runtime: rt, Node: "local"}
				removed, kept, err := removeIdleOverlays(eng.DestroyOverlays, name, owned)
				if err != nil {
					return fmt.Errorf("removing the overlays of %s: %w", scope, err)
				}
				if len(removed) == 0 {
					fmt.Fprintf(cmd.OutOrStdout(),
						"%s had no containers left, and none of its %d overlay object(s) "+
							"was removed\n", scope, len(owned))
					reportKeptOverlays(cmd.OutOrStdout(), kept)
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"%s had no containers left, and %d overlay object(s) that it still "+
						"owned have been removed\n", scope, len(removed))
				reportKeptOverlays(cmd.OutOrStdout(), kept)
				return nil
			}
			if !yes {
				fmt.Fprintf(cmd.OutOrStdout(), "about to remove %d containers of %s; pass --yes to proceed\n",
					len(cs), scope)
				return nil
			}

			// Without a manifest there is no topology, and everything below
			// used to dereference one. `twinet destroy --lab NAME` -- the one
			// path the command's own help recommended for a lab whose manifest
			// is gone -- panicked with a nil pointer before removing anything.
			//
			// The containers carry their own identity in their labels, which is
			// what makes this possible at all, so the devices are reconstructed
			// from them and the same preservation guarantee holds either way.
			if top == nil {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"no manifest: this removes lab %q from this machine only -- its containers "+
						"here, and the overlay endpoints those containers were using here. No "+
						"other machine is contacted or changed, and a lab spread over a cluster "+
						"keeps running everywhere else.\n", name)
			}
			store, err := destroyStore(top)
			if err != nil {
				return err
			}
			devTop := top
			if devTop == nil {
				devTop = topologyFromLabels(name, cs)
			}
			// A destroy of a solved lab must not file the reference as each
			// student's saved configuration. The cluster path was fixed and
			// this one, which single-node labs use, was not.
			// The node the devices are actually placed on, not the string
			// "local".
			//
			// CaptureAll selects devices by node, and with a manifest they are
			// placed on the machine's real name -- so this matched nothing,
			// captured nothing, reported "captured 0 snapshots" and then
			// removed the containers. The reconstructed devices of the
			// manifest-less path are the ones that are "local".
			capNode := "local"
			if top != nil {
				capNode = localNode(top)
			}
			eng := &deploy.Engine{Runtime: rt, Node: capNode, State: store,
				WritesReference: labWasSolved(top)}
			// Capture before removing. A destroy that discards a student's
			// configuration without recording it is unrecoverable, and the
			// person running it is usually not the person who loses the work.
			if n, err := eng.CaptureAll(cmd.Context(), devTop, store); err != nil {
				return fmt.Errorf("refusing to destroy %s: its configuration could not be captured first: %w", name, err)
			} else if n > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "captured %d configuration snapshots before destroy\n", n)
			}
			if err := eng.Destroy(cmd.Context(), name); err != nil {
				return err
			}
			// What is left behind is collected rather than warned about. A
			// leftover bridge or a stale placement record is not visible in
			// `docker ps`, so the next deployment inherits it and fails in a
			// way that has nothing to do with the cause -- and "removed 212
			// containers" scrolling past is not something anybody re-reads.
			// 461 VXLAN devices across three nodes were found belonging to four
			// labs whose containers had been removed weeks earlier.
			vnis = append(vnis, owned...)

			var left []string
			var keptOverlays []uint32
			if !keep && len(vnis) > 0 {
				_, kept, err := removeIdleOverlays(eng.DestroyOverlays, name, vnis)
				if err != nil {
					left = append(left, fmt.Sprintf("the overlay bridges and tunnels are "+
						"still in place (%v); the next deployment will find them and may "+
						"reuse them for a different lab", err))
				}
				keptOverlays = kept
			}
			// The record describes containers that no longer exist. Leaving it
			// would pin the next deployment to an arrangement chosen for a lab
			// that is gone, and silently forgo any improvement to the placer.
			if top != nil {
				if err := os.Remove(filepath.Join(labPrivateDir(top), place.RecordName)); err != nil &&
					!errors.Is(err, os.ErrNotExist) {
					left = append(left, fmt.Sprintf("the placement record could not be "+
						"cleared (%v); the next deployment will be pinned to the "+
						"arrangement chosen for the lab that has just been removed", err))
				}
			}
			fmt.Fprint(cmd.OutOrStdout(), destroyRemovedMessage(len(cs), name, machineOnly))
			reportKeptOverlays(cmd.OutOrStdout(), keptOverlays)
			if len(left) > 0 {
				return fmt.Errorf("the containers are gone but the lab is not fully "+
					"removed:\n  %s", strings.Join(left, "\n  "))
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	cmd.Flags().StringVar(&lab, "lab", "",
		"name of the lab to remove; needs this lab's manifest, or --this-node-only")
	cmd.Flags().BoolVar(&localOnly, "this-node-only", false,
		"remove only what the named lab has on this machine; no other node is contacted or "+
			"changed, and overlay objects still carrying an interface are kept")
	cmd.Flags().BoolVar(&keep, "keep-overlays", false, "leave VXLAN bridges and tunnels in place")
	cmd.Flags().BoolVar(&force, "force", false,
		"skip state capture and irreversibly remove an orphaned cluster lab")
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster deployments (or set TWINET_TOKEN)")
	return cmd
}

// destroyScope, destroyNoOpMessage, and destroyRemovedMessage keep the wording
// of an outcome next to the thing that decides it.
//
// "nothing to remove for lab cos461" and "removed lab cos461" were printed by a
// command that had inspected one machine of three, and nothing in either line
// said so. The reader cannot check a scope they were not told about, which is
// how a lab was reported gone while it was still running on two other nodes.
func destroyScope(name string, machineOnly bool) string {
	if machineOnly {
		return fmt.Sprintf("lab %q on this machine", name)
	}
	return fmt.Sprintf("lab %q", name)
}

func destroyNoOpMessage(name string, machineOnly bool) string {
	out := fmt.Sprintf("nothing to remove for %s\n", destroyScope(name, machineOnly))
	if machineOnly {
		out += "no other machine was inspected, and none was changed\n"
	}
	return out
}

func destroyRemovedMessage(containers int, name string, machineOnly bool) string {
	out := fmt.Sprintf("removed %d containers of %s\n", containers, destroyScope(name, machineOnly))
	if machineOnly {
		out += "no other machine was contacted, and none was changed\n"
	}
	return out
}

// overlayPortsOfLab reports how many interfaces are still attached to each
// overlay object a lab owns on this machine. It is a variable so the rule that
// depends on it can be tested without a host to build overlays on.
var overlayPortsOfLab = netx.OverlayPortsOfLab

// removeIdleOverlays removes the overlay objects of a lab that nothing is
// attached to any more, and reports the ones it deliberately left alone.
//
// An overlay whose bridge still has a port is carrying a cable for something,
// whatever an ownership record says. Cutting it is not a cleanup: it is a
// silent outage in whatever is still using it, and the machine that runs the
// cleanup is rarely the machine that notices. This is the same rule `twinet
// node sweep` applies, so a lab cannot be cleaned up more aggressively by
// naming it than by sweeping for it.
func removeIdleOverlays(remove func([]uint32) error, lab string, candidates []uint32) (removed, kept []uint32, err error) {
	if len(candidates) == 0 {
		return nil, nil, nil
	}
	ports, portErr := overlayPortsOfLab(lab)
	if portErr != nil {
		// Not knowing which overlays are in use is a reason to remove none of
		// them. An identifier still held is recoverable; a live link cut by a
		// cleanup that could not see it is not.
		return nil, candidates, fmt.Errorf("cannot tell which overlay objects of lab %q are "+
			"still carrying traffic, so none were removed: %w", lab, portErr)
	}
	seen := map[uint32]bool{}
	for _, vni := range candidates {
		if seen[vni] {
			continue
		}
		seen[vni] = true
		if ports[vni] > 0 {
			kept = append(kept, vni)
			continue
		}
		removed = append(removed, vni)
	}
	sort.Slice(removed, func(i, j int) bool { return removed[i] < removed[j] })
	sort.Slice(kept, func(i, j int) bool { return kept[i] < kept[j] })
	if len(removed) == 0 {
		return nil, kept, nil
	}
	if err := remove(removed); err != nil {
		return nil, append(kept, removed...), err
	}
	return removed, kept, nil
}

// reportKeptOverlays says what was left behind and why, rather than letting a
// count of removals imply that everything is gone.
func reportKeptOverlays(out io.Writer, kept []uint32) {
	if len(kept) == 0 {
		return
	}
	names := make([]string, 0, len(kept))
	for _, vni := range kept {
		names = append(names, strconv.FormatUint(uint64(vni), 10))
	}
	fmt.Fprintf(out, "kept %d overlay object(s) that still have an interface attached "+
		"(VNI %s); something is using them, so they were not removed\n",
		len(kept), strings.Join(names, ", "))
}

func newExecCmd(opts *Options) *cobra.Command {
	var (
		asFilter int
		kind     string
		all      bool
		token    string
	)
	cmd := &cobra.Command{
		Use:   "exec [device] -- command...",
		Short: "Run a command in one device or across many",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}

			var targets []*model.Device
			var command []string
			if all || asFilter > 0 || kind != "" {
				command = args
				for _, d := range top.SortedDevices() {
					if asFilter > 0 && d.ASN != asFilter {
						continue
					}
					if kind != "" && string(d.Kind) != kind {
						continue
					}
					targets = append(targets, d)
				}
			} else {
				if len(args) < 2 {
					return fmt.Errorf("usage: twinet exec <device> -- <command>")
				}
				d, ok := resolveDevice(top, args[0])
				if !ok {
					return fmt.Errorf("no device %q; try `twinet inspect`", args[0])
				}
				targets = []*model.Device{d}
				command = args[1:]
			}
			if len(targets) == 0 {
				return fmt.Errorf("no devices matched")
			}

			// Fan out: running one command across a hundred routers is a
			// routine operational need, and doing it serially is why the legacy
			// platform's equivalent scripts took minutes. When the lab spans a
			// cluster the command is brokered through each device's own node,
			// so a student or a TA never needs to know or care where their AS
			// happens to be running.
			type out struct {
				dev *model.Device
				res runtime.ExecResult
				err error
			}

			var (
				cluster *client.Cluster
				local   runtime.Runtime
			)
			if clustered(top) {
				tok, err := tokenFor(token)
				if err != nil {
					return err
				}
				cluster = client.NewCluster(top.Lab, tok)
			} else {
				local, err = localRuntime(top)
				if err != nil {
					return err
				}
			}

			runOne := func(ctx context.Context, d *model.Device) (runtime.ExecResult, error) {
				if cluster == nil {
					return local.Exec(ctx, d.Container, runtime.ExecCmd{Cmd: command})
				}
				n, ok := cluster.Node(d.Node)
				if !ok {
					return runtime.ExecResult{}, fmt.Errorf("device %s is placed on unknown node %q", d.ID, d.Node)
				}
				r, err := n.Exec(ctx, agent.ExecRequest{Container: d.Container, Cmd: command})
				return runtime.ExecResult{ExitCode: r.ExitCode, Stdout: r.Stdout, Stderr: r.Stderr}, err
			}

			results := make([]out, len(targets))
			var wg sync.WaitGroup
			sem := make(chan struct{}, 32)
			for i, d := range targets {
				wg.Add(1)
				go func(i int, d *model.Device) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					res, err := runOne(cmd.Context(), d)
					results[i] = out{dev: d, res: res, err: err}
				}(i, d)
			}
			wg.Wait()

			failed := 0
			for _, r := range results {
				if len(targets) > 1 {
					fmt.Fprintf(cmd.OutOrStdout(), "=== %s ===\n", r.dev.ID)
				}
				if r.err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "%v\n", r.err)
					failed++
					continue
				}
				if r.res.Stdout != "" {
					fmt.Fprint(cmd.OutOrStdout(), r.res.Stdout)
				}
				if r.res.Stderr != "" {
					fmt.Fprint(cmd.ErrOrStderr(), r.res.Stderr)
				}
				if r.res.ExitCode != 0 {
					failed++
				}
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d command(s) failed", failed, len(targets))
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&asFilter, "as", 0, "run across every device of one AS")
	cmd.Flags().StringVar(&kind, "kind", "", "run across every device of one kind")
	cmd.Flags().BoolVar(&all, "all", false, "run across every device")
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs (or set TWINET_TOKEN)")
	return cmd
}

// loadAndPlace loads, validates, expands and places the topology.
// resolveImageIDs stamps each device with the digest its image reference
// currently resolves to.
//
// A tag rebuilt in place is different software under an unchanged name. Without
// this the spec hash never moves, so the new image is never deployed: the lab
// keeps running the old one while every report says it is up to date.
func resolveImageIDs(ctx context.Context, top *model.Topology, token string) error {
	refs := map[string]bool{}
	for _, d := range top.Devices {
		if d.Image != "" {
			refs[d.Image] = true
		}
	}
	list := make([]string, 0, len(refs))
	for r := range refs {
		list = append(list, r)
	}
	sort.Strings(list)
	// A reference that advertises a digest it cannot honour is refused before
	// any node is contacted: it is neither a pin nor an honest tag, and every
	// check below would reason about it as though it were one or the other.
	if err := refuseMalformedPins(list); err != nil {
		return err
	}

	// The agents are asked, not the local machine. The controller need not run
	// containers at all, and here it could not even talk to the daemon -- so
	// resolving locally returned nothing for every image, the spec hash never
	// moved, and a rebuilt image was never deployed. The symptom was a fix that
	// simply did not appear in the lab, with every report saying the deployment
	// was current.
	seen := map[string]string{}
	if clustered(top) {
		if tok, err := tokenFor(token); err == nil {
			cl := client.NewCluster(top.Lab, tok)
			required := requiredImageNodes(top)
			// Every node is asked, and their answers are compared.
			//
			// This used to accept the first node's answer and stop. Nodes drift
			// -- one is rebuilt, a push half-succeeds, a pull is interrupted --
			// and when they do, a student's routers run whichever build landed
			// on whichever node their AS was placed on. Measured on this
			// cluster: all four images differed between node-0 and the other
			// two while every report said the deployment was current. A mark
			// that depends on where a container was scheduled is not a mark,
			// and nothing anywhere would have said so.
			byRef := map[string]map[string]string{}
			for _, n := range cl.Nodes {
				var needed []string
				for _, ref := range list {
					if required[ref][n.Name] {
						needed = append(needed, ref)
					}
				}
				if len(needed) == 0 {
					continue
				}
				got, err := n.ImageDigests(ctx, needed)
				if err != nil {
					continue
				}
				for ref, id := range got {
					if id == "" {
						// Not pulled here yet; the deployment will pull it.
						continue
					}
					if byRef[ref] == nil {
						byRef[ref] = map[string]string{}
					}
					byRef[ref][n.Name] = id
					seen[ref] = id
				}
			}
			// Pinned references are held to the stronger rule first, so a
			// cache that disagrees with the locked manifest is named as
			// exactly that rather than as a tag that might have moved.
			if err := imageCachesAllowDeployment(byRef, required); err != nil {
				return err
			}
		}
	} else {
		rt, err := localRuntime(top)
		if err != nil {
			return err
		}
		for _, ref := range list {
			// An image that is not here yet will be pulled, and the deployment
			// that pulls it stamps the identity next time; refusing here would
			// make a first deploy impossible.
			if id, err := rt.ImageDigest(ctx, ref); err == nil {
				seen[ref] = id
			}
		}
	}

	for _, d := range top.SortedDevices() {
		d.ImageID = stampedImageIdentity(d.Image, seen, d.ImageID)
	}
	return nil
}

// stampedImageIdentity decides what a device's image identity is, given what
// the survey found.
//
// An immutable reference is its own identity and outranks anything a cache
// says. A runtime answers a digest query with whatever local alias it holds --
// a repository-qualified spelling, a config ID, an entry left by an earlier
// pull of the same tag -- and adopting that would replace an authored,
// verified digest with an identity nothing has proven, and would move the
// container spec hash between two callers that were given the same lock.
//
// An identity the caller already established survives an empty survey: a
// release or grading lock has stamped the required manifest, and this is the
// first pull, so no node had anything to report.
func stampedImageIdentity(ref string, surveyed map[string]string, current string) string {
	if pinned := images.Digest(ref); pinned != "" {
		return pinned
	}
	if resolved := surveyed[ref]; resolved != "" {
		return resolved
	}
	return current
}

// imageCachesAllowDeployment is every refusal the preflight survey can make,
// in the order that produces the most specific message.
//
// A pinned reference is judged against the manifest it names; a tag is judged
// against the other nodes, because nothing else can speak for it.
func imageCachesAllowDeployment(byRef map[string]map[string]string,
	required map[string]map[string]bool,
) error {
	if err := pinnedCachesMatchTheirDigest(byRef); err != nil {
		return err
	}
	if err := sameEverywhere(byRef); err != nil {
		return err
	}
	return allOrNoneHaveIt(byRef, required)
}

// refuseMalformedPins rejects a reference that claims a sha256 digest but does
// not carry a well-formed one.
//
// Such a reference cannot be verified after the pull and cannot be trusted
// before it, and treating it as a mutable tag would let it deploy on the
// strength of a coincidence: nothing about `@sha256:deadbeef` says the author
// meant a moving tag.
func refuseMalformedPins(refs []string) error {
	var problems []string
	for _, ref := range refs {
		if images.ClaimsDigest(ref) && !images.IsImmutable(ref) {
			problems = append(problems, "  "+ref)
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("these image references claim a digest that is not one:\n%s\n"+
		"A sha256 manifest digest is exactly 64 lower-case hexadecimal characters. "+
		"Correct the reference, or regenerate the image lock with `twinet images lock` "+
		"so the deployment pulls a manifest it can prove",
		strings.Join(problems, "\n"))
}

// pinnedCachesMatchTheirDigest refuses a node whose cache answers a
// digest-pinned reference with a different manifest.
//
// Every node was asked about the same immutable reference, so there is one
// correct answer and it is written in the reference itself. A node that
// reports another manifest under it is not a tag that moved -- it is a cache
// that cannot be believed, and the same query after the pull would fail the
// transaction anyway, so it is refused here where nothing has been touched.
func pinnedCachesMatchTheirDigest(byRef map[string]map[string]string) error {
	var problems []string
	for _, ref := range sortedKeysOf(byRef) {
		want := images.Digest(ref)
		if want == "" {
			continue
		}
		for _, node := range sortedKeysOf(byRef[ref]) {
			got := byRef[ref][node]
			if images.SameDigest(ref, got) {
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"  %s is %s on %s, not the pinned %s", ref, got, node, want))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("these nodes hold something other than the pinned manifest:\n%s\n"+
		"The reference names one manifest and cannot mean another, so this cache "+
		"cannot serve it. Remove the image on the listed node and let the "+
		"deployment pull the pinned digest again",
		strings.Join(problems, "\n"))
}

func requiredImageNodes(top *model.Topology) map[string]map[string]bool {
	required := map[string]map[string]bool{}
	if top == nil {
		return required
	}
	for _, device := range top.Devices {
		if device.Image == "" || device.Node == "" {
			continue
		}
		if required[device.Image] == nil {
			required[device.Image] = map[string]bool{}
		}
		required[device.Image][device.Node] = true
	}
	return required
}

// allOrNoneHaveIt refuses a deployment in which only some of the nodes that
// will run a *mutable* image reference hold it.
//
// A required node without the image is about to pull it, and the tag may have
// been rebuilt since the other required nodes pulled theirs -- so the
// deployment stamps the old digest into every container's specification while
// one node quietly runs new software. Nodes that will not run this image do not
// participate in its coherence boundary.
//
// No required node having it is the ordinary first deployment and is allowed:
// they will all pull the same tag within seconds of each other, and the next
// deployment resolves and agrees.
//
// A digest-pinned reference has no such hazard and is not refused. A
// registry reference of the form repository@sha256:... names one manifest, so
// a node that is missing it can only pull that manifest or fail; unequal
// caches are then an ordinary consequence of a partial run, not a source of
// divergence. Refusing them blocked the release scale benchmark on any cluster
// whose nodes had not pulled identically, and the refusal's own remedy -- pin
// it by digest -- was already in force, which left the operator with nothing
// to do but preload the images by hand. What makes this safe is not the survey
// but the proof afterwards: every assigned node reports its post-pull digest
// and the transaction refuses to commit unless each one is the locked
// manifest.
func allOrNoneHaveIt(byRef map[string]map[string]string,
	required map[string]map[string]bool,
) error {
	var problems []string
	for _, ref := range sortedKeysOf(required) {
		want := required[ref]
		// A bare sha256 identity is not exempt: it names no registry, so a
		// node that lacks it has nothing to pull, and the deployment should
		// say so here rather than fail halfway through.
		if len(want) <= 1 || images.IsImmutable(ref) {
			continue
		}
		var have, missing []string
		for _, node := range sortedKeysOf(want) {
			if byRef[ref][node] != "" {
				have = append(have, node)
			} else {
				missing = append(missing, node)
			}
		}
		if len(have) == 0 || len(missing) == 0 {
			continue
		}
		problems = append(problems, fmt.Sprintf(
			"  %s is cached on %s but missing from %s", ref,
			strings.Join(have, ", "), strings.Join(missing, ", ")))
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("the nodes assigned these mutable image tags do not share one cache state:\n%s\n"+
		"The missing nodes are about to pull, and if the tag has been rebuilt since "+
		"the other assigned nodes pulled theirs, the lab can run different software "+
		"under one name. Preload the image through the selected runtime on every "+
		"listed node, or pin it by digest so the tag cannot move",
		strings.Join(problems, "\n"))
}

// sameEverywhere refuses a deployment whose nodes do not agree on what a
// mutable tag is.
//
// The alternative is to deploy anyway and let each student run whatever build
// happens to be on the node their AS landed on. Nothing downstream can detect
// that, and no report would mention it.
//
// Digest-pinned references are answered by pinnedCachesMatchTheirDigest, which
// compares each node against the manifest the reference names rather than
// against the other nodes -- a stricter question with an answer an operator can
// act on, and one whose remedy is not the pinning that is already in force.
func sameEverywhere(byRef map[string]map[string]string) error {
	var problems []string
	for _, ref := range sortedKeysOf(byRef) {
		if images.Digest(ref) != "" {
			continue
		}
		perNode := byRef[ref]
		ids := map[string][]string{}
		for node, id := range perNode {
			// Runtimes spell the same manifest differently: containerd
			// answers with the bare digest, Docker with a repository-qualified
			// one. Comparing the spelling would refuse a cluster that agrees.
			key := id
			if digest := images.Digest(id); digest != "" {
				key = digest
			}
			ids[key] = append(ids[key], node)
		}
		if len(ids) <= 1 {
			continue
		}
		var parts []string
		for _, id := range sortedKeysOf(ids) {
			nodes := ids[id]
			sort.Strings(nodes)
			parts = append(parts, fmt.Sprintf("%s on %s", shortID(id), strings.Join(nodes, ",")))
		}
		problems = append(problems, fmt.Sprintf("  %s is %s", ref, strings.Join(parts, "; ")))
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("the nodes do not agree on what these images are:\n%s\n"+
		"A student's devices would run whichever build landed on the node their\n"+
		"system was placed on, and no report would say so. Push the images again\n"+
		"and pull them everywhere, or pin them by digest in the manifest",
		strings.Join(problems, "\n"))
}

func sortedKeysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func shortID(id string) string {
	if i := strings.IndexByte(id, ':'); i >= 0 {
		id = id[i+1:]
	}
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// loadAndPlace resolves the manifest and works out which node every device is
// on.
//
// The recorded placement is honoured whenever there is one. Every command that
// touches a device -- exec, grade, save, restore, the gateway -- resolves it
// through here, so if this returned a different answer than the deploy did, all
// of them would look for containers on nodes that do not have them. That is not
// hypothetical: adding one student to a running term moved seven of the other
// ten autonomous systems, and `twinet exec` then failed on each of them with
// "no such container", which reads like a broken lab.
func loadAndPlace(opts *Options) (*model.Topology, error) {
	top, err := load(opts)
	if err != nil {
		return nil, err
	}
	if _, err := placeWithRecord(top, false); err != nil {
		return nil, err
	}
	return top, nil
}

func loadAndPlaceUnpinned(opts *Options) (*model.Topology, error) {
	top, err := loadExpanded(opts, false)
	if err != nil {
		return nil, err
	}
	if _, err := placeWithRecord(top, false); err != nil {
		return nil, err
	}
	return top, nil
}

// labPrivateDir is where the controller keeps what it knows about a lab.
func labPrivateDir(top *model.Topology) string {
	return filepath.Join(top.Lab.Dir, ".twinet")
}

// placeWithRecord places the topology, honouring the record of where the lab
// was last deployed.
func placeWithRecord(top *model.Topology, rebalance bool) (*place.Assignment, error) {
	rec, err := place.LoadRecord(labPrivateDir(top), top.Name)
	if err != nil {
		return nil, err
	}
	return place.Place(top, place.Options{Fixed: rec, Rebalance: rebalance})
}

// localNode picks the node this invocation acts for. Single-node labs use the
// front node; cluster deployments will resolve by hostname in the agent.
func localNode(top *model.Topology) string {
	host, _ := os.Hostname()
	if _, ok := top.Lab.NodeByName(host); ok {
		return host
	}
	if i := strings.IndexByte(host, '.'); i > 0 {
		if _, ok := top.Lab.NodeByName(host[:i]); ok {
			return host[:i]
		}
	}
	return top.Lab.FrontNode()
}

func underlayOf(top *model.Topology, node string) string {
	if n, ok := top.Lab.NodeByName(node); ok {
		return n.UnderlayIP
	}
	return ""
}

func peerUnderlays(top *model.Topology) map[string]string {
	out := map[string]string{}
	for _, n := range top.Lab.Placement.Nodes {
		if n.UnderlayIP != "" {
			out[n.Name] = n.UnderlayIP
		}
	}
	return out
}

// parseScope turns a --only selector into the plan scopes it names.
func parseScope(sel string) ([]string, error) {
	switch {
	case sel == "":
		return nil, nil
	case strings.HasPrefix(sel, "as="):
		var asn int
		if _, err := fmt.Sscanf(sel, "as=%d", &asn); err != nil || asn <= 0 {
			return nil, fmt.Errorf("bad selector %q; use as=12", sel)
		}
		return []string{fmt.Sprintf("as%d", asn)}, nil
	case sel == "services":
		return []string{"services"}, nil
	case sel == "peering":
		return []string{"peering"}, nil
	default:
		return nil, fmt.Errorf("unknown selector %q; use as=N, peering or services", sel)
	}
}

func resolveDevice(top *model.Topology, name string) (*model.Device, bool) {
	if d, ok := top.Device(name); ok {
		return d, true
	}
	var found *model.Device
	n := 0
	for _, d := range top.SortedDevices() {
		if d.Name == name || d.Container == name {
			found = d
			n++
		}
	}
	if n == 1 {
		return found, true
	}
	return nil, false
}

func printScopeFailures(w io.Writer, rep *plan.Report) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SCOPE\tFAILURE")
	for _, s := range rep.FailedScopes() {
		for _, e := range rep.ScopeErrors[s] {
			fmt.Fprintf(tw, "%s\t%s\n", s, firstLine(e.Error()))
		}
	}
	_ = tw.Flush()
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// progress renders deployment progress without drowning the terminal when a
// thousand containers are coming up at once.
type progress struct {
	mu      sync.Mutex
	w       io.Writer
	total   int
	done_   int
	quiet   bool
	lastLen int
	start   time.Time
	failed  []string
}

func newProgress(w io.Writer, total int, quiet bool) *progress {
	return &progress{w: w, total: total, quiet: quiet, start: time.Now()}
}

func (p *progress) StepStarted(*plan.Step) {}

func (p *progress) StepFinished(r plan.Result) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done_++
	if r.Err != nil {
		p.failed = append(p.failed, r.Step.Describe)
	}
	if p.quiet {
		return
	}
	line := fmt.Sprintf("  [%d/%d] %s", p.done_, p.total, r.Step.Describe)
	if r.Err != nil {
		line = fmt.Sprintf("  [%d/%d] FAILED %s: %s", p.done_, p.total, r.Step.Describe, firstLine(r.Err.Error()))
	}
	if len(line) > 100 {
		line = line[:97] + "..."
	}
	pad := ""
	if n := p.lastLen - len(line); n > 0 {
		pad = strings.Repeat(" ", n)
	}
	if r.Err != nil {
		fmt.Fprintf(p.w, "\r%s%s\n", line, pad)
		p.lastLen = 0
		return
	}
	fmt.Fprintf(p.w, "\r%s%s", line, pad)
	p.lastLen = len(line)
}

func (p *progress) done() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.quiet && p.lastLen > 0 {
		fmt.Fprintf(p.w, "\r%s\r", strings.Repeat(" ", p.lastLen))
	}
}

var _ = sort.Strings
var _ = context.Background

// localStore opens the snapshot store a single-node lab keeps beside its
// manifest, so that the same preservation guarantees hold whether a lab runs on
// one machine or a cluster.
func localStore(top *model.Topology) (*state.Store, error) {
	dir := filepath.Join(top.Lab.Dir, ".twinet", "state")
	st, err := state.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("open state store %s: %w", dir, err)
	}
	return st, nil
}

// strategyOf names the strategy the record was produced with.
func strategyOf(top *model.Topology, rebalance, adopted bool) string {
	s := top.Lab.Placement.Strategy
	if s == "" {
		s = "pack-by-as"
	}

	switch {
	case rebalance:
		return s + " (rebalanced)"
	case adopted:
		// The placer did not choose this; the running containers did. Saying
		// so matters, because it explains an assignment the strategy would
		// not produce and would otherwise look like a bug in the placer.
		return s + " (adopted from the running lab)"
	}
	return s
}

// warnSingleNodeDurability keeps the loss boundary visible at the command that
// starts a lab. Manifest validation also warns, but deploy output is commonly
// the only log an operator retains.
func warnSingleNodeDurability(w io.Writer, top *model.Topology) {
	if top == nil || top.Lab == nil || clustered(top) {
		return
	}
	fmt.Fprintf(w,
		"WARNING: %s is single-node; student state has one local durable copy and cannot survive this node or disk loss\n",
		top.Name)
}

func placementRecordMoved(previous, next *place.Record) bool {
	if previous == nil || next == nil {
		return false
	}
	changed := func(before, after map[string]string) bool {
		for key, old := range before {
			if now, ok := after[key]; ok && now != old {
				return true
			}
		}
		return false
	}
	beforeAS, afterAS := map[string]string{}, map[string]string{}
	for asn, node := range previous.ByAS {
		beforeAS[strconv.Itoa(asn)] = node
	}
	for asn, node := range next.ByAS {
		afterAS[strconv.Itoa(asn)] = node
	}
	return changed(beforeAS, afterAS) ||
		changed(previous.ByGroup, next.ByGroup) ||
		changed(previous.ByService, next.ByService) ||
		changed(previous.ByServiceReplica, next.ByServiceReplica)
}

func unavailableClusterNodes(results []client.NodeResult[agent.StatusResponse]) []string {
	var out []string
	for _, result := range results {
		if result.Err != nil || (result.Value.StateStoreHealthy != nil && !*result.Value.StateStoreHealthy) {
			out = append(out, result.Node)
		}
	}
	sort.Strings(out)
	return out
}

func effectiveNodeLossPolicy(lab *model.Lab) string {
	if lab == nil || lab.Placement.OnNodeLoss == "" {
		return "fail"
	}
	return lab.Placement.OnNodeLoss
}

func removeUnavailableNodes(lab *model.Lab, unavailable []string) error {
	if lab == nil {
		return fmt.Errorf("cannot remove unavailable nodes from a nil lab")
	}
	skip := map[string]bool{}
	for _, name := range unavailable {
		skip[name] = true
	}
	kept := make([]model.NodeSpec, 0, len(lab.Placement.Nodes))
	for _, node := range lab.Placement.Nodes {
		if !skip[node.Name] {
			kept = append(kept, node)
		}
	}
	if len(kept) == 0 {
		return fmt.Errorf("all placement nodes are unavailable")
	}
	lab.Placement.Nodes = kept
	lab.Normalize()
	return nil
}

func ensureSurvivingDurability(lab *model.Lab) error {
	if lab == nil {
		return fmt.Errorf("durability needs a lab")
	}
	domains := map[string]bool{}
	for _, node := range lab.Placement.Nodes {
		domains[node.Domain()] = true
	}
	if need := lab.State.ReplicationFactor; need > len(domains) {
		return fmt.Errorf("cannot reschedule safely: durable replication factor %d needs %d surviving failure domains, but only %d remain",
			need, need, len(domains))
	}
	return nil
}

// warnAboutMoves says out loud when an AS is not where it was.
//
// Moving an AS destroys and rebuilds every container in it, so a student's
// running processes, shell history and anything not captured by preservation
// are lost. That is sometimes the right thing -- a node has been removed, or a
// rebalance was asked for -- but it is never something to discover afterwards.
func warnAboutMoves(w io.Writer, a *place.Assignment, rebalance bool) {
	// Said on every path, including --rebalance, because a node being asked
	// for more than it has is exactly what a rebalance can produce.
	for _, o := range a.Overloaded {
		fmt.Fprintf(w, "warning: %s; the containers that do not fit are killed under "+
			"load rather than refused now, which looks like a broken lab\n", o)
	}
	if rebalance {
		fmt.Fprintln(w, "warning: --rebalance recomputes placement; every AS that moves "+
			"has its containers destroyed and rebuilt")
		return
	}
	for _, m := range a.Moved {
		fmt.Fprintf(w, "warning: %s, so it moves and its containers are rebuilt\n", m)
	}
}

// adoptRunningPlacement reconstructs the record from the containers that are
// actually running.
//
// A lab can be running with no record: it was deployed by an earlier version,
// or the record was lost, or somebody cleaned the lab directory. Placing it
// afresh in that state is the worst available outcome, because the arithmetic
// silently disagrees with reality and every command that has to find a device
// reports "no such container" while the container is running perfectly well one
// node over. What is running is the authority; the record only remembers it.
func adoptRunningPlacement(ctx context.Context, top *model.Topology, token string) (*place.Record, error) {
	if !clustered(top) {
		return nil, nil
	}
	tok, tokErr := tokenFor(token)
	if tokErr != nil {
		// Without a token nothing can be asked, and the deploy that follows
		// will fail on the same missing token with a clearer message than
		// this one could give.
		return nil, nil //nolint:nilerr // deploy reports the missing token
	}
	cs, errs := client.NewCluster(top.Lab, tok).Containers(ctx, top.Name)
	if len(errs) > 0 {
		// A node that cannot be asked might be holding half the lab. Adopting
		// what the reachable ones say would pin those and re-place the rest,
		// which is a worse answer than declining to adopt at all.
		return nil, fmt.Errorf("the running placement could not be read from every node (%v); "+
			"fix the unreachable node, or pass --rebalance to place the lab afresh "+
			"and accept that containers move", errs[0])
	}
	if len(cs) == 0 {
		return nil, nil
	}
	r := &place.Record{Lab: top.Name, Strategy: "adopted", ByAS: map[int]string{},
		ByService: map[string]string{}, ByServiceReplica: map[string]string{}}
	conflict := map[int]string{}
	for _, c := range cs {
		node := c.Label(deploy.LabelNode)
		asn, err := strconv.Atoi(c.Label(deploy.LabelAS))
		if err != nil || node == "" {
			continue
		}
		if asn == 0 {
			if d := c.Label(deploy.LabelDevice); d != "" {
				service, replica := serviceRecordKeyOf(top, d)
				if replica != "" {
					r.ByServiceReplica[replica] = node
					if r.ByService[service] == "" {
						r.ByService[service] = node
					}
				} else {
					r.ByService[service] = node
				}
			}
			continue
		}
		if prev, ok := r.ByAS[asn]; ok && prev != node {
			conflict[asn] = prev + " and " + node
			continue
		}
		r.ByAS[asn] = node
	}
	if len(conflict) > 0 {
		var parts []string
		for asn, where := range conflict {
			parts = append(parts, fmt.Sprintf("AS %d has containers on %s", asn, where))
		}
		sort.Strings(parts)
		return nil, fmt.Errorf("the running lab is already split across nodes, which placement "+
			"never produces:\n  %s\nRun `twinet destroy` and deploy again, or pass --rebalance",
			strings.Join(parts, "\n  "))
	}
	return r, nil
}

// serviceRecordKeyOf maps a service container name to its service and stable
// replica record key. Legacy singleton callers receive an empty replica key.
func serviceRecordKeyOf(top *model.Topology, device string) (string, string) {
	for _, n := range top.SortedServiceNames() {
		service := top.Services[n]
		if service == nil {
			continue
		}
		for _, replica := range service.SortedReplicas() {
			if replica != nil && replica.Device != nil && replica.Device.Name == device {
				return n, replica.ID
			}
		}
		if service.Device != nil && service.Device.Name == device {
			return n, ""
		}
	}
	return device, ""
}

// destroyStore opens the snapshot store to capture into before a destroy.
//
// With a manifest that is the store beside it. Without one there is nowhere
// obvious, so it goes under the working directory -- the alternative was
// dereferencing a topology that is not there, which is what this command did.
func destroyStore(top *model.Topology) (*state.Store, error) {
	if top != nil {
		return localStore(top)
	}
	dir := filepath.Join(".twinet", "state")
	st, err := state.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("open state store %s: %w", dir, err)
	}
	return st, nil
}

// topologyFromLabels reconstructs just enough of a topology to capture what the
// containers hold, from the labels they carry.
//
// It is not the lab: there are no links, and no addresses. It is the set of
// devices, their kinds and their autonomous systems, which is what capturing
// configuration needs and all that a container can tell us about itself.
func topologyFromLabels(lab string, cs []runtime.Container) *model.Topology {
	top := &model.Topology{
		Name:    lab,
		Lab:     &model.Lab{Metadata: model.Meta{Name: lab}},
		Devices: map[string]*model.Device{},
		ASes:    map[int]*model.AS{},
	}
	for _, c := range cs {
		id := c.Labels[deploy.LabelDeviceID]
		if id == "" {
			continue
		}
		asn, _ := strconv.Atoi(c.Labels[deploy.LabelAS])
		d := &model.Device{
			ID:        id,
			Name:      c.Labels[deploy.LabelDevice],
			Kind:      model.DeviceKind(c.Labels[deploy.LabelKind]),
			ASN:       asn,
			Container: c.Name,
			Owner:     c.Labels[deploy.LabelOwner],
			// The node this device is on, as far as the engine reading it is
			// concerned, is this one: these containers were found by asking
			// this machine's daemon. Leaving it empty made CaptureAll -- which
			// selects devices by node -- match nothing at all, so a destroy
			// without a manifest reported "captured 0 snapshots" and removed a
			// term's work. The engine that does the capturing is constructed
			// with node "local", so that is what they are.
			Node: "local",
		}
		top.Devices[id] = d
		if asn > 0 {
			as, ok := top.ASes[asn]
			if !ok {
				// Every reconstructed system is treated as a student's.
				//
				// Only student-owned devices are captured, and a container's
				// labels do not record whose the AS was. Guessing "not a
				// student's" means destroying work without saving it, which
				// cannot be undone; guessing the other way costs some snapshots
				// of the platform's own configuration, which cost nothing.
				as = &model.AS{ASN: asn, Role: model.RoleStudent}
				top.ASes[asn] = as
			}
			as.Devices = append(as.Devices, d)
		}
	}
	return top
}

// labWasSolved reports whether a single-node lab's recorded state says it was
// last deployed with the reference solution on it.
//
// A cluster records the mode with the topology on each node. A single-node lab
// keeps its state beside the manifest, so the same question is answered from
// the marker the deploy writes there.
func labWasSolved(top *model.Topology) bool {
	if top == nil {
		// Without a manifest there is nothing that says otherwise, and the
		// safe assumption is the one that does not file the answer as work.
		return false
	}
	raw, err := os.ReadFile(filepath.Join(labPrivateDir(top), "mode"))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(raw)) == string(render.ModeSolve)
}

// recordLabMode remembers how a single-node lab was last deployed.
func recordLabMode(top *model.Topology, mode string) {
	dir := labPrivateDir(top)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "mode"), []byte(mode), 0o644)
}
