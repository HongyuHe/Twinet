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
	)
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy the lab, converging whatever is already running",
		Long: `Deploy is idempotent. It compares what the manifest describes against what
is actually running and creates only what is missing, so it is safe to re-run
after a partial failure, a reboot, or a topology edit.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			top, err := load(opts)
			if err != nil {
				return err
			}
			rec, err := place.LoadRecord(labPrivateDir(top), top.Name)
			if err != nil {
				return err
			}
			adopted := false
			if rec == nil && !rebalance {
				// No record, but the lab may still be running -- deployed by
				// an earlier version, or the record lost. What is running is
				// the authority.
				rec, err = adoptRunningPlacement(cmd.Context(), top, token)
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
			a, err := place.Place(top, place.Options{Fixed: rec, Rebalance: rebalance})
			if err != nil {
				return err
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
			if err := resolveImageIDs(cmd.Context(), top, token); err != nil {
				return err
			}
			// Written before anything is created, so that a deploy which
			// fails half way leaves a record matching the containers that
			// did come up. Writing it afterwards would mean a crash left the
			// lab placed one way and the record saying another, which is the
			// drift the record exists to prevent.
			if !dryRun {
				if err := place.SaveRecord(labPrivateDir(top),
					a.Record(top.Name, strategyOf(top, rebalance, adopted))); err != nil {
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
				return deployCluster(cmd.Context(), top, tok, agent.ApplyRequest{
					Mode:       modeName(solve),
					PullPolicy: pull,
					Workers:    workers,
					DryRun:     dryRun,
					// A deployment that moves an autonomous system to a
					// different machine must remove it from the old one.
					//
					// Pruning was opt-in, and the engine's own comment says
					// what that costs: the moved system runs on both nodes and
					// announces the same prefix from two places, which is a
					// fault nobody would think to look for because both halves
					// look correct. A move is exactly when it matters, so a
					// move now prunes whether it was asked for or not.
					Prune:      (prune || rebalance) && only == "",
					Generation: time.Now().UTC().Format("20060102T150405"),
					OnlySteps:  scope,
				}, cmd.OutOrStdout(), cmd.ErrOrStderr())
			}

			rt := runtime.NewDocker()
			ver, err := rt.Ping(cmd.Context())
			if err != nil {
				return fmt.Errorf("cannot reach the container engine: %w", err)
			}
			if !quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "twinet: docker %s, lab %s (topology %s)\n",
					ver, top.Name, top.Hash)
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
				Runtime:         rt,
				Node:            node,
				State:           store,
				PullPolicy:      runtime.PullPolicy(pull),
				Renderer:        render.New(top, mode),
				Authoritative:   mode == render.ModeSolve,
				WritesReference: mode == render.ModeSolve,
				UnderlayIP:      underlayOf(top, node),
				PeerUnderlay:    peerUnderlays(top),
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
				return fmt.Errorf("nothing is placed on node %q; check placement.nodes", node)
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
		"deploy even though a node is asked for more than it declares room for")
	cmd.Flags().BoolVar(&rebalance, "rebalance", false,
		"recompute placement from scratch; every AS that moves has its containers rebuilt "+
			"and removed from the node it left")
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
		yes   bool
		lab   string
		keep  bool
		token string
	)
	cmd := &cobra.Command{
		Use:   "destroy",
		Short: "Remove every container and overlay object belonging to the lab",
		Long: `Destroy works from container labels, so it can clean up a deployment even
if the manifest that created it is no longer available.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var top *model.Topology
			name := lab
			var vnis []uint32
			if name == "" {
				t, err := loadAndPlace(opts)
				if err != nil {
					return fmt.Errorf("%w\n(pass --lab NAME to destroy without a manifest)", err)
				}
				top = t
				name = top.Name
				for _, l := range top.Links {
					vnis = append(vnis, l.VNI)
				}
			} else if t, err := loadAndPlace(opts); err == nil && clustered(t) {
				// A name and a manifest together: the name says which lab, the
				// manifest says which machines. Without this, naming a lab fell
				// straight through to the local container runtime and tried to
				// clean a cluster's lab up on this machine alone -- which is
				// also the instruction this code prints when a grading harness
				// fails to come down, so the documented recovery did not work.
				// Three abandoned harnesses were found on this cluster and
				// could not be removed with the command that names them.
				top = t
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
				var bad int
				for _, r := range c.Destroy(cmd.Context(), name, vnis) {
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

			rt := runtime.NewDocker()
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
			var strayVNIs []uint32
			if top == nil && !keep {
				if owned, oerr := netx.ListOverlaysOfLab(name); oerr == nil {
					strayVNIs = owned
				}
			}
			if len(cs) == 0 && len(strayVNIs) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "nothing to remove for lab %q\n", name)
				return nil
			}
			if len(cs) == 0 {
				eng := &deploy.Engine{Runtime: rt, Node: "local"}
				if err := eng.DestroyOverlays(strayVNIs); err != nil {
					return fmt.Errorf("removing the overlays of lab %q: %w", name, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"lab %q had no containers left, and %d overlay object(s) that it still "+
						"owned have been removed\n", name, len(strayVNIs))
				return nil
			}
			if !yes {
				fmt.Fprintf(cmd.OutOrStdout(), "about to remove %d containers of lab %q; pass --yes to proceed\n",
					len(cs), name)
				return nil
			}

			// Without a manifest there is no topology, and everything below
			// used to dereference one. `twinet destroy --lab NAME` -- the one
			// path the command's own help recommends for a lab whose manifest
			// is gone -- panicked with a nil pointer before removing anything.
			//
			// The containers carry their own identity in their labels, which is
			// what makes the command possible at all, so the devices are
			// reconstructed from them and the same preservation guarantee
			// holds either way.
			if top == nil {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"no manifest, so this removes lab %q from this machine only. "+
						"A lab spread over a cluster keeps running everywhere else; "+
						"destroy it with its manifest, or run this on each node.\n", name)
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
			// Without a manifest there are no VNIs to remove, and the overlays
			// were simply left behind: 461 VXLAN devices across three nodes
			// were found belonging to four labs whose containers had been
			// removed weeks earlier. They carry the owning lab's name on the
			// device itself, which is exactly so that this is possible without
			// consulting anything.
			if top == nil && !keep {
				vnis = append(vnis, strayVNIs...)
			}

			var left []string
			if !keep && len(vnis) > 0 {
				if err := eng.DestroyOverlays(vnis); err != nil {
					left = append(left, fmt.Sprintf("the overlay bridges and tunnels are "+
						"still in place (%v); the next deployment will find them and may "+
						"reuse them for a different lab", err))
				}
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
			fmt.Fprintf(cmd.OutOrStdout(), "removed %d containers of lab %q\n", len(cs), name)
			if len(left) > 0 {
				return fmt.Errorf("the containers are gone but the lab is not fully "+
					"removed:\n  %s", strings.Join(left, "\n  "))
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	cmd.Flags().StringVar(&lab, "lab", "", "lab name, when no manifest is available")
	cmd.Flags().BoolVar(&keep, "keep-overlays", false, "leave VXLAN bridges and tunnels in place")
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster deployments (or set TWINET_TOKEN)")
	return cmd
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
				local = runtime.NewDocker()
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
				got, err := n.ImageDigests(ctx, list)
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
			if err := sameEverywhere(byRef); err != nil {
				return err
			}
			if err := allOrNoneHaveIt(byRef, list, len(cl.Nodes)); err != nil {
				return err
			}
		}
	} else {
		rt := runtime.NewDocker()
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
		d.ImageID = seen[d.Image]
	}
	return nil
}

// sameEverywhere refuses a deployment whose nodes do not agree on what an image
// is.
//
// The alternative is to deploy anyway and let each student run whatever build
// happens to be on the node their AS landed on. Nothing downstream can detect
// that, and no report would mention it.
// allOrNoneHaveIt refuses a deployment in which some nodes hold an image and
// others do not.
//
// A node without the image is about to pull it, and the tag may have been
// rebuilt since the others pulled theirs -- so the deployment stamps the old
// digest into every container's specification while one node quietly runs new
// software. Nothing downstream can tell, and a student's mark then depends on
// which machine their autonomous system was placed on.
//
// Nobody having it is the ordinary first deployment and is allowed: they will
// all pull the same tag within seconds of each other, and the next deployment
// resolves and agrees.
func allOrNoneHaveIt(byRef map[string]map[string]string, refs []string, nodes int) error {
	if nodes <= 1 {
		return nil
	}
	var problems []string
	for _, ref := range refs {
		have := len(byRef[ref])
		if have == 0 || have == nodes {
			continue
		}
		problems = append(problems, fmt.Sprintf(
			"  %s is on %d of %d nodes (%s)", ref, have, nodes,
			strings.Join(sortedKeysOf(byRef[ref]), ", ")))
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("some nodes hold these images and some do not:\n%s\n"+
		"The nodes without them are about to pull, and if the tag has been rebuilt "+
		"since the others pulled theirs, half the lab runs different software while "+
		"every report says one thing. Pull on every node first (`docker pull <image>` "+
		"on each), or refer to the image by digest so the tag cannot move",
		strings.Join(problems, "\n"))
}

func sameEverywhere(byRef map[string]map[string]string) error {
	var problems []string
	for _, ref := range sortedKeysOf(byRef) {
		perNode := byRef[ref]
		ids := map[string][]string{}
		for node, id := range perNode {
			ids[id] = append(ids[id], node)
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
	r := &place.Record{Lab: top.Name, Strategy: "adopted", ByAS: map[int]string{}, ByService: map[string]string{}}
	conflict := map[int]string{}
	for _, c := range cs {
		node := c.Label(deploy.LabelNode)
		asn, err := strconv.Atoi(c.Label(deploy.LabelAS))
		if err != nil || node == "" {
			continue
		}
		if asn == 0 {
			if d := c.Label(deploy.LabelDevice); d != "" {
				r.ByService[serviceNameOf(top, d)] = node
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

// serviceNameOf maps a service device name back to the service that owns it.
func serviceNameOf(top *model.Topology, device string) string {
	for _, n := range top.SortedServiceNames() {
		if svc := top.Services[n]; svc != nil && svc.Device != nil && svc.Device.Name == device {
			return n
		}
	}
	return device
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
