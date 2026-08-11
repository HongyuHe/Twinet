package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/render"
	"github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

func newDeployCmd(opts *Options) *cobra.Command {
	var (
		solve   bool
		dryRun  bool
		workers int
		pull    string
		only    string
		quiet   bool
		token   string
		prune   bool
	)
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy the lab, converging whatever is already running",
		Long: `Deploy is idempotent. It compares what the manifest describes against what
is actually running and creates only what is missing, so it is safe to re-run
after a partial failure, a reboot, or a topology edit.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			resolveImageIDs(cmd.Context(), top, token)
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
					Prune:      prune && only == "",
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
			eng := &deploy.Engine{
				Runtime:       rt,
				Node:          node,
				State:         store,
				PullPolicy:    runtime.PullPolicy(pull),
				Renderer:      render.New(top, mode),
				Authoritative: mode == render.ModeSolve,
				UnderlayIP:    underlayOf(top, node),
				PeerUnderlay:  peerUnderlays(top),
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

			s := top.Stats()
			fmt.Fprintf(cmd.OutOrStdout(),
				"\ndeployed %d devices and %d links in %s\n",
				s.Devices, s.Links, rep.Duration.Round(time.Millisecond))
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
			if len(cs) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "nothing to remove for lab %q\n", name)
				return nil
			}
			if !yes {
				fmt.Fprintf(cmd.OutOrStdout(), "about to remove %d containers of lab %q; pass --yes to proceed\n",
					len(cs), name)
				return nil
			}

			store, err := localStore(top)
			if err != nil {
				return err
			}
			eng := &deploy.Engine{Runtime: rt, Node: "local", State: store}
			// Capture before removing. A destroy that discards a student's
			// configuration without recording it is unrecoverable, and the
			// person running it is usually not the person who loses the work.
			if n, err := eng.CaptureAll(cmd.Context(), top, store); err != nil {
				return fmt.Errorf("refusing to destroy %s: its configuration could not be captured first: %w", name, err)
			} else if n > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "captured %d configuration snapshots before destroy\n", n)
			}
			if err := eng.Destroy(cmd.Context(), name); err != nil {
				return err
			}
			if !keep && len(vnis) > 0 {
				if err := eng.DestroyOverlays(vnis); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: overlay cleanup: %v\n", err)
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %d containers of lab %q\n", len(cs), name)
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
func resolveImageIDs(ctx context.Context, top *model.Topology, token string) {
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
			for _, n := range cl.Nodes {
				got, err := n.ImageDigests(ctx, list)
				if err != nil {
					continue
				}
				for ref, id := range got {
					if id != "" && seen[ref] == "" {
						seen[ref] = id
					}
				}
				if len(seen) == len(list) {
					break
				}
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
}

func loadAndPlace(opts *Options) (*model.Topology, error) {
	top, err := load(opts)
	if err != nil {
		return nil, err
	}
	if _, err := place.Place(top, place.Options{}); err != nil {
		return nil, err
	}
	return top, nil
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
