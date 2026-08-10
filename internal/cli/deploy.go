package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/render"
	"github.com/HongyuHe/twinet/internal/runtime"
)

func newDeployCmd(opts *Options) *cobra.Command {
	var (
		solve   bool
		dryRun  bool
		workers int
		pull    string
		only    string
		quiet   bool
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
			if only != "" {
				if err := restrict(top, only); err != nil {
					return err
				}
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
			eng := &deploy.Engine{
				Runtime:      rt,
				Node:         node,
				PullPolicy:   runtime.PullPolicy(pull),
				Renderer:     render.New(top, mode),
				UnderlayIP:   underlayOf(top, node),
				PeerUnderlay: peerUnderlays(top),
			}

			p, err := eng.Build(top)
			if err != nil {
				return err
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
	cmd.Flags().StringVar(&only, "only", "", "restrict to a scope, e.g. as=12 or services")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress per-step progress")
	return cmd
}

func newDestroyCmd(opts *Options) *cobra.Command {
	var (
		yes  bool
		lab  string
		keep bool
	)
	cmd := &cobra.Command{
		Use:   "destroy",
		Short: "Remove every container and overlay object belonging to the lab",
		Long: `Destroy works from container labels, so it can clean up a deployment even
if the manifest that created it is no longer available.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt := runtime.NewDocker()
			name := lab
			var vnis []uint32
			if name == "" {
				top, err := loadAndPlace(opts)
				if err != nil {
					return fmt.Errorf("%w\n(pass --lab NAME to destroy without a manifest)", err)
				}
				name = top.Name
				for _, l := range top.Links {
					vnis = append(vnis, l.VNI)
				}
			}
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

			eng := &deploy.Engine{Runtime: rt, Node: "local"}
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
	return cmd
}

func newExecCmd(opts *Options) *cobra.Command {
	var (
		asFilter int
		kind     string
		all      bool
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
			rt := runtime.NewDocker()

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
			// platform's equivalent scripts took minutes.
			type out struct {
				dev *model.Device
				res runtime.ExecResult
				err error
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
					res, err := rt.Exec(cmd.Context(), d.Container, runtime.ExecCmd{Cmd: command})
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
	return cmd
}

// loadAndPlace loads, validates, expands and places the topology.
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

// restrict prunes the topology to a scope, so a redeploy can target one AS
// without touching the other ninety-nine.
func restrict(top *model.Topology, sel string) error {
	switch {
	case strings.HasPrefix(sel, "as="):
		var asn int
		if _, err := fmt.Sscanf(sel, "as=%d", &asn); err != nil {
			return fmt.Errorf("bad selector %q; use as=12", sel)
		}
		if _, ok := top.ASes[asn]; !ok {
			return fmt.Errorf("AS %d is not in this lab", asn)
		}
		for id, d := range top.Devices {
			if d.ASN != asn {
				delete(top.Devices, id)
			}
		}
	case sel == "services":
		for id, d := range top.Devices {
			if d.ASN != 0 {
				delete(top.Devices, id)
			}
		}
	default:
		return fmt.Errorf("unknown selector %q; use as=N or services", sel)
	}
	var keep []*model.Link
	for _, l := range top.Links {
		_, a := top.Devices[l.A.Device.ID]
		_, b := top.Devices[l.B.Device.ID]
		if a && b {
			keep = append(keep, l)
		}
	}
	top.Links = keep
	return nil
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
