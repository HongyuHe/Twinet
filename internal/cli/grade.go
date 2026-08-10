package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
	"github.com/HongyuHe/twinet/internal/runtime"
)

func newGradeCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grade",
		Short: "Grade student work against a rubric",
		Long: `Grading is rubric-driven and produces structured, reproducible results.

Every check returns the evidence it observed, not merely a verdict, so feedback
can quote the routing-table entry that was wrong rather than saying "FAIL".`,
	}
	cmd.AddCommand(
		newGradeRunCmd(opts),
		newGradeBatchCmd(opts),
		newGradeChecksCmd(),
		newGradeValidateCmd(),
	)
	return cmd
}

func newGradeChecksCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "checks",
		Short: "List the checks a rubric may refer to",
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "CHECK\tWHAT IT VERIFIES")
			for _, c := range grade.Checks() {
				fmt.Fprintf(w, "%s\t%s\n", c.Name, c.Describe)
			}
			return w.Flush()
		},
	}
}

func newGradeValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <rubric.yaml>",
		Short: "Check a rubric before a grading run depends on it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := grade.LoadRubric(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"%s is valid: %d questions worth %.2f points in total\n",
				r.Metadata.Name, len(r.Questions), r.MaxTotal())
			return nil
		},
	}
}

func newGradeRunCmd(opts *Options) *cobra.Command {
	var (
		rubricPath string
		asList     []int
		outDir     string
		parallel   int
		token      string
		converge   time.Duration
		quiet      bool
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Grade the autonomous systems of a running lab",
		Long: `Grades one or more ASes of a deployed lab and writes structured reports.

Submissions are graded concurrently, and every wait is a convergence predicate
rather than a fixed sleep, so a whole class completes in minutes rather than
the hours a sleep-driven serial grader takes.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if rubricPath == "" {
				rubricPath = filepath.Join(top.Lab.Dir, "rubric", "cos461.yaml")
			}
			rubric, err := grade.LoadRubric(rubricPath)
			if err != nil {
				return err
			}

			exec, err := execFunc(cmd.Context(), top, token)
			if err != nil {
				return err
			}

			targets := asList
			if len(targets) == 0 {
				for _, asn := range top.SortedASNs() {
					if top.ASes[asn].Role == model.RoleStudent {
						targets = append(targets, asn)
					}
				}
			}
			if len(targets) == 0 {
				return fmt.Errorf("no student ASes to grade; pass --as")
			}

			if outDir == "" {
				outDir = filepath.Join("reports", time.Now().UTC().Format("2006-01-02_15-04-05"))
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}

			if parallel <= 0 {
				parallel = 8
			}
			start := time.Now()
			reports := make([]*grade.Report, len(targets))
			var wg sync.WaitGroup
			sem := make(chan struct{}, parallel)
			var mu sync.Mutex
			done := 0

			for i, asn := range targets {
				wg.Add(1)
				go func(i, asn int) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					env := &grade.Env{Topology: top, AS: asn, Exec: exec}
					rep := grade.Run(cmd.Context(), rubric, env, grade.RunOptions{
						ConvergeTimeout: converge,
						Parallel:        4,
					})
					rep.Submission = fmt.Sprintf("as%d", asn)
					if as, ok := top.ASes[asn]; ok && as.OwnerGroup != "" {
						rep.Submission = as.OwnerGroup
					}
					reports[i] = rep

					mu.Lock()
					done++
					if !quiet {
						fmt.Fprintf(cmd.ErrOrStderr(), "  [%d/%d] %-12s %.2f / %.2f\n",
							done, len(targets), rep.Submission, rep.Total, rep.MaxTotal)
					}
					mu.Unlock()
				}(i, asn)
			}
			wg.Wait()

			summary := grade.Summarise(rubric.Metadata.Name, reports, time.Since(start))
			if err := writeReports(outDir, summary); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprint(cmd.OutOrStdout(), summary.Text())
			fmt.Fprintf(cmd.OutOrStdout(), "\nreports written to %s\n", outDir)
			return releaseGuard(summary, cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVarP(&rubricPath, "rubric", "r", "", "rubric file (default: <lab>/rubric/cos461.yaml)")
	cmd.Flags().IntSliceVar(&asList, "as", nil, "AS numbers to grade (default: every student AS)")
	cmd.Flags().StringVarP(&outDir, "out", "o", "", "directory for reports")
	cmd.Flags().IntVarP(&parallel, "parallel", "p", 8, "submissions graded concurrently")
	cmd.Flags().DurationVar(&converge, "converge-timeout", 90*time.Second,
		"how long to wait for the control plane to settle")
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs (or set TWINET_TOKEN)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress per-submission progress")
	return cmd
}

// execFunc builds the command-execution closure a check uses, routing through
// node agents when the lab spans a cluster.
func execFunc(ctx context.Context, top *model.Topology, token string) (
	func(context.Context, string, []string) (runtime.ExecResult, error), error) {

	if !clustered(top) {
		rt := runtime.NewDocker()
		return func(ctx context.Context, deviceID string, cmd []string) (runtime.ExecResult, error) {
			d, ok := top.Device(deviceID)
			if !ok {
				return runtime.ExecResult{}, fmt.Errorf("no device %q", deviceID)
			}
			return rt.Exec(ctx, d.Container, runtime.ExecCmd{Cmd: cmd})
		}, nil
	}

	tok, err := tokenFor(token)
	if err != nil {
		return nil, err
	}
	cl := client.NewCluster(top.Lab, tok)
	return func(ctx context.Context, deviceID string, cmd []string) (runtime.ExecResult, error) {
		d, ok := top.Device(deviceID)
		if !ok {
			return runtime.ExecResult{}, fmt.Errorf("no device %q", deviceID)
		}
		n, ok := cl.Node(d.Node)
		if !ok {
			return runtime.ExecResult{}, fmt.Errorf("device %s is on unknown node %q", deviceID, d.Node)
		}
		r, err := n.Exec(ctx, agent.ExecRequest{Container: d.Container, Cmd: cmd})
		return runtime.ExecResult{ExitCode: r.ExitCode, Stdout: r.Stdout, Stderr: r.Stderr}, err
	}, nil
}

// writeReports emits per-student JSON and text plus a class summary.
//
// Structured output is what makes a grading run usable afterwards: the legacy
// graders produced text logs or SQLite blobs and left bundling to a human.
// lifecycleFunc returns a function that changes a device container's run
// state, wherever in the cluster that container happens to live.
func lifecycleFunc(top *model.Topology, token string) (
	func(context.Context, string, string) error, error) {

	if !clustered(top) {
		rt := runtime.NewDocker()
		return func(ctx context.Context, deviceID, action string) error {
			d, ok := top.Device(deviceID)
			if !ok {
				return fmt.Errorf("no device %q", deviceID)
			}
			switch action {
			case "pause":
				return rt.Pause(ctx, d.Container)
			case "unpause":
				return rt.Unpause(ctx, d.Container)
			case "stop":
				return rt.Stop(ctx, d.Container, 10*time.Second)
			case "start":
				return rt.Start(ctx, d.Container)
			case "restart":
				if err := rt.Stop(ctx, d.Container, 10*time.Second); err != nil {
					return err
				}
				return rt.Start(ctx, d.Container)
			}
			return fmt.Errorf("unknown action %q", action)
		}, nil
	}

	tok, err := tokenFor(token)
	if err != nil {
		return nil, err
	}
	cl := client.NewCluster(top.Lab, tok)
	return func(ctx context.Context, deviceID, action string) error {
		d, ok := top.Device(deviceID)
		if !ok {
			return fmt.Errorf("no device %q", deviceID)
		}
		n, ok := cl.Node(d.Node)
		if !ok {
			return fmt.Errorf("device %s is on unknown node %q", deviceID, d.Node)
		}
		return n.Lifecycle(ctx, agent.LifecycleRequest{Container: d.Container, Action: action})
	}, nil
}

// reshapeFunc returns a function that puts an interface back to the shaping
// the topology declares, wherever in the cluster the device lives.
func reshapeFunc(top *model.Topology, token string) (
	func(context.Context, string, string) error, error) {

	shapingOf := func(deviceID, iface string) (netx.Shaping, int, error) {
		d, ok := top.Device(deviceID)
		if !ok {
			return netx.Shaping{}, 0, fmt.Errorf("no device %q", deviceID)
		}
		for _, i := range d.Ifaces {
			if i.Name != iface || i.Link == nil {
				continue
			}
			p := i.Link.Props
			return netx.Shaping{
				Bandwidth: p.Bandwidth, Delay: p.Delay,
				Queue: p.Queue, Loss: p.Loss,
			}, derefInt(p.MTU), nil
		}
		// An interface with no link carries no declared shaping, so clearing
		// it is the correct restoration.
		return netx.Shaping{}, 0, nil
	}

	if !clustered(top) {
		rt := runtime.NewDocker()
		return func(ctx context.Context, deviceID, iface string) error {
			d, ok := top.Device(deviceID)
			if !ok {
				return fmt.Errorf("no device %q", deviceID)
			}
			s, mtu, err := shapingOf(deviceID, iface)
			if err != nil {
				return err
			}
			ns, err := rt.NSPath(ctx, d.Container)
			if err != nil {
				return err
			}
			_ = mtu
			return netx.ReshapeInNS(ns, iface, s, 0)
		}, nil
	}

	tok, err := tokenFor(token)
	if err != nil {
		return nil, err
	}
	cl := client.NewCluster(top.Lab, tok)
	return func(ctx context.Context, deviceID, iface string) error {
		d, ok := top.Device(deviceID)
		if !ok {
			return fmt.Errorf("no device %q", deviceID)
		}
		n, ok := cl.Node(d.Node)
		if !ok {
			return fmt.Errorf("device %s is on unknown node %q", deviceID, d.Node)
		}
		s, mtu, err := shapingOf(deviceID, iface)
		if err != nil {
			return err
		}
		return n.Reshape(ctx, agent.ReshapeRequest{
			Container: d.Container, Iface: iface, Shaping: s, MTU: mtu,
		})
	}, nil
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// releaseGuard refuses to let a run that did not fully work be mistaken for a
// clean set of marks. It is the last line of defence against the worst failure
// this system can have: a platform fault becoming a student's zero.
func releaseGuard(s *grade.Summary, out io.Writer) error {
	q := s.Quarantined()
	if len(q) == 0 {
		return nil
	}
	fmt.Fprintf(out, "\n%d of %d submission(s) could not be graded and are quarantined:\n",
		len(q), len(s.Reports))
	for _, r := range q {
		fmt.Fprintf(out, "  %-14s %s\n", r.Submission, firstLine(reportProblem(r)))
	}
	fmt.Fprintln(out, "\nTheir rows carry no total, so they cannot be imported as marks by accident.")
	fmt.Fprintln(out, "Re-run those submissions once the cause is fixed.")
	return fmt.Errorf("%d submission(s) need review; no marks were released for them", len(q))
}

func reportProblem(r *grade.Report) string {
	if r.Err != "" {
		return r.Err
	}
	if len(r.Warnings) > 0 {
		return r.Warnings[0]
	}
	return "grading did not complete correctly"
}

func writeReports(dir string, s *grade.Summary) error {
	for _, r := range s.Reports {
		if r == nil {
			continue
		}
		raw, err := r.JSON()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, r.Submission+".json"), raw, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, r.Submission+".txt"), []byte(r.Text()), 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "summary.csv"), []byte(s.CSV()), 0o644); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "summary.json"), raw, 0o644)
}
