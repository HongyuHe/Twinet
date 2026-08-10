package cli

import (
	"context"
	"encoding/json"
	"fmt"
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
			return nil
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
