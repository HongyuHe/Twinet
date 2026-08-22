package cli

import (
	"context"
	"encoding/json"
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
	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/integrity"
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
		newGradeClassCmd(opts),
		newGradeChecksCmd(opts),
		newGradeValidateCmd(),
	)
	return cmd
}

func newGradeChecksCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "checks",
		Short: "List the checks a rubric may refer to",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.JSON {
				// Only what a caller can use. A check carries the function
				// that runs it, which does not serialise -- and encoding the
				// whole struct failed at run time on a flag that is supposed
				// to be the machine-readable one.
				out := make([]map[string]string, 0)
				for _, c := range grade.Checks() {
					out = append(out, map[string]string{
						"check": c.Name, "verifies": c.Describe,
					})
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
			}
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
		rubricPath    string
		asList        []int
		outDir        string
		parallel      int
		checkParallel int
		token         string
		converge      time.Duration
		quiet         bool
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Grade the autonomous systems of a running lab",
		Long: `Grades one or more ASes of a deployed lab exactly as they are, and writes
structured reports.

This is a diagnostic, not the way to mark a class. It reads whatever is in the
lab right now: it does not put anybody's system back to the reference first, so
each system is measured across its neighbours in whatever state they happen to
be in, and one student's broken configuration lowers their neighbours' marks.

Use it to check the reference solution, to investigate one submission, or to see
where a lab stands. To mark a class, use "twinet grade class", which loads one
submission at a time onto a blank system with the rest of the internet at the
reference, and holds the nodes off from repairing anything while it does.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if rubricPath == "" {
				p, err := defaultRubric(top.Lab.Dir)
				if err != nil {
					return err
				}
				rubricPath = p
			}
			rubric, err := grade.LoadRubric(rubricPath)
			if err != nil {
				return err
			}
			if err := rubric.ValidateTopology(top); err != nil {
				return err
			}

			exec, err := execFunc(cmd.Context(), top, token)
			if err != nil {
				return err
			}

			// The nodes are asked to leave the lab alone for this too. Reading
			// a system takes seconds, but a repair rewiring a device in the
			// middle of it re-renders configuration, and in a solved lab that
			// is the reference being written over whatever is there -- which
			// this command would then report as the answer.
			held, herr := holdLab(cmd.Context(), top, token, cmd.ErrOrStderr())
			if herr != nil {
				return herr
			}
			defer held.Release()
			defer func() {
				// If the nodes stopped holding the lab partway, what was read
				// afterwards may be a repair in progress rather than the lab.
				select {
				case <-held.Lost:
					fmt.Fprintf(cmd.ErrOrStderr(),
						"\nwarning: the nodes stopped holding this lab off from automatic "+
							"repair during this run (%s), so anything read after that moment "+
							"may be a repair in progress rather than the lab as deployed\n",
						held.Reason())
				default:
				}
			}()

			targets := asList
			if len(targets) == 0 {
				for _, asn := range top.SortedASNs() {
					if top.ASes[asn].Role == model.RoleStudent {
						targets = append(targets, asn)
					}
				}
				if len(targets) > 1 {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"reading all %d systems as they stand. These are not class marks: "+
							"nothing has been put back to the reference, so each system is "+
							"measured across its neighbours in whatever state they are in, and "+
							"one broken submission lowers its neighbours' scores.\nUse "+
							"`twinet grade class` to mark a class.\n", len(targets))
				}
			}
			if len(targets) == 0 {
				return fmt.Errorf("no student ASes to grade; pass --as")
			}

			if outDir == "" {
				outDir = filepath.Join("reports", time.Now().UTC().Format("2006-01-02-150405"))
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
						ConvergeTimeout:     converge,
						Parallel:            checkParallel,
						ObservationParallel: checkParallel,
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
			// --json is a global flag, and this command accepted it and printed
			// the human summary anyway. Anything parsing the output got prose
			// where it expected an object, which is a confusing way to find out
			// that a flag does nothing.
			if opts.JSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(summary); err != nil {
					return err
				}
				return releaseGuard(summary, cmd.ErrOrStderr())
			}
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprint(cmd.OutOrStdout(), summary.Text())
			fmt.Fprintf(cmd.OutOrStdout(), "\nreports written to %s\n", outDir)
			return releaseGuard(summary, cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVarP(&rubricPath, "rubric", "r", "", "rubric file (default: the one under <lab>/rubric/)")
	cmd.Flags().IntSliceVar(&asList, "as", nil, "AS numbers to grade (default: every student AS)")
	cmd.Flags().StringVarP(&outDir, "out", "o", "", "directory for reports")
	cmd.Flags().IntVarP(&parallel, "parallel", "p", 8, "submissions graded concurrently")
	cmd.Flags().IntVar(&checkParallel, "check-parallel", 16,
		"maximum non-conflicting checks and passive observations per submission")
	// Four minutes, not ninety seconds.
	//
	// Ninety was a guess and it was wrong: an iBGP session in the 12-AS lab was
	// measured taking three minutes and twenty seconds to establish after a
	// redeploy. The wait gave up first, the question was flagged for review,
	// and the report showed 54 of 56 sessions established -- a correct answer
	// described as an incomplete one, with the truth of it buried in a warning.
	// This matches what `grade batch` and `grade class` already use.
	cmd.Flags().DurationVar(&converge, "converge-timeout", 4*time.Minute,
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
		rt, err := localRuntime(top)
		if err != nil {
			return nil, err
		}
		tools := integrity.NewChecker(rt)
		return func(ctx context.Context, deviceID string, cmd []string) (runtime.ExecResult, error) {
			d, ok := top.Device(deviceID)
			if !ok {
				return runtime.ExecResult{}, fmt.Errorf("no device %q", deviceID)
			}
			// The same rule as the clustered path: a container's programs are
			// its owner's to replace, so they are compared against the image
			// before anything they print becomes a mark.
			c, err := rt.Inspect(ctx, d.Container)
			if err != nil {
				return runtime.ExecResult{}, err
			}
			findings, err := tools.Verify(ctx, c)
			if err != nil {
				return runtime.ExecResult{}, fmt.Errorf("the programs in %s could not be "+
					"checked against %s, so the evidence they produce cannot be relied "+
					"on: %w", c.Name, c.Image, err)
			}
			if len(findings) > 0 {
				return runtime.ExecResult{}, &integrity.Error{Container: c.Name, Findings: findings}
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
		r, err := n.Exec(ctx, agent.ExecRequest{
			Container: d.Container, Cmd: cmd, Hold: currentHoldToken(), Grading: true})
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
		rt, err := localRuntime(top)
		if err != nil {
			return nil, err
		}
		return func(ctx context.Context, deviceID, action string) error {
			d, ok := top.Device(deviceID)
			if !ok {
				return fmt.Errorf("no device %q", deviceID)
			}
			apply := func(container string) error {
				switch action {
				case "pause":
					return rt.Pause(ctx, container)
				case "unpause":
					return rt.Unpause(ctx, container)
				case "stop":
					return rt.Stop(ctx, container, 10*time.Second)
				case "start":
					return rt.Start(ctx, container)
				case "restart":
					if err := rt.Stop(ctx, container, 10*time.Second); err != nil {
						return err
					}
					return rt.Start(ctx, container)
				}
				return fmt.Errorf("unknown action %q", action)
			}
			if !deploy.UsesFRRControl(d) {
				return apply(d.Container)
			}
			control := deploy.FRRControlContainer(d)
			if observed, err := rt.Inspect(ctx, control); err != nil || observed.State == runtime.StateAbsent {
				// A lab deployed before the sidecar migration remains
				// manageable until its next convergence recreates the router.
				return apply(d.Container)
			}
			switch action {
			case "pause":
				if err := apply(control); err != nil {
					return err
				}
				return apply(d.Container)
			case "unpause":
				if err := apply(d.Container); err != nil {
					return err
				}
				return apply(control)
			case "stop":
				if err := apply(control); err != nil {
					return err
				}
				return apply(d.Container)
			case "start":
				if err := apply(d.Container); err != nil {
					return err
				}
				return apply(control)
			case "restart":
				if err := rt.Stop(ctx, control, 10*time.Second); err != nil {
					return err
				}
				if err := rt.Stop(ctx, d.Container, 10*time.Second); err != nil {
					return err
				}
				if err := rt.Start(ctx, d.Container); err != nil {
					return err
				}
				return rt.Start(ctx, control)
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
		_, ok = cl.Node(d.Node)
		if !ok {
			return fmt.Errorf("device %s is on unknown node %q", deviceID, d.Node)
		}
		return cl.Lifecycle(ctx, top.Name, d.Node,
			agent.LifecycleRequest{Container: d.Container, Action: action, Hold: currentHoldToken()})
	}, nil
}

// nodeStateFunc returns a function that reports a device container's run state.
func nodeStateFunc(top *model.Topology, token string) (
	func(context.Context, string) (string, error), error) {

	if !clustered(top) {
		rt, err := localRuntime(top)
		if err != nil {
			return nil, err
		}
		return func(ctx context.Context, deviceID string) (string, error) {
			d, ok := top.Device(deviceID)
			if !ok {
				return "", fmt.Errorf("no device %q", deviceID)
			}
			c, err := rt.Inspect(ctx, d.Container)
			if err != nil {
				return "", err
			}
			return string(c.State), nil
		}, nil
	}

	tok, err := tokenFor(token)
	if err != nil {
		return nil, err
	}
	cl := client.NewCluster(top.Lab, tok)
	return func(ctx context.Context, deviceID string) (string, error) {
		d, ok := top.Device(deviceID)
		if !ok {
			return "", fmt.Errorf("no device %q", deviceID)
		}
		n, ok := cl.Node(d.Node)
		if !ok {
			return "", fmt.Errorf("device %s is on unknown node %q", deviceID, d.Node)
		}
		return n.ContainerState(ctx, d.Container)
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
		rt, err := localRuntime(top)
		if err != nil {
			return nil, err
		}
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
		_, ok = cl.Node(d.Node)
		if !ok {
			return fmt.Errorf("device %s is on unknown node %q", deviceID, d.Node)
		}
		s, mtu, err := shapingOf(deviceID, iface)
		if err != nil {
			return err
		}
		return cl.Reshape(ctx, top.Name, d.Node, agent.ReshapeRequest{
			Container: d.Container, Iface: iface, Shaping: s, MTU: mtu,
			Hold: currentHoldToken(),
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
// quarantineUnreadable turns the submissions that could not be read into
// reports, so they travel through exactly the same summary, CSV, report-writing
// and release path as a submission that failed while being graded.
//
// Both grading commands need this and they must agree, so there is one of it.
// The alternative -- each command printing its own list of skipped files -- is
// how a submission ends up mentioned on stderr and absent from the reports
// directory, which is indistinguishable from never having been handed in.
func quarantineUnreadable(bad []unreadable, rubric *grade.Rubric, lab string) []*grade.Report {
	out := make([]*grade.Report, 0, len(bad))
	for _, u := range bad {
		out = append(out, &grade.Report{
			Submission: u.Name,
			AS:         u.AS,
			Lab:        lab,
			Rubric:     rubric.Metadata.Name,
			MaxTotal:   rubric.MaxTotal(),
			GradedAt:   time.Now().UTC(),
			// The reason is written where the decision was made and used
			// verbatim. It used to be prefixed here with "this submission
			// could not be read", which was wrong for a submission that read
			// perfectly and was withdrawn because two entries claimed its
			// name -- the report told a student something untrue about their
			// own work, which is the whole of what this project is for.
			Err: u.Reason,
			// Never a zero. A file the grader could not open says nothing
			// about the work inside it.
			NeedsReview: true,
		})
	}
	return out
}

// announceUnreadable says at the start which submissions will not be graded.
//
// The summary says so too, but an hour later. An operator who learns at the
// start that one archive is corrupt can fix it and re-run before the class run
// has finished; one who learns at the end has to run the whole thing again.
func announceUnreadable(w io.Writer, bad []unreadable, gradeable int) {
	if len(bad) == 0 {
		return
	}
	fmt.Fprintf(w, "%d submission(s) will not be graded:\n", len(bad))
	for _, u := range bad {
		fmt.Fprintf(w, "  %-14s %s\n", u.Name, firstLine(u.Reason))
	}
	if gradeable == 0 {
		fmt.Fprintln(w, "They are reported as needing review. Nothing else was handed in, "+
			"so there is nothing to grade.")
		return
	}
	fmt.Fprintf(w, "They are reported as needing review, and the other %d are graded normally.\n",
		gradeable)
}

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

// writeReports writes one file per submission plus the class summary.
//
// Two reports sharing a submission name is refused rather than resolved. The
// files are named after the submission, so the second silently replaced the
// first: a student who scored full marks was handed a report saying they had
// not been graded, because a second entry in the directory carried their name.
// Whatever produced two reports for one name is a defect, and a grader that
// quietly overwrites one mark with another is the worst possible way to find
// out about it.
func writeReports(dir string, s *grade.Summary) error {
	seen := map[string]string{}
	for _, r := range s.Reports {
		if r == nil {
			continue
		}
		key := strings.ToLower(r.Submission)
		if prev, dup := seen[key]; dup {
			return fmt.Errorf("two reports were produced for %q (%s, and again %s), and "+
				"writing both would leave only one of them; no reports were written",
				r.Submission, prev, describeReport(r))
		}
		seen[key] = describeReport(r)
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

// defaultRubric finds the rubric of a lab that did not name one.
//
// The default used to be the literal path <lab>/rubric/cos461.yaml, so every
// course other than the one this project started with had to pass --rubric on
// every command, and a lab whose rubric was named after itself reported that
// the file did not exist rather than that the flag was needed. A lab with one
// rubric does not need to be told which one to use; a lab with several does,
// and is told so by name.
func defaultRubric(dir string) (string, error) {
	rd := filepath.Join(dir, "rubric")
	entries, err := os.ReadDir(rd)
	if err != nil {
		return "", fmt.Errorf("this lab has no rubric directory (%s), so there is nothing "+
			"to grade against: pass --rubric", rd)
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if n := e.Name(); strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") {
			found = append(found, filepath.Join(rd, n))
		}
	}
	sort.Strings(found)
	switch len(found) {
	case 0:
		return "", fmt.Errorf("%s holds no rubric, so there is nothing to grade against", rd)
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("this lab has %d rubrics (%s); say which one with --rubric",
			len(found), strings.Join(found, ", "))
	}
}

// describeReport says what a report is, for the message about two of them.
func describeReport(r *grade.Report) string {
	if r.NeedsReview || r.Err != "" {
		return "held for review"
	}
	return fmt.Sprintf("marked %.2f", r.Total)
}
