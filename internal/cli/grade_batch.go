package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/harness"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// submission is one student group's work, on disk.
type submission struct {
	Group string
	AS    int
	Dir   string
	// Files maps a router's short name to the FRR configuration submitted for
	// it. A submission that names a router the AS does not have is a mistake
	// worth reporting rather than ignoring: silently dropping it would mark
	// the student on an empty router and tell them their routing is wrong.
	Files map[string]string
	// Scripts maps a device's short name to a shell script run inside it.
	//
	// Not everything a student configures is FRR. VLANs live in the switch,
	// tunnels and host routes are set with ip(8), and a grader that could only
	// load FRR configuration would mark those exercises as failed no matter
	// what the student did.
	Scripts map[string]string
}

func newGradeBatchCmd(opts *Options) *cobra.Command {
	var (
		subDir     string
		rubricPath string
		outDir     string
		parallel   int
		depth      int
		keepHosts  bool
		keepLabs   bool
		token      string
		converge   time.Duration
		settle     time.Duration
	)
	cmd := &cobra.Command{
		Use:   "batch",
		Short: "Grade every submission in its own disposable lab",
		Long: `Batch grading gives each submission a private network.

Grading a whole class in one shared lab is convenient and wrong: a group that
misconfigures a border router moves the marks of the groups behind it, and a
re-run after one group resubmits silently re-marks everyone. Nothing in the
output distinguishes "this student was wrong" from "someone else was".

Each submission is instead graded in a harness: its own AS in full, surrounded
by the smallest neighbourhood that still exercises it, deployed under a lab name
unique to that submission so container names, overlay identifiers and addresses
cannot collide with any other. The harness is destroyed afterwards, whatever the
mark, unless --keep-labs is given for a dispute.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			class, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if rubricPath == "" {
				rubricPath = filepath.Join(class.Lab.Dir, "rubric", "cos461.yaml")
			}
			rubric, err := grade.LoadRubric(rubricPath)
			if err != nil {
				return err
			}
			subs, err := readSubmissions(subDir, class)
			if err != nil {
				return err
			}
			if len(subs) == 0 {
				return fmt.Errorf("no submissions found under %s", subDir)
			}
			tok, err := tokenFor(token)
			if err != nil {
				return err
			}
			if outDir == "" {
				outDir = filepath.Join("reports", time.Now().UTC().Format("2006-01-02_15-04-05"))
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			if parallel <= 0 {
				parallel = 4
			}

			fmt.Fprintf(cmd.ErrOrStderr(),
				"grading %d submission(s), %d at a time, each in its own lab\n",
				len(subs), parallel)

			start := time.Now()
			reports := make([]*grade.Report, len(subs))
			var wg sync.WaitGroup
			sem := make(chan struct{}, parallel)
			var mu sync.Mutex
			done := 0

			for i, s := range subs {
				wg.Add(1)
				go func(i int, s submission) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					rep := gradeOne(cmd.Context(), class, rubric, s, batchOpts{
						token: tok, depth: depth, keepHosts: keepHosts,
						keepLab: keepLabs, converge: converge, settle: settle,
						outDir: outDir,
					})
					reports[i] = rep

					mu.Lock()
					done++
					fmt.Fprintf(cmd.ErrOrStderr(), "  [%d/%d] %-12s %.2f / %.2f\n",
						done, len(subs), rep.Submission, rep.Total, rep.MaxTotal)
					mu.Unlock()
				}(i, s)
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
	cmd.Flags().StringVarP(&subDir, "submissions", "s", "submissions", "directory of per-group submissions")
	cmd.Flags().StringVarP(&rubricPath, "rubric", "r", "", "rubric to grade against")
	cmd.Flags().StringVarP(&outDir, "out", "o", "", "where to write reports")
	cmd.Flags().IntVarP(&parallel, "parallel", "p", 4, "harnesses deployed concurrently")
	cmd.Flags().IntVar(&depth, "depth", 0, "AS hops of neighbourhood to keep; 0 keeps the whole topology")
	cmd.Flags().BoolVar(&keepHosts, "keep-hosts", true, "keep one host per neighbour, for end-to-end checks")
	cmd.Flags().BoolVar(&keepLabs, "keep-labs", false, "do not destroy harnesses, for investigating a disputed mark")
	cmd.Flags().StringVar(&token, "token", "", "agent token (or TWINET_TOKEN)")
	cmd.Flags().DurationVar(&converge, "converge-timeout", 3*time.Minute, "how long a convergence predicate may wait")
	cmd.Flags().DurationVar(&settle, "settle", 45*time.Second, "grace period after configuring before checks begin")
	return cmd
}

type batchOpts struct {
	token     string
	depth     int
	keepHosts bool
	keepLab   bool
	converge  time.Duration
	settle    time.Duration
	outDir    string
}

// gradeOne deploys a harness, loads the submission into it, grades it and tears
// it down. A failure at any stage produces a report explaining the failure
// rather than an absent mark, because a submission that crashes the grader
// still needs a defensible answer for the student.
func gradeOne(ctx context.Context, class *model.Topology, rubric *grade.Rubric,
	s submission, o batchOpts) *grade.Report {

	fail := func(stage string, err error) *grade.Report {
		return &grade.Report{
			Submission: s.Group,
			MaxTotal:   rubric.MaxTotal(),
			AS:         s.AS,
			Err:        fmt.Sprintf("%s: %v", stage, err),
			// A submission the grader could not mark must never look like a
			// submission that scored zero on its merits.
			NeedsReview: true,
		}
	}

	h, err := harness.Slice(class, s.AS, harness.Options{
		Depth: o.depth, KeepHosts: o.keepHosts, Suffix: s.Group,
	})
	if err != nil {
		return fail("building the harness", err)
	}

	// Record which network produced the mark, before anything can go wrong.
	// A student disputing a grade is entitled to see the exact topology.
	sum := harness.Describe(class, h, s.AS, o.depth)
	if raw, err := json.MarshalIndent(sum, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(o.outDir, s.Group+".harness.json"), raw, 0o644)
	}

	c := client.NewCluster(h.Lab, o.token)
	defer func() {
		if o.keepLab {
			return
		}
		// Teardown runs even when grading panicked or the context was
		// cancelled, and with its own deadline, because a harness left behind
		// consumes the cluster that the rest of the class is waiting for.
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
		defer cancel()
		_ = destroyLab(tctx, c, h)
	}()

	if err := deployQuiet(ctx, c, h, s.AS); err != nil {
		return fail("deploying the harness", err)
	}

	exec, err := execFunc(ctx, h, o.token)
	if err != nil {
		return fail("connecting to the harness", err)
	}
	if err := applySubmission(ctx, exec, h, s); err != nil {
		return fail("loading the submission", err)
	}
	if o.settle > 0 {
		select {
		case <-time.After(o.settle):
		case <-ctx.Done():
			return fail("waiting to settle", ctx.Err())
		}
	}

	rep := grade.Run(ctx, rubric, &grade.Env{Topology: h, AS: s.AS, Exec: exec},
		grade.RunOptions{ConvergeTimeout: o.converge, Parallel: 4})
	rep.Submission = s.Group
	rep.Lab = h.Name

	// A reduced harness can fail a correct submission for a reason the student
	// cannot see: a check that names a peer, or a route from a particular
	// origin, cannot pass if that AS was sliced away. The mark is still
	// produced, because refusing to mark helps nobody, but it is flagged so it
	// is never released as if it were a clean result.
	if missing := missingASes(class, h); len(missing) > 0 {
		rep.NeedsReview = true
		rep.Warnings = append(rep.Warnings, fmt.Sprintf(
			"graded in a reduced harness: AS %s were not deployed, so any check "+
				"that depends on them could not pass; re-grade at full breadth "+
				"(--depth 0) before releasing this mark", joinInts(missing)))
	}
	return rep
}

// missingASes reports which ASes of the class topology a harness left out.
func missingASes(class, h *model.Topology) []int {
	var out []int
	for asn := range class.ASes {
		if _, ok := h.ASes[asn]; !ok {
			out = append(out, asn)
		}
	}
	sort.Ints(out)
	return out
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, ", ")
}

func deployQuiet(ctx context.Context, c *client.Cluster, h *model.Topology, target int) error {
	if problems := c.CheckUnderlay(ctx, h); len(problems) > 0 {
		return fmt.Errorf("underlay cannot carry the harness: %s", problems[0])
	}
	results := c.Apply(ctx, h, agent.ApplyRequest{
		// The surrounding internet is solved so the submission is marked
		// against neighbours that actually work; the graded AS keeps platform
		// mode so what is marked is the student's own configuration.
		Mode:       "solve",
		Ungraded:   target,
		PullPolicy: string(rt.PullIfMissing),
		Workers:    8,
		Generation: time.Now().UTC().Format("20060102T150405.000"),
	})
	for _, r := range results {
		if r.Err != nil {
			return fmt.Errorf("node %s: %w", r.Node, r.Err)
		}
		for scope, msgs := range r.Value.Failures {
			if len(msgs) > 0 {
				return fmt.Errorf("node %s, %s: %s", r.Node, scope, firstLine(msgs[0]))
			}
		}
	}
	return nil
}

func destroyLab(ctx context.Context, c *client.Cluster, h *model.Topology) error {
	vnis := make([]uint32, 0, len(h.Links))
	for _, l := range h.Links {
		if l.VNI != 0 {
			vnis = append(vnis, l.VNI)
		}
	}
	results := c.DestroyEphemeral(ctx, h.Name, vnis)
	for _, r := range results {
		if r.Err != nil {
			return r.Err
		}
	}
	return nil
}

// applySubmission writes each submitted configuration into its router and asks
// FRR to adopt it.
//
// The configuration is applied through the running daemon rather than by
// rewriting the file and restarting, so that a syntax error is reported as a
// rejected line the student can be shown, instead of a router that silently
// fails to come up and grades as a total loss.
func applySubmission(ctx context.Context, exec execFn, h *model.Topology, s submission) error {
	as, ok := h.ASes[s.AS]
	if !ok {
		return fmt.Errorf("AS %d is not in the harness", s.AS)
	}
	known := map[string]*model.Device{}
	for _, d := range as.Devices {
		known[strings.ToUpper(d.Name)] = d
	}

	var missing []string
	for name := range s.Scripts {
		if _, ok := known[strings.ToUpper(name)]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range s.Files {
		if _, ok := known[strings.ToUpper(name)]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("submission names router(s) that AS %d does not have: %s",
			s.AS, strings.Join(missing, ", "))
	}

	names := make([]string, 0, len(s.Files))
	for name := range s.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		d := known[strings.ToUpper(name)]
		if err := loadFRRConfig(ctx, exec, d, s.Files[name]); err != nil {
			return fmt.Errorf("%s: %w", d.ID, err)
		}
	}

	// Scripts run after the routing configuration, because a tunnel or a host
	// route may depend on an address the configuration has just brought up.
	names = names[:0]
	for name := range s.Scripts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		d := known[strings.ToUpper(name)]
		res, err := exec(ctx, d.ID, []string{"sh", "-c", s.Scripts[name]})
		if err != nil {
			return fmt.Errorf("%s: running the submitted script: %w", d.ID, err)
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("%s: the submitted script exited %d: %s",
				d.ID, res.ExitCode, firstLine(res.Stderr+res.Stdout))
		}
	}
	return nil
}

// loadFRRConfig installs a submitted configuration and restarts FRR onto it.
//
// The obvious approach, feeding the file to "vtysh -f", does not work for a
// whole configuration: vtysh accepts commands, and a configuration file also
// contains directives such as "frr version" that exist only for the daemons'
// own startup parser. Feeding one in fails at that line, and the failure looks
// like a student error when it is the grader's.
//
// So the submission is installed exactly where a real deployment puts it and
// FRR is restarted onto it, which is also the only way to be sure the mark
// reflects the file the student submitted rather than that file layered on top
// of whatever the router was already running.
func loadFRRConfig(ctx context.Context, exec execFn, d *model.Device, body string) error {
	script := strings.Join([]string{
		"set -e",
		"cat > /etc/frr/frr.conf <<'TWINET_EOF'\n" + body + "\nTWINET_EOF",
		"chown frr:frr /etc/frr/frr.conf 2>/dev/null || true",
		"chmod 640 /etc/frr/frr.conf",
		// watchfrr keeps its own pid file and outlives a plain stop, after
		// which the daemons can never start again. It has to go first.
		"for p in $(ps -ef | awk '/watchfrr/ && !/awk/ {print $1}'); do kill $p 2>/dev/null || true; done",
		"/usr/lib/frr/frrinit.sh stop >/dev/null 2>&1 || true",
		"rm -f /var/run/frr/*.pid /var/run/frr/*.vty 2>/dev/null || true",
		"/usr/lib/frr/frrinit.sh start",
	}, "\n")

	res, err := exec(ctx, d.ID, []string{"sh", "-c", script})
	if err != nil {
		return fmt.Errorf("installing the configuration: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("installing the configuration: %s",
			firstLine(res.Stdout+res.Stderr))
	}

	// A daemon that rejected the file exits, and FRR's own start script does
	// not fail when that happens. Asking vtysh which daemons answered is the
	// only reliable signal, and it is also the feedback the student needs.
	res, err = exec(ctx, d.ID, []string{"sh", "-c",
		"sleep 2; vtysh -c 'show version' >/dev/null 2>&1 && vtysh -c 'show running-config' | head -1"})
	if err != nil {
		return fmt.Errorf("checking that frr came up: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("frr did not come up on the submitted configuration: %s",
			firstLine(res.Stdout+res.Stderr))
	}
	return nil
}

// readSubmissions reads a directory of per-group submissions.
//
// Layout: one directory per group, named after the group in the manifest or
// "as<N>", containing one file per router. The AS is resolved from the manifest
// rather than from the directory name, so a group cannot be marked as, or
// against, an AS that is not theirs.
func readSubmissions(dir string, class *model.Topology) ([]submission, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading submissions: %w", err)
	}
	byGroup := map[string]int{}
	for asn, as := range class.ASes {
		if as.Role != model.RoleStudent {
			continue
		}
		byGroup[strings.ToLower(fmt.Sprintf("as%d", asn))] = asn
		if as.OwnerGroup != "" {
			byGroup[strings.ToLower(as.OwnerGroup)] = asn
		}
	}

	var subs []submission
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		group := e.Name()
		asn, ok := byGroup[strings.ToLower(group)]
		if !ok {
			// Try a trailing number, so "group-7" maps to AS 7 if AS 7 is a
			// student AS. Anything else is refused: guessing here would grade
			// one group's work under another group's name.
			if n, err := strconv.Atoi(strings.TrimLeft(group, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_")); err == nil {
				if as, ok := class.ASes[n]; ok && as.Role == model.RoleStudent {
					asn = n
					ok2 := true
					_ = ok2
				} else {
					return nil, fmt.Errorf("submission %q does not correspond to a student AS", group)
				}
			} else {
				return nil, fmt.Errorf("submission %q does not correspond to a student AS", group)
			}
		}

		sub := submission{
			Group: group, AS: asn, Dir: filepath.Join(dir, group),
			Files: map[string]string{}, Scripts: map[string]string{},
		}
		files, err := os.ReadDir(sub.Dir)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if f.IsDir() || strings.HasPrefix(f.Name(), ".") {
				continue
			}
			ext := filepath.Ext(f.Name())
			if ext != ".conf" && ext != ".cfg" && ext != ".txt" && ext != ".sh" {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(sub.Dir, f.Name()))
			if err != nil {
				return nil, err
			}
			base := strings.TrimSuffix(f.Name(), ext)
			if ext == ".sh" {
				sub.Scripts[base] = string(raw)
			} else {
				sub.Files[base] = string(raw)
			}
		}
		if len(sub.Files) == 0 && len(sub.Scripts) == 0 {
			return nil, fmt.Errorf("submission %q contains no configuration files", group)
		}
		subs = append(subs, sub)
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].Group < subs[j].Group })
	return subs, nil
}

// execFn runs a command inside a device of a harness. It matches the shape the
// grading engine expects, so a harness and the shared lab are graded by exactly
// the same code path.
type execFn = func(ctx context.Context, deviceID string, cmd []string) (rt.ExecResult, error)
