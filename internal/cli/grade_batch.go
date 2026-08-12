package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/harness"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
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
				outDir = filepath.Join("reports", time.Now().UTC().Format("2006-01-02-150405"))
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			if parallel <= 0 {
				parallel = 8
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
			if err := releaseGuard(summary, cmd.ErrOrStderr()); err != nil {
				return err
			}
			// A harness left behind keeps its containers and its overlay
			// identifiers. At class scale a handful of those exhaust the
			// cluster, and every later submission then fails for reasons that
			// have nothing to do with its author -- so this cannot exit zero.
			if TeardownFailed() {
				return fmt.Errorf("the marks are written, but at least one grading harness " +
					"could not be removed and is still using this cluster's containers and " +
					"network identifiers; the failures are named above. Remove them with " +
					"`twinet destroy --lab <name>` before the next run")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&subDir, "submissions", "s", "submissions", "directory of per-group submissions")
	cmd.Flags().StringVarP(&rubricPath, "rubric", "r", "", "rubric to grade against")
	cmd.Flags().StringVarP(&outDir, "out", "o", "", "where to write reports")
	cmd.Flags().IntVarP(&parallel, "parallel", "p", 8, "harnesses deployed concurrently")
	cmd.Flags().IntVar(&depth, "depth", 0, "AS hops of neighbourhood to keep; 0 keeps the whole topology")
	cmd.Flags().BoolVar(&keepHosts, "keep-hosts", true, "keep one host per neighbour, for end-to-end checks")
	cmd.Flags().BoolVar(&keepLabs, "keep-labs", false, "do not destroy harnesses, for investigating a disputed mark")
	cmd.Flags().StringVar(&token, "token", "", "agent token (or TWINET_TOKEN)")
	cmd.Flags().BoolVar(&allowUnsignedBundles, "allow-unsigned", false,
		"grade archives that carry no signature (only for archives collected by an older build)")
	cmd.Flags().DurationVar(&converge, "converge-timeout", 3*time.Minute, "how long a convergence predicate may wait")
	cmd.Flags().DurationVar(&settle, "settle", 0,
		"fixed grace period after configuring; 0 waits for convergence instead, which is both faster and correct")
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
		if err := destroyLab(tctx, c, h); err != nil {
			teardownFailed.Store(true)
			// Reported, not discarded. A harness that fails to come down keeps
			// its containers and its overlay identifiers, and at class scale a
			// handful of those exhaust the cluster -- after which every later
			// submission fails for reasons that have nothing to do with its
			// author. Four abandoned labs and 351 leftover overlay devices
			// were found on this cluster, and nothing had ever said so.
			slog.Error("a grading harness could not be removed; it is still using this "+
				"cluster's containers and network identifiers, and must be removed by hand "+
				"with `twinet destroy --lab <name>` before the next class-scale run",
				"lab", h.Name, "submission", s.Group, "err", err)
		}
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
		// An explicit fixed wait, for the rare case where someone needs one.
		select {
		case <-time.After(o.settle):
		case <-ctx.Done():
			return fail("waiting to settle", ctx.Err())
		}
	}

	// Otherwise wait for the control plane to settle, not for a fixed period.
	//
	// A fixed sleep is wrong in both directions: too short and a correct
	// submission is marked before its sessions come up, too long and every
	// submission in the class pays for the slowest one. It is also a fixed cost
	// per submission, which is the thing that decides whether grading a class
	// takes twenty minutes or an hour. The engine already has convergence
	// predicates; the only reason this was a sleep is that it was written
	// before they were wired in here.
	if err := grade.WaitConverged(ctx, &grade.Env{Topology: h, AS: s.AS, Exec: exec}, o.converge); err != nil {
		// Not fatal: a submission that never converges is a submission that
		// scores badly, which is a mark rather than an error. The checks below
		// will observe whatever state it reached.
		_ = err
	}

	rep := grade.Run(ctx, rubric, &grade.Env{Topology: h, AS: s.AS, Exec: exec},
		grade.RunOptions{ConvergeTimeout: o.converge, Parallel: 4})
	rep.Submission = s.Group
	rep.Lab = h.Name
	// Provenance, so a mark can be traced to exact software. An image tag is
	// not an identity: rebuilt later it is different software, and a regrade
	// against it is not comparable with the first.
	rep.Images = imageDigests(ctx, c, h)
	rep.Controller = Version

	// Nodes that disagree about what an image is means this mark was produced
	// by whichever build happened to be on whichever node this AS landed on.
	// Recording that in the provenance and releasing the mark anyway is the
	// worst of both: the evidence is there and nobody is told to look at it.
	for ref, id := range rep.Images {
		if !strings.HasPrefix(id, "DISAGREEMENT") {
			continue
		}
		rep.NeedsReview = true
		rep.Err = appendNote(rep.Err, fmt.Sprintf(
			"the nodes of this cluster do not agree on what %s is (%s), so this mark was "+
				"produced by whichever build was on whichever node this system was placed "+
				"on; make the images match and grade again", ref, strings.TrimPrefix(id, "DISAGREEMENT: ")))
	}

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

// imageDigests resolves every image the lab uses to the digest in use, for the
// provenance recorded beside a mark.
//
// It used to take the first node that answered and stop. Nodes drift, and when
// they do a student's routers run whichever build landed on whichever node
// their AS was placed on -- so the report stated one image identity for marks
// produced by two. An image the nodes do not agree on is recorded as exactly
// that, because a provenance line that quietly names one of two builds is worse
// than one that says the question has no single answer.
func imageDigests(ctx context.Context, c *client.Cluster, top *model.Topology) map[string]string {
	seen := map[string]bool{}
	var refs []string
	for _, d := range top.Devices {
		if d.Image != "" && !seen[d.Image] {
			seen[d.Image] = true
			refs = append(refs, d.Image)
		}
	}
	sort.Strings(refs)

	byRef := map[string]map[string]string{}
	for _, n := range c.Nodes {
		got, err := n.ImageDigests(ctx, refs)
		if err != nil {
			continue
		}
		for ref, id := range got {
			if id == "" {
				continue
			}
			if byRef[ref] == nil {
				byRef[ref] = map[string]string{}
			}
			byRef[ref][n.Name] = id
		}
	}

	out := map[string]string{}
	for ref, perNode := range byRef {
		nodes := sortedKeysOf(perNode)
		first := perNode[nodes[0]]
		agreed := true
		var parts []string
		for _, n := range nodes {
			parts = append(parts, fmt.Sprintf("%s on %s", shortID(perNode[n]), n))
			if perNode[n] != first {
				agreed = false
			}
		}
		if agreed {
			out[ref] = first
			continue
		}
		out[ref] = "DISAGREEMENT: " + strings.Join(parts, "; ")
	}
	return out
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
	deconflictOverlays(ctx, c, h)
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
		if err := checkSubmittedScript(s.Scripts[name]); err != nil {
			return fmt.Errorf("%s: %w", d.ID, err)
		}
		// Applied line by line, tolerating a line that is already true.
		//
		// A harness is deployed from the same model the submission was
		// captured from, so most addresses are already configured and the
		// kernel says so. Treating that as a failure quarantined the entire
		// class: eight submissions, every one of them correct, reported
		// ungradeable because re-adding an address that was already there
		// returns non-zero. A submission is a description of the state the
		// student wants, not a transcript that must replay cleanly.
		if err := applyDeviceScript(ctx, exec, d, s.Scripts[name]); err != nil {
			return err
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
	// The configuration is base64-encoded rather than written through a shell
	// heredoc. A submission is a file a student controls, and a line reading
	// exactly TWINET_EOF ends the heredoc early -- everything after it becomes
	// shell, running as root inside the container. Encoding removes the
	// delimiter entirely, so there is nothing left to escape.
	script := strings.Join([]string{
		"set -e",
		"printf '%s' " + shellQuote(base64.StdEncoding.EncodeToString([]byte(body))) +
			" | base64 -d > /etc/frr/frr.conf",
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
	// not fail when that happens, so the daemons have to be counted.
	//
	// This used to ask `vtysh -c "show version"`, which answers as long as any
	// one daemon is up. A submission whose OSPF configuration was rejected
	// therefore loaded successfully with ospfd dead, and was then marked on a
	// network in which its routers could not learn a route -- against a lab
	// that looked healthy. Every process the daemons file enables is now
	// checked by name.
	// Polled rather than slept on.
	//
	// A fixed two-second wait is a guess about how long FRR takes to bind, and
	// on a node running two hundred containers it is sometimes wrong -- so a
	// perfectly good submission was quarantined for being slow. Waiting for the
	// answer instead is both faster in the common case and correct in the rare
	// one; the deadline is what keeps a genuinely rejected configuration from
	// hanging the run.
	probe := "for d in " + strings.Join(render.EnabledDaemons(), " ") +
		"; do pidof \"$d\" >/dev/null 2>&1 || printf '%s ' \"$d\"; done"
	deadline := time.Now().Add(frrStartWait)
	var down []string
	for {
		res, err = exec(ctx, d.ID, []string{"sh", "-c", probe})
		if err != nil {
			return fmt.Errorf("checking that frr came up: %w", err)
		}
		down = strings.Fields(res.Stdout)
		if len(down) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("frr did not come up on the submitted configuration within %s: %s "+
		"%s not running, which usually means %s rejected a line of it",
		frrStartWait, strings.Join(down, ", "),
		map[bool]string{true: "is", false: "are"}[len(down) == 1],
		map[bool]string{true: "it", false: "they"}[len(down) == 1])
}

// frrStartWait bounds how long a submission's routing daemons are given to
// bind. Long enough for a loaded node, short enough that a rejected
// configuration is reported rather than waited on.
var frrStartWait = 30 * time.Second

// submissionFromArchive reads a submission out of a `twinet save` archive.
//
// The topology hash inside is checked against the lab being graded. A
// configuration is only meaningful relative to a topology -- addresses move
// when a lab is edited -- so grading an archive from a different revision
// produces failures the student could not have avoided, attributed to them.
func submissionFromArchive(p string, class *model.Topology) (submission, error) {
	b, files, err := readBundle(p)
	if err != nil {
		return submission{}, fmt.Errorf("%s: %w", filepath.Base(p), err)
	}
	group := b.Group
	if group == "" {
		group = strings.TrimSuffix(strings.TrimSuffix(filepath.Base(p), ".tar.gz"), ".tgz")
	}
	as, ok := class.ASes[b.AS]
	if !ok || as.Role != model.RoleStudent {
		return submission{}, fmt.Errorf("%s claims AS %d, which is not a student AS in this lab",
			filepath.Base(p), b.AS)
	}
	if b.Topology != "" && b.Topology != class.Hash {
		return submission{}, fmt.Errorf(
			"%s was written against topology %s but this lab is %s; grading it would "+
				"attribute to the student failures they could not have avoided",
			filepath.Base(p), short(b.Topology), short(class.Hash))
	}

	sub := submission{
		Group: group, AS: b.AS, Dir: p,
		Files: map[string]string{}, Scripts: map[string]string{},
	}
	for name, body := range files {
		switch {
		case strings.HasSuffix(name, ".conf"):
			sub.Files[strings.TrimSuffix(name, ".conf")] = string(body)
		case strings.HasSuffix(name, ".sh"):
			sub.Scripts[strings.TrimSuffix(name, ".sh")] = string(body)
		}
	}
	if len(sub.Files) == 0 && len(sub.Scripts) == 0 {
		return submission{}, fmt.Errorf("%s contains no configuration", filepath.Base(p))
	}
	return sub, nil
}

// shellQuote makes a string safe to pass as a single shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// applyDeviceScript runs a submitted script one command at a time, tolerating
// commands whose effect is already in place.
func applyDeviceScript(ctx context.Context, exec execFn, d *model.Device, body string) error {
	// Every line's exit status is examined.
	//
	// The runner used to end each command with `|| true`, so a script in which
	// every single line failed still reported success and the student was
	// marked on state that was never installed. It swallowed a real bug too:
	// the leading "-" that marks an optional line was passed to the shell as
	// part of the command, so `-ip tunnel del gre1` ran as a command called
	// "-ip", failed, was ignored -- and then `ip tunnel add gre1` failed
	// because the tunnel it was supposed to have removed was still there. The
	// 6in4 answer could not be restored from a student's own archive.
	//
	// The marker is stripped here, and only a line carrying it may fail.
	runner := strings.Join([]string{
		"rc=0",
		"while IFS= read -r c; do",
		`  case "$c" in ''|\#*) continue;; esac`,
		"  opt=0",
		`  case "$c" in -*) opt=1; c=${c#-};; esac`,
		`  if ! err=$($c 2>&1 >/dev/null); then`,
		`    if [ "$opt" = 0 ]; then`,
		`      echo "$c: $err" >&2`,
		"      rc=1",
		"    fi",
		"  fi",
		"done <<'TWINET_APPLY'",
		body,
		"TWINET_APPLY",
		"exit $rc",
	}, "\n")

	res, err := exec(ctx, d.ID, []string{"sh", "-c", runner})
	if err != nil {
		return fmt.Errorf("%s: running the submitted script: %w", d.ID, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s: the submitted script could not be applied: %s",
			d.ID, firstLine(res.Stderr+res.Stdout))
	}
	return nil
}

// resetToStudentStart returns one autonomous system to the state its owner was
// given: the platform's own addressing, the starting FRR configuration, and
// none of the kernel state a submission's scripts install.
//
// A submission has to be loaded onto this, not onto the solved lab. The
// difference decides what an omission means. A submission carries the files the
// student wrote; a router they never touched, or a file their archive does not
// contain, keeps whatever was already in the container -- and in a lab deployed
// at the reference that is the model answer. The student scores for a router
// they never configured, and the report cannot tell anyone it happened, because
// from the grader's side a correct router looks the same however it got that
// way.
func resetToStudentStart(ctx context.Context, exec execFn, top *model.Topology, asn int) error {
	as, ok := top.ASes[asn]
	if !ok {
		return fmt.Errorf("AS %d is not in the harness", asn)
	}
	devices := append([]*model.Device{}, as.Devices...)
	sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
	for _, d := range devices {
		if err := wipeDeviceState(ctx, exec, d); err != nil {
			return err
		}
		if d.Kind != model.KindRouter {
			continue
		}
		cfg, err := render.Router(top, d)
		if err != nil {
			return fmt.Errorf("%s: rendering the starting configuration: %w", d.ID, err)
		}
		if err := loadFRRConfig(ctx, exec, d, cfg.Platform); err != nil {
			return fmt.Errorf("%s: restoring the starting configuration: %w", d.ID, err)
		}
	}
	return nil
}

// wipeDeviceState removes what a submission can install and puts back what the
// platform owns, without recreating the container.
func wipeDeviceState(ctx context.Context, exec execFn, d *model.Device) error {
	lines := []string{
		// Tunnels first: deleting one takes the routes through it as well.
		`ip -d tunnel show 2>/dev/null | while read -r l; do ` +
			`case "$l" in sit0:*) continue;; esac; n=${l%%:*}; ` +
			`[ -n "$n" ] && ip tunnel del "$n" 2>/dev/null; done`,
		// Routes with no proto are the hand-installed ones, which is exactly
		// what distinguishes a student's work from a routing daemon's.
		`ip -o -4 route show | grep -v " proto " | while read -r r; do ` +
			`ip route del $r 2>/dev/null; done`,
		`ip -o -6 route show 2>/dev/null | grep -v " proto " | grep -v "^fe80" | ` +
			`while read -r r; do ip -6 route del $r 2>/dev/null; done`,
		// A switch's VLAN assignments are a submitted answer too.
		`if command -v ovs-vsctl >/dev/null 2>&1; then ` +
			`for b in $(ovs-vsctl list-br 2>/dev/null); do ` +
			`for p in $(ovs-vsctl list-ports "$b" 2>/dev/null); do ` +
			`ovs-vsctl clear port "$p" tag 2>/dev/null; ` +
			`ovs-vsctl clear port "$p" trunks 2>/dev/null; done; done; fi`,
	}
	// Addresses are flushed per interface and the planned ones put back, rather
	// than flushed wholesale: in the state a student starts from, the platform
	// has already addressed the interfaces it owns, and a deployment is what
	// puts those back. Doing it here means the reset does not depend on one.
	for _, i := range d.Ifaces {
		if i.Name == "" || i.Name == "lo" {
			continue
		}
		lines = append(lines, fmt.Sprintf("ip addr flush dev %s scope global 2>/dev/null", i.Name))
		if i.Owner != model.OwnerPlatform {
			continue
		}
		if i.Addr4 != "" {
			lines = append(lines, fmt.Sprintf("ip addr replace %s dev %s 2>/dev/null", i.Addr4, i.Name))
		}
		if i.Addr6 != "" {
			lines = append(lines, fmt.Sprintf("ip -6 addr replace %s dev %s 2>/dev/null", i.Addr6, i.Name))
		}
	}
	lines = append(lines, "exit 0")
	res, err := exec(ctx, d.ID, []string{"sh", "-c", strings.Join(lines, "\n")})
	if err != nil {
		return fmt.Errorf("%s: clearing the previous submission: %w", d.ID, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s: clearing the previous submission: %s",
			d.ID, firstLine(res.Stderr+res.Stdout))
	}
	// The script above suppresses every individual error and ends with
	// `exit 0`, deliberately: a route that another line already removed, or an
	// interface a student never addressed, must not stop the reset. But that
	// makes its exit status worthless as evidence, and the thing it is evidence
	// *for* is that the next student is being graded on their own work rather
	// than on the last one's.
	//
	// So the device is read back. Anything the reset was supposed to remove and
	// did not is reported, by name, and grading stops rather than marking
	// somebody against a system still carrying somebody else's tunnels.
	return verifyWiped(ctx, exec, d)
}

// verifyWiped reads a device back and reports what the reset failed to remove.
//
// Every section ends in a sentinel rather than in the exit status of a
// pipeline. The first version of this ended with a `grep` for stale routes, and
// grep exits 1 when it finds nothing -- which is the desired state. So a device
// that had been reset perfectly reported "the reset could not be checked", and
// a class run quarantined all eight submissions. Absence is the answer here,
// and an absence probe must not signal failure by finding nothing.
//
// The sentinel is what distinguishes "nothing left" from "the probe never
// ran": if the last line is missing, the device could not be read, and that is
// reported as its own condition rather than as a clean device.
func verifyWiped(ctx context.Context, exec execFn, d *model.Device) error {
	var b strings.Builder
	b.WriteString("echo '--tunnels'\n")
	b.WriteString("ip -d tunnel show 2>/dev/null | grep -v '^sit0:' | cut -d: -f1 || true\n")
	b.WriteString("echo '--routes'\n")
	b.WriteString(`ip -o -4 route show 2>/dev/null | grep -v " proto " || true` + "\n")
	b.WriteString("echo '--routes6'\n")
	b.WriteString(`ip -o -6 route show 2>/dev/null | grep -v " proto " | grep -v "^fe80" || true` + "\n")
	// The addresses the platform owns are put back by the reset, and a
	// submission can leave others behind. Both were cleared with errors
	// suppressed, so neither was ever confirmed.
	b.WriteString("echo '--addrs'\n")
	for _, i := range d.Ifaces {
		if i.Name == "" || i.Name == "lo" {
			continue
		}
		fmt.Fprintf(&b, "ip -o -4 addr show dev %s 2>/dev/null | "+
			`awk '{print "%s " $4}' || true`+"\n", i.Name, i.Name)
	}
	// A switch's VLAN assignments are a submitted answer too, and clearing them
	// was equally unchecked.
	b.WriteString("echo '--vlans'\n")
	b.WriteString("if command -v ovs-vsctl >/dev/null 2>&1; then " +
		"for br in $(ovs-vsctl list-br 2>/dev/null); do " +
		"for p in $(ovs-vsctl list-ports \"$br\" 2>/dev/null); do " +
		"t=$(ovs-vsctl get port \"$p\" tag 2>/dev/null | tr -d '[]\" '); " +
		"k=$(ovs-vsctl get port \"$p\" trunks 2>/dev/null | tr -d '[]\" '); " +
		"[ -n \"$t\" ] && [ \"$t\" != '[]' ] && echo \"$p tag=$t\"; " +
		"[ -n \"$k\" ] && [ \"$k\" != '[]' ] && echo \"$p trunks=$k\"; " +
		"done; done; fi || true\n")
	b.WriteString("echo '--done'\n")
	b.WriteString("exit 0\n")

	res, err := exec(ctx, d.ID, []string{"sh", "-c", b.String()})
	if err != nil {
		return fmt.Errorf("%s: checking that the previous submission was cleared: %w", d.ID, err)
	}
	if !strings.Contains(res.Stdout, "--done") {
		return fmt.Errorf("%s: checking that the previous submission was cleared did not "+
			"finish (exit %d): %s", d.ID, res.ExitCode, firstLine(res.Stderr+res.Stdout))
	}

	// What the platform's own addressing should be, so an address that belongs
	// there is not reported as somebody's leftover.
	want := map[string]bool{}
	for _, i := range d.Ifaces {
		if i.Owner == model.OwnerPlatform && i.Addr4 != "" {
			want[i.Name+" "+i.Addr4] = true
		}
	}

	var left []string
	section := ""
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "--") {
			section = strings.TrimPrefix(line, "--")
			continue
		}
		switch section {
		case "tunnels":
			left = append(left, "tunnel "+line)
		case "routes", "routes6":
			left = append(left, "route "+line)
		case "addrs":
			if !want[line] {
				left = append(left, "address "+line)
			}
		case "vlans":
			left = append(left, "vlan "+line)
		}
	}
	if len(left) == 0 {
		return nil
	}
	sort.Strings(left)
	if len(left) > 6 {
		left = append(left[:6], fmt.Sprintf("... and %d more", len(left)-6))
	}
	return fmt.Errorf("%s still carries the previous submission's work after being reset "+
		"(%s). Grading the next submission here would mark it on somebody else's "+
		"configuration", d.ID, strings.Join(left, "; "))
}

// scriptCommands are the commands a submitted script may use.
//
// Some answers are not FRR configuration: VLANs live in the switch, tunnels and
// host routes are set with ip(8). Those exercises need commands to be run, so
// the grader has to execute something a student wrote.
//
// It runs as root in that student's own container. The container is
// unprivileged and holds only the network capabilities, and the harness is
// disposable, so the blast radius is their own lab -- but "the sandbox will
// hold" is a poor last line of defence when the alternative costs a list. The
// list is what an answer to these exercises actually needs; anything else is
// refused with the offending line quoted, which is also better feedback than a
// mysterious failure.
var scriptCommands = map[string]bool{
	"ip": true, "tc": true, "ovs-vsctl": true, "ovs-ofctl": true,
	"sysctl": true, "ifconfig": true, "route": true, "bridge": true,
	"iptables": true, "ip6tables": true, "echo": true, "true": true, "sleep": true,
}

// checkSubmittedScript refuses anything outside the vocabulary the exercises
// need.
func checkSubmittedScript(body string) error {
	for n, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		// A leading "-" marks a line that may fail harmlessly. It is a marker
		// for the runner, not part of the command, so it is removed before the
		// command is identified -- otherwise the allowlist would see "-ip".
		t = strings.TrimPrefix(t, "-")
		// Substitution and chaining would let an allowed first word introduce
		// an arbitrary second one.
		if strings.ContainsAny(t, "`$") {
			return fmt.Errorf("line %d uses shell substitution, which submitted scripts may not: %q", n+1, t)
		}
		for _, part := range splitScriptCommands(t) {
			f := strings.Fields(part)
			if len(f) == 0 {
				continue
			}
			if !scriptCommands[f[0]] {
				return fmt.Errorf("line %d runs %q, which is not one of the commands a submission may use (%s)",
					n+1, f[0], strings.Join(sortedScriptCommands(), ", "))
			}
		}
	}
	return nil
}

// splitScriptCommands breaks a line on the separators a shell would act on, so
// each command in a chain is checked rather than only the first.
//
// Redirections are removed first, because they are not commands and splitting
// through one invents a fragment that is not there. A perfectly ordinary
// guarded line -- `ip link show tun6 >/dev/null 2>&1 || ip tunnel add ...` --
// was rejected because splitting on & left "1" standing alone, and the operator
// was told the submission was trying to run a command called "1".
//
// A redirection cannot smuggle anything in: the target is a filename, and
// substitution is refused outright before this point, so nothing inside one can
// become something to execute.
func splitScriptCommands(line string) []string {
	return strings.FieldsFunc(redirection.ReplaceAllString(line, " "), func(r rune) bool {
		return r == ';' || r == '|' || r == '&'
	})
}

// redirection matches the file descriptor redirections a shell would consume:
// ">file", "2>>file", "2>&1", "<file".
var redirection = regexp.MustCompile(`[0-9]*(>>?|<)\s*(&[0-9]+|[^\s;|&]+)`)

func sortedScriptCommands() []string {
	out := make([]string, 0, len(scriptCommands))
	for c := range scriptCommands {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
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
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		// An archive produced by `twinet save` is a submission too, and the
		// common case: a class hands in tarballs, not directory trees. Reading
		// only directories meant the grader could not consume its own output.
		if !e.IsDir() {
			if !strings.HasSuffix(e.Name(), ".tar.gz") && !strings.HasSuffix(e.Name(), ".tgz") {
				continue
			}
			sub, err := submissionFromArchive(filepath.Join(dir, e.Name()), class)
			if err != nil {
				return nil, err
			}
			subs = append(subs, sub)
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
	if err := refuseDuplicates(subs); err != nil {
		return nil, err
	}
	return subs, nil
}

// refuseDuplicates rejects a submission set in which two entries claim the same
// group or the same autonomous system.
//
// Both were accepted, and both lost work silently. Two archives for one group
// wrote their reports to the same filename, so whichever was graded second
// overwrote the first and nothing said which had survived. Two submissions for
// one AS were silently dropped down to one by the wave planner, and in batch
// mode were given the same harness name and could be deployed into the same
// lab at once.
//
// There is no correct guess available here. "Latest wins" is a policy about
// late submissions that belongs to a course, not to a grader, and picking one
// silently is how a student is marked on an attempt they did not intend to
// hand in. So it stops, names both, and lets a person decide.
func refuseDuplicates(subs []submission) error {
	byGroup := map[string][]string{}
	byAS := map[int][]string{}
	for _, s := range subs {
		key := strings.ToLower(s.Group)
		byGroup[key] = append(byGroup[key], s.Group)
		byAS[s.AS] = append(byAS[s.AS], s.Group)
	}

	var problems []string
	for g, all := range byGroup {
		if len(all) > 1 {
			problems = append(problems, fmt.Sprintf(
				"%d submissions claim to be group %q", len(all), g))
		}
	}
	for as, groups := range byAS {
		if len(groups) > 1 {
			sort.Strings(groups)
			problems = append(problems, fmt.Sprintf(
				"AS %d is claimed by %s", as, strings.Join(groups, ", ")))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("this set of submissions is ambiguous, so nothing was graded:\n  %s\n"+
		"Two submissions for one system cannot both be graded against the same lab, and "+
		"choosing between them is a decision about late work that belongs to whoever "+
		"runs the course. Remove or rename the ones that should not count",
		strings.Join(problems, "\n  "))
}

// execFn runs a command inside a device of a harness. It matches the shape the
// grading engine expects, so a harness and the shared lab are graded by exactly
// the same code path.
type execFn = func(ctx context.Context, deviceID string, cmd []string) (rt.ExecResult, error)

// unhealthyRouters names the routers that are not running the routing
// processes the lab gave them, with what each is missing.
//
// It is the precondition for grading anybody. A router with no ospfd has no
// symptom of its own: it simply stops answering, and what shows up is its
// *neighbours* failing to converge -- so the marks land on students whose work
// is correct, naming an autonomous system that is not the one at fault. That
// has happened three times during development, and each time it cost hours,
// because every configuration involved was right.
//
// Checking 212 routers costs a few seconds. Grading a class against a broken
// lab costs an hour and produces marks that have to be thrown away.
func unhealthyRouters(ctx context.Context, exec execFn, top *model.Topology) []string {
	var (
		mu  sync.Mutex
		bad []string
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, 32)
	script := "miss=''; for p in " + strings.Join(render.EnabledDaemons(), " ") +
		"; do pidof \"$p\" >/dev/null 2>&1 || miss=\"$miss $p\"; done; echo \"$miss\""
	for _, d := range top.SortedDevices() {
		if d.Kind != model.KindRouter {
			continue
		}
		wg.Add(1)
		go func(d *model.Device) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := exec(ctx, d.ID, []string{"sh", "-c", script})
			if err != nil || res.ExitCode != 0 {
				// A router that cannot be read is not a router that is well.
				// This used to return quietly, so a stopped container, an
				// unreachable node or a failing exec all counted as healthy and
				// the class was graded against them -- the students who lost
				// marks were the neighbours of whatever could not be seen.
				//
				// It is reported as its own condition rather than as a dead
				// daemon, so nobody is sent to look in the wrong place.
				detail := "could not be read"
				if err != nil {
					detail = fmt.Sprintf("could not be read: %v", err)
				} else if line := firstLine(res.Stderr + res.Stdout); line != "" {
					detail = "could not be read: " + line
				}
				mu.Lock()
				bad = append(bad, d.ID+" ("+detail+")")
				mu.Unlock()
				return
			}
			if missing := strings.TrimSpace(res.Stdout); missing != "" {
				mu.Lock()
				bad = append(bad, d.ID+" ("+missing+")")
				mu.Unlock()
			}
		}(d)
	}
	wg.Wait()
	sort.Strings(bad)
	return bad
}

// wiringWait bounds how long loading a submission waits for the lab to finish
// moving underneath it.
const wiringWait = 90 * time.Second

// waitForWiring blocks until every device has the interfaces the lab says it
// has, or gives up and says which one does not.
//
// Removing an interface and adding it back is how the platform rewires a
// device, so for a moment during any deploy or repair the interface genuinely
// is not there. A submission loaded in that moment failed on its first line --
// `ip addr replace ... dev port_BOS: Cannot find device "port_BOS"` -- and its
// owner was held for review for something that had nothing to do with them.
// Seven of eight students in one class run were quarantined this way.
//
// Waiting is the right response because the condition is temporary by
// construction: whatever removed the interface is in the middle of putting it
// back. Waiting forever is not, because the same message is what a genuinely
// misconfigured lab produces, and a grading run that hangs silently is worse
// than one that stops and says why. So it waits, briefly, and then reports the
// device and the interface it gave up on.
func waitForWiring(ctx context.Context, exec execFn, devices []*model.Device, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		missing, err := firstMissingIface(ctx, exec, devices)
		if err != nil || missing == "" {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s after waiting %s. Something is rewiring this lab -- "+
				"a deploy, or a node repairing a device -- or the interface is genuinely "+
				"absent and the lab needs redeploying", missing, limit)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// miswiredDevices names every device of the lab that does not have the
// interfaces the lab says it has, or cannot be read at all.
//
// This is a precondition for grading anybody, for the same reason the daemon
// sweep is. A device with a missing cable produces no symptom of its own: its
// neighbours fail to reach through it, and the marks land on whoever owns
// them. Checking two hundred devices costs a few seconds against the forty
// minutes a class run costs.
func miswiredDevices(ctx context.Context, exec execFn, top *model.Topology) []string {
	var (
		mu  sync.Mutex
		bad []string
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, 32)
	for _, d := range top.SortedDevices() {
		wg.Add(1)
		go func(d *model.Device) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			what, err := firstMissingIface(ctx, exec, []*model.Device{d})
			switch {
			case err != nil:
				mu.Lock()
				bad = append(bad, fmt.Sprintf("%s (could not be read: %v)", d.ID, err))
				mu.Unlock()
			case what != "":
				mu.Lock()
				bad = append(bad, what)
				mu.Unlock()
			}
		}(d)
	}
	wg.Wait()
	sort.Strings(bad)
	return bad
}

// firstMissingIface names a device interface the lab expects and the container
// does not have, or "" if they all agree.
func firstMissingIface(ctx context.Context, exec execFn, devices []*model.Device) (string, error) {
	for _, d := range devices {
		want := map[string]bool{}
		for _, i := range d.Ifaces {
			if i.Name != "" && i.Name != "lo" && (i.Link != nil || i.VLAN > 0) {
				want[i.Name] = true
			}
		}
		if len(want) == 0 {
			continue
		}
		res, err := exec(ctx, d.ID, []string{"sh", "-c",
			`ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1`})
		if err != nil {
			return "", fmt.Errorf("%s: checking its interfaces: %w", d.ID, err)
		}
		if res.ExitCode != 0 {
			return "", fmt.Errorf("%s: listing its interfaces exited %d: %s",
				d.ID, res.ExitCode, firstLine(res.Stderr+res.Stdout))
		}
		have := map[string]bool{}
		for _, n := range strings.Fields(res.Stdout) {
			have[n] = true
		}
		names := make([]string, 0, len(want))
		for n := range want {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if !have[n] {
				return fmt.Sprintf("%s has no interface %s", d.ID, n), nil
			}
		}
	}
	return "", nil
}

// waitForASWiring waits for one autonomous system's devices to have the
// interfaces the lab says they have.
func waitForASWiring(ctx context.Context, exec execFn, top *model.Topology, asn int) error {
	as, ok := top.ASes[asn]
	if !ok {
		return fmt.Errorf("AS %d is not in the harness", asn)
	}
	return waitForWiring(ctx, exec, as.Devices, wiringWait)
}

// notReadyToGrade explains why a lab cannot be graded yet, and what to do.
//
// It is one function because the two preconditions -- routing processes and
// wiring -- have the same shape, the same consequence and the same remedy, and
// because the remedy has a step people miss: a deploy that collided with
// something else on a node reports it and exits non-zero, having left that
// node's devices created but unconfigured.
func notReadyToGrade(what string, bad []string, manifest string) error {
	shown := bad
	tail := ""
	if len(shown) > 8 {
		shown = shown[:8]
		tail = fmt.Sprintf("\n  ... and %d more", len(bad)-len(shown))
	}
	return fmt.Errorf("%d %s, so nothing can be graded against it yet:\n  %s%s\n"+
		"A broken device has no symptom of its own -- its neighbours fail to converge, "+
		"and the marks land on students whose work is correct.\nRun `twinet deploy -m %s "+
		"--solve` to put it right, and note that a node busy with something else refuses "+
		"the deploy, so check that it reported no problems before grading",
		len(bad), what, strings.Join(shown, "\n  "), tail, manifest)
}

// appendNote joins report notes without losing either.
func appendNote(have, add string) string {
	if have == "" {
		return add
	}
	return have + "; " + add
}

// imageDisagreements names the images this cluster's nodes do not agree on.
//
// An image tag is not an identity: rebuilt in place it is different software
// under the same name. When two nodes hold different builds, a student's
// routers run whichever one landed on the node their system was placed on, and
// every report says the deployment is current.
func imageDisagreements(ctx context.Context, top *model.Topology, token string) []string {
	if !clustered(top) {
		return nil
	}
	tok, err := tokenFor(token)
	if err != nil {
		return nil
	}
	c := client.NewCluster(top.Lab, tok)
	var bad []string
	for ref, id := range imageDigests(ctx, c, top) {
		if strings.HasPrefix(id, "DISAGREEMENT") {
			bad = append(bad, ref+": "+strings.TrimPrefix(id, "DISAGREEMENT: "))
		}
	}
	sort.Strings(bad)
	return bad
}

// teardownFailed records that a grading harness could not be removed.
//
// It was logged and the run exited zero, so a class-scale run could leave a
// handful of labs consuming the cluster and report success -- after which later
// submissions fail for reasons that have nothing to do with their authors.
var teardownFailed atomic.Bool

// TeardownFailed reports whether any harness was left behind.
func TeardownFailed() bool { return teardownFailed.Load() }

// labImages resolves the digest of every image a lab uses, for the provenance
// recorded beside a mark.
func labImages(ctx context.Context, top *model.Topology, token string) map[string]string {
	if !clustered(top) {
		return nil
	}
	tok, err := tokenFor(token)
	if err != nil {
		return nil
	}
	return imageDigests(ctx, client.NewCluster(top.Lab, tok), top)
}
