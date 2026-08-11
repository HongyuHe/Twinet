package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
			return releaseGuard(summary, cmd.ErrOrStderr())
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

// imageDigests resolves every image the lab uses to the digest in use.
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
	for _, n := range c.Nodes {
		if got, err := n.ImageDigests(ctx, refs); err == nil && len(got) > 0 {
			return got
		}
	}
	return nil
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
	res, err := exec(ctx, d.ID, []string{"sh", "-c",
		"while IFS= read -r c; do case \"$c\" in ''|\\#*) continue;; esac; $c 2>/dev/null || true; done <<'TWINET_APPLY'\n" +
			body + "\nTWINET_APPLY"})
	if err != nil {
		return fmt.Errorf("%s: running the submitted script: %w", d.ID, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s: the submitted script could not be applied: %s",
			d.ID, firstLine(res.Stderr+res.Stdout))
	}
	return nil
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
	return subs, nil
}

// execFn runs a command inside a device of a harness. It matches the shape the
// grading engine expects, so a harness and the shared lab are graded by exactly
// the same code path.
type execFn = func(ctx context.Context, deviceID string, cmd []string) (rt.ExecResult, error)
