package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/HongyuHe/twinet/internal/nos"
	"github.com/HongyuHe/twinet/internal/place"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/svc"
)

// submission is one student group's work, on disk.
type submission struct {
	Group string
	AS    int
	Dir   string
	// Attempt is a signed benchmark/regrade identity. It is empty for normal
	// student submissions, which retain the one-final-submission policy.
	Attempt string
	// ArchiveSHA256 identifies an archive plan entry and remains in its report
	// so a benchmark cannot associate an expected score with another bundle.
	ArchiveSHA256 string
	// Controller is preserved when a signed reference archive is transformed
	// into benchmark/attestation mutations, so archive bytes do not depend on
	// a presentation-version tag added after collection.
	Controller string
	// TakenAt is retained when an attestation mutation is re-signed so a
	// deterministic fixture differs only in its declared transformation.
	TakenAt time.Time
	// Files maps a router's short name to the routing configuration submitted
	// for it. A submission that names a router the AS does not have is a
	// mistake worth reporting rather than ignoring: silently dropping it would
	// mark the student on an empty router and tell them their routing is
	// wrong.
	Files map[string]string
	// NOS maps a router's short name to the network operating system its
	// configuration was captured from, where the archive recorded one.
	//
	// An empty entry means an archive written before the field existed, which
	// is FRR by construction. It is never treated as "whatever this device
	// happens to run": a configuration is one vendor's syntax, and feeding it
	// to another's parser produces a router that accepted nothing and a mark
	// indistinguishable from a student who submitted nothing.
	NOS map[string]string
	// ROAs is what this system had authorised at the lab's trust anchor.
	//
	// Publishing is a student action rather than a line of configuration, so
	// it appears in no running-config. Without it, a re-mark in a private
	// harness -- whose trust anchor starts empty -- loses the mark for the
	// question about publishing, for a group that published correctly.
	ROAs []byte
	// Scripts maps a device's short name to a shell script run inside it.
	//
	// Not everything a student configures is FRR. VLANs live in the switch,
	// tunnels and host routes are set with ip(8), and a grader that could only
	// load FRR configuration would mark those exercises as failed no matter
	// what the student did.
	Scripts map[string]string
}

func (s submission) Identity() string {
	if s.Attempt == "" {
		return s.Group
	}
	return s.Group + "--" + s.Attempt
}

var attemptIdentity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validAttempt(value string) bool {
	return attemptIdentity.MatchString(value)
}

func newGradeBatchCmd(opts *Options) *cobra.Command {
	var (
		subDir          string
		rubricPath      string
		outDir          string
		parallel        int
		depth           int
		reduce          bool
		fullHarness     bool
		allAttempts     bool
		attestationPath string
		attestationKey  string
		keepHosts       bool
		keepLabs        bool
		token           string
		converge        time.Duration
		settle          time.Duration
	)
	cmd := &cobra.Command{
		Use:   "batch",
		Short: "Grade every submission in a compact isolated harness",
		Long: `Batch grading gives each submission a private network.

Grading a whole class in one shared lab is convenient and wrong: a group that
misconfigures a border router moves the marks of the groups behind it, and a
re-run after one group resubmits silently re-marks everyone. Nothing in the
output distinguishes "this student was wrong" from "someone else was".

Each submission is instead graded in a harness: its own AS in full, surrounded
by deterministic synthetic reference peers. The default compact harness retains
the target and IXPs while collapsing remote interiors; the first compact result
is compared with a full isolated harness before compact marks are released.

Warm workers reuse only a reset, uniquely named harness for the same target AS:
every lease restores the exact student baseline before and after loading one
submission. Use --full-harness (normally with --keep-labs) for a dispute, or
--reduce/--depth to select legacy slicing explicitly.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if allAttempts && token != "" {
				return fmt.Errorf("--all-attempts release batches require TWINET_TOKEN from the environment; --token is forbidden")
			}
			if fullHarness {
				if reduce || depth != 0 {
					return fmt.Errorf("--full-harness cannot be combined with --reduce or --depth")
				}
				keepHosts = true
			}
			class, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if rubricPath == "" {
				p, err := defaultRubric(class.Lab.Dir)
				if err != nil {
					return err
				}
				rubricPath = p
			}
			rubric, err := grade.LoadRubric(rubricPath)
			if err != nil {
				return err
			}
			if err := rubric.ValidateTopology(class); err != nil {
				return err
			}
			compact, auditHash, auditNote := compactEligibility(class, rubric, attestationPath, attestationKey)
			if !fullHarness && !reduce && depth == 0 && !compact {
				fmt.Fprintf(cmd.ErrOrStderr(), "compact harness disabled: %s; using full isolated fallback\n", auditNote)
			}
			subs, unread, err := readSubmissionsWithAttempts(subDir, class, allAttempts)
			if err != nil {
				return err
			}
			if len(subs) == 0 && len(unread) == 0 {
				return fmt.Errorf("no submissions found under %s", subDir)
			}
			announceUnreadable(cmd.ErrOrStderr(), unread, len(subs))
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
			start := time.Now()
			reports := make([]*grade.Report, len(subs))
			plans := make([]*batchHarness, 0, len(subs))
			for i, sub := range subs {
				h, err := harness.Slice(class, sub.AS,
					batchHarnessOptions(depth, reduce, fullHarness, compact, keepHosts, sub.Identity()))
				if err != nil {
					reports[i] = ungradeableReport(sub, rubric, "building the harness", err)
					continue
				}
				plans = append(plans, &batchHarness{
					index: i, queueIndex: len(plans), submission: sub, topology: h,
				})
			}

			c := client.NewCluster(class.Lab, tok)
			workloads := make([]place.Workload, 0, len(plans))
			for _, plan := range plans {
				workloads = append(workloads, place.Workload{
					Name: plan.submission.Identity(), DemandByNode: place.TopologyDemandByNode(plan.topology),
				})
			}
			var waves [][]int
			if len(workloads) > 0 {
				inventory, err := c.Inventories(cmd.Context())
				if err != nil {
					return fmt.Errorf("cannot schedule grading harnesses before marking: %w", err)
				}
				parallel, err = place.SafeWorkerCount(class.Lab, inventory, workloads, parallel)
				if err != nil {
					return fmt.Errorf("cannot derive a capacity-safe grading worker count: %w", err)
				}
				if parallel < 1 {
					return fmt.Errorf("cannot derive a non-zero capacity-safe grading worker count")
				}
				waves, err = place.ScheduleWaves(class.Lab, inventory, workloads, parallel)
				if err != nil {
					return fmt.Errorf("cannot schedule grading harnesses before marking: %w", err)
				}
			}
			fmt.Fprintf(cmd.ErrOrStderr(),
				"grading %d submission(s) in %d capacity-safe wave(s), at most %d at a time\n",
				len(plans), len(waves), parallel)

			var warm *warmBatchManager
			if !keepLabs && compact {
				workersByASN := map[int]int{}
				for _, plan := range plans {
					workersByASN[plan.submission.AS]++
				}
				for asn, workers := range workersByASN {
					if workers > parallel {
						workersByASN[asn] = parallel
					}
				}
				warm = newWarmBatchManager(class, rubric, batchOpts{
					token: tok, depth: depth, keepHosts: keepHosts, reduce: reduce, fullHarness: fullHarness,
					compact: compact, auditHash: auditHash,
					keepLab: false, converge: converge, settle: settle, outDir: outDir,
				}, workersByASN)
			}
			var mu sync.Mutex
			done := 0
			for waveIndex := 0; waveIndex < len(waves); waveIndex++ {
				wave := waves[waveIndex]
				wavePlans := make([]*batchHarness, 0, len(wave))
				waveWorkloads := make([]place.Workload, 0, len(wave))
				for _, index := range wave {
					wavePlans = append(wavePlans, plans[index])
					waveWorkloads = append(waveWorkloads, workloads[index])
				}
				if err := waitForHarnessCapacity(cmd.Context(), c, class.Lab, waveWorkloads); err != nil {
					return fmt.Errorf("harness wave was not admitted before marking: %w", err)
				}
				var wg sync.WaitGroup
				var retryMu sync.Mutex
				var retry []int
				for _, plan := range wavePlans {
					wg.Add(1)
					go func(plan *batchHarness) {
						defer wg.Done()
						var rep *grade.Report
						if warm != nil {
							rep = warm.grade(cmd.Context(), plan.submission)
						} else {
							rep = gradeOneHarness(cmd.Context(), class, rubric, plan.submission, plan.topology, batchOpts{
								token: tok, depth: depth, keepHosts: keepHosts, reduce: reduce, fullHarness: fullHarness,
								keepLab: keepLabs, converge: converge, settle: settle,
								outDir: outDir,
							})
						}
						if capacityBlockedReport(rep) {
							retryMu.Lock()
							retry = append(retry, plan.queueIndex)
							retryMu.Unlock()
							return
						}
						reports[plan.index] = rep

						mu.Lock()
						done++
						fmt.Fprintf(cmd.ErrOrStderr(), "  [%d/%d] %-12s %.2f / %.2f\n",
							done, len(subs), rep.Identity(), rep.Total, rep.MaxTotal)
						mu.Unlock()
					}(plan)
				}
				wg.Wait()
				if len(retry) > 0 {
					// A concurrent external deployment won capacity between
					// the preflight and agent admission. These submissions
					// have not been marked; queue them for a fresh capacity
					// check instead of quarantining correct work for host
					// pressure.
					sort.Ints(retry)
					waves = append(waves, retry)
					fmt.Fprintf(cmd.ErrOrStderr(),
						"  capacity changed during admission; queued %d harness(es) for a later safe wave\n",
						len(retry))
				}
			}
			if warm != nil {
				tctx, cancel := context.WithTimeout(context.WithoutCancel(cmd.Context()), 3*time.Minute)
				err := warm.close(tctx)
				cancel()
				if err != nil {
					teardownFailed.Store(true)
					return fmt.Errorf("destroying warm grading harnesses: %w", err)
				}
			}

			reports = append(reports, quarantineUnreadable(unread, rubric, class.Name)...)
			for _, report := range reports {
				applyBatchReportProvenance(report, class, rubric)
			}
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
					"`twinet -m <class manifest> destroy --lab <name> --yes` before the next " +
					"run: the class manifest is what says which machines to reach")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&subDir, "submissions", "s", "submissions", "directory of per-group submissions")
	cmd.Flags().StringVarP(&rubricPath, "rubric", "r", "", "rubric to grade against")
	cmd.Flags().StringVarP(&outDir, "out", "o", "", "where to write reports")
	cmd.Flags().IntVarP(&parallel, "parallel", "p", 0,
		"maximum harnesses deployed concurrently (0 derives a safe width from live admission)")
	cmd.Flags().IntVar(&depth, "depth", 0, "legacy AS hops of neighbourhood to keep (disables compact harness)")
	cmd.Flags().BoolVar(&reduce, "reduce", false,
		"use the legacy router-facing reducer instead of the compact synthetic harness")
	cmd.Flags().BoolVar(&fullHarness, "full-harness", false,
		"force the complete reference topology; use with --keep-labs to investigate a disputed mark")
	cmd.Flags().BoolVar(&allAttempts, "all-attempts", false,
		"accept repeated group/AS archives only when every duplicate has a distinct signed attempt identity")
	cmd.Flags().BoolVar(&keepHosts, "keep-hosts", true, "keep one host per neighbour, for end-to-end checks")
	cmd.Flags().StringVar(&attestationPath, "compact-attestation", "",
		"signed compact/full equivalence attestation required to enable compact harnesses")
	cmd.Flags().StringVar(&attestationKey, "compact-attestation-key", "",
		"PEM public key that verifies --compact-attestation")
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
	token         string
	depth         int
	reduce        bool
	fullHarness   bool
	compact       bool
	auditHash     string
	keepHosts     bool
	keepLab       bool
	converge      time.Duration
	settle        time.Duration
	outDir        string
	warmNamespace string
}

// batchHarnessOptions makes compact synthetic reference peers the normal
// isolated grading substrate. The target AS remains whole; --full-harness is
// the dispute path, while --reduce/--depth explicitly retain legacy slicing
// behavior for audits and migration comparisons.
func batchHarnessOptions(depth int, reduce, full, compact, keepHosts bool, suffix string) harness.Options {
	options := harness.Options{Depth: depth, KeepHosts: keepHosts, Reduce: reduce, Suffix: suffix}
	switch {
	case full:
		options.Depth = 0
		options.Reduce = false
		options.Synthetic = false
		options.KeepHosts = true
	case reduce || depth > 0:
		options.Synthetic = false
	case compact:
		options.Depth = 0
		options.Synthetic = true
	default:
		options.Depth = 0
		options.Reduce = false
		options.Synthetic = false
	}
	return options
}

type batchHarness struct {
	index      int
	queueIndex int
	submission submission
	topology   *model.Topology
}

func ungradeableReport(s submission, rubric *grade.Rubric, stage string, err error) *grade.Report {
	return &grade.Report{
		Submission:    s.Group,
		Attempt:       s.Attempt,
		ArchiveSHA256: s.ArchiveSHA256,
		GraderSource:  grade.GraderSource,
		MaxTotal:      rubric.MaxTotal(),
		AS:            s.AS,
		Err:           fmt.Sprintf("%s: %v", stage, err),
		NeedsReview:   true,
	}
}

func applyBatchReportProvenance(report *grade.Report, class *model.Topology, rubric *grade.Rubric) {
	if report == nil {
		return
	}
	if class != nil {
		report.Manifest = class.Hash
		if class.Lab != nil {
			report.ImageLock = class.Lab.Images.LockDigest
		}
	}
	if rubric != nil {
		report.Rubric = rubric.Metadata.Name
		report.RubricHash = compactRubricHash(rubric)
	}
	report.Controller = Version
	report.GraderSource = grade.GraderSource
}

const capacityAdmissionPrefix = "capacity admission: "

func capacityBlockedReport(rep *grade.Report) bool {
	return rep != nil && strings.HasPrefix(rep.Err, capacityAdmissionPrefix)
}

type capacityAdmissionError struct{ err error }

func (e *capacityAdmissionError) Error() string { return e.err.Error() }
func (e *capacityAdmissionError) Unwrap() error { return e.err }

// waitForHarnessCapacity queues a wave while another lab is consuming the
// shared node budget. It never lets a correct submission enter gradeOne until
// the entire wave fits; pressure therefore cannot turn into a post-deployment
// quarantine attributed to the student.
func waitForHarnessCapacity(ctx context.Context, c *client.Cluster, lab *model.Lab,
	workloads []place.Workload,
) error {
	if len(workloads) == 0 {
		return nil
	}
	for {
		inventory, err := c.Inventories(ctx)
		if err == nil {
			waves, scheduleErr := place.ScheduleWaves(lab, inventory, workloads, len(workloads))
			if scheduleErr == nil && len(waves) == 1 {
				return nil
			}
			err = scheduleErr
			if err == nil {
				err = fmt.Errorf("current infrastructure capacity requires this wave to wait")
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for capacity: %w", ctx.Err())
		case <-time.After(2 * time.Second):
			slog.Info("waiting for capacity-safe grading wave", "reason", err)
		}
	}
}

func gradeOneHarness(ctx context.Context, class *model.Topology, rubric *grade.Rubric,
	s submission, h *model.Topology, o batchOpts,
) *grade.Report {

	fail := func(stage string, err error) *grade.Report {
		rep := ungradeableReport(s, rubric, stage, err)
		rep.HarnessType = batchHarnessType(o)
		var capacityErr *capacityAdmissionError
		if errors.As(err, &capacityErr) {
			rep.Err = capacityAdmissionPrefix + err.Error()
		}
		return rep
	}

	// Record which network produced the mark, before anything can go wrong.
	// A student disputing a grade is entitled to see the exact topology.
	sum := harness.Describe(class, h, s.AS, o.depth)
	if raw, err := json.MarshalIndent(sum, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(o.outDir, s.Group+".harness.json"), raw, 0o644)
	}

	c := client.NewCluster(h.Lab, o.token)
	// A harness exists only while this process is marking against it. The
	// heartbeat is what says so; the nodes reclaim the lab if it stops, which
	// is the entire difference between a controller that is killed here and a
	// cluster that has to be cleaned up by hand afterwards.
	//
	// It starts before the deployment, so a run interrupted between deploy and
	// the first renewal is still covered by the lease the deployment created.
	owner := client.EphemeralOwnerName("grade-batch")
	heartbeat := c.KeepEphemeralAlive(ctx, h.Name, owner, ephemeralHarnessTTL)
	defer heartbeat.Stop()
	defer func() {
		if o.keepLab {
			// A kept harness is still disposable: --keep-labs is for
			// investigating one mark, not for creating a permanent lab. It is
			// granted the longest single lifetime a node will give so an
			// investigation has room, and it is still bounded, so an
			// investigation that is abandoned does not cost the cluster
			// indefinitely.
			kctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer cancel()
			if err := c.RenewEphemeral(kctx, h.Name, owner, keptHarnessTTL); err != nil {
				slog.Warn("could not extend a kept harness's lifetime", "lab", h.Name, "err", err)
			}
			slog.Info("keeping a grading harness for investigation; it is still ephemeral "+
				"and the cluster will reclaim it once its lifetime ends",
				"lab", h.Name, "lifetime", keptHarnessTTL)
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
				"with `twinet -m <class manifest> destroy --lab <name> --yes` before the next "+
				"class-scale run",
				"lab", h.Name, "submission", s.Group, "err", err)
		}
	}()

	// A harness of this name may already exist, and if it does it is not
	// empty.
	//
	// The name is a function of the lab, the AS and the group, so a regrade
	// gets the same one -- and after --keep-labs or a teardown that failed,
	// the containers from the previous attempt are still running with the
	// previous submission's configuration on them. Applies are not
	// authoritative on a node agent: they add what the plan says and leave
	// what it does not mention, so a route, a tunnel, a ROA or a route-map
	// from the last attempt survives into this one and the group is marked
	// for work it did not submit this time.
	if err := clearStaleHarness(ctx, c, h); err != nil {
		return fail("clearing the previous attempt's harness", err)
	}

	if err := deployQuiet(ctx, c, h, s.AS, owner); err != nil {
		return fail("deploying the harness", err)
	}

	exec, err := execFunc(ctx, h, o.token)
	if err != nil {
		return fail("connecting to the harness", err)
	}
	if err := applySubmission(ctx, exec, h, s); err != nil {
		return fail("loading the submission", err)
	}

	// The reference side of every inter-AS link is moved to whatever addresses
	// this group actually configured.
	//
	// The assignment lets a group pick its own peering addresses, and only
	// class grading did this: a group that used its own /30 kept the reference
	// on the planned address, so the session never came up and it lost the eBGP
	// and policy marks for an answer the assignment explicitly permits --
	// exactly the marks `grade batch` exists to award fairly.
	ads, undoAdapt, why := adaptNeighbours(ctx, exec, h, s.AS)
	if o.keepLab && len(ads) > 0 {
		// Only matters when the lab outlives the run; otherwise the harness
		// goes away and takes the adaptation with it.
		defer func() {
			uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer cancel()
			if err := undoAdapt(uctx); err != nil {
				slog.Error("a peering adaptation could not be undone in a kept harness",
					"lab", h.Name, "err", err)
			}
		}()
	}
	for _, ad := range ads {
		slog.Info("adapted a reference peer to the submission's addressing",
			"submission", s.Group, "why", ad.Because, "device", ad.Device,
			"address", ad.Added, "session", ad.Session)
	}
	if len(why) > 0 {
		// Not a mark. A reference peer that could not be moved means the
		// session under test cannot come up for a reason that is the grader's,
		// not the student's, and a zero here would be indistinguishable from a
		// student who never configured it.
		return fail("adapting the reference to this submission's peering addresses",
			fmt.Errorf("%s", strings.Join(why, "; ")))
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
		preConvergedRunOptions(o.converge))
	rep.Submission = s.Group
	rep.Attempt = s.Attempt
	rep.ArchiveSHA256 = s.ArchiveSHA256
	rep.Lab = h.Name
	rep.HarnessType = batchHarnessType(o)
	// Provenance, so a mark can be traced to exact software. An image tag is
	// not an identity: rebuilt later it is different software, and a regrade
	// against it is not comparable with the first.
	rep.Images = imageDigests(ctx, c, h)
	rep.Controller = Version
	rep.ImageLock = h.Lab.Images.LockDigest
	rep.Agents = agentVersions(ctx, c)

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

func batchHarnessType(o batchOpts) string {
	switch {
	case o.fullHarness:
		return "full"
	case o.reduce || o.depth > 0:
		return "legacy-reduced"
	case o.compact:
		return "compact-synthetic"
	default:
		return "full-audit-fallback"
	}
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

func agentVersions(ctx context.Context, c *client.Cluster) map[string]string {
	out := map[string]string{}
	if c == nil {
		return out
	}
	for _, result := range c.Status(ctx) {
		if result.Err == nil && result.Value.Version != "" {
			out[result.Node] = result.Value.Version
		}
	}
	return out
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, ", ")
}

// ephemeralHarnessTTL is how long a node holds a grading harness between
// heartbeats. It is long enough to survive a slow or briefly unreachable
// cluster and short enough that an abandoned class-scale run is reclaimed
// before the next one needs the capacity.
const ephemeralHarnessTTL = 15 * time.Minute

// keptHarnessTTL is the one-off lifetime a harness kept with --keep-labs is
// given when the run that created it ends. Nothing renews it afterwards, so it
// is how long an investigation has before the cluster takes the harness back.
const keptHarnessTTL = time.Hour

func deployQuiet(ctx context.Context, c *client.Cluster, h *model.Topology, target int, owner string) error {
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
		// Nobody's work lives in a harness, and nothing outside this process
		// wants it. Saying so at deployment is what lets a node reclaim it
		// when this process is killed before its teardown runs.
		Ephemeral:           true,
		EphemeralTTLSeconds: int(ephemeralHarnessTTL.Seconds()),
		EphemeralOwner:      owner,
		Workers:             harnessDeployWorkers(len(h.Devices)),
		Generation:          time.Now().UTC().Format("20060102T150405.000"),
		StrictAdmission:     true,
	})
	for _, r := range results {
		if r.Err != nil {
			if strings.Contains(r.Err.Error(), "strict admission") ||
				strings.Contains(r.Err.Error(), "allocatable") {
				return &capacityAdmissionError{err: fmt.Errorf("node %s: %w", r.Node, r.Err)}
			}
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

func harnessDeployWorkers(devices int) int {
	workers := (devices + 39) / 40
	if workers < 8 {
		return 8
	}
	if workers > 56 {
		return 56
	}
	return workers
}

func destroyLab(ctx context.Context, c *client.Cluster, h *model.Topology) error {
	return destroyLabHeld(ctx, c, h, "")
}

func destroyLabHeld(ctx context.Context, c *client.Cluster, h *model.Topology, hold string) error {
	vnis := make([]uint32, 0, len(h.Links))
	for _, l := range h.Links {
		if l.VNI != 0 {
			vnis = append(vnis, l.VNI)
		}
	}
	results := c.DestroyEphemeralHeld(ctx, h.Name, vnis, hold)
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
		if err := loadRouterConfig(ctx, exec, d, submissionConfigNOS(s.NOS, name), s.Files[name],
			nos.LoadOptions{RequireDaemons: true}); err != nil {
			return fmt.Errorf("%s: %w", d.ID, err)
		}
		// A submission's routing configuration can reset sessions while the
		// validator is still reconnecting -- and a route that arrives before
		// the ROAs is filtered as if there were none. The daemon records the
		// validation state afterwards but does not re-run the policy, so a
		// submission that rejects invalid announcements perfectly still ends
		// up carrying the lab's hijack. The refresh is what makes the answer
		// visible; it runs in the background because it waits on a service.
		refreshRPKIInBackground(ctx, exec, d)
	}

	// What the group authorised at the trust anchor, replayed before anything
	// is measured so the routes it makes valid are valid while they converge.
	if len(s.ROAs) > 0 {
		if err := replayROAs(ctx, exec, h, as, s.ROAs); err != nil {
			return err
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

// loadRouterConfigBody installs a submitted configuration through the device's
// own provider and proves the control plane survived it.
//
// The provider owns the mechanism -- FRR's exact-reload tool, BIRD's
// `configure` -- because both share the same requirement and neither shares an
// implementation: the configuration must be adopted by the running daemon, so
// that a line it rejects is reported as a rejected line the student can be
// shown instead of a router that silently failed to come up and grades as a
// total loss.
func loadRouterConfigBody(ctx context.Context, exec execFn, d *model.Device, declared, body string) error {
	return loadRouterConfig(ctx, exec, d, declared, body, nos.LoadOptions{RequireDaemons: true})
}

// loadPlatformConfig restores a student's empty platform baseline. It must
// restart the routing daemons, but deliberately does not require all of them
// to remain up: the student has not supplied the OSPF/BGP configuration that
// starts their routing exercise yet. Every actual submission still goes
// through loadRouterConfigBody, which rejects a daemon that dies on its
// submitted file.
func loadPlatformConfig(ctx context.Context, exec execFn, d *model.Device, body string) error {
	provider, err := nos.Resolve(d)
	if err != nil {
		return fmt.Errorf("its network operating system could not be resolved: %w", err)
	}
	return loadRouterConfig(ctx, exec, d, provider.ConfigFile().NOS, body, nos.LoadOptions{})
}

// refreshRPKIInBackground re-runs inbound policy once the validator answers.
func refreshRPKIInBackground(ctx context.Context, exec execFn, d *model.Device) {
	if d.Kind != model.KindRouter {
		return
	}
	// The script is FRR's own CLI and asks about an RPKI cache. A NOS that
	// declares no origin validation has neither, and running it there would
	// put an FRR binary inside a container that does not have one.
	provider, err := nos.Resolve(d)
	if err != nil || !provider.Capabilities().Supports(nos.FeatureRPKI) {
		return
	}
	// Detached from this exec: the wait is for another container's service, and
	// nothing here should hold a grading run open for it. A router with no
	// validator configured leaves the loop on its own.
	script := "(" + render.RPKIRefreshScript + ") >/dev/null 2>&1 &"
	if _, err := exec(ctx, d.ID, []string{"sh", "-c", script}); err != nil {
		slog.Debug("could not start the origin-validation refresh", "device", d.ID, "err", err)
	}
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
	if b.Attempt != "" && !validAttempt(b.Attempt) {
		return submission{}, fmt.Errorf("%s has unsafe attempt identity %q", filepath.Base(p), b.Attempt)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return submission{}, fmt.Errorf("%s: digest archive: %w", filepath.Base(p), err)
	}
	archiveDigest := sha256.Sum256(raw)

	sub := submission{
		Group: group, AS: b.AS, Dir: p, Attempt: b.Attempt,
		ArchiveSHA256: hex.EncodeToString(archiveDigest[:]), Controller: b.Controller, TakenAt: b.TakenAt,
		Files: map[string]string{}, Scripts: map[string]string{}, NOS: map[string]string{},
	}
	m, err := classifyBundle(files)
	if err != nil {
		return submission{}, fmt.Errorf("%s: %w", filepath.Base(p), err)
	}
	sub.ROAs = m.ROAs
	for name, body := range m.Configs {
		sub.Files[name] = string(body)
		if declared := submissionConfigNOS(b.NOS, name); declared != "" {
			sub.NOS[name] = declared
		}
	}
	for name, body := range m.Scripts {
		sub.Scripts[name] = string(body)
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
		// Run through a shell, because the syntax the checker accepts is
		// shell syntax.
		//
		// The line used to be run as a bare `$c`, which word-splits and globs
		// but does not act on operators. So `ip link show tun6 >/dev/null 2>&1
		// || ip tunnel add ...` -- the ordinary guarded form, which the checker
		// accepts and which the reference answer itself uses -- ran ip(8) with
		// ">/dev/null", "2>&1" and "||" as arguments, failed, and was reported
		// to the student as their mistake. And `true && ip ...` silently ran
		// nothing but `true`, so the configuration was never installed and the
		// submission was marked on a device where nothing had happened.
		//
		// Nothing new gets in: every word of every fragment has already been
		// checked against the allowlist, and substitution is refused outright,
		// so there is no way for a shell to turn this text into a command the
		// checker did not see.
		`  if ! err=$(sh -c "$c" 2>&1 >/dev/null); then`,
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
		if err := loadPlatformConfig(ctx, exec, d, cfg.Platform); err != nil {
			return fmt.Errorf("%s: restoring the starting configuration: %w", d.ID, err)
		}
	}
	// What this system published at the trust anchor is part of what it did,
	// so it is part of what the reset removes.
	//
	// It was not, and publishing is not a line of configuration that wiping a
	// device takes away: the previous occupant's authorisation -- the
	// reference's, on the first submission of a run -- stayed at the anchor,
	// and a submission that never published one inherited it and scored the
	// mark for it.
	return withdrawROAs(ctx, exec, top, as)
}

// withdrawROAs removes every authorisation this system holds at the trust
// anchor, and confirms none is left.
func withdrawROAs(ctx context.Context, exec execFn, top *model.Topology, as *model.AS) error {
	addr := svc.RPKIAddrFor(top, as.ASN)
	if addr == "" || len(as.Routers) == 0 {
		return nil
	}
	r := rpkiFacingRouter(as)
	held, err := publishedROAs(ctx, exec, top, as)
	if err != nil {
		// Unreadable is not empty. Carrying on would grade the next submission
		// against whatever is still published, with nothing saying so.
		return fmt.Errorf("AS %d: what it has published could not be read (%w), so it "+
			"cannot be cleared before the next submission", as.ASN, err)
	}
	for _, v := range held {
		body := fmt.Sprintf(`{"prefix":%q,"asn":%d,"withdraw":true}`, v.Prefix, v.ASN)
		res, err := exec(ctx, r.ID, []string{"sh", "-c", fmt.Sprintf(
			"curl -sf -m 5 -X POST http://%s%s/roas -d %s", addr, svc.PublishListen,
			shellQuote(body))})
		if err != nil {
			return fmt.Errorf("AS %d: withdrawing %s: %w", as.ASN, v.Prefix, err)
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("AS %d: withdrawing %s: the trust anchor refused: %s",
				as.ASN, v.Prefix, firstLine(res.Stderr+res.Stdout))
		}
	}
	// Read back, because a withdrawal that quietly failed leaves the next
	// submission holding somebody else's answer.
	left, err := publishedROAs(ctx, exec, top, as)
	if err != nil {
		return fmt.Errorf("AS %d: what it has published could not be re-read: %w", as.ASN, err)
	}
	if len(left) > 0 {
		return fmt.Errorf("AS %d still has %d authorisation(s) at the trust anchor after "+
			"being cleared", as.ASN, len(left))
	}
	return nil
}

// kernelFallbackTunnels are the tunnel devices the kernel creates for itself
// when a tunnel module is loaded, one per encapsulation, and refuses to let
// anybody delete.
//
// They are not anybody's answer: `ip tunnel del gre0` fails with "Operation
// not permitted" on every device where the gre module has ever been loaded --
// which, in a course that teaches tunnelling, is every router a student has
// touched. Only sit0 was excluded, so the reset could not remove gre0, the
// read-back that follows counted it as the previous submission's leftover
// work, and every submission in the run was quarantined:
//
//	group3  loading the submission: as3/ATL still carries the previous
//	        submission's work after being reset (tunnel gre0)
//
// A whole class receives no marks, honestly and uselessly. They carry no state
// between submissions either: any address on one is flushed and any route
// through one is removed by the lines that follow.
var kernelFallbackTunnels = []string{
	"sit0", "gre0", "gretap0", "erspan0", "tunl0",
	"ip6tnl0", "ip6gre0", "ip6gretap0", "ip_vti0", "ip6_vti0",
}

// fallbackTunnelPattern matches those names at the head of an `ip tunnel show`
// line, for a grep that keeps only what somebody actually created.
func fallbackTunnelPattern() string {
	return "^(" + strings.Join(kernelFallbackTunnels, "|") + "):"
}

// fallbackTunnelCases is the same set as shell `case` patterns.
func fallbackTunnelCases() string {
	out := make([]string, 0, len(kernelFallbackTunnels))
	for _, n := range kernelFallbackTunnels {
		out = append(out, n+":*")
	}
	return strings.Join(out, "|")
}

// wipeDeviceState removes what a submission can install and puts back what the
// platform owns, without recreating the container.
func wipeDeviceState(ctx context.Context, exec execFn, d *model.Device) error {
	lines := []string{
		// Tunnels first: deleting one takes the routes through it as well.
		`ip -d tunnel show 2>/dev/null | while read -r l; do ` +
			`case "$l" in ` + fallbackTunnelCases() + `) continue;; esac; n=${l%%:*}; ` +
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
			`ovs-vsctl del-fail-mode "$b" 2>/dev/null; ` +
			`for p in $(ovs-vsctl list-ports "$b" 2>/dev/null); do ` +
			`ovs-vsctl clear port "$p" tag 2>/dev/null; ` +
			`ovs-vsctl clear port "$p" trunks 2>/dev/null; ` +
			// vlan_mode is part of the answer too, and clearing the other two
			// without it leaves the reference's trunk ports behind. In Open
			// vSwitch a trunk port with no trunks list carries every VLAN, so
			// a student who configured nothing inherited a working answer.
			`ovs-vsctl clear port "$p" vlan_mode 2>/dev/null; done; done; fi`,
	}
	// Addresses are flushed per interface and the planned ones put back, rather
	// than flushed wholesale: in the state a student starts from, the platform
	// has already addressed the interfaces it owns, and a deployment is what
	// puts those back. Doing it here means the reset does not depend on one.
	for _, i := range d.Ifaces {
		if i.Name == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("ip link set dev %s up 2>/dev/null", i.Name))
		// The loopback is included.
		//
		// It was skipped, and a restart of FRR does not flush kernel
		// addresses, so every submission inherited the previous one's loopback
		// -- and the reference's, on the first run. That is marks for
		// addressing nobody did, and an OSPF and iBGP fabric that comes up
		// because the addresses the student was asked to configure are already
		// there. Flushing global scope leaves 127.0.0.1, which is link-local
		// to the host and not anybody's answer.
		lines = append(lines, fmt.Sprintf("ip addr flush dev %s scope global 2>/dev/null", i.Name))
		if i.Owner != model.OwnerPlatform {
			continue
		}
		if i.Addr4 != "" {
			lines = append(lines, fmt.Sprintf("ip addr replace %s brd + dev %s 2>/dev/null", i.Addr4, i.Name))
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
	b.WriteString("ip -d tunnel show 2>/dev/null | grep -Ev '" + fallbackTunnelPattern() +
		"' | cut -d: -f1 || true\n")
	b.WriteString("echo '--routes'\n")
	b.WriteString(`ip -o -4 route show 2>/dev/null | grep -v " proto " || true` + "\n")
	b.WriteString("echo '--routes6'\n")
	b.WriteString(`ip -o -6 route show 2>/dev/null | grep -v " proto " | grep -v "^fe80" || true` + "\n")
	// The addresses the platform owns are put back by the reset, and a
	// submission can leave others behind. Both were cleared with errors
	// suppressed, so neither was ever confirmed.
	b.WriteString("echo '--addrs'\n")
	for _, i := range d.Ifaces {
		if i.Name == "" {
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
		"m=$(ovs-vsctl get port \"$p\" vlan_mode 2>/dev/null | tr -d '[]\" '); " +
		"[ -n \"$t\" ] && [ \"$t\" != '[]' ] && echo \"$p tag=$t\"; " +
		"[ -n \"$k\" ] && [ \"$k\" != '[]' ] && echo \"$p trunks=$k\"; " +
		"[ -n \"$m\" ] && [ \"$m\" != '[]' ] && echo \"$p vlan_mode=$m\"; " +
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
			if strings.HasSuffix(line, " 127.0.0.1/8") {
				// The kernel's own, on every device, always.
				continue
			}
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

// unreadable is a handed-in submission that could not be turned into something
// gradeable: a corrupt archive, a name that matches no student AS, a bundle
// written against a different topology, a directory with no configuration in
// it.
type unreadable struct {
	Name   string
	AS     int
	Reason string
}

// readSubmissions reads a directory of per-group submissions.
//
// Layout: one directory per group, named after the group in the manifest or
// "as<N>", containing one file per router. The AS is resolved from the manifest
// rather than from the directory name, so a group cannot be marked as, or
// against, an AS that is not theirs.
//
// One unreadable submission does not stop the others. It used to: any corrupt
// archive returned an error from here, both grading commands passed it
// straight up, and a class of a hundred got no marks at all because one
// student's upload was truncated. The operator's only move was to find the bad
// file by hand and take it out of the directory -- and taking a submission out
// of the directory is exactly how a student silently ends up with no mark.
//
// So a submission that cannot be read is now carried out of here as an
// `unreadable` and becomes a quarantined report: named, excluded from the
// class statistics, given no total, and re-run once the cause is fixed. The
// distinction that matters is between one submission being bad and the *set*
// being ambiguous. A directory that cannot be listed, or two archives claiming
// the same AS, still stops everything, because in those cases there is no way
// to know which students would be silently skipped.
func readSubmissions(dir string, class *model.Topology) ([]submission, []unreadable, error) {
	return readSubmissionsWithAttempts(dir, class, false)
}

func readSubmissionsWithAttempts(dir string, class *model.Topology,
	allAttempts bool,
) ([]submission, []unreadable, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("reading submissions: %w", err)
	}
	var bad []unreadable
	reject := func(name string, asn int, format string, args ...any) {
		bad = append(bad, unreadable{Name: name, AS: asn,
			Reason: "this submission could not be read, so it was not graded: " +
				fmt.Sprintf(format, args...)})
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
				reject(archiveGroup(e.Name()), 0, "%v", err)
				continue
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
			n, err := strconv.Atoi(strings.TrimLeft(group, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"))
			if err != nil {
				reject(group, 0, "%q does not correspond to a student AS in this lab", group)
				continue
			}
			as, ok := class.ASes[n]
			if !ok || as.Role != model.RoleStudent {
				reject(group, 0, "%q does not correspond to a student AS in this lab", group)
				continue
			}
			asn = n
		}

		sub := submission{
			Group: group, AS: asn, Dir: filepath.Join(dir, group),
			Files: map[string]string{}, Scripts: map[string]string{},
		}
		files, err := os.ReadDir(sub.Dir)
		if err != nil {
			reject(group, asn, "%v", err)
			continue
		}
		failed := false
		for _, f := range files {
			if f.IsDir() || strings.HasPrefix(f.Name(), ".") {
				continue
			}
			ext := filepath.Ext(f.Name())
			if ext != ".conf" && ext != ".cfg" && ext != ".txt" && ext != ".sh" &&
				f.Name() != "roas.json" {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(sub.Dir, f.Name()))
			if err != nil {
				reject(group, asn, "%v", err)
				failed = true
				break
			}
			if f.Name() == "roas.json" {
				sub.ROAs = raw
				continue
			}
			base := strings.TrimSuffix(f.Name(), ext)
			if ext == ".sh" {
				sub.Scripts[base] = string(raw)
			} else {
				sub.Files[base] = string(raw)
			}
		}
		if failed {
			continue
		}
		if len(sub.Files) == 0 && len(sub.Scripts) == 0 {
			reject(group, asn, "contains no configuration files")
			continue
		}
		subs = append(subs, sub)
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].Identity() < subs[j].Identity() })
	sort.Slice(bad, func(i, j int) bool { return bad[i].Name < bad[j].Name })
	subs, bad = withdrawContestedWithAttempts(subs, bad, allAttempts)
	return subs, bad, nil
}

// withdrawContested takes out of the marking anything that more than one
// submission claims, and reports it instead.
//
// Ambiguity used to stop the whole run. That was right when there was nowhere
// else for it to go: choosing between two submissions for one system is a
// decision about late work that belongs to whoever runs the course, and the
// alternative was to silently mark a student on work they did not hand in.
// But it meant one student's stray directory left a hundred others unmarked,
// which is finding 129 in a second dress. Quarantine answers the objection
// that made it fatal -- nothing is silent: every contested submission is
// named before the run, named in the CSV with no total, named again by the
// release guard, and the command still exits non-zero.
//
// Contested entries are withdrawn on both sides. A group name claimed by a
// readable submission *and* an unreadable one is the case that made this
// necessary: the readable one was graded, and then the quarantine report for
// the same name overwrote it, so a student who scored full marks was handed a
// report saying they had not been graded at all and the CSV carried two
// contradictory rows for them. One name yields one report, always.
func withdrawContested(subs []submission, bad []unreadable) ([]submission, []unreadable) {
	return withdrawContestedWithAttempts(subs, bad, false)
}

func withdrawContestedWithAttempts(subs []submission, bad []unreadable,
	allAttempts bool,
) ([]submission, []unreadable) {
	if allAttempts {
		return withdrawContestedAttempts(subs, bad)
	}
	return withdrawContestedLegacy(subs, bad)
}

func withdrawContestedLegacy(subs []submission, bad []unreadable) ([]submission, []unreadable) {
	byName := map[string][]string{}
	byAS := map[int]map[string]bool{}
	note := func(name string, asn int, what string) {
		key := strings.ToLower(name)
		byName[key] = append(byName[key], what)
		if asn > 0 {
			if byAS[asn] == nil {
				byAS[asn] = map[string]bool{}
			}
			byAS[asn][key] = true
		}
	}
	for _, s := range subs {
		note(s.Group, s.AS, describeClaim(s.Group, s.Dir))
	}
	for _, u := range bad {
		note(u.Name, u.AS, describeClaim(u.Name, ""))
	}

	// A name is contested when two entries carry it; an AS is contested when
	// two *different* names claim it.
	contestedName := map[string]string{}
	for key, all := range byName {
		if len(all) > 1 {
			sort.Strings(all)
			contestedName[key] = fmt.Sprintf(
				"%d submissions claim to be %q (%s), so none of them was graded. "+
					"Choosing between them is a decision about late work that belongs to "+
					"whoever runs the course. Remove or rename the ones that should not count",
				len(all), key, strings.Join(all, ", "))
		}
	}
	for asn, names := range byAS {
		if len(names) < 2 {
			continue
		}
		var all []string
		for n := range names {
			all = append(all, n)
		}
		sort.Strings(all)
		for _, n := range all {
			if _, already := contestedName[n]; already {
				continue
			}
			contestedName[n] = fmt.Sprintf(
				"AS %d is claimed by %s, so none of them was graded. Two submissions for "+
					"one system cannot both be graded against the same lab, and choosing "+
					"between them is a decision about late work that belongs to whoever "+
					"runs the course. Remove or rename the ones that should not count",
				asn, strings.Join(all, ", "))
		}
	}
	if len(contestedName) == 0 {
		return subs, bad
	}

	keptAS := map[string]int{}
	kept := subs[:0]
	for _, s := range subs {
		key := strings.ToLower(s.Group)
		if _, out := contestedName[key]; out {
			keptAS[key] = s.AS
			continue
		}
		kept = append(kept, s)
	}
	held := bad[:0]
	for _, u := range bad {
		key := strings.ToLower(u.Name)
		if _, out := contestedName[key]; out {
			if u.AS > 0 {
				keptAS[key] = u.AS
			}
			continue
		}
		held = append(held, u)
	}
	// One report per contested name, naming every claimant, so two withdrawn
	// entries cannot collide with each other either.
	var names []string
	for n := range contestedName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		held = append(held, unreadable{Name: n, AS: keptAS[n], Reason: contestedName[n]})
	}
	sort.Slice(held, func(i, j int) bool { return held[i].Name < held[j].Name })
	return kept, held
}

// withdrawContestedAttempts admits a narrow benchmark/regrade exception to
// the one-final-submission rule. A repeated group or AS is safe only when
// every claimant is a readable signed archive with a non-empty, unique
// attempt. Any directory submission, unreadable archive, missing attempt, or
// duplicate attempt remains contested exactly like an ordinary class run.
func withdrawContestedAttempts(subs []submission, bad []unreadable) ([]submission, []unreadable) {
	type claim struct {
		subIndex int
		badIndex int
		name     string
		asn      int
		attempt  string
		source   string
	}
	byGroup := map[string][]claim{}
	byAS := map[int][]claim{}
	for index, sub := range subs {
		value := claim{
			subIndex: index, badIndex: -1, name: sub.Group, asn: sub.AS,
			attempt: sub.Attempt, source: describeClaim(sub.Group, sub.Dir),
		}
		key := strings.ToLower(sub.Group)
		byGroup[key] = append(byGroup[key], value)
		if sub.AS > 0 {
			byAS[sub.AS] = append(byAS[sub.AS], value)
		}
	}
	for index, unread := range bad {
		value := claim{
			subIndex: -1, badIndex: index, name: unread.Name, asn: unread.AS,
			source: describeClaim(unread.Name, ""),
		}
		key := strings.ToLower(unread.Name)
		byGroup[key] = append(byGroup[key], value)
		if unread.AS > 0 {
			byAS[unread.AS] = append(byAS[unread.AS], value)
		}
	}

	accepted := func(values []claim) bool {
		if len(values) < 2 {
			return true
		}
		seen := map[string]bool{}
		for _, value := range values {
			if value.subIndex < 0 || value.attempt == "" || !validAttempt(value.attempt) {
				return false
			}
			key := strings.ToLower(value.attempt)
			if seen[key] {
				return false
			}
			seen[key] = true
		}
		return true
	}

	heldSubs := map[int]bool{}
	heldBad := map[int]bool{}
	reasons := map[string]string{}
	mark := func(values []claim, reason string) {
		for _, value := range values {
			if value.subIndex >= 0 {
				heldSubs[value.subIndex] = true
			}
			if value.badIndex >= 0 {
				heldBad[value.badIndex] = true
			}
			key := strings.ToLower(value.name)
			if _, exists := reasons[key]; !exists {
				reasons[key] = reason
			}
		}
	}
	for group, values := range byGroup {
		if accepted(values) {
			continue
		}
		var sources []string
		for _, value := range values {
			sources = append(sources, value.source)
		}
		sort.Strings(sources)
		mark(values, fmt.Sprintf(
			"%d submissions claim to be %q (%s), but repeated submissions require "+
				"--all-attempts and a distinct signed non-empty attempt on every item",
			len(values), group, strings.Join(sources, ", ")))
	}
	for asn, values := range byAS {
		if accepted(values) {
			continue
		}
		var sources []string
		for _, value := range values {
			sources = append(sources, value.source)
		}
		sort.Strings(sources)
		mark(values, fmt.Sprintf(
			"AS %d is claimed by %s, but repeated submissions require --all-attempts "+
				"and a distinct signed non-empty attempt on every item",
			asn, strings.Join(sources, ", ")))
	}
	if len(heldSubs) == 0 && len(heldBad) == 0 {
		return subs, bad
	}

	keptSubs := make([]submission, 0, len(subs)-len(heldSubs))
	for index, sub := range subs {
		if !heldSubs[index] {
			keptSubs = append(keptSubs, sub)
		}
	}
	keptBad := make([]unreadable, 0, len(bad)-len(heldBad)+len(reasons))
	for index, unread := range bad {
		if !heldBad[index] {
			keptBad = append(keptBad, unread)
		}
	}
	asByName := map[string]int{}
	for index, sub := range subs {
		if heldSubs[index] {
			asByName[strings.ToLower(sub.Group)] = sub.AS
		}
	}
	for index, unread := range bad {
		if heldBad[index] && unread.AS > 0 {
			asByName[strings.ToLower(unread.Name)] = unread.AS
		}
	}
	var names []string
	for name := range reasons {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		keptBad = append(keptBad, unreadable{Name: name, AS: asByName[name], Reason: reasons[name]})
	}
	sort.Slice(keptSubs, func(i, j int) bool { return keptSubs[i].Identity() < keptSubs[j].Identity() })
	sort.Slice(keptBad, func(i, j int) bool { return keptBad[i].Name < keptBad[j].Name })
	return keptSubs, keptBad
}

// describeClaim names where a claim on a group name came from, so an operator
// looking at a contested name can tell which files to go and look at.
func describeClaim(name, dir string) string {
	if dir == "" {
		return name + " (unreadable)"
	}
	return filepath.Base(dir)
}

// archiveGroup is the group an archive appears to belong to, from its filename.
//
// It is only used to name a submission that could not be opened, where the
// bundle's own metadata is exactly what is unavailable. The name a student
// uploaded is the one the operator has to go and look for.
func archiveGroup(name string) string {
	return strings.TrimSuffix(strings.TrimSuffix(name, ".tar.gz"), ".tgz")
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
		out := map[string]string{}
		for _, device := range top.Devices {
			if device.Image != "" && device.ImageID != "" {
				out[device.Image] = device.ImageID
			}
		}
		return out
	}
	tok, err := tokenFor(token)
	if err != nil {
		return nil
	}
	return imageDigests(ctx, client.NewCluster(top.Lab, tok), top)
}

func labAgentVersions(ctx context.Context, top *model.Topology, token string) map[string]string {
	if !clustered(top) {
		return nil
	}
	tok, err := tokenFor(token)
	if err != nil {
		return nil
	}
	return agentVersions(ctx, client.NewCluster(top.Lab, tok))
}

// clearStaleHarness removes any earlier deployment of a harness before it is
// used again, and refuses rather than grading on top of one it cannot remove.
func clearStaleHarness(ctx context.Context, c *client.Cluster, h *model.Topology) error {
	found, errs := c.Containers(ctx, h.Name)
	if len(errs) > 0 {
		// A node that cannot be asked might be the one holding the remains. It
		// is not safe to assume otherwise.
		var msgs []string
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		return fmt.Errorf("could not establish whether an earlier attempt is still "+
			"deployed: %s", strings.Join(msgs, "; "))
	}
	if len(found) == 0 {
		return nil
	}
	slog.Warn("an earlier deployment of this harness is still up and is being removed "+
		"before the submission is loaded", "lab", h.Name, "containers", len(found))
	if err := destroyLab(ctx, c, h); err != nil {
		return err
	}
	// Verified, not assumed: destroy reports what it asked for, and a container
	// that survived it is exactly the one that would carry the last attempt's
	// configuration into this mark.
	still, errs := c.Containers(ctx, h.Name)
	if len(errs) > 0 {
		var msgs []string
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		return fmt.Errorf("could not confirm the earlier attempt is gone: %s",
			strings.Join(msgs, "; "))
	}
	if len(still) > 0 {
		names := make([]string, 0, len(still))
		for _, cn := range still {
			names = append(names, cn.Name)
		}
		sort.Strings(names)
		return fmt.Errorf("%d container(s) from an earlier attempt survived teardown: %s",
			len(still), strings.Join(names, ", "))
	}
	return nil
}
