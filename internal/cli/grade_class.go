package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/model"
)

// Grading a class in waves.
//
// A private lab per submission is the obvious way to isolate students from each
// other, and measuring it showed what it costs: one full-breadth harness is the
// whole class topology, so grading a hundred submissions means deploying the
// class a hundred times. On a three-node cluster eight concurrent harnesses
// already saturate the fabric, and the run takes twenty minutes for eight
// submissions.
//
// The insight that makes it cheap is that a harness and the class lab differ in
// exactly one way: in a harness every autonomous system except one is the
// reference solution. So the class lab is deployed once with every AS solved,
// and submissions are loaded in waves of systems that cannot reach each other's
// announcements.
//
// "Cannot reach" is the part that has to be got right, and the first version of
// it was wrong. It required only that two submissions not be neighbours, on the
// reasoning that everything else they could see was the reference. But two
// students hanging off the same reference transit do affect each other: AS1
// runs ordinary BGP and re-advertises what its customers send it, so AS3's bad
// announcement lands in AS5's table and changes the paths AS5 is marked on.
// Submissions now conflict at distance two as well.
//
// That is sound against propagation through one reference system and not
// against three hops through two. `twinet grade batch` gives each submission
// its own lab and has no such caveat; this command trades that for the ability
// to grade a class in minutes rather than hours.
//
// The number of waves is the chromatic number of the peering graph, which for a
// tiered internet is small and does not grow with the class: adding students
// adds autonomous systems, not adjacency.
func newGradeClassCmd(opts *Options) *cobra.Command {
	var (
		subDir     string
		rubricPath string
		outDir     string
		token      string
		converge   time.Duration
		parallel   int
		keepLoaded bool
		perWave    int
	)
	cmd := &cobra.Command{
		Use:   "class",
		Short: "Grade a whole class in the deployed lab, in independent waves",
		Long: `Grades every submission in one already-deployed lab.

A private lab per submission isolates students perfectly and costs a full
deployment each. This gets the same isolation far more cheaply: the lab is
deployed once with every autonomous system solved, and one submission at a time
is loaded into it. Everything that submission can see is then either its own
work or the reference solution, which is exactly what a private harness
provides -- and unlike a private harness it costs one system's reset rather
than a whole deployment.

Before each submission is loaded, its system is returned to the state a student
is given, so a router the submission does not mention is unconfigured rather
than still holding the model answer. Afterwards the system goes back to the
reference, so no submission is ever marked against another's work.

--per-wave loads several submissions at once. It is faster and it is not
provably isolated: submissions are batched so that no two are within two
autonomous systems of each other, which is sound against every failure that has
been demonstrated but is a heuristic, not a proof. Influence can travel three
hops through two reference systems. Use it for a dry run; leave it alone when
the marks are final.

The lab must already be deployed with --solve.`,
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
			subs, err := readSubmissions(subDir, top)
			if err != nil {
				return err
			}
			if len(subs) == 0 {
				return fmt.Errorf("no submissions found under %s", subDir)
			}
			exec, err := execFunc(cmd.Context(), top, token)
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
				parallel = 16
			}

			// Ask the nodes to leave this lab to us for the duration. This must
			// come before the health check below: that check reads every
			// router, and a repair loop rewiring one underneath it would make
			// it report a problem that does not exist.
			held, err := holdLab(cmd.Context(), top, token, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			defer held.Release()

			// Nobody is graded against a lab that is not working. Both halves
			// matter: a router with no routing process and a device with a
			// missing cable are invisible where they are and expensive
			// somewhere else, on somebody else's mark.
			if bad := miswiredDevices(cmd.Context(), exec, top); len(bad) > 0 {
				return notReadyToGrade("device(s) in this lab do not have the interfaces "+
					"the lab says they have", bad, opts.Manifest)
			}
			if bad := unhealthyRouters(cmd.Context(), exec, top); len(bad) > 0 {
				return notReadyToGrade("router(s) in this lab are not running their "+
					"routing processes", bad, opts.Manifest)
			}

			var waves [][]submission
			if perWave > 1 {
				waves = independentWaves(top, subs)
				fmt.Fprintf(cmd.ErrOrStderr(),
					"grading %d submission(s) in %d wave(s); within a wave no two submissions "+
						"are within two systems of each other.\nThat is a heuristic, not a proof of "+
						"isolation: run without --per-wave for marks that are final.\n",
					len(subs), len(waves))
			} else {
				for _, s := range subs {
					waves = append(waves, []submission{s})
				}
				fmt.Fprintf(cmd.ErrOrStderr(),
					"grading %d submission(s), one at a time: everything else in the lab stays "+
						"at the reference\n", len(subs))
			}

			start := time.Now()
			var reports []*grade.Report
			// Set once the deployed lab can no longer be trusted to represent
			// the reference solution.
			contaminated := ""

			for i, wave := range waves {
				// If the nodes have stopped leaving this lab alone, everything
				// from here on is being graded against a lab something else is
				// changing. That is not a slow run or a bad mark, it is an
				// unknown one, so the rest is held for review rather than
				// scored.
				select {
				case <-held.Lost:
					contaminated = fmt.Sprintf("the nodes stopped holding this lab off "+
						"from automatic repair partway through: %s", held.Reason())
					reports = append(reports, quarantine(waves[i:], rubric.MaxTotal(), contaminated)...)
				default:
				}
				if contaminated != "" {
					break
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "\nwave %d/%d: %s\n", i+1, len(waves), groupNames(wave))

				loaded := make([]submission, 0, len(wave))
				for _, s := range wave {
					// Wait for the lab to stop moving before touching it. A
					// deploy or a repair rewires by removing an interface and
					// adding it back, and a submission loaded during that
					// instant fails on its first line for a reason that has
					// nothing to do with its author.
					err := waitForASWiring(cmd.Context(), exec, top, s.AS)
					if err == nil {
						err = resetToStudentStart(cmd.Context(), exec, top, s.AS)
					}
					if err == nil {
						err = applySubmission(cmd.Context(), exec, top, s)
					}
					if err != nil {
						// A submission that failed partway through loading has
						// left its AS in neither the reference state nor its
						// own. Its neighbours in this wave are graded across
						// that AS, so leaving it there would quietly move their
						// marks. Put it back before going on.
						note := fmt.Sprintf("loading the submission: %v", err)
						if rerr := redeployScopes(cmd.Context(), top, token,
							[]string{fmt.Sprintf("as%d", s.AS)}); rerr != nil {
							note += fmt.Sprintf("; and AS %d could not be returned to the "+
								"reference afterwards (%v), so this wave is suspect", s.AS, rerr)
							contaminated = fmt.Sprintf(
								"AS %d was left part-loaded after %s failed and could not be reset: %v",
								s.AS, s.Group, rerr)
						}
						reports = append(reports, &grade.Report{
							Submission: s.Group, AS: s.AS, MaxTotal: rubric.MaxTotal(),
							Err: note, NeedsReview: true,
						})
						continue
					}
					loaded = append(loaded, s)
				}
				if contaminated != "" {
					reports = append(reports, quarantine(waves[i:], rubric.MaxTotal(), contaminated)...)
					break
				}

				// One convergence wait for the whole wave rather than one per
				// submission: they are converging simultaneously in the same
				// network, so waiting for each in turn would charge the class
				// for the same seconds repeatedly.
				waitWave(cmd.Context(), top, exec, loaded, converge)

				got := gradeWave(cmd.Context(), top, rubric, loaded, exec, converge, parallel,
					cmd.ErrOrStderr())
				reports = append(reports, got...)

				if !keepLoaded {
					if err := restoreWave(cmd.Context(), opts, top, loaded, token); err != nil {
						// Carrying on would grade every later wave against this
						// wave's work and report the results as if they were
						// sound. A mark that is wrong and labelled correct is
						// worse than no mark: the student has no reason to
						// appeal and the grader has no reason to look.
						contaminated = err.Error()
						fmt.Fprintf(cmd.ErrOrStderr(),
							"\n  %v\n  the remaining waves cannot be graded against a known-good "+
								"internet and are held for review\n", err)
						if i+1 < len(waves) {
							reports = append(reports,
								quarantine(waves[i+1:], rubric.MaxTotal(), contaminated)...)
						}
						break
					}
				}
			}

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
	cmd.Flags().StringVarP(&subDir, "submissions", "s", "submissions", "directory of submissions")
	cmd.Flags().StringVarP(&rubricPath, "rubric", "r", "", "rubric to grade against")
	cmd.Flags().StringVarP(&outDir, "out", "o", "", "where to write reports")
	cmd.Flags().StringVar(&token, "token", "", "agent token")
	// Five minutes, from measurement rather than taste: a clean run of eight
	// submissions on a twelve-AS lab took 4m 56s per submission end to end,
	// nearly all of it waiting for OSPF, then BGP sessions, then the BGP table
	// to stop changing. A budget below that turns a slow lab into a bad mark,
	// which is the most expensive kind of wrong answer this produces.
	cmd.Flags().DurationVar(&converge, "converge-timeout", 5*time.Minute,
		"how long a convergence predicate may wait")
	cmd.Flags().IntVarP(&parallel, "parallel", "p", 16, "submissions graded concurrently within a wave")
	cmd.Flags().IntVar(&perWave, "per-wave", 1,
		"submissions loaded into the lab at once; above 1 trades provable isolation for speed")
	cmd.Flags().BoolVar(&keepLoaded, "keep-loaded", false,
		"leave the last wave's submissions in the lab, for investigating a disputed mark")
	return cmd
}

// independentWaves groups submissions so that no two in a wave are neighbours.
//
// Greedy colouring over the peering graph. Optimal colouring is NP-hard and
// pointless here: one extra wave costs a few minutes, and a tiered internet
// colours in a handful of colours whatever order it is walked in.
func independentWaves(top *model.Topology, subs []submission) [][]submission {
	adj := map[int]map[int]bool{}
	for _, l := range top.Links {
		if !l.InterAS || l.A == nil || l.B == nil || l.A.Device == nil || l.B.Device == nil {
			continue
		}
		a, b := l.A.Device.ASN, l.B.Device.ASN
		if a == b {
			continue
		}
		if adj[a] == nil {
			adj[a] = map[int]bool{}
		}
		if adj[b] == nil {
			adj[b] = map[int]bool{}
		}
		adj[a][b], adj[b][a] = true, true
	}

	// Sharing an exchange does not make two systems neighbours for this
	// purpose, and treating it as though it did was expensive: every member of
	// an exchange became adjacent to every other, which collapsed the
	// independence the waves exist to exploit and turned eight submissions into
	// six waves.
	//
	// At an exchange each member peers with the route server, not with the
	// other members. A broken member cannot stop another member's session
	// establishing, cannot change what that member advertises, and cannot alter
	// its interior -- which is what every question is marked on. What it can do
	// is fail to announce a prefix, and no question marks a student on
	// receiving some other student's routes.
	//
	// A direct peering is different: a neighbour that is broken is a session
	// that never comes up, and that is a mark the student loses for someone
	// else's work. Those stay adjacent.

	// Two submissions also conflict when they share a neighbour, not only when
	// they are neighbours.
	//
	// The original rule was direct adjacency, on the reasoning that everything
	// a submission can see is either its own work or the reference. That is
	// false as soon as two students hang off the same reference transit. AS3
	// and AS5 are not adjacent, but both attach to AS1, AS2 and the exchange;
	// AS1 runs ordinary BGP and re-advertises what its customers send it, so a
	// bad announcement from AS3 arrives in AS5's table and changes the paths
	// AS5 is marked on. A correct student loses marks for another student's
	// mistake, and the report gives no hint of it.
	//
	// Conflicting at distance two closes that. It is not a proof of isolation
	// -- influence can travel three hops through two reference systems, and the
	// only construction that rules that out completely is one submission per
	// lab, which is `twinet grade batch`. It is the difference between a rule
	// that is sound against the failure that was demonstrated and one that was
	// merely never tested. `grade class` documents the trade; `grade batch` is
	// there for a run where the marks are final and the cost is worth paying.
	share := func(a, b int) bool {
		for n := range adj[a] {
			if adj[b][n] {
				return true
			}
		}
		return false
	}

	// Most-constrained first, which keeps the number of waves down.
	order := append([]submission(nil), subs...)
	sort.Slice(order, func(i, j int) bool {
		di, dj := len(adj[order[i].AS]), len(adj[order[j].AS])
		if di != dj {
			return di > dj
		}
		return order[i].AS < order[j].AS
	})

	var waves [][]submission
	placed := map[int]bool{}
	for _, s := range order {
		if placed[s.AS] {
			continue
		}
		for w := range waves {
			conflict := false
			for _, other := range waves[w] {
				if adj[s.AS][other.AS] || s.AS == other.AS || share(s.AS, other.AS) {
					conflict = true
					break
				}
			}
			if !conflict {
				waves[w] = append(waves[w], s)
				placed[s.AS] = true
				break
			}
		}
		if !placed[s.AS] {
			waves = append(waves, []submission{s})
			placed[s.AS] = true
		}
	}
	for w := range waves {
		sort.Slice(waves[w], func(i, j int) bool { return waves[w][i].Group < waves[w][j].Group })
	}
	return waves
}

// waitWave waits for the whole wave's control planes together.
func waitWave(ctx context.Context, top *model.Topology, exec execFn,
	wave []submission, timeout time.Duration) {

	var wg sync.WaitGroup
	for _, s := range wave {
		wg.Add(1)
		go func(s submission) {
			defer wg.Done()
			// A submission that never converges is a submission that scores
			// badly, which is a mark rather than an error, so the outcome is
			// deliberately ignored here and left to the checks.
			_ = grade.WaitConverged(ctx, &grade.Env{Topology: top, AS: s.AS, Exec: exec}, timeout)
		}(s)
	}
	wg.Wait()
}

func gradeWave(ctx context.Context, top *model.Topology, rubric *grade.Rubric,
	wave []submission, exec execFn, converge time.Duration, parallel int,
	progress interface{ Write([]byte) (int, error) }) []*grade.Report {

	out := make([]*grade.Report, len(wave))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, s := range wave {
		wg.Add(1)
		go func(i int, s submission) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rep := grade.Run(ctx, rubric, &grade.Env{Topology: top, AS: s.AS, Exec: exec},
				grade.RunOptions{ConvergeTimeout: converge, Parallel: 4})
			rep.Submission = s.Group
			rep.Lab = top.Name
			rep.Controller = Version
			out[i] = rep

			mu.Lock()
			fmt.Fprintf(progress, "  %-12s %.2f / %.2f\n", rep.Submission, rep.Total, rep.MaxTotal)
			mu.Unlock()
		}(i, s)
	}
	wg.Wait()
	return out
}

// restoreWave puts the graded systems back to the reference solution, so the
// next wave is marked against a correct internet rather than against whatever
// the previous wave left behind.
func restoreWave(ctx context.Context, opts *Options, top *model.Topology,
	wave []submission, token string) error {

	if len(wave) == 0 {
		return nil
	}
	var scopes []string
	for _, s := range wave {
		scopes = append(scopes, fmt.Sprintf("as%d", s.AS))
	}
	if err := redeployScopes(ctx, top, token, scopes); err != nil {
		return fmt.Errorf("%s could not be returned to the reference solution: %w",
			groupNames(wave), err)
	}
	return nil
}

// quarantine produces a held-for-review report for every submission that could
// not be graded against a known-good internet.
//
// Reporting these as failures would be a lie in the student's disfavour, and
// reporting them as passes would be a lie in the grader's. They are recorded as
// ungraded, with the reason, so a human decides.
func quarantine(waves [][]submission, maxTotal float64, reason string) []*grade.Report {
	var out []*grade.Report
	for _, w := range waves {
		for _, s := range w {
			out = append(out, &grade.Report{
				Submission: s.Group, AS: s.AS, MaxTotal: maxTotal,
				NeedsReview: true,
				Err: "not graded: the lab could not be returned to the reference solution " +
					"before this wave, so any mark would be measuring an earlier " +
					"submission's work as much as this one's (" + reason + ")",
			})
		}
	}
	return out
}

func groupNames(wave []submission) string {
	names := make([]string, len(wave))
	for i, s := range wave {
		names[i] = s.Group
	}
	sort.Strings(names)
	return joinComma(names)
}

func joinComma(v []string) string {
	out := ""
	for i, s := range v {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
