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
// reference solution. Two submissions therefore cannot affect each other's
// marks as long as they are not neighbours -- and in a course topology most
// pairs are not. So the class lab is deployed once with every AS solved, and
// submissions are loaded in waves of mutually non-adjacent autonomous systems.
// Everything a submission can see is either its own work or the reference.
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
	)
	cmd := &cobra.Command{
		Use:   "class",
		Short: "Grade a whole class in the deployed lab, in independent waves",
		Long: `Grades every submission in one already-deployed lab.

A private lab per submission isolates students perfectly and costs a full
deployment each. This gets the same isolation far more cheaply: the lab is
deployed once with every autonomous system solved, and submissions are loaded in
waves of systems that are not neighbours. Everything a submission can see is
then either its own work or the reference solution, which is exactly what a
private harness provides.

The lab must already be deployed with --solve. Between waves, the systems just
graded are returned to the reference, so no submission is ever marked against
another's work.`,
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
				outDir = filepath.Join("reports", time.Now().UTC().Format("2006-01-02_15-04-05"))
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			if parallel <= 0 {
				parallel = 16
			}

			waves := independentWaves(top, subs)
			fmt.Fprintf(cmd.ErrOrStderr(),
				"grading %d submission(s) in %d wave(s); within a wave no two submissions are neighbours\n",
				len(subs), len(waves))

			start := time.Now()
			var reports []*grade.Report

			for i, wave := range waves {
				fmt.Fprintf(cmd.ErrOrStderr(), "\nwave %d/%d: %s\n", i+1, len(waves), groupNames(wave))

				loaded := make([]submission, 0, len(wave))
				for _, s := range wave {
					if err := applySubmission(cmd.Context(), exec, top, s); err != nil {
						reports = append(reports, &grade.Report{
							Submission: s.Group, AS: s.AS, MaxTotal: rubric.MaxTotal(),
							Err: fmt.Sprintf("loading the submission: %v", err), NeedsReview: true,
						})
						continue
					}
					loaded = append(loaded, s)
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
					restoreWave(cmd.Context(), opts, top, loaded, token, cmd.ErrOrStderr())
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
	cmd.Flags().DurationVar(&converge, "converge-timeout", 4*time.Minute, "how long a convergence predicate may wait")
	cmd.Flags().IntVarP(&parallel, "parallel", "p", 16, "submissions graded concurrently within a wave")
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

	// Two systems that share an exchange are neighbours for this purpose: at an
	// exchange everyone sees everyone, so a broken member is visible to every
	// other member even without a direct cable.
	members := map[int][]int{}
	for asn, as := range top.ASes {
		if as.Role == model.RoleIXP {
			continue
		}
		for _, d := range as.Devices {
			for _, i := range d.Ifaces {
				if i.Role == model.RoleIXPLink && i.Peer != nil && i.Peer.Device != nil {
					ixp := i.Peer.Device.ASN
					members[ixp] = append(members[ixp], asn)
				}
			}
		}
	}
	for _, ms := range members {
		for _, a := range ms {
			for _, b := range ms {
				if a == b {
					continue
				}
				if adj[a] == nil {
					adj[a] = map[int]bool{}
				}
				adj[a][b] = true
			}
		}
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
				if adj[s.AS][other.AS] || s.AS == other.AS {
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
	wave []submission, token string, errOut interface{ Write([]byte) (int, error) }) {

	if len(wave) == 0 {
		return
	}
	var scopes []string
	for _, s := range wave {
		scopes = append(scopes, fmt.Sprintf("as%d", s.AS))
	}
	if err := redeployScopes(ctx, top, token, scopes); err != nil {
		fmt.Fprintf(errOut,
			"  warning: %s could not be returned to the reference (%v); "+
				"later waves may be marked against this wave's work\n",
			groupNames(wave), err)
	}
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
