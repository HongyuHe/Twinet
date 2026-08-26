package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/harness"
	"github.com/HongyuHe/twinet/internal/model"
)

const warmBaselineExecTimeout = 2 * time.Minute

func warmHarnessBaselineTimeout(devices int, requested time.Duration) time.Duration {
	minimum := 3 * time.Minute
	switch {
	case devices >= 1000:
		minimum = 10 * time.Minute
	case devices >= 300:
		minimum = 5 * time.Minute
	}
	if requested > minimum {
		return requested
	}
	return minimum
}

func warmHarnessCleanupTimeout(devices int) time.Duration {
	switch {
	case devices >= 1000:
		return 10 * time.Minute
	case devices >= 300:
		return 5 * time.Minute
	default:
		return 3 * time.Minute
	}
}

// warmBatchManager owns one compact private pool per target AS. A normal
// class has one submission per AS and still benefits from the compact harness;
// release mutations for the same AS reuse its already-deployed substrate.
type warmBatchManager struct {
	class  *model.Topology
	rubric *grade.Rubric
	opts   batchOpts

	mu           sync.Mutex
	pools        map[int]*harness.WarmPool
	creating     map[int]chan struct{}
	createErr    map[int]error
	workersByASN map[int]int
}

func newWarmBatchManager(class *model.Topology, rubric *grade.Rubric, opts batchOpts,
	workersByASN map[int]int,
) *warmBatchManager {
	return &warmBatchManager{class: class, rubric: rubric, opts: opts,
		pools:    map[int]*harness.WarmPool{},
		creating: map[int]chan struct{}{}, createErr: map[int]error{},
		workersByASN: workersByASN}
}

func (m *warmBatchManager) grade(ctx context.Context, submission submission) *grade.Report {
	pool, err := m.pool(ctx, submission.AS)
	if err != nil {
		return ungradeableReport(submission, m.rubric, "creating warm harness", err)
	}
	var report *grade.Report
	err = pool.With(ctx, func(ctx context.Context, lease harness.WarmHarness) error {
		worker, ok := lease.(*warmBatchHarness)
		if !ok {
			return fmt.Errorf("warm pool returned unexpected harness type %T", lease)
		}
		report = worker.grade(ctx, submission)
		return nil
	})
	if err != nil {
		return ungradeableReport(submission, m.rubric, "resetting warm harness", err)
	}
	if report == nil {
		return ungradeableReport(submission, m.rubric, "grading warm harness",
			fmt.Errorf("warm harness produced no report"))
	}
	if m.opts.auditHash != "" {
		report.EquivalenceAuditHash = m.opts.auditHash
	}
	return report
}

func (m *warmBatchManager) pool(ctx context.Context, asn int) (*harness.WarmPool, error) {
	m.mu.Lock()
	if pool := m.pools[asn]; pool != nil {
		m.mu.Unlock()
		return pool, nil
	}
	if done := m.creating[asn]; done != nil {
		m.mu.Unlock()
		select {
		case <-done:
			m.mu.Lock()
			pool, err := m.pools[asn], m.createErr[asn]
			m.mu.Unlock()
			return pool, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	done := make(chan struct{})
	m.creating[asn] = done
	m.mu.Unlock()

	workers := m.workersByASN[asn]
	if workers < 1 {
		workers = 1
	}
	namespace := m.opts.warmNamespace
	if namespace == "" {
		namespace = "warm"
	}
	pool, err := harness.NewWarmPool(ctx, workers, func(ctx context.Context, worker int) (harness.WarmHarness, error) {
		options := batchHarnessOptions(m.opts.depth, m.opts.reduce, m.opts.fullHarness, m.opts.compact,
			m.opts.keepHosts, fmt.Sprintf("%s-as%d-w%d", namespace, asn, worker))
		topology, err := harness.Slice(m.class, asn, options)
		if err != nil {
			return nil, err
		}
		return newWarmBatchHarness(ctx, m.class, m.rubric, topology, asn, m.opts)
	})
	if err != nil {
		m.mu.Lock()
		m.createErr[asn] = err
		delete(m.creating, asn)
		close(done)
		m.mu.Unlock()
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pools[asn] = pool
	delete(m.creating, asn)
	close(done)
	return pool, nil
}

func (m *warmBatchManager) close(ctx context.Context) error {
	m.mu.Lock()
	pools := make([]*harness.WarmPool, 0, len(m.pools))
	for _, pool := range m.pools {
		pools = append(pools, pool)
	}
	m.mu.Unlock()
	var first error
	for _, pool := range pools {
		if err := pool.Close(ctx); err != nil && first == nil {
			first = err
		}
	}
	return first
}

type warmBatchHarness struct {
	class       *model.Topology
	rubric      *grade.Rubric
	top         *model.Topology
	asn         int
	opts        batchOpts
	c           *client.Cluster
	exec        execFn
	hold        *labHold
	mu          sync.Mutex
	grades      int
	taint       error
	destroyOnce sync.Once
	destroyErr  error
}

func newWarmBatchHarness(ctx context.Context, class *model.Topology, rubric *grade.Rubric,
	top *model.Topology, asn int, opts batchOpts,
) (*warmBatchHarness, error) {
	if top.Lab == nil || top.Lab.Images.LockDigest == "" {
		return nil, fmt.Errorf("warm harness %s has no immutable image lock", top.Name)
	}
	cluster := client.NewCluster(top.Lab, opts.token)
	if err := clearStaleHarness(ctx, cluster, top); err != nil {
		return nil, err
	}
	if err := deployQuiet(ctx, cluster, top, asn); err != nil {
		cleanupCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx), warmHarnessCleanupTimeout(len(top.Devices)),
		)
		defer cancel()
		if cleanupErr := destroyLab(cleanupCtx, cluster, top); cleanupErr != nil {
			return nil, fmt.Errorf("%v; cleaning failed warm deployment: %w", err, cleanupErr)
		}
		return nil, err
	}
	held, err := holdLab(ctx, top, opts.token, io.Discard)
	if err != nil {
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		_ = destroyLab(tctx, cluster, top)
		return nil, err
	}
	exec, err := execFuncWithHoldTimeout(ctx, top, opts.token, held.token, warmBaselineExecTimeout)
	if err != nil {
		held.Release()
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		_ = destroyLab(tctx, cluster, top)
		return nil, err
	}
	baselineTimeout := warmHarnessBaselineTimeout(len(top.Devices), opts.converge)
	if err := grade.WaitReferenceBaseline(ctx, top, asn, exec, nil, baselineTimeout); err != nil {
		held.Release()
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		_ = destroyLab(tctx, cluster, top)
		return nil, fmt.Errorf("verifying solved reference baseline: %w", err)
	}
	return &warmBatchHarness{class: class, rubric: rubric, top: top, asn: asn,
		opts: opts, c: cluster, exec: exec, hold: held}, nil
}

func (w *warmBatchHarness) WarmIdentity() harness.WarmIdentity {
	return harness.WarmIdentity{
		Namespace: w.top.Name,
		// Apply transactions fence this deployment. The topology hash is the
		// stable audit identity retained by the pool alongside that fence.
		Fence:     w.top.Hash,
		ImageLock: w.top.Lab.Images.LockDigest,
	}
}

func (w *warmBatchHarness) Reset(ctx context.Context) error {
	err := resetToStudentStart(ctx, w.exec, w.top, w.asn)
	if err == nil || !strings.Contains(err.Error(), "frr did not come up") {
		return err
	}
	// An agent has committed the containers before the ungraded target's
	// initial FRR bootstrap necessarily finishes. Retrying the clean platform
	// reset once serializes with that bootstrap; accepting a half-started
	// daemon set would instead make every later mutation ungradeable.
	select {
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
		return err
	}
	if retry := resetToStudentStart(ctx, w.exec, w.top, w.asn); retry != nil {
		return fmt.Errorf("%v; retrying warm baseline reset: %w", err, retry)
	}
	return nil
}

func (w *warmBatchHarness) Destroy(ctx context.Context) error {
	w.destroyOnce.Do(func() {
		w.destroyErr = destroyLab(ctx, w.c, w.top)
		if w.hold != nil {
			w.hold.Release()
		}
	})
	return w.destroyErr
}

func (w *warmBatchHarness) WarmTaint() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.taint
}

func (w *warmBatchHarness) markTainted(err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	if w.taint == nil {
		w.taint = err
	}
	w.mu.Unlock()
}

func (w *warmBatchHarness) grade(ctx context.Context, submission submission) *grade.Report {
	w.mu.Lock()
	reuse := w.grades
	w.grades++
	w.mu.Unlock()
	fail := func(stage string, err error) *grade.Report {
		rep := ungradeableReport(submission, w.rubric, stage, err)
		rep.HarnessType = batchHarnessType(w.opts) + "-warm"
		rep.WarmWorker = w.top.Name
		rep.WarmReuseCount = reuse
		rep.WarmColdDeploy = reuse == 0
		return rep
	}
	if err := applySubmission(ctx, w.exec, w.top, submission); err != nil {
		return fail("loading the submission", err)
	}
	_, undo, why := adaptNeighbours(ctx, w.exec, w.top, w.asn)
	if len(why) > 0 {
		if err := undo(context.WithoutCancel(ctx)); err != nil {
			w.markTainted(err)
		}
		return fail("adapting the reference to this submission's peering addresses",
			fmt.Errorf("%s", joinComma(why)))
	}
	undoAdapt := func() error {
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		return undo(uctx)
	}
	if w.opts.settle > 0 {
		select {
		case <-time.After(w.opts.settle):
		case <-ctx.Done():
			rep := fail("waiting to settle", ctx.Err())
			if err := undoAdapt(); err != nil {
				w.markTainted(err)
				rep.Err = appendNote(rep.Err, "undoing peering adaptation: "+err.Error())
			}
			return rep
		}
	} else {
		_ = grade.WaitConverged(ctx, &grade.Env{Topology: w.top, AS: w.asn, Exec: w.exec}, w.opts.converge)
	}
	rep := grade.Run(ctx, w.rubric, &grade.Env{Topology: w.top, AS: w.asn, Exec: w.exec},
		preConvergedRunOptions(w.opts.converge))
	rep.Submission = submission.Group
	rep.Attempt = submission.Attempt
	rep.ArchiveSHA256 = submission.ArchiveSHA256
	rep.Lab = w.top.Name
	rep.HarnessType = batchHarnessType(w.opts) + "-warm"
	rep.WarmWorker = w.top.Name
	rep.WarmReuseCount = reuse
	rep.WarmColdDeploy = reuse == 0
	rep.Images = imageDigests(ctx, w.c, w.top)
	rep.Controller = Version
	rep.ImageLock = w.top.Lab.Images.LockDigest
	rep.Agents = agentVersions(ctx, w.c)
	if err := undoAdapt(); err != nil {
		w.markTainted(err)
		rep.NeedsReview = true
		rep.Err = appendNote(rep.Err, "undoing peering adaptation: "+err.Error())
	}
	return rep
}
