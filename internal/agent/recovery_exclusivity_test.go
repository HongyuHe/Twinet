package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

func TestRestartPendingTransactionSuppressesOrdinaryMaintenance(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before := coordinationTestServer(t, store)
	before.transactions["lab"] = applyTransaction{
		Generation: "failed", Phase: transactionRollbackNeeded,
	}
	if err := before.saveCoordinationLocked(); err != nil {
		t.Fatal(err)
	}

	after := coordinationTestServer(t, store)
	after.loadCoordination()
	router := &model.Device{ID: "as1/R1", Node: "node-0", Container: "r1"}
	peer := &model.Device{ID: "as1/R2", Node: "node-0", Container: "r2"}
	left := &model.Iface{Name: "p1", Device: router}
	right := &model.Iface{Name: "p2", Device: peer}
	link := &model.Link{ID: "recovering-link", A: left, B: right}
	left.Link, right.Link, left.Peer, right.Peer = link, link, right, left
	router.Ifaces, peer.Ifaces = []*model.Iface{left}, []*model.Iface{right}
	after.current["lab"] = &model.Topology{
		Name: "lab", Devices: map[string]*model.Device{router.ID: router, peer.ID: peer},
	}
	after.reconcileQueue = make(chan reconcileRequest, 1)
	after.reconcilePending = map[string]bool{}
	var repaired int
	after.repairHook = func(context.Context, *model.Topology, []*model.Device) { repaired++ }

	after.handleRuntimeEvent(context.Background(), rt.Event{
		Name: "device", Labels: map[string]string{
			deploy.LabelLab: "lab", deploy.LabelDeviceID: "as1/R1",
		},
	})
	select {
	case request := <-after.reconcileQueue:
		t.Fatalf("event repair was queued during persisted recovery: %+v", request)
	default:
	}
	// Startup/sample/full audit ticks must consult the same persisted record;
	// no runtime is installed here, so a missed suppression would panic while
	// trying to survey a peer recovery has intentionally removed.
	after.reconcileSample(context.Background())
	after.reconcileOnce(context.Background())
	after.reconcileTarget(context.Background(), reconcileRequest{lab: "lab", device: "as1/R1"})
	if repaired != 0 {
		t.Fatal("reconcile repaired while a restarted agent had a pending transaction")
	}
	after.captureDueState(context.Background())
	if after.durabilityBusy["lab"] {
		t.Fatal("periodic durability capture started during pending recovery")
	}

	after.rt = maintenanceRuntime{}
	protected, _, err := after.gcProtectedLabs(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !protected["lab"] {
		t.Fatal("GC did not protect a lab with a persisted pending transaction")
	}

	delete(after.transactions, "lab") // finalization is the only release point.
	if reason := after.ordinaryMaintenanceSuppression("lab"); reason != "" {
		t.Fatalf("terminal transaction still suppressed maintenance: %s", reason)
	}
}

type maintenanceRuntime struct{ rt.Runtime }

func (maintenanceRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) { return nil, nil }

func TestPreparingTransactionCancelsPeriodicCapture(t *testing.T) {
	server := coordinationTestServer(t, nil)
	periodicCtx, ok := server.beginPeriodicDurability(context.Background(), "lab")
	if !ok {
		t.Fatal("could not start synthetic periodic capture")
	}
	lease, err := server.acquireMutationLease(LeaseAcquireRequest{Lab: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.prepareGeneration("lab", lease.Fence, "", "new",
		[]byte(`{"lab":"lab","mode":"platform"}`), "platform", 0, nil, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-periodicCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("preparing transaction did not cancel periodic durability work")
	}
	server.endDurability("lab")
}

func TestRecoveryPreemptsCancelableReconcileLease(t *testing.T) {
	server := coordinationTestServer(t, nil)
	repairCtx, cancelRepair := context.WithCancel(context.Background())
	defer cancelRepair()
	repairID, repairDone, err := server.acquireOperation("lab", "reconcile", cancelRepair)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-repairCtx.Done()
		server.releaseOperation("lab", repairID, repairDone)
	}()
	_, cancelRecovery := context.WithCancel(context.Background())
	defer cancelRecovery()
	recoveryID, recoveryDone, err := server.acquireRecoveryOperation(
		context.Background(), "lab", time.Now().Add(time.Minute), cancelRecovery, true)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-repairCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("recovery did not cancel the active reconcile operation")
	}
	server.mu.Lock()
	held := server.ops["lab"]
	server.mu.Unlock()
	if held == nil || held.id != recoveryID || held.kind != "recovery" {
		t.Fatalf("canceled reconcile released recovery lease: %+v", held)
	}
	server.releaseRecoveryOperation("lab", recoveryID, recoveryDone)
}

func TestRecoveryWaitsForCancelledApplyToQuiesce(t *testing.T) {
	server := coordinationTestServer(t, nil)
	applyCtx, cancelApply := context.WithCancel(context.Background())
	applyID, applyDone, err := server.acquireOperation("lab", "apply", cancelApply)
	if err != nil {
		t.Fatal(err)
	}
	lateCreateStarted := make(chan struct{})
	allowLateCreateToFinish := make(chan struct{})
	applyFinished := make(chan struct{})
	go func() {
		<-applyCtx.Done()
		close(lateCreateStarted)
		<-allowLateCreateToFinish
		server.releaseOperation("lab", applyID, applyDone)
		close(applyFinished)
	}()

	recoveryAcquired := make(chan struct{})
	var recoveryID uint64
	var recoveryDone chan struct{}
	go func() {
		recoveryID, recoveryDone, err = server.acquireRecoveryOperation(
			context.Background(), "lab", time.Now().Add(time.Minute), func() {}, true)
		close(recoveryAcquired)
	}()
	select {
	case <-lateCreateStarted:
	case <-time.After(time.Second):
		t.Fatal("recovery did not cancel the apply")
	}
	select {
	case <-recoveryAcquired:
		t.Fatal("recovery started before the late runtime mutation quiesced")
	default:
	}
	close(allowLateCreateToFinish)
	select {
	case <-applyFinished:
	case <-time.After(time.Second):
		t.Fatal("cancelled apply did not finish")
	}
	select {
	case <-recoveryAcquired:
	case <-time.After(time.Second):
		t.Fatal("recovery did not acquire after apply quiesced")
	}
	if err != nil {
		t.Fatal(err)
	}
	server.releaseRecoveryOperation("lab", recoveryID, recoveryDone)
}

func TestRecoveryCannotObserveZeroThenAllowLateScaleRecreation(t *testing.T) {
	server := coordinationTestServer(t, nil)
	runtime := newBulkRecoveryRuntime(0)
	applyCtx, cancelApply := context.WithCancel(context.Background())
	applyID, applyDone, err := server.acquireOperation("scale", "apply", cancelApply)
	if err != nil {
		t.Fatal(err)
	}
	lateCreateReady := make(chan struct{})
	allowLateCreate := make(chan struct{})
	go func() {
		<-applyCtx.Done()
		close(lateCreateReady)
		<-allowLateCreate
		runtime.create(626)
		server.releaseOperation("scale", applyID, applyDone)
	}()

	recoveryDone := make(chan error, 1)
	go func() {
		recoveryID, done, acquireErr := server.acquireRecoveryOperation(
			context.Background(), "scale", time.Now().Add(time.Minute), func() {}, true)
		if acquireErr != nil {
			recoveryDone <- acquireErr
			return
		}
		defer server.releaseRecoveryOperation("scale", recoveryID, done)
		containers, listErr := runtime.List(context.Background(), rt.Filter{})
		if listErr != nil {
			recoveryDone <- listErr
			return
		}
		recoveryDone <- runBoundedRecoveryItems(context.Background(), 8, containers, time.Second,
			func(container rt.Container) string { return container.Name },
			func(ctx context.Context, container rt.Container) error {
				return runtime.Remove(ctx, container.Name, true)
			})
	}()
	<-lateCreateReady
	if got := runtime.count(); got != 0 {
		t.Fatalf("pre-quiescence inventory=%d, want initial zero", got)
	}
	select {
	case err := <-recoveryDone:
		t.Fatalf("recovery observed the transient zero before late creates quiesced: %v", err)
	default:
	}
	close(allowLateCreate)
	if err := <-recoveryDone; err != nil {
		t.Fatal(err)
	}
	if got := runtime.count(); got != 0 {
		t.Fatalf("late apply recreation survived recovery: %d containers", got)
	}
}

func TestExactRecoveryContainerReusesExitedAndConflictContracts(t *testing.T) {
	spec := &rt.Spec{
		Name: "expected",
		Labels: map[string]string{
			deploy.LabelSpec:            "old-spec",
			deploy.LabelRuntimeContract: deploy.RuntimeSpecContractVersion,
		},
	}
	t.Run("exited matching contract starts without create", func(t *testing.T) {
		runtime := &exactRecoveryRuntime{container: rt.Container{
			Name: spec.Name, State: rt.StateExited, Labels: cloneRecoveryLabels(spec.Labels),
		}}
		server := &Server{rt: runtime}
		if err := server.ensureExactRecoveryContainer(context.Background(), spec); err != nil {
			t.Fatal(err)
		}
		if runtime.creates != 0 || runtime.starts != 1 || runtime.container.State != rt.StateRunning {
			t.Fatalf("exited exact contract lifecycle = %+v", runtime)
		}
	})
	t.Run("name conflict adopts matching contract", func(t *testing.T) {
		runtime := &exactRecoveryRuntime{createConflict: true, spec: spec}
		server := &Server{rt: runtime}
		if err := server.ensureExactRecoveryContainer(context.Background(), spec); err != nil {
			t.Fatal(err)
		}
		if runtime.creates != 1 || runtime.starts != 0 || runtime.container.State != rt.StateRunning {
			t.Fatalf("matching conflict was not adopted: %+v", runtime)
		}
	})
}

func TestExactRecoveryContainerReturnsDelayedStartDeadline(t *testing.T) {
	spec := &rt.Spec{
		Name: "expected",
		Labels: map[string]string{
			deploy.LabelSpec:            "old-spec",
			deploy.LabelRuntimeContract: deploy.RuntimeSpecContractVersion,
		},
	}
	runtime := &exactRecoveryRuntime{container: rt.Container{
		Name: spec.Name, State: rt.StateExited, Labels: cloneRecoveryLabels(spec.Labels),
	}, waitStart: true}
	server := &Server{rt: runtime}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := server.ensureExactRecoveryContainer(ctx, spec); err == nil {
		t.Fatal("delayed Docker start was accepted after its context deadline")
	}
}

func cloneRecoveryLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		out[key] = value
	}
	return out
}

type exactRecoveryRuntime struct {
	rt.Runtime
	container      rt.Container
	spec           *rt.Spec
	creates        int
	starts         int
	createConflict bool
	waitStart      bool
}

func (r *exactRecoveryRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return r.container, nil
}

func (r *exactRecoveryRuntime) Remove(context.Context, string, bool) error {
	r.container = rt.Container{State: rt.StateAbsent}
	return nil
}

func (r *exactRecoveryRuntime) Create(_ context.Context, spec *rt.Spec) (string, error) {
	r.creates++
	if r.createConflict {
		r.container = rt.Container{Name: spec.Name, State: rt.StateRunning, Labels: cloneRecoveryLabels(spec.Labels)}
		return "", errors.New("name is already in use")
	}
	r.container = rt.Container{Name: spec.Name, State: rt.StateCreated, Labels: cloneRecoveryLabels(spec.Labels)}
	return spec.Name, nil
}

func (r *exactRecoveryRuntime) Start(ctx context.Context, _ string) error {
	r.starts++
	if r.waitStart {
		<-ctx.Done()
		return ctx.Err()
	}
	r.container.State = rt.StateRunning
	return nil
}
