package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type eventRepairRuntime struct {
	rt.Runtime
	state rt.State
	err   error
}

func (r *eventRepairRuntime) Inspect(context.Context, string) (rt.Container, error) {
	if r.err != nil {
		return rt.Container{}, r.err
	}
	return rt.Container{State: r.state}, nil
}

type rotatingEventSource struct {
	mu      sync.Mutex
	streams chan *rt.Memory
}

func (s *rotatingEventSource) Subscribe(ctx context.Context, filter rt.EventFilter) rt.EventSubscription {
	memory := rt.NewMemory()
	subscription := memory.Subscribe(ctx, filter)
	select {
	case s.streams <- memory:
	default:
	}
	return subscription
}

func observabilityTopology() (*model.Topology, *model.Device) {
	device := &model.Device{
		ID: "as1/R1", Name: "R1", Node: "node-0", Container: "twinet-lab-as1-r1",
		Kind: model.KindRouter,
	}
	top := &model.Topology{
		Name: "lab", Devices: map[string]*model.Device{device.ID: device},
		ASes: map[int]*model.AS{},
	}
	return top, device
}

func TestRuntimeEventLoopReconnectsAfterTerminalStream(t *testing.T) {
	source := &rotatingEventSource{streams: make(chan *rt.Memory, 3)}
	server := &Server{cfg: Config{Node: "node-0"}, eventSource: source}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		server.runtimeEventLoop(ctx)
		close(done)
	}()
	first := <-source.streams
	first.Fail(errors.New("transport reset"))
	select {
	case <-source.streams:
	case <-time.After(time.Second):
		t.Fatal("agent did not reconnect to a terminal runtime event stream")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("event loop did not stop when its context was canceled")
	}
}

func TestRuntimeEventQueuesTargetedRepair(t *testing.T) {
	top, device := observabilityTopology()
	repaired := make(chan []*model.Device, 1)
	server := &Server{
		cfg:     Config{Node: "node-0"},
		rt:      &eventRepairRuntime{state: rt.StateExited},
		current: map[string]*model.Topology{top.Name: top},
		ops:     map[string]*lease{},
		repairHook: func(_ context.Context, _ *model.Topology, devices []*model.Device) {
			repaired <- devices
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server.startReconcileWorkers(ctx)
	server.handleRuntimeEvent(ctx, rt.Event{
		Name: device.Container, Action: rt.EventDie,
		Labels: map[string]string{
			deploy.LabelManaged:  "true",
			deploy.LabelLab:      top.Name,
			deploy.LabelDeviceID: device.ID,
		},
	})
	select {
	case devices := <-repaired:
		if len(devices) != 1 || devices[0].ID != device.ID {
			t.Fatalf("event repaired %#v, want only %s", devices, device.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("a die event did not promptly queue a targeted repair")
	}
}

func TestUnknownAndBackoffRemainExplicitAndRecover(t *testing.T) {
	top, device := observabilityTopology()
	server := &Server{
		cfg: Config{Node: "node-0"},
		rt:  &eventRepairRuntime{err: context.DeadlineExceeded},
	}
	observation := server.observeDevice(context.Background(), top.Name, device, true)
	if observation.Health != healthUnknown {
		t.Fatalf("unreadable runtime health = %s, want unknown", observation.Health)
	}
	if got := ClassifyChange(DesiredObserved{
		Desired: true, SpecMatches: true, State: observation.State, Health: observation.Health,
	}); got != ChangeUnknown {
		t.Fatalf("unknown observation class = %s, want unknown", got)
	}

	now := time.Unix(1_700_000_000, 0)
	server.now = func() time.Time { return now }
	for range repairAttemptsBeforeGivingUp {
		server.repairFailed(top.Name, device.ID, "test failure", errors.New("not ready"))
	}
	if !server.givingUpOn(top.Name, device.ID) {
		t.Fatal("repeated failures did not enter bounded backoff")
	}
	now = now.Add(repairDelay(repairAttemptsBeforeGivingUp) + time.Millisecond)
	if server.givingUpOn(top.Name, device.ID) {
		t.Fatal("a failed device was permanently abandoned instead of becoming retryable")
	}
	server.repairSucceeded(top.Name, device.ID)
	if server.givingUpOn(top.Name, device.ID) {
		t.Fatal("a healthy recovery did not clear repair history")
	}
}

func TestDesiredObservedChangeClassesRemainMinimal(t *testing.T) {
	cases := []struct {
		name     string
		observed DesiredObserved
		want     ChangeClass
	}{
		{"live", DesiredObserved{Desired: true, SpecMatches: true, State: rt.StateRunning, Health: healthHealthy}, ChangeLive},
		{"config", DesiredObserved{Desired: true, SpecMatches: true, State: rt.StateRunning, Health: healthBroken, Reason: "routing daemon is down"}, ChangeConfig},
		{"rewire", DesiredObserved{Desired: true, SpecMatches: true, State: rt.StateRunning, Health: healthPartial}, ChangeRewire},
		{"restart", DesiredObserved{Desired: true, SpecMatches: true, State: rt.StateExited, Health: healthBroken}, ChangeRestart},
		{"recreate", DesiredObserved{Desired: true, SpecMatches: true, State: rt.StateAbsent, Health: healthBroken}, ChangeRecreate},
		{"delete", DesiredObserved{Desired: false}, ChangeDelete},
		{"unknown", DesiredObserved{Desired: true, SpecMatches: false, Health: healthUnknown}, ChangeUnknown},
	}
	for _, testCase := range cases {
		if got := ClassifyChange(testCase.observed); got != testCase.want {
			t.Errorf("%s class = %s, want %s", testCase.name, got, testCase.want)
		}
	}
}

func TestRepairRechecksHoldBeforeMutating(t *testing.T) {
	top, device := observabilityTopology()
	called := make(chan struct{}, 1)
	server := &Server{
		cfg: Config{Node: "node-0"},
		holds: map[string]*hold{
			top.Name: {holder: "grading", token: "hold", until: time.Now().Add(time.Minute)},
		},
		repairHook: func(context.Context, *model.Topology, []*model.Device) {
			called <- struct{}{}
		},
	}
	server.repairLab(context.Background(), top, []*model.Device{device})
	select {
	case <-called:
		t.Fatal("repair hook ran despite a grading hold acquired before repair")
	default:
	}
}

func TestEventScopeOrderAndBoundedMetrics(t *testing.T) {
	server := &Server{cfg: Config{Node: "node-0", Token: "secret", EventCapacity: 2}}
	ring := server.eventLog()
	ring.append(Event{
		Timestamp: time.Unix(20, 0), Lab: "lab-b", Scope: "api", Action: "x", Result: "success",
	})
	ring.append(Event{
		Timestamp: time.Unix(10, 0), Lab: "lab-b", Scope: "api", Action: "x", Result: "success",
	})
	ring.append(Event{
		Timestamp: time.Unix(30, 0), Lab: "lab-a", Scope: "api", Action: "x", Result: "success",
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	request.Header.Set("Authorization", "Bearer "+DiagnosticToken("secret", "lab-a"))
	response := httptest.NewRecorder()
	server.authDiag(server.handleEvents)(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("scoped event endpoint = %d: %s", response.Code, response.Body.String())
	}
	var page EventsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 || page.Events[0].Lab != "lab-a" || page.Events[0].Sequence != 3 {
		t.Fatalf("diagnostic stream leaked or lost events: %#v", page.Events)
	}
	merged := []Event{
		{Timestamp: time.Unix(5, 0), Node: "node-b", Lab: "lab", Sequence: 2},
		{Timestamp: time.Unix(5, 0), Node: "node-a", Lab: "lab-z", Sequence: 3},
		{Timestamp: time.Unix(5, 0), Node: "node-a", Lab: "lab-a", Sequence: 4},
	}
	SortEvents(merged)
	if merged[0].Node != "node-a" || merged[0].Lab != "lab-a" || merged[2].Node != "node-b" {
		t.Fatalf("cluster event order is not deterministic: %#v", merged)
	}

	metrics := newAgentMetrics()
	for range 100 {
		metrics.observeOperation("unbounded-user-supplied-operation", time.Millisecond, nil)
	}
	text := metrics.prometheusText()
	if count := stringCount(text, `operation="other"`); count == 0 {
		t.Fatal("unbounded operation names were not collapsed into a bounded metric label")
	}
	if stringCount(text, "unbounded-user-supplied-operation") != 0 {
		t.Fatal("unbounded operation name leaked into Prometheus labels")
	}
	metricsServer := &Server{cfg: Config{Node: "node-0"}, rt: &gcRuntime{}}
	metricsResponse := httptest.NewRecorder()
	metricsServer.handleMetrics(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metricsText := metricsResponse.Body.String()
	for _, family := range []string{
		"twinet_operation_duration_seconds",
		"twinet_deployment_phase_duration_seconds",
		"twinet_runtime_calls_total",
		"twinet_limiter_pressure",
		"twinet_inventory_resources",
		"twinet_containers",
		"twinet_overlays",
		"twinet_overlay_reservations",
		"twinet_convergence_devices",
		"twinet_repairs_total",
		"twinet_grading_infrastructure_outcomes_total",
		"twinet_underlay_health",
	} {
		if indexOf(metricsText, family) < 0 {
			t.Errorf("metrics response is missing %s", family)
		}
	}
}

func TestAutomaticGCRespectsGraceAndActiveLabs(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	removed := []uint32{}
	server := &Server{
		cfg: Config{Node: "node-0", GCGrace: time.Second},
		rt:  &gcRuntime{},
		now: func() time.Time { return now },
		gcFindOrphans: func(_ map[string]bool) ([]netx.Orphan, error) {
			return []netx.Orphan{{VNI: 77, Owner: "gone"}}, nil
		},
		gcRemoveOverlay: func(vni uint32) error {
			removed = append(removed, vni)
			return nil
		},
		gcDeleteHostLink: func(string) error { return nil },
		gcListMultiplex:  func(string) ([]netx.MultiplexOverlay, error) { return nil, nil },
		gcRemoveEmptyMultiplex: func(string) ([]string, error) {
			return nil, nil
		},
	}
	if _, err := server.gcOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatal("garbage collection removed an overlay before its grace period")
	}
	now = now.Add(2 * time.Second)
	summary, err := server.gcOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || len(summary.RemovedOverlays) != 1 {
		t.Fatalf("node-0 with no managed containers did not collect stale overlay: %#v", summary)
	}

	activeTop, _ := observabilityTopology()
	activeTop.Name = "active"
	server.current = map[string]*model.Topology{"active": activeTop}
	server.gcFindOrphans = func(_ map[string]bool) ([]netx.Orphan, error) {
		return []netx.Orphan{{VNI: 78, Owner: "active"}}, nil
	}
	now = now.Add(2 * time.Second)
	if _, err := server.gcOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err := server.gcOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 {
		t.Fatal("automatic GC touched an active lab")
	}
}

func TestAutomaticGCCollectsStaleMultiplexBindingsAndPair(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	bindingPresent := true
	var removedVNIs []uint32
	server := &Server{
		cfg: Config{Node: "node-0", GCGrace: time.Second},
		rt:  &gcRuntime{},
		now: func() time.Time { return now },
		gcFindOrphans: func(map[string]bool) ([]netx.Orphan, error) {
			return nil, nil
		},
		gcRemoveOverlay: func(vni uint32) error {
			removedVNIs = append(removedVNIs, vni)
			bindingPresent = false
			return nil
		},
		gcDeleteHostLink: func(string) error { return nil },
		gcListMultiplex: func(string) ([]netx.MultiplexOverlay, error) {
			overlay := netx.MultiplexOverlay{Lab: "gone", Vxlan: "twvp-stale", Bridge: "twbp-stale"}
			if bindingPresent {
				overlay.VNIs = []uint32{88}
			}
			return []netx.MultiplexOverlay{overlay}, nil
		},
		gcRemoveEmptyMultiplex: func(string) ([]string, error) {
			return []string{"twbp-stale", "twvp-stale"}, nil
		},
	}
	for range 4 {
		if _, err := server.gcOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Second)
	}
	if len(removedVNIs) != 1 || removedVNIs[0] != 88 {
		t.Fatalf("stale multiplex VNI was not removed: %v", removedVNIs)
	}
	summary, err := server.gcOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.RemovedPairs) == 0 {
		t.Fatal("empty stale multiplex bridge/VXLAN pair was not collected")
	}
}

type gcRuntime struct{ rt.Runtime }

func (*gcRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) { return nil, nil }

func stringCount(value, needle string) int {
	count := 0
	for {
		if start := indexOf(value, needle); start >= 0 {
			count++
			value = value[start+len(needle):]
			continue
		}
		return count
	}
}

func indexOf(value, needle string) int {
	for index := 0; index+len(needle) <= len(value); index++ {
		if value[index:index+len(needle)] == needle {
			return index
		}
	}
	return -1
}
