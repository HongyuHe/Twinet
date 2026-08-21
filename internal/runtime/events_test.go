package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"
)

func TestDockerAPIEventSubscriptionFiltersNormalizesAndOrders(t *testing.T) {
	actions := []string{
		"create",
		"start",
		"die",
		"stop",
		"destroy",
		"restart",
		"oom",
		"health_status: healthy",
	}
	fake := newEngineFake(t, func(w http.ResponseWriter, r *http.Request) {
		if servePing(w, r) {
			return
		}
		if enginePath(r) != "/events" {
			http.Error(w, "unexpected Docker API request", http.StatusNotFound)
			return
		}
		var filters map[string]map[string]bool
		if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil {
			t.Errorf("decode event filters: %v", err)
		} else {
			if !filters["type"]["container"] {
				t.Errorf("event filters = %#v, want container type", filters)
			}
			if !filters["label"]["twinet.lab=lab-a"] {
				t.Errorf("event filters = %#v, want Twinet label", filters)
			}
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		encoder := json.NewEncoder(w)
		for i, action := range actions {
			if err := encoder.Encode(engineEvent("container-a", action, "container-a", "lab-a", int64(1_000_000_000+i))); err != nil {
				t.Errorf("write event: %v", err)
				return
			}
		}
		_ = encoder.Encode(engineEvent("container-b", "start", "container-b", "lab-b", 2_000_000_000))
		_ = encoder.Encode(map[string]any{
			"Type":   "image",
			"Action": "create",
			"Actor":  map[string]any{"ID": "image-id"},
			"time":   3,
		})
	})
	docker := newEngineDocker(t, fake)

	events, terminal := collectEvents(t, docker.Subscribe(context.Background(), EventFilter{
		Labels: map[string]string{"twinet.lab": "lab-a"},
	}))
	if !errors.Is(terminal, io.EOF) {
		t.Fatalf("event terminal error = %v, want io.EOF", terminal)
	}
	wantActions := []EventAction{
		EventCreate,
		EventStart,
		EventDie,
		EventStop,
		EventDestroy,
		EventRestart,
		EventOOM,
		EventHealth,
	}
	if len(events) != len(wantActions) {
		t.Fatalf("received %d events, want %d: %#v", len(events), len(wantActions), events)
	}
	gotActions := make([]EventAction, 0, len(events))
	for i, event := range events {
		gotActions = append(gotActions, event.Action)
		if event.Container != "container-a" || event.Name != "container-a" {
			t.Errorf("event %d identity = %#v, want container-a", i, event)
		}
		if len(event.Labels) != 1 || event.Labels["twinet.lab"] != "lab-a" {
			t.Errorf("event %d labels = %#v, want Twinet label only", i, event.Labels)
		}
		if want := time.Unix(0, int64(1_000_000_000+i)); !event.At.Equal(want) {
			t.Errorf("event %d timestamp = %s, want %s", i, event.At, want)
		}
	}
	if !slices.Equal(gotActions, wantActions) {
		t.Errorf("event actions = %#v, want %#v", gotActions, wantActions)
	}
}

func TestDockerAPIEventSubscriptionCancellation(t *testing.T) {
	started := make(chan struct{})
	closed := make(chan struct{})
	fake := newEngineFake(t, func(w http.ResponseWriter, r *http.Request) {
		if servePing(w, r) {
			return
		}
		if enginePath(r) != "/events" {
			http.Error(w, "unexpected Docker API request", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(closed)
	})
	docker := newEngineDocker(t, fake)
	ctx, cancel := context.WithCancel(context.Background())
	subscription := docker.Subscribe(ctx, EventFilter{})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Docker event stream did not start")
	}
	cancel()

	events, terminal := collectEvents(t, subscription)
	if len(events) != 0 {
		t.Fatalf("received events after cancellation: %#v", events)
	}
	if !errors.Is(terminal, context.Canceled) {
		t.Fatalf("event cancellation error = %v, want context canceled", terminal)
	}
	waitForEventStreamClose(t, closed)
}

func TestDockerAPIEventSubscriptionClosesWithRuntime(t *testing.T) {
	started := make(chan struct{})
	closed := make(chan struct{})
	fake := newEngineFake(t, func(w http.ResponseWriter, r *http.Request) {
		if servePing(w, r) {
			return
		}
		if enginePath(r) != "/events" {
			http.Error(w, "unexpected Docker API request", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(closed)
	})
	docker := newEngineDocker(t, fake)
	subscription := docker.Subscribe(context.Background(), EventFilter{})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Docker event stream did not start")
	}
	if err := docker.Close(); err != nil {
		t.Fatalf("close Docker runtime: %v", err)
	}

	events, terminal := collectEvents(t, subscription)
	if len(events) != 0 {
		t.Fatalf("received events after runtime close: %#v", events)
	}
	if !errors.Is(terminal, context.Canceled) {
		t.Fatalf("runtime close event error = %v, want context canceled", terminal)
	}
	waitForEventStreamClose(t, closed)
}

func TestDockerAPIEventSubscriptionReportsStreamErrors(t *testing.T) {
	fake := newEngineFake(t, func(w http.ResponseWriter, r *http.Request) {
		if servePing(w, r) {
			return
		}
		if enginePath(r) != "/events" {
			http.Error(w, "unexpected Docker API request", http.StatusNotFound)
			return
		}
		http.Error(w, "event stream failed", http.StatusInternalServerError)
	})
	docker := newEngineDocker(t, fake)

	events, terminal := collectEvents(t, docker.Subscribe(context.Background(), EventFilter{}))
	if len(events) != 0 {
		t.Fatalf("received events from failed stream: %#v", events)
	}
	if terminal == nil || errors.Is(terminal, ErrEventStreamClosed) {
		t.Fatalf("event stream error = %v, want daemon error", terminal)
	}
}

func TestDockerCLIEventArguments(t *testing.T) {
	got := dockerCLIEventArgs(EventFilter{Labels: map[string]string{
		"twinet.lab":  "lab-a",
		"twinet.role": "",
	}})
	want := []string{
		"events", "--format", "{{json .}}",
		"--filter", "type=container",
		"--filter", "label=twinet.lab=lab-a",
		"--filter", "label=twinet.role",
	}
	if !slices.Equal(got, want) {
		t.Errorf("CLI event arguments = %#v, want %#v", got, want)
	}
}

func TestMemoryEventSubscriptionFiltersCancelsAndOrders(t *testing.T) {
	memory := NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	subscription := memory.Subscribe(ctx, EventFilter{Labels: map[string]string{"twinet.lab": "lab-a"}})

	startedAt := time.Unix(100, 0)
	memory.Emit(Event{
		Container: "other",
		Action:    EventCreate,
		Labels:    map[string]string{"twinet.lab": "lab-b"},
		At:        startedAt,
	})
	memory.Emit(Event{
		Container: "router-a",
		Action:    EventCreate,
		Labels:    map[string]string{"twinet.lab": "lab-a"},
		At:        startedAt,
	})
	memory.Emit(Event{
		Container: "router-a",
		Action:    EventStart,
		Labels:    map[string]string{"twinet.lab": "lab-a"},
		At:        startedAt.Add(time.Second),
	})
	memory.Emit(Event{
		Container: "router-a",
		Action:    EventHealth,
		Labels:    map[string]string{"twinet.lab": "lab-a"},
		At:        startedAt.Add(2 * time.Second),
	})

	var delivered []Event
	for range 3 {
		select {
		case event := <-subscription.Events:
			delivered = append(delivered, event)
		case <-time.After(time.Second):
			t.Fatal("memory event was not delivered")
		}
	}
	if got, want := []EventAction{delivered[0].Action, delivered[1].Action, delivered[2].Action},
		[]EventAction{EventCreate, EventStart, EventHealth}; !slices.Equal(got, want) {
		t.Errorf("memory event actions = %#v, want %#v", got, want)
	}
	if delivered[0].Container != "router-a" || delivered[0].Labels["twinet.lab"] != "lab-a" {
		t.Errorf("memory event identity/labels = %#v", delivered[0])
	}
	cancel()

	remaining, terminal := collectEvents(t, subscription)
	if len(remaining) != 0 {
		t.Fatalf("received events after memory cancellation: %#v", remaining)
	}
	if !errors.Is(terminal, context.Canceled) {
		t.Fatalf("memory cancellation error = %v, want context canceled", terminal)
	}
}

func TestMemoryEventSubscriptionReportsFailures(t *testing.T) {
	memory := NewMemory()
	subscription := memory.Subscribe(context.Background(), EventFilter{})
	want := errors.New("memory event transport failed")
	memory.Fail(want)

	events, terminal := collectEvents(t, subscription)
	if len(events) != 0 {
		t.Fatalf("received events after memory failure: %#v", events)
	}
	if !errors.Is(terminal, want) {
		t.Fatalf("memory stream error = %v, want %v", terminal, want)
	}
}

func engineEvent(id, action, name, lab string, nanos int64) map[string]any {
	return map[string]any{
		"Type":   "container",
		"Action": action,
		"Actor": map[string]any{
			"ID": id,
			"Attributes": map[string]string{
				"name":       name,
				"image":      "example:latest",
				"twinet.lab": lab,
			},
		},
		"time":     nanos / int64(time.Second),
		"timeNano": nanos,
	}
}

func collectEvents(t *testing.T, subscription EventSubscription) ([]Event, error) {
	t.Helper()
	var (
		events   []Event
		terminal error
	)
	eventCh, errorCh := subscription.Events, subscription.Errors
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for eventCh != nil || errorCh != nil {
		select {
		case event, ok := <-eventCh:
			if !ok {
				eventCh = nil
				continue
			}
			events = append(events, event)
		case err, ok := <-errorCh:
			if !ok {
				errorCh = nil
				continue
			}
			if terminal != nil {
				t.Errorf("received more than one terminal event error: %v and %v", terminal, err)
			}
			terminal = err
		case <-timeout.C:
			t.Fatal("event subscription did not terminate")
		}
	}
	if terminal == nil {
		t.Fatal("event subscription closed without a terminal error")
	}
	return events, terminal
}

func waitForEventStreamClose(t *testing.T, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Engine event response body was not closed")
	}
}
