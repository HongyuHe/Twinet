package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultEventCapacity = 4096
	maxEventDetail       = 1024
	maxEventPage         = 1000
)

type eventCorrelationKey struct{}

var eventCorrelationSequence atomic.Uint64

// Event is one structured operational observation. It intentionally carries
// identifiers in the event body rather than as Prometheus labels: events are
// bounded and queryable, while metric cardinality must remain bounded.
type Event struct {
	Sequence  uint64    `json:"sequence"`
	Timestamp time.Time `json:"timestamp"`
	Node      string    `json:"node"`
	// AgentVersion is the exact source build that recorded this event. It is
	// provenance, never a compatibility decision.
	AgentVersion string `json:"agent_version,omitempty"`
	Lab          string `json:"lab,omitempty"`
	Generation   string `json:"generation,omitempty"`
	// FenceGeneration identifies the fenced controller mutation that caused
	// this event. It is separate from Generation: a deployment generation is
	// content addressed, while a fence generation orders competing writers.
	FenceGeneration uint64 `json:"fence_generation,omitempty"`
	// Identity and CertificateSerial make a privileged mutation attributable
	// without retaining bearer credentials or certificate bodies.
	Identity          string `json:"identity,omitempty"`
	CertificateSerial string `json:"certificate_serial,omitempty"`
	// Target is the container, device, or cluster object the request changed.
	Target        string `json:"target,omitempty"`
	Scope         string `json:"scope"`
	CorrelationID string `json:"correlation_id,omitempty"`
	Action        string `json:"action"`
	Result        string `json:"result"`
	Detail        string `json:"detail,omitempty"`
}

// EventsResponse is the finite page returned by GET /v1/events when follow is
// not requested. Next is a node-local cursor; callers use it with after to
// resume after a disconnect.
type EventsResponse struct {
	Events []Event `json:"events"`
	Next   uint64  `json:"next"`
}

type eventWatcher struct {
	lab string
	ch  chan Event
}

type eventRing struct {
	mu        sync.Mutex
	persistMu sync.Mutex
	capacity  int
	node      string
	next      uint64
	items     []Event
	watchers  map[uint64]eventWatcher
	nextWatch uint64
	persist   func([]Event)
}

func newEventRing(capacity int, node string, persist func([]Event)) *eventRing {
	if capacity <= 0 {
		capacity = defaultEventCapacity
	}
	return &eventRing{
		capacity: capacity,
		node:     node,
		watchers: map[uint64]eventWatcher{},
		persist:  persist,
	}
}

func (r *eventRing) restore(events []Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(events) > r.capacity {
		events = events[len(events)-r.capacity:]
	}
	r.items = append([]Event(nil), events...)
	for _, event := range r.items {
		if event.Sequence > r.next {
			r.next = event.Sequence
		}
	}
}

func (r *eventRing) append(event Event) Event {
	r.mu.Lock()
	r.next++
	event.Sequence = r.next
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}
	if event.Node == "" {
		event.Node = r.node
	}
	event.Scope = boundedEventScope(event.Scope)
	event.Action = boundedEventText(event.Action, 80)
	event.Result = boundedEventResult(event.Result)
	event.Identity = boundedEventText(event.Identity, 160)
	event.CertificateSerial = boundedEventText(event.CertificateSerial, 128)
	event.Target = boundedEventText(event.Target, 256)
	event.Detail = boundedEventText(event.Detail, maxEventDetail)
	r.items = append(r.items, event)
	if len(r.items) > r.capacity {
		copy(r.items, r.items[len(r.items)-r.capacity:])
		r.items = r.items[:r.capacity]
	}
	for _, watcher := range r.watchers {
		if watcher.lab != "" && watcher.lab != event.Lab {
			continue
		}
		select {
		case watcher.ch <- event:
		default:
			// A slow caller must not block repair or runtime-event intake. It
			// can reconnect from its cursor; the retained ring still holds the
			// authoritative order.
		}
	}
	r.mu.Unlock()
	r.save()
	return event
}

func (r *eventRing) save() {
	if r.persist == nil {
		return
	}
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	r.mu.Lock()
	snapshot := append([]Event(nil), r.items...)
	r.mu.Unlock()
	r.persist(snapshot)
}

func (r *eventRing) after(after uint64, lab string, limit int) ([]Event, uint64) {
	if limit <= 0 || limit > maxEventPage {
		limit = maxEventPage
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, 0, limit)
	next := after
	for _, event := range r.items {
		if event.Sequence <= after || (lab != "" && event.Lab != lab) {
			continue
		}
		out = append(out, event)
		next = event.Sequence
		if len(out) == limit {
			break
		}
	}
	return out, next
}

func (r *eventRing) subscribe(after uint64, lab string) ([]Event, uint64, <-chan Event, func()) {
	// A follow subscription must bridge the retained history and live events
	// without a cursor hole. Pages are capped at maxEventPage, but follow
	// emits every retained matching event before registering its watcher.
	limit := r.capacity
	r.mu.Lock()
	initial := make([]Event, 0, limit)
	next := after
	for _, event := range r.items {
		if event.Sequence <= after || (lab != "" && event.Lab != lab) {
			continue
		}
		initial = append(initial, event)
		next = event.Sequence
		if len(initial) == limit {
			break
		}
	}
	r.nextWatch++
	id := r.nextWatch
	ch := make(chan Event, 256)
	r.watchers[id] = eventWatcher{lab: lab, ch: ch}
	r.mu.Unlock()
	return initial, next, ch, func() {
		r.mu.Lock()
		if _, ok := r.watchers[id]; ok {
			delete(r.watchers, id)
			close(ch)
		}
		r.mu.Unlock()
	}
}

func boundedEventScope(value string) string {
	switch value {
	case "api", "runtime", "reconcile", "gc", "matrix", "grading", "underlay",
		"deploy", "durability", "coordination", "inventory":
		return value
	default:
		return "other"
	}
}

func boundedEventResult(value string) string {
	switch value {
	case "success", "error", "unknown", "scheduled", "skipped", "backoff",
		"held", "exempt", "canceled", "healthy", "broken", "partial", "denied":
		return value
	default:
		return "other"
	}
}

func boundedEventText(value string, limit int) string {
	value = redactEventText(value)
	value = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(value), "\r", " "), "\n", " ")
	if len(value) > limit {
		return value[:limit] + "…"
	}
	return value
}

// redactEventText keeps operational error messages useful without letting a
// bearer credential, private key, or PEM body become durable audit data. Event
// writers deliberately share this final choke point; a future handler cannot
// accidentally bypass redaction by calling recordEvent directly.
func redactEventText(value string) string {
	replacements := []struct {
		prefix string
	}{
		{"Bearer "},
		{"bearer "},
		{"Authorization:"},
		{"authorization:"},
		{"token="},
		{"token:"},
		{"secret="},
		{"secret:"},
		{"-----BEGIN "},
	}
	for _, replacement := range replacements {
		for {
			index := strings.Index(value, replacement.prefix)
			if index < 0 {
				break
			}
			end := index + len(replacement.prefix)
			for end < len(value) {
				switch value[end] {
				case ' ', '\t', '\r', '\n', ',', ';', '"', '\'':
					goto replace
				}
				end++
			}
		replace:
			value = value[:index] + "[redacted]" + value[end:]
		}
	}
	return value
}

func (s *Server) eventLog() *eventRing {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if s.events != nil {
		return s.events
	}
	capacity := s.cfg.EventCapacity
	if capacity <= 0 {
		capacity = defaultEventCapacity
	}
	store := s.store
	ring := newEventRing(capacity, s.cfg.Node, func(events []Event) {
		if store == nil {
			return
		}
		raw, err := json.Marshal(events)
		if err == nil {
			_ = store.PutEventJournal(raw)
		}
	})
	if store != nil {
		if raw, err := store.EventJournal(); err == nil && len(raw) > 0 {
			var saved []Event
			if json.Unmarshal(raw, &saved) == nil {
				ring.restore(saved)
			}
		}
	}
	s.events = ring
	return ring
}

func (s *Server) recordEvent(lab, generation, scope, correlation, action, result, detail string) Event {
	if correlation == "" {
		correlation = s.requestCorrelation(nil)
	}
	if generation == "" && lab != "" {
		s.mu.Lock()
		if state, ok := s.generations[lab]; ok {
			generation = state.Committed
		}
		s.mu.Unlock()
	}
	return s.eventLog().append(Event{
		Node: s.cfg.Node, AgentVersion: Version, Lab: lab, Generation: generation, Scope: scope,
		CorrelationID: correlation, Action: action, Result: result, Detail: detail,
	})
}

func (s *Server) requestCorrelation(r *http.Request) string {
	if r != nil {
		if value, ok := r.Context().Value(eventCorrelationKey{}).(string); ok && value != "" {
			return value
		}
		if value := validCorrelation(r.Header.Get("X-Twinet-Correlation-ID")); value != "" {
			return value
		}
	}
	return fmt.Sprintf("%s-%x", s.cfg.Node, eventCorrelationSequence.Add(1))
}

func validCorrelation(value string) string {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > 128 {
		return ""
	}
	for _, runeValue := range value {
		switch {
		case runeValue >= 'a' && runeValue <= 'z',
			runeValue >= 'A' && runeValue <= 'Z',
			runeValue >= '0' && runeValue <= '9',
			runeValue == '-', runeValue == '_', runeValue == '.', runeValue == ':':
		default:
			return ""
		}
	}
	return value
}

func withEventCorrelation(s *Server, r *http.Request) *http.Request {
	if r == nil {
		return r
	}
	id := s.requestCorrelation(r)
	return r.WithContext(context.WithValue(r.Context(), eventCorrelationKey{}, id))
}

// SortEvents gives callers a deterministic cluster order. Sequences are only
// node-local, so timestamp, node, lab, and sequence are all required for a
// stable merged view.
func SortEvents(events []Event) {
	sort.Slice(events, func(i, j int) bool {
		if !events[i].Timestamp.Equal(events[j].Timestamp) {
			return events[i].Timestamp.Before(events[j].Timestamp)
		}
		if events[i].Node != events[j].Node {
			return events[i].Node < events[j].Node
		}
		if events[i].Lab != events[j].Lab {
			return events[i].Lab < events[j].Lab
		}
		return events[i].Sequence < events[j].Sequence
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	lab := r.URL.Query().Get("lab")
	if scope, scoped := scopedRequestOf(r); scoped && scope.Lab != "" && scope.Lab != "*" {
		if lab != "" && lab != scope.Lab {
			httpError(w, http.StatusForbidden, errors.New("this diagnostic session is scoped to another lab"))
			return
		}
		lab = scope.Lab
	} else if scope, diagnostic := diagScopeOf(r); diagnostic {
		if lab != "" && lab != scope {
			httpError(w, http.StatusForbidden, errors.New("this diagnostic session is scoped to another lab"))
			return
		}
		lab = scope
	}
	after, err := parseEventUint(r.URL.Query().Get("after"))
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 1 {
			httpError(w, http.StatusBadRequest, errors.New("event limit must be a positive integer"))
			return
		}
		limit = parsed
	}
	if r.URL.Query().Get("follow") != "true" && r.URL.Query().Get("follow") != "1" {
		events, next := s.eventLog().after(after, lab, limit)
		writeJSON(w, EventsResponse{Events: events, Next: next})
		return
	}

	initial, next, stream, cancel := s.eventLog().subscribe(after, lab)
	defer cancel()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	encoder := json.NewEncoder(w)
	flush, _ := w.(http.Flusher)
	write := func(event Event) bool {
		if err := encoder.Encode(event); err != nil {
			return false
		}
		if flush != nil {
			flush.Flush()
		}
		return true
	}
	for _, event := range initial {
		if !write(event) {
			return
		}
		next = event.Sequence
	}
	for {
		// A watcher is deliberately non-blocking. Drain the retained ring
		// first so an event produced while a long initial history is encoded
		// cannot be lost merely because its watcher buffer filled.
		if backlog, _ := s.eventLog().after(next, lab, defaultEventCapacity); len(backlog) > 0 {
			for _, event := range backlog {
				if !write(event) {
					return
				}
				next = event.Sequence
			}
			continue
		}
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-stream:
			if !ok {
				return
			}
			if event.Sequence <= next {
				continue
			}
			if !write(event) {
				return
			}
			next = event.Sequence
		}
	}
}

func parseEventUint(raw string) (uint64, error) {
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, errors.New("event cursor must be an unsigned integer")
	}
	return value, nil
}
