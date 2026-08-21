package runtime

import (
	"context"
	"sync"
	"time"
)

const memoryEventQueueSize = 64

var _ EventSource = (*Memory)(nil)

// Memory is an in-memory EventSource for runtime consumers and tests.
type Memory struct {
	mu          sync.RWMutex
	subscribers map[*memoryEventSubscription]struct{}
	closed      bool
}

type memoryEventSubscription struct {
	filter EventFilter
	queue  chan Event
	events chan Event
	errors chan error
	stop   chan error
	done   chan struct{}
}

// NewMemory constructs an in-memory event fake.
func NewMemory() *Memory {
	return &Memory{subscribers: make(map[*memoryEventSubscription]struct{})}
}

// Name identifies the in-memory fake.
func (m *Memory) Name() string { return "memory" }

// Subscribe receives events emitted after the subscription is created.
func (m *Memory) Subscribe(ctx context.Context, filter EventFilter) EventSubscription {
	if err := ctx.Err(); err != nil {
		return failedEventSubscription(err)
	}
	subscription, events, errs := newEventSubscription()
	sub := &memoryEventSubscription{
		filter: cloneEventFilter(filter),
		queue:  make(chan Event, memoryEventQueueSize),
		events: events,
		errors: errs,
		stop:   make(chan error, 1),
		done:   make(chan struct{}),
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return failedEventSubscription(ErrEventStreamClosed)
	}
	m.subscribers[sub] = struct{}{}
	m.mu.Unlock()

	go m.runSubscription(ctx, sub)
	return subscription
}

// Emit publishes an event to every matching active subscriber in order.
func (m *Memory) Emit(event Event) {
	action, ok := normalizeEventAction(string(event.Action))
	if !ok {
		return
	}
	event.Action = action
	if event.At.IsZero() {
		event.At = time.Now()
	}
	event = cloneEvent(event)

	m.mu.RLock()
	subscribers := make([]*memoryEventSubscription, 0, len(m.subscribers))
	for sub := range m.subscribers {
		subscribers = append(subscribers, sub)
	}
	m.mu.RUnlock()

	for _, sub := range subscribers {
		if !eventMatches(sub.filter, event) {
			continue
		}
		select {
		case sub.queue <- cloneEvent(event):
		case <-sub.done:
		}
	}
}

// Publish is an alias for Emit.
func (m *Memory) Publish(event Event) { m.Emit(event) }

// Fail terminates all active subscriptions with err.
func (m *Memory) Fail(err error) {
	if err == nil {
		err = ErrEventStreamClosed
	}
	m.mu.RLock()
	subscribers := make([]*memoryEventSubscription, 0, len(m.subscribers))
	for sub := range m.subscribers {
		subscribers = append(subscribers, sub)
	}
	m.mu.RUnlock()
	for _, sub := range subscribers {
		select {
		case sub.stop <- err:
		default:
		}
	}
}

// Close terminates active subscriptions.
func (m *Memory) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	subscribers := make([]*memoryEventSubscription, 0, len(m.subscribers))
	for sub := range m.subscribers {
		subscribers = append(subscribers, sub)
	}
	m.mu.Unlock()
	for _, sub := range subscribers {
		select {
		case sub.stop <- ErrEventStreamClosed:
		default:
		}
	}
	return nil
}

func (m *Memory) runSubscription(ctx context.Context, sub *memoryEventSubscription) {
	terminal := ErrEventStreamClosed
	defer func() {
		m.mu.Lock()
		delete(m.subscribers, sub)
		m.mu.Unlock()
		close(sub.done)
		finishEventSubscription(sub.events, sub.errors, terminal)
	}()

	for {
		select {
		case err := <-sub.stop:
			terminal = err
			return
		default:
		}
		select {
		case err := <-sub.stop:
			terminal = err
			return
		case <-ctx.Done():
			terminal = ctx.Err()
			return
		case event := <-sub.queue:
			select {
			case sub.events <- event:
			case err := <-sub.stop:
				terminal = err
				return
			case <-ctx.Done():
				terminal = ctx.Err()
				return
			}
		}
	}
}
