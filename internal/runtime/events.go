package runtime

import (
	"errors"
	"strings"
	"time"
)

// ErrEventStreamClosed reports a backend stream that closed without a terminal
// error. Consumers can safely reconnect after receiving it.
var ErrEventStreamClosed = errors.New("runtime event stream closed without a terminal error")

func newEventSubscription() (EventSubscription, chan Event, chan error) {
	events := make(chan Event)
	errs := make(chan error, 1)
	return EventSubscription{Events: events, Errors: errs}, events, errs
}

func failedEventSubscription(err error) EventSubscription {
	subscription, events, errs := newEventSubscription()
	finishEventSubscription(events, errs, err)
	return subscription
}

func finishEventSubscription(events chan Event, errs chan error, err error) {
	if err == nil {
		err = ErrEventStreamClosed
	}
	errs <- err
	close(errs)
	close(events)
}

func normalizeContainerEvent(container, name, action string, attributes map[string]string, seconds, nanos int64) (Event, bool) {
	normalisedAction, ok := normalizeEventAction(action)
	if !ok {
		return Event{}, false
	}
	if name == "" {
		name = attributes["name"]
	}
	at := time.Unix(seconds, 0)
	if nanos != 0 {
		at = time.Unix(0, nanos)
	}
	return Event{
		Container: container,
		Name:      name,
		Action:    normalisedAction,
		Labels:    eventLabels(attributes),
		At:        at,
	}, true
}

func normalizeEventAction(action string) (EventAction, bool) {
	switch EventAction(strings.TrimSpace(action)) {
	case EventCreate, EventStart, EventDie, EventStop, EventDestroy, EventRestart, EventOOM, EventHealth:
		return EventAction(strings.TrimSpace(action)), true
	}
	if strings.HasPrefix(strings.TrimSpace(action), "health_status") {
		return EventHealth, true
	}
	return "", false
}

func eventLabels(attributes map[string]string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	labels := make(map[string]string, len(attributes))
	for key, value := range attributes {
		switch key {
		case "name", "image":
			continue
		default:
			labels[key] = value
		}
	}
	if len(labels) == 0 {
		return nil
	}
	return labels
}

func eventMatches(filter EventFilter, event Event) bool {
	for key, value := range filter.Labels {
		got, ok := event.Labels[key]
		if !ok || (value != "" && got != value) {
			return false
		}
	}
	return true
}

func cloneEvent(event Event) Event {
	if event.Labels == nil {
		return event
	}
	labels := make(map[string]string, len(event.Labels))
	for key, value := range event.Labels {
		labels[key] = value
	}
	event.Labels = labels
	return event
}

func cloneEventFilter(filter EventFilter) EventFilter {
	return EventFilter{Labels: cloneStringMap(filter.Labels)}
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
