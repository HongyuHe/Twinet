package svc

import (
	"sort"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

// Collection is one bounded observation emitted by a local matrix or
// measurement worker. It is intentionally metadata rather than an unbounded
// stream of probe output: detailed matrix results already have their typed
// document, while this surface tells the web/UI collector which replica and
// node produced it.
type Collection struct {
	Service string    `json:"service"`
	Replica string    `json:"replica,omitempty"`
	Node    string    `json:"node"`
	Result  string    `json:"result"`
	At      time.Time `json:"at"`
}

// ServiceCollector retains a bounded, deterministic event surface for locally
// executed service work. It is deliberately in-process and explicit: callers
// publish declared observations rather than relying on hidden mutable
// coordination among service containers.
type ServiceCollector struct {
	mu       sync.Mutex
	capacity int
	events   []Collection
}

// NewServiceCollector builds a bounded collector.
func NewServiceCollector(capacity int) *ServiceCollector {
	if capacity <= 0 {
		capacity = 256
	}
	return &ServiceCollector{capacity: capacity}
}

// Publish records one collection event.
func (c *ServiceCollector) Publish(event Collection) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	} else {
		event.At = event.At.UTC()
	}
	c.events = append(c.events, event)
	if len(c.events) > c.capacity {
		copy(c.events, c.events[len(c.events)-c.capacity:])
		c.events = c.events[:c.capacity]
	}
}

// Events returns a stable snapshot for a web/API caller.
func (c *ServiceCollector) Events() []Collection {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append([]Collection(nil), c.events...)
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.Before(out[j].At)
		}
		if out[i].Node != out[j].Node {
			return out[i].Node < out[j].Node
		}
		return out[i].Replica < out[j].Replica
	})
	return out
}

// LocalWorkers reports the declared local work partitions of one service. A
// matrix/measurement controller can dispatch one batch to each returned
// replica/node pair and aggregate its results through Collector.
func LocalWorkers(top *model.Topology, serviceName string) []Collection {
	if top == nil {
		return nil
	}
	service := top.Services[serviceName]
	if service == nil {
		return nil
	}
	var out []Collection
	for _, replica := range service.SortedReplicas() {
		if replica == nil {
			continue
		}
		out = append(out, Collection{
			Service: service.Kind, Replica: replica.ID, Node: replica.Node, Result: "declared",
		})
	}
	if len(out) == 0 && service.Device != nil {
		out = append(out, Collection{Service: service.Kind, Node: service.Device.Node, Result: "declared"})
	}
	return out
}
