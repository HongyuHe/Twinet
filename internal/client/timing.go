package client

import (
	"sort"
	"time"
)

// PhaseTimings is a bounded controller-phase timing map. Names are fixed by
// the deployment protocol; lab/device IDs never become timing labels.
type PhaseTimings map[string]time.Duration

func (p PhaseTimings) measure(name string, fn func() error) error {
	start := time.Now()
	err := fn()
	p[name] += time.Since(start)
	return err
}

func (p PhaseTimings) add(name string, elapsed time.Duration) {
	p[name] += elapsed
}

// Milliseconds returns a stable JSON-friendly timing map for CLI/API output.
func (p PhaseTimings) Milliseconds() map[string]int64 {
	out := make(map[string]int64, len(p))
	for name, elapsed := range p {
		out[name] = elapsed.Milliseconds()
	}
	return out
}

func (p PhaseTimings) Names() []string {
	out := make([]string, 0, len(p))
	for name := range p {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
