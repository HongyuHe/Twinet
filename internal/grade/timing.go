package grade

import (
	"sort"
	"sync"
	"time"
)

type phaseRecorder struct {
	mu     sync.Mutex
	phases []PhaseTiming
}

func (r *phaseRecorder) measure(name string, fn func()) {
	start := time.Now().UTC()
	fn()
	end := time.Now().UTC()
	r.mu.Lock()
	r.phases = append(r.phases, PhaseTiming{
		Name: name, StartedAt: start, FinishedAt: end,
		Duration: end.Sub(start).Round(time.Millisecond).String(),
	})
	r.mu.Unlock()
}

func (r *phaseRecorder) append(name string, start, end time.Time) {
	r.mu.Lock()
	r.phases = append(r.phases, PhaseTiming{
		Name: name, StartedAt: start.UTC(), FinishedAt: end.UTC(),
		Duration: end.Sub(start).Round(time.Millisecond).String(),
	})
	r.mu.Unlock()
}

func (r *phaseRecorder) appendDetail(phase PhaseTiming) {
	r.mu.Lock()
	r.phases = append(r.phases, phase)
	r.mu.Unlock()
}

func (r *phaseRecorder) list() []PhaseTiming {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]PhaseTiming(nil), r.phases...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].Name < out[j].Name
		}
		return out[i].StartedAt.Before(out[j].StartedAt)
	})
	return out
}
