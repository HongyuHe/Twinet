package agent

import (
	"strings"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// ChangeClass is the smallest desired-versus-observed repair action. Keeping
// these classes explicit prevents a harmless qdisc/config change from being
// implemented as a container replacement, and makes event traces explain why
// a repair touched a device.
type ChangeClass string

const (
	ChangeLive     ChangeClass = "live"
	ChangeConfig   ChangeClass = "config"
	ChangeRewire   ChangeClass = "rewire"
	ChangeRestart  ChangeClass = "restart"
	ChangeRecreate ChangeClass = "recreate"
	ChangeDelete   ChangeClass = "delete"
	ChangeUnknown  ChangeClass = "unknown"
)

// DesiredObserved is a compact desired/observed comparison suitable for both
// the event-driven path and low-frequency audits.
type DesiredObserved struct {
	Desired     bool
	SpecMatches bool
	State       rt.State
	Health      deviceHealth
	Reason      string
}

// ClassifyChange computes the minimal safe repair class. Unknown observations
// are explicit and never folded into live: callers wait for a readable
// observation rather than mutating a host based on a guess.
func ClassifyChange(observed DesiredObserved) ChangeClass {
	if !observed.Desired {
		return ChangeDelete
	}
	if observed.State == rt.StateAbsent {
		return ChangeRecreate
	}
	if observed.Health == healthUnknown {
		return ChangeUnknown
	}
	if !observed.SpecMatches {
		return ChangeRecreate
	}
	switch observed.State {
	case rt.StateCreated, rt.StateExited, rt.StateDead, rt.StateRestarting, rt.StatePaused:
		return ChangeRestart
	}
	switch observed.Health {
	case healthHealthy:
		return ChangeLive
	case healthPartial:
		return ChangeRewire
	case healthBroken:
		reason := strings.ToLower(observed.Reason)
		switch {
		case strings.Contains(reason, "daemon"), strings.Contains(reason, "healthcheck"):
			return ChangeConfig
		default:
			return ChangeRewire
		}
	default:
		return ChangeLive
	}
}

func deviceChangeClass(observation deviceObservation) ChangeClass {
	return ClassifyChange(DesiredObserved{
		Desired: true, SpecMatches: observation.SpecMatches, State: observation.State,
		Health: observation.Health, Reason: observation.Reason,
	})
}
