package cli

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/fault"
	"github.com/HongyuHe/twinet/internal/model"
)

// A scenario that names its own answer cannot measure anything once it is
// published.
//
// Every example scenario shipped with Twinet says, in plain YAML, which fault
// goes on which device and which interface. The repository is public. An agent
// that has read it -- deliberately, or because it was trained on the internet
// -- answers correctly without looking at the network, and scores exactly like
// one that diagnosed the fault. Hiding the file from the agent's filesystem and
// cutting its route to the internet stops it fetching the answer during the
// run; neither does anything about an answer it already knows.
//
// So a scenario says what *kind* of thing is broken and leaves the choice to
// the run. The selector below enumerates every target the fault could be
// applied to in the deployed topology and draws one with the episode's seed.
// The seed is drawn afresh unless the operator asks for a particular one, and
// is recorded in the episode, so a run is reproducible after the fact without
// being predictable before it.
type Selector struct {
	// Kind is the family of targets to draw from.
	Kind string `yaml:"kind" json:"kind"`
	// AS restricts the draw to these autonomous systems.
	AS []int `yaml:"as,omitempty" json:"as,omitempty"`
	// Exclude names devices that must not be chosen, for a lab where some
	// device is load-bearing for the exercise itself.
	Exclude []string `yaml:"exclude,omitempty" json:"exclude,omitempty"`
	// Prefix and Params are carried through to the drawn target unchanged, for
	// faults that need an argument the topology cannot supply.
	Prefix string            `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Params map[string]string `yaml:"params,omitempty" json:"params,omitempty"`
}

// The families a scenario may draw from. Each is a shape of target rather than
// a fault type, because several faults take the same shape.
const (
	selectInternalLink = "internal_link" // a router interface onto another router of the same AS
	selectExternalLink = "external_link" // a router interface onto another AS
	selectRouter       = "router"
	selectHost         = "host"
)

var selectorKinds = []string{selectInternalLink, selectExternalLink, selectRouter, selectHost}

// Valid reports why a selector cannot be used, or nil.
func (s *Selector) Valid() error {
	if s == nil {
		return nil
	}
	for _, k := range selectorKinds {
		if s.Kind == k {
			return nil
		}
	}
	if s.Kind == "" {
		return fmt.Errorf("select: needs a kind, one of %s", strings.Join(selectorKinds, ", "))
	}
	return fmt.Errorf("select: %q is not a target family; expected one of %s",
		s.Kind, strings.Join(selectorKinds, ", "))
}

// candidates enumerates every target this selector could draw, in a stable
// order so that a seed means the same thing on every run of the same lab.
func (s *Selector) candidates(top *model.Topology) []fault.Target {
	allowed := map[int]bool{}
	for _, a := range s.AS {
		allowed[a] = true
	}
	excluded := map[string]bool{}
	for _, e := range s.Exclude {
		excluded[e] = true
	}
	var out []fault.Target
	for _, dev := range top.Devices {
		if dev.ASN == 0 {
			continue
		}
		if len(allowed) > 0 && !allowed[dev.ASN] {
			continue
		}
		if excluded[dev.Name] || excluded[dev.ID] {
			continue
		}
		switch s.Kind {
		case selectRouter:
			if dev.Kind == model.KindRouter {
				out = append(out, fault.Target{AS: dev.ASN, Device: dev.Name,
					Prefix: s.Prefix, Params: s.Params})
			}
		case selectHost:
			if dev.Kind == model.KindHost {
				out = append(out, fault.Target{AS: dev.ASN, Device: dev.Name,
					Prefix: s.Prefix, Params: s.Params})
			}
		case selectInternalLink, selectExternalLink:
			if dev.Kind != model.KindRouter {
				continue
			}
			for _, i := range dev.Ifaces {
				if i.Link == nil || i.Peer == nil || i.Peer.Device == nil {
					continue
				}
				if i.Peer.Device.Kind != model.KindRouter {
					continue
				}
				if s.Kind == selectInternalLink && i.Link.InterAS {
					continue
				}
				if s.Kind == selectExternalLink && !i.Link.InterAS {
					continue
				}
				t := fault.Target{AS: dev.ASN, Device: dev.Name, Iface: i.Name,
					Prefix: s.Prefix, Params: s.Params}
				if i.Link.InterAS {
					t.Peer = i.Peer.Device.ASN
				}
				out = append(out, t)
			}
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].AS != out[b].AS {
			return out[a].AS < out[b].AS
		}
		if out[a].Device != out[b].Device {
			return out[a].Device < out[b].Device
		}
		return out[a].Iface < out[b].Iface
	})
	return out
}

// drawTargets resolves every fault's target, drawing the ones a scenario left
// to the run.
//
// Each fault gets an ordered list of candidates rather than a single choice.
// The first is the draw; the rest are what to try if it turns out the fault
// cannot be applied there -- a link that is already down cannot be brought
// down, and a fault that would change nothing is refused rather than recorded
// as the cause of something. Without the fallback, one candidate in twenty
// being unsuitable means one episode in twenty failing outright, which a
// benchmark run overnight would discover in the morning.
//
// Each draw uses its own stream from the seed, so adding a fault to a scenario
// does not change what the earlier ones chose, and a suite that reruns one
// episode gets the same network back.
func drawTargets(top *model.Topology, specs []FaultSpec, seed int64) ([][]fault.Target, error) {
	out := make([][]fault.Target, len(specs))
	for i, spec := range specs {
		if spec.Select == nil {
			out[i] = []fault.Target{spec.Target}
			continue
		}
		if err := spec.Select.Valid(); err != nil {
			return nil, fmt.Errorf("faults[%d]: %w", i, err)
		}
		cands := spec.Select.candidates(top)
		// A fault the topology cannot host is refused rather than skipped: an
		// episode with fewer faults than its scenario says is not the episode
		// anybody asked for, and its ground truth would be quietly wrong.
		if len(cands) == 0 {
			return nil, fmt.Errorf("faults[%d]: nothing in this lab matches select %s%s",
				i, spec.Select.Kind, asFilter(spec.Select.AS))
		}
		r := rand.New(rand.NewSource(seed + int64(i)*7919))
		r.Shuffle(len(cands), func(a, b int) { cands[a], cands[b] = cands[b], cands[a] })
		for j := range cands {
			// A target the scenario did pin wins over the draw, so a scenario
			// can fix the prefix and leave the device to chance.
			if spec.Target.Prefix != "" {
				cands[j].Prefix = spec.Target.Prefix
			}
			if len(spec.Target.Params) > 0 {
				cands[j].Params = spec.Target.Params
			}
		}
		out[i] = cands
	}
	return out, nil
}

// describeDraw says which of how many candidates a fault landed on. It is only
// ever shown to the operator, and only on request: it is the answer.
func describeDraw(kind string, t fault.Target, of int) string {
	where := t.Device
	if t.Iface != "" {
		where += ":" + t.Iface
	}
	return fmt.Sprintf("%s on as%d/%s (1 of %d)", kind, t.AS, where, of)
}

func asFilter(as []int) string {
	if len(as) == 0 {
		return ""
	}
	parts := make([]string, len(as))
	for i, a := range as {
		parts[i] = fmt.Sprintf("%d", a)
	}
	return " in AS " + strings.Join(parts, ",")
}

// pinnedTargets lists the faults whose target is written down in the scenario
// file, which is what makes a published scenario unusable for scoring.
func pinnedTargets(specs []FaultSpec) []string {
	var out []string
	for _, spec := range specs {
		if spec.Select != nil {
			continue
		}
		where := spec.Target.Device
		if where == "" {
			where = "an unnamed device"
		}
		if spec.Target.Iface != "" {
			where += ":" + spec.Target.Iface
		}
		out = append(out, fmt.Sprintf("%s on %s", spec.Type, where))
	}
	return out
}
