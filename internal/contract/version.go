// Package contract describes compatibility boundaries that are intentionally
// independent from a source build identifier.
package contract

import (
	"fmt"
	"strconv"
	"strings"
)

// Range advertises a current contract revision and the inclusive interval it
// can safely exchange with. Binary versions are deliberately not represented:
// a bug-fix rebuild may change a source SHA without changing a wire, renderer,
// or persisted-state contract.
type Range struct {
	Current       string `json:"current"`
	MinCompatible string `json:"min_compatible"`
	MaxCompatible string `json:"max_compatible"`
}

// Set is the complete contract the controller and node must agree on before a
// rolling deployment can mutate a lab.
type Set struct {
	Protocol Range `json:"protocol"`
	Renderer Range `json:"renderer"`
	State    Range `json:"state"`
}

type version struct {
	major int
	minor int
	patch int
}

func parse(value string) (version, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if value == "" {
		return version{}, fmt.Errorf("empty version")
	}
	core, _, _ := strings.Cut(value, "-")
	parts := strings.Split(core, ".")
	if len(parts) > 3 {
		return version{}, fmt.Errorf("%q has more than three numeric components", value)
	}
	var values [3]int
	for i, part := range parts {
		if part == "" {
			return version{}, fmt.Errorf("%q has an empty numeric component", value)
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return version{}, fmt.Errorf("%q is not a non-negative dotted version", value)
		}
		values[i] = n
	}
	return version{major: values[0], minor: values[1], patch: values[2]}, nil
}

func (v version) compare(other version) int {
	switch {
	case v.major != other.major:
		return compareInt(v.major, other.major)
	case v.minor != other.minor:
		return compareInt(v.minor, other.minor)
	default:
		return compareInt(v.patch, other.patch)
	}
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func (v version) in(minimum, maximum version) bool {
	return v.compare(minimum) >= 0 && v.compare(maximum) <= 0
}

// Validate rejects an incomplete or self-contradictory advertised range.
func (r Range) Validate() error {
	current, err := parse(r.Current)
	if err != nil {
		return fmt.Errorf("current: %w", err)
	}
	minimum, err := parse(r.MinCompatible)
	if err != nil {
		return fmt.Errorf("minimum: %w", err)
	}
	maximum, err := parse(r.MaxCompatible)
	if err != nil {
		return fmt.Errorf("maximum: %w", err)
	}
	if minimum.compare(maximum) > 0 {
		return fmt.Errorf("minimum %s exceeds maximum %s", r.MinCompatible, r.MaxCompatible)
	}
	if !current.in(minimum, maximum) {
		return fmt.Errorf("current %s is outside [%s, %s]",
			r.Current, r.MinCompatible, r.MaxCompatible)
	}
	return nil
}

// Compatible reports whether two advertised ranges can safely interact. Both
// current values must be accepted by the other side; a mere interval overlap
// is insufficient when one participant is already outside that overlap.
func (r Range) Compatible(other Range) (bool, error) {
	if err := r.Validate(); err != nil {
		return false, err
	}
	if err := other.Validate(); err != nil {
		return false, err
	}
	current, _ := parse(r.Current)
	otherCurrent, _ := parse(other.Current)
	minimum, _ := parse(r.MinCompatible)
	maximum, _ := parse(r.MaxCompatible)
	otherMinimum, _ := parse(other.MinCompatible)
	otherMaximum, _ := parse(other.MaxCompatible)
	return current.in(otherMinimum, otherMaximum) &&
		otherCurrent.in(minimum, maximum), nil
}

// Empty reports whether no contract fields were supplied.
func (s Set) Empty() bool {
	return s.Protocol.Current == "" && s.Renderer.Current == "" && s.State.Current == ""
}

// Compatible checks every independent contract and returns field-specific
// diagnostics suitable for a refusal before mutation.
func (s Set) Compatible(other Set) error {
	for _, part := range []struct {
		name string
		a    Range
		b    Range
	}{
		{"protocol", s.Protocol, other.Protocol},
		{"renderer", s.Renderer, other.Renderer},
		{"state", s.State, other.State},
	} {
		ok, err := part.a.Compatible(part.b)
		if err != nil {
			return fmt.Errorf("%s contract is invalid: controller=%+v node=%+v: %w",
				part.name, part.a, part.b, err)
		}
		if !ok {
			return fmt.Errorf("%s contract is incompatible: controller=%s [%s, %s], node=%s [%s, %s]",
				part.name,
				part.a.Current, part.a.MinCompatible, part.a.MaxCompatible,
				part.b.Current, part.b.MinCompatible, part.b.MaxCompatible)
		}
	}
	return nil
}
