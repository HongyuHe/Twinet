package model

import (
	"fmt"
	"strconv"

	"gopkg.in/yaml.v3"
)

// UnmarshalYAML accepts the compact named/count forms used by generated
// interiors while retaining the extended mapping for a prefix override.
func (r *RouterSet) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.SequenceNode:
		var names []string
		if err := n.Decode(&names); err != nil {
			return err
		}
		r.Names = names
		return nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!int":
			count, err := strconv.Atoi(n.Value)
			if err != nil {
				return fmt.Errorf("line %d: router count %q is not an integer", n.Line, n.Value)
			}
			r.Count = count
		case "!!null":
			*r = RouterSet{}
		default:
			// A single named router is useful for a deliberately tiny
			// two-tier fixture; ring validation will still reject a
			// one-router cycle with a precise message.
			r.Names = []string{n.Value}
		}
		return nil
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			switch n.Content[i].Value {
			case "names", "count", "prefix":
			default:
				return fmt.Errorf("line %d: unknown router-set field %q", n.Content[i].Line, n.Content[i].Value)
			}
		}
		type plain RouterSet
		var p plain
		if err := n.Decode(&p); err != nil {
			return err
		}
		*r = RouterSet(p)
		return nil
	default:
		return fmt.Errorf("line %d: routers must be a name list, count, or mapping", n.Line)
	}
}

// UnmarshalYAML accepts a named hub or hub: true for the stable default name.
func (h *HubName) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: hub must be a router name or true", n.Line)
	}
	if n.Tag == "!!bool" {
		switch n.Value {
		case "true":
			*h = HubName("hub")
		case "false":
			*h = ""
		default:
			return fmt.Errorf("line %d: hub boolean %q is invalid", n.Line, n.Value)
		}
		return nil
	}
	if n.Tag == "!!null" {
		*h = ""
		return nil
	}
	*h = HubName(n.Value)
	return nil
}

// UnmarshalYAML accepts both the compact and extended link forms:
//
//	internal_links:
//	  - [MSP, NYC]                          # compact
//	  - {a: MSP, b: NYC, delay: 25ms}       # extended
//
// The compact form keeps hand-written templates readable; the extended form is
// what generators emit and what per-link shaping requires.
func (l *InternalLink) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.SequenceNode:
		var pair []string
		if err := n.Decode(&pair); err != nil {
			return err
		}
		if len(pair) != 2 {
			return fmt.Errorf("line %d: compact link form needs exactly 2 endpoints, got %d", n.Line, len(pair))
		}
		l.A, l.B = pair[0], pair[1]
		return nil
	case yaml.MappingNode:
		type plain InternalLink // avoid recursion
		var p plain
		if err := n.Decode(&p); err != nil {
			return err
		}
		*l = InternalLink(p)
		if l.A == "" || l.B == "" {
			return fmt.Errorf("line %d: link needs both 'a' and 'b'", n.Line)
		}
		return nil
	default:
		return fmt.Errorf("line %d: link must be a [a, b] pair or a mapping", n.Line)
	}
}

// MarshalYAML emits the compact form when no shaping overrides are present.
func (l InternalLink) MarshalYAML() (any, error) {
	if l.Bandwidth == "" && l.Delay == "" && l.Queue == "" && l.Loss == "" && l.MTU == nil &&
		l.Subnet == "" && l.SubnetV6 == "" {
		return []string{l.A, l.B}, nil
	}
	type plain InternalLink
	return plain(l), nil
}

// UnmarshalYAML lets a provisioning rule be written either as a bare string
// (a device kind or a well-known scope) or as a full mapping.
func (r *ProvisionRule) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		r.Scope = n.Value
		return nil
	}
	type plain ProvisionRule
	var p plain
	if err := n.Decode(&p); err != nil {
		return err
	}
	*r = ProvisionRule(p)
	return nil
}
