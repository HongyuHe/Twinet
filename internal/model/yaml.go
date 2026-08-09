package model

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

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
