package model

import "sort"

// Behaviours are the scripted, reversible perturbations an exercise is built
// around, as opposed to the faults an incident is built around. A manifest
// declares them by kind; each kind names the fault that implements it.
//
// The vocabulary lives here, with the rest of the manifest's vocabulary, so
// that the validator can refuse an unimplemented kind without importing either
// the fault registry or the command layer.
// behaviourKinds maps a manifest's kind onto the registered fault that
// implements it. A kind with no implementation is refused by the validator
// rather than accepted and ignored.
var behaviourKinds = map[string]string{
	"bgp-hijack": "bgp_hijacking",
	"link-down":  "link_down",
}

// BehaviourKinds lists the kinds a manifest may declare.
func BehaviourKinds() []string {
	out := make([]string, 0, len(behaviourKinds))
	for k := range behaviourKinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// BehaviourFault returns the fault implementing a kind.
func BehaviourFault(kind string) (string, bool) {
	f, ok := behaviourKinds[kind]
	return f, ok
}
