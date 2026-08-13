package model

import "sort"

// Configuration domains: the units that "Twinet configures this, the student
// configures that" is decided in.
//
// They exist because the declaration existed first and did nothing. A template
// could say `provisioned: [{scope: all}]` or `student: [ospf, ebgp]` and pass
// validation, and ownership was then decided solely by whether the AS's role
// was "student" -- so a course that wanted OSPF given and BGP assigned wrote
// exactly that, was told the manifest was valid, and got a lab where the
// students were handed neither. Every domain named here compiles into
// behaviour; anything else is refused by the manifest validator rather than
// accepted and ignored.
const (
	DomainLoopbacks        = "loopbacks"
	DomainRouterInterfaces = "router_interfaces"
	DomainHostAddressing   = "host_addressing"
	DomainL2               = "l2"
	DomainOSPF             = "ospf"
	DomainBGP              = "bgp"
	DomainMPLS             = "mpls"
	DomainAll              = "all"

	// Domains that name real student work but that Twinet cannot hand out on
	// their own. They may be listed under `student`, where they are a true
	// statement about the lab, and `scope: all` covers them; naming one in a
	// `provisioned` rule is refused rather than accepted and ignored, because
	// the configuration they describe is not separable from the stanza it is
	// rendered in.
	DomainBGPPolicy = "bgp_policy"
	DomainIPv6      = "ipv6"
	DomainRPKI      = "rpki"
)

// studentOnlyDomains cannot be provisioned individually.
var studentOnlyDomains = map[string]bool{
	DomainBGPPolicy: true, DomainIPv6: true, DomainRPKI: true,
}

// CanProvision reports whether a domain may appear in a `provisioned` rule.
func CanProvision(domain string) bool { return !studentOnlyDomains[domain] }

// domainAliases maps the spellings a manifest may use onto the domain that is
// actually rendered. iBGP and eBGP are one FRR stanza, so they are one domain;
// a manifest that provisions one without the other is refused rather than
// silently given both.
var domainAliases = map[string]string{
	"ibgp":     DomainBGP,
	"ebgp":     DomainBGP,
	"l2_vlans": DomainL2,
}

// KnownDomains is every domain a manifest may name, for validation messages.
func KnownDomains() []string {
	out := []string{
		DomainAll, DomainLoopbacks, DomainRouterInterfaces, DomainHostAddressing,
		DomainL2, DomainOSPF, DomainBGP, DomainMPLS,
		DomainBGPPolicy, DomainIPv6, DomainRPKI,
	}
	for a := range domainAliases {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// NormaliseDomain resolves an alias and reports whether the name is known.
func NormaliseDomain(s string) (string, bool) {
	if d, ok := domainAliases[s]; ok {
		return d, true
	}
	switch s {
	case DomainAll, DomainLoopbacks, DomainRouterInterfaces, DomainHostAddressing,
		DomainL2, DomainOSPF, DomainBGP, DomainMPLS,
		DomainBGPPolicy, DomainIPv6, DomainRPKI:
		return s, true
	}
	return "", false
}

// Provides reports whether Twinet configures a domain for this AS, leaving the
// student nothing to do in it.
func (a *AS) Provides(domain string) bool {
	if a == nil {
		return true
	}
	if a.Role != RoleStudent {
		return true
	}
	return a.Provisioned[domain]
}
