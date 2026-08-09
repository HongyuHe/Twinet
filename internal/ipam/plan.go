// Package ipam evaluates a lab's declarative addressing plan.
//
// It replaces the legacy platform's config/subnet_config.sh, a 191-line bash
// file of functions built from undocumented magic offsets (+101, +151, +200,
// 158.X., 157.0.0., 198.X.) that every other script had to `source`, and whose
// values were independently restated in the assignment wiki, the DNS generator,
// the website and the autograder.
//
// Here the plan is data: a set of Go-template expressions evaluated against a
// typed context, with CIDR helpers, and with every result checked for validity
// and overlap.
package ipam

import (
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strings"
	"text/template"
)

// Ctx is the binding environment for an addressing expression. Not every field
// is meaningful for every expression; unused ones are simply zero.
type Ctx struct {
	AS        int    // the autonomous system number
	PeerAS    int    // the AS at the other end, for inter-AS links
	RouterID  int    // stable per-AS router index
	PeerID    int    // router index at the other end
	LinkIndex int    // stable index of the link within its scope
	L2ID      int    // layer-2 domain index
	VLAN      int    // VLAN id
	VLANIndex int    // 0-based position of the VLAN within its domain
	IXP       int    // IXP AS number
	Host      int    // host index within a subnet
	Name      string // free-form: service name, device name
	Region    string
}

// Plan is a compiled addressing plan. Compilation happens once per lab; the
// templates are then executed many thousands of times, so we parse up front.
type Plan struct {
	tmpl map[string]*template.Template
	src  map[string]string
}

// Field names in the plan. Using constants keeps the compiler honest about
// which expressions exist.
const (
	FieldASBlock          = "as_block"
	FieldASBlockV6        = "as_block_v6"
	FieldRouterLoopback   = "router_loopback"
	FieldRouterLoopbackV6 = "router_loopback_v6"
	FieldRouterRouter     = "router_router"
	FieldRouterHost       = "router_host"
	FieldL2Domain         = "l2_domain"
	FieldL2DomainV6       = "l2_domain_v6"
	FieldL2VLAN           = "l2_vlan"
	FieldL2VLANV6         = "l2_vlan_v6"
	FieldInterAS          = "inter_as"
	FieldIXPPeering       = "ixp_peering"
)

// Compile parses every non-empty expression in the plan.
func Compile(exprs map[string]string) (*Plan, error) {
	p := &Plan{tmpl: map[string]*template.Template{}, src: map[string]string{}}
	names := make([]string, 0, len(exprs))
	for k := range exprs {
		names = append(names, k)
	}
	sort.Strings(names)
	var errs []string
	for _, name := range names {
		expr := exprs[name]
		if strings.TrimSpace(expr) == "" {
			continue
		}
		t, err := template.New(name).Funcs(FuncMap()).Option("missingkey=error").Parse(expr)
		if err != nil {
			errs = append(errs, fmt.Sprintf("addressing.%s: %v", name, err))
			continue
		}
		p.tmpl[name] = t
		p.src[name] = expr
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errs, "\n"))
	}
	return p, nil
}

// Has reports whether the plan defines the named expression.
func (p *Plan) Has(name string) bool { _, ok := p.tmpl[name]; return ok }

// Source returns the raw expression text, for diagnostics.
func (p *Plan) Source(name string) string { return p.src[name] }

// Eval evaluates a named expression, returning the rendered string.
func (p *Plan) Eval(name string, ctx Ctx) (string, error) {
	t, ok := p.tmpl[name]
	if !ok {
		return "", fmt.Errorf("addressing.%s is not defined", name)
	}
	var b strings.Builder
	if err := t.Execute(&b, ctx); err != nil {
		return "", fmt.Errorf("addressing.%s: %w", name, err)
	}
	return strings.TrimSpace(b.String()), nil
}

// Prefix evaluates an expression and parses the result as a CIDR prefix.
func (p *Plan) Prefix(name string, ctx Ctx) (netip.Prefix, error) {
	s, err := p.Eval(name, ctx)
	if err != nil {
		return netip.Prefix{}, err
	}
	pf, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("addressing.%s produced %q which is not a CIDR prefix: %w", name, s, err)
	}
	return pf.Masked(), nil
}

// Addr evaluates an expression and parses the result as an address with prefix
// length, e.g. "12.0.1.1/24". The address is *not* masked.
func (p *Plan) Addr(name string, ctx Ctx) (netip.Prefix, error) {
	s, err := p.Eval(name, ctx)
	if err != nil {
		return netip.Prefix{}, err
	}
	pf, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("addressing.%s produced %q which is not addr/len: %w", name, s, err)
	}
	return pf, nil
}

// ---------------------------------------------------------------------------
// Overlap detection
// ---------------------------------------------------------------------------

// Claim records that some object claims a prefix, so conflicts can be reported
// with both claimants named. The legacy platform had no such check: two
// overlapping subnets simply produced a network that misbehaved at runtime.
type Claim struct {
	Prefix netip.Prefix
	Owner  string // human-readable, e.g. "as12 link ATL--BOS"
	Field  string // which plan expression produced it
}

// Registry accumulates claims and reports overlaps.
type Registry struct {
	claims []Claim
	// exempt holds prefixes that are allowed to overlap, such as the per-AS
	// aggregate /8 that legitimately contains all of that AS's subnets.
	exempt []netip.Prefix
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Exempt marks a prefix as an aggregate: other claims may fall inside it.
func (r *Registry) Exempt(p netip.Prefix) { r.exempt = append(r.exempt, p.Masked()) }

// Claim records a claim.
func (r *Registry) Claim(p netip.Prefix, owner, field string) {
	r.claims = append(r.claims, Claim{Prefix: p.Masked(), Owner: owner, Field: field})
}

// Conflict describes two claims that overlap.
type Conflict struct {
	A, B Claim
}

func (c Conflict) String() string {
	return fmt.Sprintf("prefix %s (%s, from addressing.%s) overlaps %s (%s, from addressing.%s)",
		c.A.Prefix, c.A.Owner, c.A.Field, c.B.Prefix, c.B.Owner, c.B.Field)
}

// Conflicts returns every pair of overlapping claims, excluding pairs where one
// side is an exempt aggregate.
//
// The check is O(n log n): claims are sorted by address, and overlap can then
// only occur between neighbours in that order (for prefixes, containment and
// disjointness are the only possibilities, so a sorted scan is sufficient once
// we compare each claim against the running maximum extent).
func (r *Registry) Conflicts() []Conflict {
	claims := append([]Claim{}, r.claims...)
	sort.Slice(claims, func(i, j int) bool {
		a, b := claims[i].Prefix, claims[j].Prefix
		if a.Addr() != b.Addr() {
			return a.Addr().Less(b.Addr())
		}
		return a.Bits() < b.Bits()
	})
	var out []Conflict
	for i := 0; i < len(claims); i++ {
		for j := i + 1; j < len(claims); j++ {
			a, b := claims[i], claims[j]
			if a.Prefix.Addr().Is4() != b.Prefix.Addr().Is4() {
				continue
			}
			// Sorted by start address: once b starts beyond a's end, and beyond
			// every subsequent claim's start, no further j can overlap i.
			if !overlaps(a.Prefix, b.Prefix) {
				if b.Prefix.Addr().Less(lastAddr(a.Prefix)) || b.Prefix.Addr() == lastAddr(a.Prefix) {
					continue
				}
				break
			}
			if r.isExempt(a.Prefix) || r.isExempt(b.Prefix) {
				continue
			}
			out = append(out, Conflict{A: a, B: b})
		}
	}
	return out
}

func (r *Registry) isExempt(p netip.Prefix) bool {
	for _, e := range r.exempt {
		if e == p {
			return true
		}
	}
	return false
}

func overlaps(a, b netip.Prefix) bool {
	return a.Overlaps(b)
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	bits := a.BitLen()
	host := bits - p.Bits()
	if host == 0 {
		return a
	}
	n := addrToBig(a)
	size := new(big.Int).Lsh(big.NewInt(1), uint(host))
	n.Add(n, size)
	n.Sub(n, big.NewInt(1))
	return bigToAddr(n, a.Is4())
}

func addrToBig(a netip.Addr) *big.Int {
	b := a.As16()
	return new(big.Int).SetBytes(b[:])
}

func bigToAddr(n *big.Int, is4 bool) netip.Addr {
	var buf [16]byte
	nb := n.Bytes()
	if len(nb) > 16 {
		nb = nb[len(nb)-16:]
	}
	copy(buf[16-len(nb):], nb)
	a := netip.AddrFrom16(buf)
	if is4 {
		return a.Unmap()
	}
	return a
}
