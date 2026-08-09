package ipam

import (
	"fmt"
	"math/big"
	"net/netip"
	"strings"
	"text/template"
)

// FuncMap returns the helper functions available inside addressing
// expressions. The set is deliberately small and total: every helper either
// returns a well-formed value or an error that names the plan field.
func FuncMap() template.FuncMap {
	return template.FuncMap{
		// arithmetic
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"mul": func(a, b int) int { return a * b },
		"div": func(a, b int) (int, error) {
			if b == 0 {
				return 0, fmt.Errorf("division by zero")
			}
			return a / b, nil
		},
		"mod": func(a, b int) (int, error) {
			if b == 0 {
				return 0, fmt.Errorf("modulo by zero")
			}
			return a % b, nil
		},
		"min": func(a, b int) int {
			if a < b {
				return a
			}
			return b
		},
		"max": func(a, b int) int {
			if a > b {
				return a
			}
			return b
		},

		// string helpers
		"lower":  strings.ToLower,
		"upper":  strings.ToUpper,
		"printf": fmt.Sprintf,

		// CIDR helpers
		"cidrSubnet":  cidrSubnet,
		"cidrHost":    cidrHost,
		"cidrAddr":    cidrAddr,
		"cidrNetwork": cidrNetwork,
		"cidrBits":    cidrBits,
		"hex":         func(n int) string { return fmt.Sprintf("%x", n) },
	}
}

// cidrSubnet carves the n-th subnet of the given new prefix length out of base.
//
//	{{ cidrSubnet "179.0.0.0/8" 42 24 }} -> "179.0.42.0/24"
func cidrSubnet(base string, index, newBits int) (string, error) {
	p, err := netip.ParsePrefix(base)
	if err != nil {
		return "", fmt.Errorf("cidrSubnet: %q is not a prefix: %w", base, err)
	}
	p = p.Masked()
	if newBits < p.Bits() || newBits > p.Addr().BitLen() {
		return "", fmt.Errorf("cidrSubnet: new prefix length %d out of range for %s", newBits, base)
	}
	shift := uint(p.Addr().BitLen() - newBits)
	maxIdx := new(big.Int).Lsh(big.NewInt(1), uint(newBits-p.Bits()))
	if big.NewInt(int64(index)).Cmp(maxIdx) >= 0 {
		return "", fmt.Errorf("cidrSubnet: index %d exceeds the %s subnets available in %s at /%d",
			index, maxIdx.String(), base, newBits)
	}
	n := addrToBig(p.Addr())
	off := new(big.Int).Lsh(big.NewInt(int64(index)), shift)
	n.Add(n, off)
	a := bigToAddr(n, p.Addr().Is4())
	return netip.PrefixFrom(a, newBits).String(), nil
}

// cidrHost returns the n-th host address inside base, keeping base's length.
//
//	{{ cidrHost "10.0.1.0/24" 1 }} -> "10.0.1.1/24"
func cidrHost(base string, index int) (string, error) {
	p, err := netip.ParsePrefix(base)
	if err != nil {
		return "", fmt.Errorf("cidrHost: %q is not a prefix: %w", base, err)
	}
	p = p.Masked()
	host := p.Addr().BitLen() - p.Bits()
	size := new(big.Int).Lsh(big.NewInt(1), uint(host))
	if big.NewInt(int64(index)).Cmp(size) >= 0 {
		return "", fmt.Errorf("cidrHost: index %d does not fit in %s", index, base)
	}
	n := addrToBig(p.Addr())
	n.Add(n, big.NewInt(int64(index)))
	a := bigToAddr(n, p.Addr().Is4())
	return netip.PrefixFrom(a, p.Bits()).String(), nil
}

// cidrAddr returns just the address part of an addr/len string.
func cidrAddr(s string) (string, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return "", fmt.Errorf("cidrAddr: %q is not addr/len: %w", s, err)
	}
	return p.Addr().String(), nil
}

// cidrNetwork masks an addr/len string down to its network prefix.
func cidrNetwork(s string) (string, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return "", fmt.Errorf("cidrNetwork: %q is not addr/len: %w", s, err)
	}
	return p.Masked().String(), nil
}

// cidrBits returns the prefix length of an addr/len string.
func cidrBits(s string) (int, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return 0, fmt.Errorf("cidrBits: %q is not addr/len: %w", s, err)
	}
	return p.Bits(), nil
}

// Host is the package-level helper used by expansion to compute the n-th host
// address inside a subnet, e.g. Host("12.0.1.0/24", 1) == "12.0.1.1/24".
func Host(subnet string, n int) (string, error) { return cidrHost(subnet, n) }
