package runtime

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var memRe = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]*)$`)

// ParseMemory converts a memory quantity into bytes.
//
// Manifests are written in Kubernetes style (512Mi, 2Gi) because that is what
// people expect from a declarative YAML resource field, but Docker's CLI wants
// its own suffixes and rejects "Mi" outright. Normalising here rather than
// making authors learn Docker's spelling keeps the manifest portable across
// backends, and the conversion is checked at validation time so an author never
// discovers the problem halfway through a deployment.
//
// Both binary (Ki, Mi, Gi) and decimal (K, M, G, and Docker's b/k/m/g) forms
// are accepted.
func ParseMemory(s string) (int64, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, nil
	}
	m := memRe.FindStringSubmatch(t)
	if m == nil {
		return 0, fmt.Errorf("%q is not a memory quantity (examples: 512Mi, 2Gi, 1024m)", s)
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("%q has a malformed number: %w", s, err)
	}
	var mult float64
	switch strings.ToLower(m[2]) {
	case "", "b":
		mult = 1
	case "k", "kb", "ki", "kib":
		mult = 1 << 10
	case "m", "mb", "mi", "mib":
		mult = 1 << 20
	case "g", "gb", "gi", "gib":
		mult = 1 << 30
	case "t", "tb", "ti", "tib":
		mult = 1 << 40
	default:
		return 0, fmt.Errorf("%q has an unknown unit %q (use Ki, Mi, Gi or k, m, g)", s, m[2])
	}
	bytes := int64(v * mult)
	if bytes < 6<<20 {
		// Docker refuses anything under 6MiB, and a container that small could
		// not run a routing daemon anyway.
		return 0, fmt.Errorf("%q is below the 6MiB minimum a container needs", s)
	}
	return bytes, nil
}

// FormatMemory renders a byte count in the form the container engine accepts.
func FormatMemory(bytes int64) string {
	if bytes <= 0 {
		return ""
	}
	return strconv.FormatInt(bytes, 10)
}
