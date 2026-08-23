package runtime

import (
	"fmt"
	"strings"
)

// NormalizePIDMode translates the OCI-private spelling into Docker's API
// contract. Docker creates a private PID namespace when PidMode is omitted;
// Docker 29 rejects the literal "private". Host and container sharing stay
// explicit, validated modes rather than being silently normalized away.
func NormalizePIDMode(mode string) (string, error) {
	mode = strings.TrimSpace(mode)
	switch mode {
	case "", "private":
		return "", nil
	case "host":
		return mode, nil
	}
	const prefix = "container:"
	if !strings.HasPrefix(mode, prefix) {
		return "", fmt.Errorf("invalid PID mode %q; use private, host, or container:<name>", mode)
	}
	name := strings.TrimPrefix(mode, prefix)
	if name == "" {
		return "", fmt.Errorf("PID mode %q has no container name", mode)
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return "", fmt.Errorf("PID mode %q has an unsafe container name", mode)
		}
	}
	return mode, nil
}
