package runtime

import "strings"

// dockerSecurityOptions translates Twinet's typed "default" seccomp profile
// into Docker's API representation. Docker applies its default seccomp profile
// only when no seccomp security-opt is sent; Docker 29 treats the literal
// `seccomp=default` as JSON and rejects it. Other profiles, including
// unconfined and explicit JSON/profile data, remain explicit.
func dockerSecurityOptions(options []string) []string {
	if len(options) == 0 {
		return nil
	}
	out := make([]string, 0, len(options))
	for _, option := range options {
		if strings.EqualFold(strings.TrimSpace(option), "seccomp=default") {
			continue
		}
		out = append(out, option)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
