package nos

import "strings"

// shellQuote wraps a value so a shell reads it as one literal word.
//
// Configuration bodies and device identifiers reach a container through
// `sh -c`. Anything a student can influence must arrive as data; a single
// quote inside is closed, escaped and reopened rather than left to end the
// literal and turn the rest of the file into commands running as root.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// firstLine is the first non-empty line of an output, for an error message
// that has to fit on one.
func firstLine(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return strings.TrimSpace(body)
}
