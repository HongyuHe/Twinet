package cli

import (
	"fmt"
	"sort"
	"time"
)

type deployPhaseTimings map[string]time.Duration

func (d deployPhaseTimings) measure(name string, fn func() error) error {
	start := time.Now()
	err := fn()
	d[name] += time.Since(start)
	return err
}

func (d deployPhaseTimings) print(out interface{ Write([]byte) (int, error) }) {
	if len(d) == 0 {
		return
	}
	names := make([]string, 0, len(d))
	for name := range d {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprint(out, "controller preflight:")
	for _, name := range names {
		fmt.Fprintf(out, " %s=%s", name, d[name].Round(time.Millisecond))
	}
	fmt.Fprintln(out)
}
