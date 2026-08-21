package netx

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// MPLSLabelSnapshot is the observable state of a network namespace's kernel
// platform-label allocator. Allocated is read from the actual MPLS route table,
// not inferred from FRR configuration.
type MPLSLabelSnapshot struct {
	Limit     int
	Allocated int
	Labels    []int
	Exhausted bool
	Detail    string
}

// SnapshotMPLSLabelsInNS reads the namespace-owned platform label limit and
// its real MPLS forwarding entries.
func SnapshotMPLSLabelsInNS(nsPath string) (out MPLSLabelSnapshot, err error) {
	err = inNS(nsPath, func() error {
		limit, err := mplsLabelLimit()
		if err != nil {
			return err
		}
		labels, err := mplsRouteLabels()
		if err != nil {
			return err
		}
		out = MPLSLabelSnapshot{Limit: limit, Allocated: len(labels), Labels: labels, Exhausted: limit == 0,
			Detail: map[bool]string{true: "platform_labels is zero; the namespace cannot allocate MPLS labels"}[limit == 0]}
		return nil
	})
	return out, err
}

// ExhaustMPLSLabelsInNS sets a bounded platform label table and reserves every
// free label in it with actual kernel MPLS routes. It then attempts one more
// route and succeeds only when the kernel returns ENOSPC. A changed FRR global
// block is deliberately not accepted as evidence here.
func ExhaustMPLSLabelsInNS(nsPath string, limit int) (out MPLSLabelSnapshot, labels []int, err error) {
	err = inNS(nsPath, func() error {
		committed := false
		originalLimit := 0
		originalKnown := false
		defer func() {
			// An allocation probe can fail after every reservation was made.
			// Do not hand a partially exhausted namespace back to the fault
			// engine with no State ownership record to restore it from.
			if committed {
				return
			}
			for _, label := range labels {
				_ = delMPLSReservation(label)
			}
			if originalKnown {
				_ = setMPLSLabelLimit(originalLimit)
			}
		}()
		originalLimit, err = mplsLabelLimit()
		if err != nil {
			return err
		}
		originalKnown = true
		before, err := mplsRouteLabels()
		if err != nil {
			return err
		}
		if limit < len(before)+2 {
			return fmt.Errorf("label limit %d leaves no controllable space above %d existing routes", limit, len(before))
		}
		if err := setMPLSLabelLimit(limit); err != nil {
			return err
		}
		used := map[int]bool{}
		for _, label := range before {
			used[label] = true
		}
		// Label 0-15 are reserved by the Linux MPLS ABI. Starting at 16 also
		// avoids fighting labels a distribution's LDP daemon commonly picks.
		for label := 16; label < limit; label++ {
			if used[label] {
				continue
			}
			if err := addMPLSReservation(label); err != nil {
				return fmt.Errorf("reserve MPLS label %d: %w", label, err)
			}
			labels = append(labels, label)
		}
		// The first label outside platform_labels must be rejected by the
		// kernel. An accepted route means this namespace did not exhaust the
		// substrate and the caller must roll everything back.
		probeErr := addMPLSReservation(limit)
		if probeErr == nil {
			_ = delMPLSReservation(limit)
			return fmt.Errorf("kernel accepted label %d beyond platform label limit %d", limit, limit)
		}
		if !isNoSpace(probeErr) {
			return fmt.Errorf("label allocation probe failed for a reason other than exhaustion: %w", probeErr)
		}
		now, err := mplsRouteLabels()
		if err != nil {
			return err
		}
		out = MPLSLabelSnapshot{Limit: limit, Allocated: len(now), Labels: now, Exhausted: true,
			Detail: "kernel rejected one additional MPLS route with ENOSPC"}
		committed = true
		return nil
	})
	return out, labels, err
}

// ProbeMPLSLabelExhaustionInNS makes a disposable allocation request one past
// the current platform range. It never reports exhaustion from a config value
// alone; only the kernel's allocation result counts.
func ProbeMPLSLabelExhaustionInNS(nsPath string) (out MPLSLabelSnapshot, err error) {
	err = inNS(nsPath, func() error {
		limit, err := mplsLabelLimit()
		if err != nil {
			return err
		}
		labels, err := mplsRouteLabels()
		if err != nil {
			return err
		}
		used := map[int]bool{}
		for _, label := range labels {
			used[label] = true
		}
		for label := 16; label < limit; label++ {
			if used[label] {
				continue
			}
			// A genuinely free in-range label is the only meaningful probe.
			// If this succeeds, the allocator is demonstrably not exhausted;
			// remove the probe immediately so observing does not mutate state.
			if err := addMPLSReservation(label); err != nil {
				if isNoSpace(err) {
					out = MPLSLabelSnapshot{Limit: limit, Allocated: len(labels), Labels: labels, Exhausted: true,
						Detail: "kernel returned ENOSPC for a free in-range MPLS label"}
					return nil
				}
				return fmt.Errorf("probe MPLS label allocation: %w", err)
			}
			if err := delMPLSReservation(label); err != nil {
				return fmt.Errorf("remove MPLS label probe %d: %w", label, err)
			}
			out = MPLSLabelSnapshot{Limit: limit, Allocated: len(labels), Labels: labels, Exhausted: false,
				Detail: "kernel accepted a free in-range MPLS label"}
			return nil
		}
		// All usable labels are occupied. Confirm the platform boundary is
		// enforced too, rather than inferring exhaustion from a count alone.
		probeErr := addMPLSReservation(limit)
		if probeErr == nil {
			_ = delMPLSReservation(limit)
			return fmt.Errorf("kernel accepted label %d outside platform range %d", limit, limit)
		}
		if !isNoSpace(probeErr) {
			return fmt.Errorf("probe MPLS platform boundary: %w", probeErr)
		}
		out = MPLSLabelSnapshot{Limit: limit, Allocated: len(labels), Labels: labels, Exhausted: true,
			Detail: "all in-range labels are occupied and the next kernel allocation returned ENOSPC"}
		return nil
	})
	return out, err
}

// RestoreMPLSLabelsInNS removes only labels allocated by one incident, then
// restores the exact previous platform-label limit. Existing LDP/kernel routes
// are never deleted because they were not in the fault's ownership record.
func RestoreMPLSLabelsInNS(nsPath string, limit int, labels []int) error {
	return inNS(nsPath, func() error {
		for _, label := range labels {
			if err := delMPLSReservation(label); err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such") {
				return fmt.Errorf("release MPLS label %d: %w", label, err)
			}
		}
		return setMPLSLabelLimit(limit)
	})
}

func mplsLabelLimit() (int, error) {
	raw, err := os.ReadFile("/proc/sys/net/mpls/platform_labels")
	if err != nil {
		return 0, fmt.Errorf("read net.mpls.platform_labels: %w", err)
	}
	limit, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0, fmt.Errorf("parse net.mpls.platform_labels %q: %w", strings.TrimSpace(string(raw)), err)
	}
	return limit, nil
}

func setMPLSLabelLimit(limit int) error {
	if limit < 0 {
		return fmt.Errorf("MPLS platform label limit must not be negative, got %d", limit)
	}
	if err := os.WriteFile("/proc/sys/net/mpls/platform_labels", []byte(strconv.Itoa(limit)), 0o644); err != nil {
		return fmt.Errorf("write net.mpls.platform_labels=%d: %w", limit, err)
	}
	return nil
}

func mplsRouteLabels() ([]int, error) {
	out, err := exec.Command("ip", "-f", "mpls", "route", "show").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list MPLS routes: %w: %s", err, strings.TrimSpace(string(out)))
	}
	seen := map[int]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		field := strings.Fields(line)
		if len(field) == 0 {
			continue
		}
		label, err := strconv.Atoi(strings.TrimSuffix(field[0], ":"))
		if err == nil {
			seen[label] = true
		}
	}
	labels := make([]int, 0, len(seen))
	for label := range seen {
		labels = append(labels, label)
	}
	sort.Ints(labels)
	return labels, nil
}

func addMPLSReservation(label int) error {
	out, err := exec.Command("ip", "-f", "mpls", "route", "replace", strconv.Itoa(label), "dev", "lo").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func delMPLSReservation(label int) error {
	out, err := exec.Command("ip", "-f", "mpls", "route", "del", strconv.Itoa(label)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func isNoSpace(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no space") || strings.Contains(s, "enospc") ||
		strings.Contains(s, "no buffer space") || strings.Contains(s, "configured maximum")
}
