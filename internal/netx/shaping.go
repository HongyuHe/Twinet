package netx

import (
	"errors"
	"fmt"
	"math"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
)

// Shaping is the traffic-shaping configuration applied to one interface.
//
// Per-link bandwidth and delay are pedagogically load-bearing in these courses:
// assignment question 2.5 asks students to discover which provider and customer
// links are slow and to engineer traffic around them. So this is a first-class
// part of the model, not a nicety.
type Shaping struct {
	// Bandwidth is a tc rate such as "1mbit". Empty means unshaped.
	Bandwidth string
	// Delay is a one-way netem delay such as "2.5ms".
	Delay string
	// Queue is the tbf latency, the maximum time a packet may sit queued.
	Queue string
	// Loss is a netem loss percentage such as "0.1%".
	Loss string
}

// Empty reports whether there is nothing to apply.
func (s Shaping) Empty() bool {
	return s.Bandwidth == "" && s.Delay == "" && s.Queue == "" && s.Loss == ""
}

// ApplyShaping installs a netem qdisc for delay and loss with a token bucket
// filter beneath it for rate limiting. It must be called in the namespace that
// owns the link.
//
// Existing qdiscs are removed first, so re-applying with changed values
// converges rather than stacking. That is what lets a link's delay be edited in
// the manifest and pushed with a redeploy that touches nothing else.
func ApplyShaping(link netlink.Link, s Shaping) error {
	if err := clearRootQdisc(link); err != nil {
		return err
	}
	if s.Empty() {
		return nil
	}

	name := link.Attrs().Name
	idx := link.Attrs().Index
	mtu := link.Attrs().MTU
	if mtu <= 0 {
		mtu = 1500
	}

	// netem at the root handles delay and loss.
	attrs := netlink.NetemQdiscAttrs{}
	if s.Delay != "" {
		us, err := ParseTime(s.Delay)
		if err != nil {
			return fmt.Errorf("interface %s: delay: %w", name, err)
		}
		attrs.Latency = uint32(us)
	}
	if s.Loss != "" {
		pct, err := ParsePercent(s.Loss)
		if err != nil {
			return fmt.Errorf("interface %s: loss: %w", name, err)
		}
		attrs.Loss = float32(pct)
	}

	// netem's default queue is 1000 packets. On a delayed, rate-limited link
	// that is easily smaller than the bandwidth-delay product, so packets are
	// dropped for reasons the student cannot see or explain. Size the queue
	// from the actual BDP instead, with a generous floor.
	attrs.Limit = netemLimit(s, mtu)

	if err := netlink.QdiscAdd(netlink.NewNetem(
		netlink.QdiscAttrs{
			LinkIndex: idx,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		}, attrs)); err != nil {
		return fmt.Errorf("interface %s: add netem: %w", name, err)
	}

	if s.Bandwidth == "" {
		return nil
	}

	rate, err := ParseRate(s.Bandwidth)
	if err != nil {
		return fmt.Errorf("interface %s: bandwidth: %w", name, err)
	}
	latencyUS := uint32(50_000) // 50ms default, matching the legacy platform
	if s.Queue != "" {
		v, err := ParseTime(s.Queue)
		if err != nil {
			return fmt.Errorf("interface %s: queue: %w", name, err)
		}
		latencyUS = uint32(v)
	}
	burst := BurstSize(rate, mtu)

	tbf := &netlink.Tbf{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: idx,
			Handle:    netlink.MakeHandle(10, 0),
			Parent:    netlink.MakeHandle(1, 1),
		},
		Rate:   rate,
		Buffer: burstToBuffer(rate, burst),
		Limit:  tbfLimit(rate, latencyUS, burst),
	}
	if err := netlink.QdiscAdd(tbf); err != nil {
		return fmt.Errorf("interface %s: add tbf: %w", name, err)
	}
	return nil
}

// clearRootQdisc removes any existing root qdisc, ignoring the pfifo_fast the
// kernel installs by default (which cannot be deleted, only replaced).
func clearRootQdisc(link netlink.Link) error {
	qs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("list qdiscs on %s: %w", link.Attrs().Name, err)
	}
	for _, q := range qs {
		if q.Attrs().Parent != netlink.HANDLE_ROOT {
			continue
		}
		switch q.Type() {
		case "pfifo_fast", "noqueue", "mq":
			continue
		}
		if err := netlink.QdiscDel(q); err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("remove %s qdisc from %s: %w", q.Type(), link.Attrs().Name, err)
		}
	}
	return nil
}

// BurstSize computes the token bucket burst: ten percent of one second of
// traffic at the configured rate, floored at ten MTUs.
//
// This reproduces the legacy platform's compute_burstsize rule (about sixty
// lines of bash doing unit conversion by string matching) so emulated link
// behaviour is unchanged for students, but as a tested function.
func BurstSize(rateBytesPerSec uint64, mtu int) uint64 {
	minBurst := uint64(10 * mtu)
	burst := rateBytesPerSec / 10
	if burst < minBurst {
		return minBurst
	}
	return burst
}

// burstToBuffer converts a burst in bytes into the tbf buffer parameter, which
// the kernel expects in "bytes worth of tokens" scaled by the timer resolution.
// netlink's Tbf takes the buffer in bytes directly.
func burstToBuffer(_ uint64, burst uint64) uint32 {
	if burst > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(burst)
}

// tbfLimit converts a maximum queueing latency into a byte limit.
func tbfLimit(rateBytesPerSec uint64, latencyUS uint32, burst uint64) uint32 {
	l := rateBytesPerSec*uint64(latencyUS)/1_000_000 + burst
	if l > math.MaxUint32 {
		return math.MaxUint32
	}
	if l == 0 {
		return uint32(burst)
	}
	return uint32(l)
}

var rateRe = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]+)$`)

// ParseRate converts a tc rate string into bytes per second.
//
// tc accepts both bit-per-second suffixes (bit, kbit, mbit, gbit) and
// byte-per-second suffixes (bps, kbps, mbps), with both decimal (k = 1000) and
// binary (ki = 1024) prefixes. Getting this wrong by a factor of eight is a
// classic source of "why is my 1mbit link actually 8mbit" confusion.
func ParseRate(s string) (uint64, error) {
	m := rateRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("%q is not a rate (examples: 1mbit, 10mbit, 100kbit)", s)
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("%q has a malformed number: %w", s, err)
	}
	unit := strings.ToLower(m[2])

	// Split the multiplier prefix from the base unit. Binary prefixes are two
	// characters (ki, mi, gi, ti) and must be tested before the decimal ones,
	// since "kibit" also starts with "k".
	var mult float64 = 1
	switch {
	case strings.HasPrefix(unit, "ti"):
		mult, unit = 1<<40, unit[2:]
	case strings.HasPrefix(unit, "gi"):
		mult, unit = 1<<30, unit[2:]
	case strings.HasPrefix(unit, "mi"):
		mult, unit = 1<<20, unit[2:]
	case strings.HasPrefix(unit, "ki"):
		mult, unit = 1<<10, unit[2:]
	case strings.HasPrefix(unit, "t"):
		mult, unit = 1e12, unit[1:]
	case strings.HasPrefix(unit, "g"):
		mult, unit = 1e9, unit[1:]
	case strings.HasPrefix(unit, "m"):
		mult, unit = 1e6, unit[1:]
	case strings.HasPrefix(unit, "k"):
		mult, unit = 1e3, unit[1:]
	}

	switch unit {
	case "bit": // bits per second
		return uint64(v * mult / 8), nil
	case "bps": // bytes per second
		return uint64(v * mult), nil
	default:
		return 0, fmt.Errorf("%q has an unknown unit %q (use bit/kbit/mbit/gbit or bps/kbps/mbps)", s, m[2])
	}
}

var timeRe = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*(s|sec|ms|msec|us|usec)$`)

// ParseTime converts a tc time string into microseconds.
func ParseTime(s string) (uint64, error) {
	m := timeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("%q is not a time (examples: 2.5ms, 25ms, 1s)", s)
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("%q has a malformed number: %w", s, err)
	}
	switch m[2] {
	case "s", "sec":
		return uint64(v * 1e6), nil
	case "ms", "msec":
		return uint64(v * 1e3), nil
	default:
		return uint64(v), nil
	}
}

// ParsePercent parses a loss percentage such as "0.1%".
func ParsePercent(s string) (float64, error) {
	t := strings.TrimSuffix(strings.TrimSpace(s), "%")
	v, err := strconv.ParseFloat(t, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a percentage (example: 0.1%%)", s)
	}
	if v < 0 || v > 100 {
		return 0, fmt.Errorf("%q is outside 0-100%%", s)
	}
	return v, nil
}

// disableTXOffload turns off checksum offload on a veth. netlink has no
// ethtool binding, so this is the one place we fall back to a helper binary,
// and failure is not fatal.
func disableTXOffload(iface string) {
	if _, err := exec.LookPath("ethtool"); err != nil {
		return
	}
	_ = exec.Command("ethtool", "-K", iface, "tx", "off").Run()
}

var errExists = syscall.EEXIST

func isExist(err error) bool {
	return errors.Is(err, syscall.EEXIST) || strings.Contains(err.Error(), "file exists")
}

// netemLimit sizes the netem queue from the bandwidth-delay product so a
// delayed, rate-limited link does not silently drop packets that a student
// would have no way to account for.
func netemLimit(s Shaping, mtu int) uint32 {
	const floor = 1000 // the kernel default, never go below it
	if s.Bandwidth == "" || s.Delay == "" {
		return floor
	}
	rate, err := ParseRate(s.Bandwidth)
	if err != nil {
		return floor
	}
	us, err := ParseTime(s.Delay)
	if err != nil {
		return floor
	}
	// Two BDPs' worth of packets, so a full window plus retransmissions fits.
	bdpBytes := rate * us / 1_000_000
	pkts := 2 * bdpBytes / uint64(mtu)
	if pkts < floor {
		return floor
	}
	if pkts > 100_000 {
		return 100_000
	}
	return uint32(pkts)
}
