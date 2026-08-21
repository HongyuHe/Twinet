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
	h, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("open netlink handle: %w", err)
	}
	defer h.Close()
	return applyShaping(h, link, s)
}

// applyShaping is ApplyShaping for a namespace-scoped netlink handle.
func applyShaping(h *netlink.Handle, link netlink.Link, s Shaping) error {
	matches, err := shapingMatches(h, link, s)
	if err != nil {
		return err
	}
	if matches {
		return nil
	}
	if err := clearRootQdisc(h, link); err != nil {
		return err
	}
	if s.Empty() {
		return nil
	}

	netem, tbf, err := desiredShaping(link, s)
	if err != nil {
		return err
	}
	// Replace, not add. clearRootQdisc deliberately leaves a pfifo_fast in
	// place, so adding at the root fails with EEXIST whenever one is there --
	// and one is there as soon as anybody runs the ordinary way of taking
	// netem off an interface, `tc qdisc replace ... root pfifo_fast`. That is
	// exactly what a student or an agent does when undoing a link fault by
	// hand, and after it the platform could never put the link's own delay and
	// rate back: every later episode on that link ran with different physics
	// than the manifest describes, silently. Replace installs at the root
	// whatever is already sitting there.
	if err := h.QdiscReplace(netem); err != nil {
		return fmt.Errorf("interface %s: add netem: %w", link.Attrs().Name, err)
	}
	if tbf == nil {
		return nil
	}
	if err := h.QdiscReplace(tbf); err != nil {
		return fmt.Errorf("interface %s: add tbf: %w", link.Attrs().Name, err)
	}
	return nil
}

// desiredShaping constructs the exact qdiscs the declared shaping requires.
// It is shared by application and observation so a no-change deployment does
// not churn qdiscs merely because the two paths did arithmetic differently.
func desiredShaping(link netlink.Link, s Shaping) (*netlink.Netem, *netlink.Tbf, error) {
	name := link.Attrs().Name
	idx := link.Attrs().Index
	mtu := link.Attrs().MTU
	if mtu <= 0 {
		mtu = 1500
	}

	attrs := netlink.NetemQdiscAttrs{}
	if s.Delay != "" {
		us, err := ParseTime(s.Delay)
		if err != nil {
			return nil, nil, fmt.Errorf("interface %s: delay: %w", name, err)
		}
		attrs.Latency = uint32(us)
	}
	if s.Loss != "" {
		pct, err := ParsePercent(s.Loss)
		if err != nil {
			return nil, nil, fmt.Errorf("interface %s: loss: %w", name, err)
		}
		attrs.Loss = float32(pct)
	}

	// netem's default queue is 1000 packets. On a delayed, rate-limited link
	// that is easily smaller than the bandwidth-delay product, so packets are
	// dropped for reasons the student cannot see or explain. Size the queue
	// from the actual BDP instead, with a generous floor.
	attrs.Limit = netemLimit(s, mtu)
	netem := netlink.NewNetem(netlink.QdiscAttrs{
		LinkIndex: idx,
		Handle:    netlink.MakeHandle(1, 0),
		Parent:    netlink.HANDLE_ROOT,
	}, attrs)

	if s.Bandwidth == "" {
		return netem, nil, nil
	}
	rate, err := ParseRate(s.Bandwidth)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %s: bandwidth: %w", name, err)
	}
	latencyUS := uint32(50_000) // 50ms default, matching the legacy platform
	if s.Queue != "" {
		v, err := ParseTime(s.Queue)
		if err != nil {
			return nil, nil, fmt.Errorf("interface %s: queue: %w", name, err)
		}
		latencyUS = uint32(v)
	}
	burst := BurstSize(rate, mtu)
	return netem, &netlink.Tbf{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: idx,
			Handle:    netlink.MakeHandle(10, 0),
			Parent:    netlink.MakeHandle(1, 1),
		},
		Rate: rate,
		// Buffer is expressed in scheduler ticks, not bytes. Passing bytes
		// silently programs a burst orders of magnitude off: a 125,000 byte
		// burst arrived as 10,000 and a 50ms queue as 142ms, which changes the
		// behaviour students measure. tc's own conversion is xmittime.
		Buffer: netlink.Xmittime(rate, uint32(burst)),
		Limit:  tbfLimit(rate, latencyUS, burst),
	}, nil
}

// shapingMatches observes the qdiscs rather than blindly replacing them.
// This makes a no-change deployment a read-only operation while still
// repairing qdiscs that were changed by a fault or by hand.
func shapingMatches(h *netlink.Handle, link netlink.Link, s Shaping) (bool, error) {
	qs, err := h.QdiscList(link)
	if err != nil {
		return false, fmt.Errorf("list qdiscs on %s: %w", link.Attrs().Name, err)
	}
	return qdiscStateMatches(qs, link, s)
}

func qdiscStateMatches(qs []netlink.Qdisc, link netlink.Link, s Shaping) (bool, error) {
	if s.Empty() {
		for _, q := range qs {
			if q.Attrs().Parent == netlink.HANDLE_ROOT && !defaultRootQdisc(q) {
				return false, nil
			}
		}
		return true, nil
	}
	wantNetem, wantTBF, err := desiredShaping(link, s)
	if err != nil {
		return false, err
	}
	var gotNetem *netlink.Netem
	var gotTBF *netlink.Tbf
	for _, q := range qs {
		switch {
		case q.Attrs().Parent == netlink.HANDLE_ROOT:
			n, ok := q.(*netlink.Netem)
			if !ok || gotNetem != nil {
				return false, nil
			}
			gotNetem = n
		case q.Attrs().Parent == netlink.MakeHandle(1, 1):
			t, ok := q.(*netlink.Tbf)
			if !ok || gotTBF != nil {
				return false, nil
			}
			gotTBF = t
		default:
			if q.Attrs().Parent == netlink.HANDLE_INGRESS {
				// Ingress filters are orthogonal to the root egress qdisc.
				continue
			}
			// An unexpected child means the observed shaping is not the
			// declaration. Replacing the root qdisc will remove it.
			return false, nil
		}
	}
	if !sameNetem(gotNetem, wantNetem) {
		return false, nil
	}
	if wantTBF == nil {
		return gotTBF == nil, nil
	}
	return sameTBF(gotTBF, wantTBF), nil
}

func defaultRootQdisc(q netlink.Qdisc) bool {
	switch q.Type() {
	case "pfifo_fast", "noqueue", "mq", "fq_codel", "fq":
		return true
	default:
		return false
	}
}

func sameNetem(got, want *netlink.Netem) bool {
	if got == nil || want == nil {
		return got == want
	}
	return got.Attrs().Handle == want.Attrs().Handle &&
		got.Attrs().Parent == want.Attrs().Parent &&
		got.Latency == want.Latency &&
		got.Limit == want.Limit &&
		got.Loss == want.Loss &&
		got.DelayCorr == want.DelayCorr &&
		got.LossCorr == want.LossCorr &&
		got.Gap == want.Gap &&
		got.Duplicate == want.Duplicate &&
		got.DuplicateCorr == want.DuplicateCorr &&
		got.Jitter == want.Jitter &&
		got.ReorderProb == want.ReorderProb &&
		got.ReorderCorr == want.ReorderCorr &&
		got.CorruptProb == want.CorruptProb &&
		got.CorruptCorr == want.CorruptCorr &&
		got.Rate64 == want.Rate64
}

func sameTBF(got, want *netlink.Tbf) bool {
	if got == nil || want == nil {
		return got == want
	}
	return got.Attrs().Handle == want.Attrs().Handle &&
		got.Attrs().Parent == want.Attrs().Parent &&
		got.Rate == want.Rate &&
		got.Limit == want.Limit &&
		got.Buffer == want.Buffer &&
		got.Peakrate == want.Peakrate &&
		got.Minburst == want.Minburst
}

// clearRootQdisc removes any existing root qdisc, ignoring the pfifo_fast the
// kernel installs by default (which cannot be deleted, only replaced).
func clearRootQdisc(h *netlink.Handle, link netlink.Link) error {
	qs, err := h.QdiscList(link)
	if err != nil {
		return fmt.Errorf("list qdiscs on %s: %w", link.Attrs().Name, err)
	}
	for _, q := range qs {
		if q.Attrs().Parent != netlink.HANDLE_ROOT {
			continue
		}
		if defaultRootQdisc(q) {
			continue
		}
		if err := h.QdiscDel(q); err != nil && !errors.Is(err, syscall.ENOENT) {
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

// tbfLimit converts a maximum queueing latency into a byte limit, using the
// same formula tc does: limit = rate * latency + burst.
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

// ReshapeInNS puts one interface inside a namespace back to a declared shaping.
//
// It exists so that undoing a traffic-control fault leaves byte-identical state
// to a deployment. Reproducing the arithmetic on tc's command line does not: a
// burst asked for in bits is converted differently from one computed in
// scheduler ticks, so a "restored" link ends up with a different queue from the
// one the topology describes. Nothing reports that, and every later measurement
// on the link is quietly wrong. Sharing this one function with the deployer is
// the only way the two can be guaranteed to agree.
func ReshapeInNS(nsPath, iface string, s Shaping, mtu int) error {
	ns, err := OpenNS(nsPath)
	if err != nil {
		return err
	}
	defer func() { _ = ns.Close() }()

	h, err := ns.Handle()
	if err != nil {
		return err
	}
	defer h.Close()
	link, err := h.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}
	return applyShaping(h, link, s)
}
