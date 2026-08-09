package netx

import "testing"

// Rate parsing must not be off by a factor of eight. tc accepts both
// bit-per-second and byte-per-second suffixes, and confusing them is a classic
// way to produce a link that is secretly 8x faster than the course intends.
func TestParseRate(t *testing.T) {
	cases := map[string]uint64{
		"1mbit":   125_000,     // 1e6 bits/s = 125,000 bytes/s
		"10mbit":  1_250_000,
		"100kbit": 12_500,
		"1gbit":   125_000_000,
		"1bit":    0,           // sub-byte rounds down
		"8bit":    1,
		"1mbps":   1_000_000,   // bytes per second
		"1kbps":   1_000,
		"1kibit":  128,         // 1024 bits/s
		"2.5mbit": 312_500,
	}
	for in, want := range cases {
		got, err := ParseRate(in)
		if err != nil {
			t.Errorf("ParseRate(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseRate(%q) = %d bytes/s, want %d", in, got, want)
		}
	}
	for _, bad := range []string{"", "fast", "1", "1mb", "-1mbit", "1 giga"} {
		if _, err := ParseRate(bad); err == nil {
			t.Errorf("ParseRate(%q) should have failed", bad)
		}
	}
}

func TestParseTime(t *testing.T) {
	cases := map[string]uint64{
		"1ms":   1000,
		"2.5ms": 2500,
		"25ms":  25000,
		"1s":    1_000_000,
		"500us": 500,
	}
	for in, want := range cases {
		got, err := ParseTime(in)
		if err != nil {
			t.Errorf("ParseTime(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseTime(%q) = %d us, want %d", in, got, want)
		}
	}
	for _, bad := range []string{"", "1", "fast", "1minute"} {
		if _, err := ParseTime(bad); err == nil {
			t.Errorf("ParseTime(%q) should have failed", bad)
		}
	}
}

func TestParsePercent(t *testing.T) {
	if v, err := ParsePercent("0.1%"); err != nil || v != 0.1 {
		t.Errorf("ParsePercent(0.1%%) = %v, %v", v, err)
	}
	for _, bad := range []string{"-1%", "101%", "abc"} {
		if _, err := ParsePercent(bad); err == nil {
			t.Errorf("ParsePercent(%q) should have failed", bad)
		}
	}
}

// BurstSize must reproduce the legacy platform's rule so that emulated link
// behaviour is unchanged for students: ten percent of a second of traffic,
// floored at ten MTUs.
func TestBurstSize(t *testing.T) {
	// 1mbit = 125,000 bytes/s; 10% = 12,500 bytes, above the 15,000 floor? No:
	// floor is 10*1500 = 15,000, so the floor wins.
	if got := BurstSize(125_000, 1500); got != 15_000 {
		t.Errorf("BurstSize(1mbit) = %d, want the 15000 byte floor", got)
	}
	// 10mbit = 1,250,000 bytes/s; 10% = 125,000, well above the floor.
	if got := BurstSize(1_250_000, 1500); got != 125_000 {
		t.Errorf("BurstSize(10mbit) = %d, want 125000", got)
	}
	// A larger MTU raises the floor.
	if got := BurstSize(125_000, 9000); got != 90_000 {
		t.Errorf("BurstSize with 9000 MTU = %d, want 90000", got)
	}
}

// A delayed, rate-limited link must have a queue at least as deep as its
// bandwidth-delay product, or it drops packets for invisible reasons.
func TestNetemLimitCoversBDP(t *testing.T) {
	// 10mbit, 25ms: BDP = 1,250,000 * 0.025 = 31,250 bytes ~= 21 packets.
	// Below the floor, so the floor wins.
	if got := netemLimit(Shaping{Bandwidth: "10mbit", Delay: "25ms"}, 1500); got != 1000 {
		t.Errorf("small BDP should use the 1000 packet floor, got %d", got)
	}
	// 1gbit, 100ms: BDP = 12,500,000 bytes ~= 8333 packets; twice that is
	// 16,666, well above the floor.
	got := netemLimit(Shaping{Bandwidth: "1gbit", Delay: "100ms"}, 1500)
	if got < 16_000 || got > 17_000 {
		t.Errorf("large BDP limit = %d, want about 16666", got)
	}
	// Unshaped links keep the kernel default.
	if got := netemLimit(Shaping{}, 1500); got != 1000 {
		t.Errorf("unshaped limit = %d, want 1000", got)
	}
}

func TestShapingEmpty(t *testing.T) {
	if !(Shaping{}).Empty() {
		t.Error("zero Shaping should be empty")
	}
	if (Shaping{Delay: "1ms"}).Empty() {
		t.Error("Shaping with a delay is not empty")
	}
}

func TestTbfLimitIsMonotonic(t *testing.T) {
	// A longer permitted queueing time must never produce a smaller limit,
	// otherwise raising `queue` in the manifest would tighten the queue.
	prev := uint32(0)
	for _, us := range []uint32{1000, 10_000, 50_000, 200_000} {
		got := tbfLimit(125_000, us, 15_000)
		if got < prev {
			t.Fatalf("tbfLimit is not monotonic: %d us gave %d after %d", us, got, prev)
		}
		prev = got
	}
}

// Names generated for overlay devices must agree with internal/alloc and fit
// the kernel's interface name limit.
func TestOverlayNamesFit(t *testing.T) {
	for _, vni := range []uint32{4096, 999_999, 16_000_000} {
		if n := BridgeName(vni); len(n) > 15 {
			t.Errorf("BridgeName(%d) = %q is too long", vni, n)
		}
		if n := VxlanName(vni); len(n) > 15 {
			t.Errorf("VxlanName(%d) = %q is too long", vni, n)
		}
	}
}
