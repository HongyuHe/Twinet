package svc

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestPayloadCoversEveryASAndTheDeliberateExceptions(t *testing.T) {
	top := loadLab(t)
	// AS 5 has no ROA, AS 7 announces something AS 3 holds a ROA for.
	p := BuildRPKI(top, []int{5}, map[int]string{3: "7.0.0.0/8"})

	byASN := map[int][]VRP{}
	for _, r := range p.Roas {
		byASN[r.ASN] = append(byASN[r.ASN], r)
	}
	if _, ok := byASN[5]; ok {
		t.Error("AS 5 was meant to have no ROA, so a student who filters not-found routes is caught")
	}
	if len(byASN[3]) < 2 {
		t.Errorf("AS 3 should hold a ROA for its own block and for the hijacked prefix, got %v", byASN[3])
	}
	for asn, as := range top.ASes {
		if as.Block == "" || asn == 5 {
			continue
		}
		found := false
		for _, r := range byASN[asn] {
			if r.Prefix == as.Block {
				found = true
			}
		}
		if !found {
			t.Errorf("AS %d has no ROA for its own block %s, so its routes would be invalid", asn, as.Block)
		}
	}
}

// A max length equal to the prefix length is what makes a more-specific
// announcement invalid, which is how a hijack is detected. Getting this wrong
// makes every hijack exercise silently unfalsifiable.
func TestMaxLengthDoesNotPermitMoreSpecifics(t *testing.T) {
	top := loadLab(t)
	for _, r := range BuildRPKI(top, nil, nil).Roas {
		var bits int
		if _, err := parsePrefixBits(r.Prefix, &bits); err != nil {
			t.Fatal(err)
		}
		if r.MaxLength != bits {
			t.Errorf("%s has maxLength %d but prefix length %d; a more-specific hijack would validate",
				r.Prefix, r.MaxLength, bits)
		}
	}
}

func parsePrefixBits(p string, out *int) (int, error) {
	pfx, err := netip.ParsePrefix(p)
	if err != nil {
		return 0, err
	}
	*out = pfx.Bits()
	return 1, nil
}

// The server has to speak enough RTR that a real router accepts the answer.
// A cache that connects and returns nothing is worse than none at all: every
// route becomes not-found and the exercise passes for the wrong reason.
func TestRTRServerAnswersAResetQuery(t *testing.T) {
	top := loadLab(t)
	srv := NewRTRServer(BuildRPKI(top, nil, nil))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() { _ = srv.Serve(ln) }()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	// Reset Query.
	q := []byte{1, 2, 0, 0, 0, 0, 0, 8}
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}

	var (
		sawResponse, sawPrefix, sawEnd bool
		prefixes                       int
	)
	for i := 0; i < 5000; i++ {
		var hdr [8]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			break
		}
		length := binary.BigEndian.Uint32(hdr[4:8])
		body := make([]byte, int(length)-8)
		if len(body) > 0 {
			if _, err := io.ReadFull(c, body); err != nil {
				break
			}
		}
		switch hdr[1] {
		case pduCacheResponse:
			sawResponse = true
		case pduIPv4Prefix:
			sawPrefix = true
			prefixes++
		case pduEndOfData:
			sawEnd = true
		}
		if sawEnd {
			break
		}
	}
	if !sawResponse || !sawPrefix || !sawEnd {
		t.Fatalf("incomplete RTR exchange: response=%v prefix=%v end=%v", sawResponse, sawPrefix, sawEnd)
	}
	if prefixes != len(srv.payload.Roas) {
		t.Errorf("served %d prefixes, payload has %d", prefixes, len(srv.payload.Roas))
	}
}
