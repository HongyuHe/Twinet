package svc

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"time"
)

// The platform authorises the systems nobody is being marked on, and nothing
// else. A student system's own ROA is the student's own action -- publishing it
// for them leaves the exercise with nothing in it, and the check that asks
// whether they did could only be scored by giving everybody the mark.
func TestPayloadCoversTheSystemsNobodyIsMarkedOn(t *testing.T) {
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
	// The declared discrepancy is the platform's, so it is published.
	hijacked := false
	for _, r := range byASN[3] {
		if r.Prefix == "7.0.0.0/8" {
			hijacked = true
		}
	}
	if !hijacked {
		t.Errorf("the declared invalid prefix is not authorised to anybody, so no "+
			"announcement of it is invalid and the exercise has nothing in it: %v", byASN[3])
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
		student := as.Role == model.RoleStudent
		if found && student {
			t.Errorf("AS %d is a student system and the platform published its ROA for it, "+
				"so the question of whether they published one cannot be asked", asn)
		}
		if !found && !student {
			t.Errorf("AS %d is not a student system and has no ROA for its own block %s, "+
				"so its routes are not-found to everybody", asn, as.Block)
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

// A router asking "what changed?" used to be told "all of this is still here",
// because a serial query was answered with the full set and every record
// carried the announcement flag. Nothing was ever removed, so a ROA withdrawn
// or corrected at the trust anchor stayed in every router's table for the life
// of the session -- which matters now that publishing is a student's own
// action, because correcting a mistake appeared to do nothing.
func TestASerialQueryCanWithdraw(t *testing.T) {
	p := &Payload{Roas: []VRP{{Prefix: "3.0.0.0/8", MaxLength: 8, ASN: 3}}}
	srv := NewRTRServer(p)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() { _ = srv.Serve(ln) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	// Ask as a router that already holds serial 0.
	q := make([]byte, 12)
	q[0], q[1] = 1, 1 // version 1, serial query
	binary.BigEndian.PutUint32(q[4:8], 12)
	binary.BigEndian.PutUint32(q[8:12], 1)

	// Nothing has changed: the answer must not be a reset.
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	if kind := readPDUKind(t, c); kind != pduCacheResponse {
		t.Fatalf("a router that is already up to date was answered with PDU %d, "+
			"which makes it discard and re-learn everything on every refresh", kind)
	}
	readUntil(t, c, pduEndOfData)

	// Now the payload changes. The router must be told to discard what it has,
	// or a withdrawal never reaches it.
	srv.Update(&Payload{Roas: nil})
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	if kind := readPDUKind(t, c); kind != pduCacheReset {
		t.Fatalf("after a ROA was withdrawn, a serial query was answered with PDU %d "+
			"instead of a cache reset, so the router keeps the withdrawn "+
			"authorisation until the session is torn down", kind)
	}
}

func readPDUKind(t *testing.T, c net.Conn) byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hdr [8]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		t.Fatal(err)
	}
	if rest := int(binary.BigEndian.Uint32(hdr[4:8])) - 8; rest > 0 {
		if _, err := io.ReadFull(c, make([]byte, rest)); err != nil {
			t.Fatal(err)
		}
	}
	return hdr[1]
}

func readUntil(t *testing.T, c net.Conn, kind byte) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if readPDUKind(t, c) == kind {
			return
		}
	}
	t.Fatalf("never saw PDU %d", kind)
}
