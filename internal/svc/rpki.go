// RPKI: the validator the lab runs, and the payload it serves.
//
// A course that teaches origin validation has to have something to validate
// against, and the honest options are all bad. A public validator makes the lab
// depend on the internet and on other people's data, so an exercise's answer
// changes when somebody else publishes a ROA. A pinned snapshot of real data is
// enormous and still arbitrary. Neither lets an exercise say "this particular
// announcement is invalid", which is the only interesting thing to teach.
//
// So the lab is its own trust anchor. The payload is derived from the topology,
// which means it is correct by construction -- every AS has a ROA for the block
// the model gave it -- and an exercise can add a deliberate discrepancy and know
// exactly what a correct router will do with it.
package svc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

// VRP is a validated ROA payload: an origin authorised for a prefix.
type VRP struct {
	Prefix    string `json:"prefix"`
	MaxLength int    `json:"maxLength"`
	ASN       int    `json:"asn"`
}

// Payload is the set of VRPs the validator serves.
type Payload struct {
	Metadata struct {
		Generated int64 `json:"generated"`
		Valid     int64 `json:"valid"`
	} `json:"metadata"`
	Roas []VRP `json:"roas"`
}

// BuildRPKI derives the validator's payload from the topology.
//
// Every AS gets a ROA for its own block, so a correctly configured router sees
// its neighbours as valid. Two deliberate exceptions make the exercise
// meaningful, and they are declared rather than incidental:
//
//   - an AS listed in Invalid announces a prefix covered by a ROA belonging to
//     somebody else, which is what a hijack looks like from the outside;
//   - an AS listed in NotFound has no ROA at all, which is the common case on
//     the real internet and the one a student most often breaks by filtering
//     everything that is not explicitly valid.
//
// Without the second, a student who rejects everything except valid routes
// scores full marks for a router that would black-hole most of the internet.
func BuildRPKI(top *model.Topology, notFound []int, invalid map[int]string) *Payload {
	p := &Payload{}
	p.Metadata.Generated = time.Now().Unix()
	p.Metadata.Valid = time.Now().Add(24 * time.Hour).Unix()

	skip := map[int]bool{}
	for _, asn := range notFound {
		skip[asn] = true
	}

	for _, asn := range top.SortedASNs() {
		as := top.ASes[asn]
		if as.Block == "" || skip[asn] {
			continue
		}
		pfx, err := netip.ParsePrefix(as.Block)
		if err != nil {
			continue
		}
		p.Roas = append(p.Roas, VRP{
			Prefix: pfx.String(),
			// A max length equal to the prefix length is deliberate: it makes a
			// more-specific announcement of the same block invalid, which is
			// how a hijack is normally detected and what the exercise needs.
			MaxLength: pfx.Bits(),
			ASN:       asn,
		})
	}

	// A ROA held by one AS for a prefix another AS announces. The announcement
	// is invalid to anyone validating, and valid-looking to anyone who is not.
	for victim, prefix := range invalid {
		if pfx, err := netip.ParsePrefix(prefix); err == nil {
			p.Roas = append(p.Roas, VRP{
				Prefix: pfx.String(), MaxLength: pfx.Bits(), ASN: victim,
			})
		}
	}

	sort.Slice(p.Roas, func(i, j int) bool {
		if p.Roas[i].ASN != p.Roas[j].ASN {
			return p.Roas[i].ASN < p.Roas[j].ASN
		}
		return p.Roas[i].Prefix < p.Roas[j].Prefix
	})
	return p
}

// JSON renders the payload in the format validators publish.
func (p *Payload) JSON() []byte {
	raw, _ := json.MarshalIndent(p, "", "  ")
	return raw
}

// ---- RTR server (RFC 8210) -------------------------------------------------
//
// Implemented here rather than by shipping a third-party validator, because the
// subset a router needs is small, and a lab that depends on an external daemon
// for a teaching exercise has traded a hundred lines for an operational
// dependency it cannot debug.

const (
	rtrVersion = 1

	pduSerialNotify  = 0
	pduSerialQuery   = 1
	pduResetQuery    = 2
	pduCacheResponse = 3
	pduIPv4Prefix    = 4
	pduIPv6Prefix    = 6
	pduEndOfData     = 7
	pduCacheReset    = 8
	pduErrorReport   = 10
)

// RTRServer serves a payload over the RTR protocol.
type RTRServer struct {
	mu      sync.RWMutex
	payload *Payload
	serial  uint32
	session uint16
}

// NewRTRServer builds a server over a payload.
func NewRTRServer(p *Payload) *RTRServer {
	return &RTRServer{payload: p, serial: 1, session: 1}
}

// Update replaces the payload and advances the serial, so a connected router
// learns that something changed rather than holding a stale view forever.
func (s *RTRServer) Update(p *Payload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payload = p
	s.serial++
}

// Serve accepts RTR connections until the listener is closed.
func (s *RTRServer) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer func() { _ = c.Close() }()
			_ = s.handle(c)
		}()
	}
}

func (s *RTRServer) handle(c net.Conn) error {
	for {
		var hdr [8]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return err
		}
		length := binary.BigEndian.Uint32(hdr[4:8])
		if length < 8 || length > 1<<20 {
			return fmt.Errorf("bad pdu length %d", length)
		}
		if rest := int(length) - 8; rest > 0 {
			if _, err := io.ReadFull(c, make([]byte, rest)); err != nil {
				return err
			}
		}

		switch hdr[1] {
		case pduResetQuery, pduSerialQuery:
			// Both are answered with the full set. Serving a delta for a
			// serial query would be correct and is unnecessary here: the
			// payload of a teaching lab is small, and a full response is
			// always a valid answer.
			if err := s.writeFull(c); err != nil {
				return err
			}
		default:
			// Anything else is ignored rather than answered with an error,
			// because a router that receives an error report tears the session
			// down and stops validating entirely.
		}
	}
}

func (s *RTRServer) writeFull(c net.Conn) error {
	s.mu.RLock()
	p, serial, session := s.payload, s.serial, s.session
	s.mu.RUnlock()

	if err := writePDU(c, pduCacheResponse, session, nil); err != nil {
		return err
	}
	for _, r := range p.Roas {
		pfx, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			continue
		}
		body := make([]byte, 0, 20)
		body = append(body, 1) // flags: announcement
		body = append(body, byte(pfx.Bits()), byte(r.MaxLength), 0)
		addr := pfx.Addr()
		body = append(body, addr.AsSlice()...)
		var asn [4]byte
		binary.BigEndian.PutUint32(asn[:], uint32(r.ASN))
		body = append(body, asn[:]...)

		kind := byte(pduIPv4Prefix)
		if addr.Is6() {
			kind = pduIPv6Prefix
		}
		if err := writePDU(c, kind, 0, body); err != nil {
			return err
		}
	}
	var end [4]byte
	binary.BigEndian.PutUint32(end[:], serial)
	// Refresh, retry and expire intervals follow the serial in a version-1
	// End of Data. A short refresh keeps an exercise responsive: a student who
	// fixes their filter should not wait an hour to see it work.
	tail := append(end[:], 0, 0, 0, 60, 0, 0, 0, 30, 0, 0, 2, 88)
	return writePDU(c, pduEndOfData, session, tail)
}

func writePDU(w io.Writer, kind byte, session uint16, body []byte) error {
	hdr := make([]byte, 8)
	hdr[0] = rtrVersion
	hdr[1] = kind
	binary.BigEndian.PutUint16(hdr[2:4], session)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(8+len(body)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(body) > 0 {
		_, err := w.Write(body)
		return err
	}
	return nil
}

// RPKIAddrFor returns the address devices in an AS reach the validator at.
func RPKIAddrFor(top *model.Topology, asn int) string {
	for _, d := range top.Devices {
		if d.Kind != model.KindService || !strings.Contains(strings.ToLower(d.Name), "rpki") {
			continue
		}
		for _, i := range d.Ifaces {
			var n int
			if _, err := fmt.Sscanf(i.Name, "as%d", &n); err != nil || n != asn {
				continue
			}
			if a, err := netip.ParsePrefix(i.Addr4); err == nil {
				return a.Addr().String()
			}
		}
	}
	return ""
}

// HijackOrigin returns the AS that deliberately announces a mis-ROA'd prefix,
// and the prefix it announces.
//
// The manifest declares a ROA held by one AS for a prefix inside another's
// space, so that an announcement of it is RPKI-invalid. A ROA on its own is
// only half of that: nothing announced the prefix, so no route in the lab was
// ever invalid, and the question "do you reject invalid announcements?" could
// not be answered by looking at any router. Every submission passed it on the
// strength of having written a route-map.
//
// The hijack is originated by a staff AS other than the ROA holder, so it
// exists for every student regardless of what any student does, and no student
// can withdraw it.
func HijackOrigin(top *model.Topology) (int, string) {
	if top.Lab == nil || len(top.Lab.RPKI.Invalid) == 0 {
		return 0, ""
	}
	holders := map[int]bool{}
	var prefix string
	for holder, p := range top.Lab.RPKI.Invalid {
		holders[holder] = true
		if prefix == "" || p < prefix {
			prefix = p
		}
	}
	for _, asn := range top.SortedASNs() {
		as := top.ASes[asn]
		if as.Role == model.RoleStaff && !holders[asn] {
			return asn, prefix
		}
	}
	return 0, ""
}
