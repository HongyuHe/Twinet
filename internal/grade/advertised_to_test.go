package grade

import (
	"testing"
)

// A router that originates no prefix of its own has nothing to advertise over
// iBGP: split horizon stops it re-advertising what it learnt from another iBGP
// peer, so a route refresh is answered with silence by a session that is
// perfectly alive.
//
// bgp.ibgp_full_mesh read that silence as death and said so:
//
//	"BOS -> ATL says Established, but no route arrived from ATL while it was
//	 asked to send its table: the session is held open by a timer that has not
//	 expired yet, and carries nothing"
//
// On the live lab all seven of ATL's sessions were Established with a quarter
// of an hour of uptime, each receiving one to five prefixes from the other
// end. Announcing the AS prefix from a subset of the routers is an ordinary
// design and every other check in the rubric passed, so a wholly correct
// submission lost a mark for seven sessions that were carrying traffic.
//
// What the peer had to send is the missing measurement, and it is the peer's
// own count, because whether a session had anything to carry is not a question
// the receiving end can answer.
func TestAPeerWithNothingToSendIsNotADeadSession(t *testing.T) {
	sums := map[string]bgpSummaryJSON{
		"ATL": summaryWith(map[string]int{"3.153.0.1": 0}),
	}
	sent, known := advertisedTo(sums, "ATL", "3.153.0.1")
	if !known {
		t.Fatal("the peer's own count was readable but reported otherwise")
	}
	if sent != 0 {
		t.Fatalf("a peer advertising nothing was read as advertising %d", sent)
	}
}

// The soundness direction. A blackholed session stays Established until the
// hold timer expires, and the sending end still believes it is advertising its
// routes -- so the count is non-zero and the silence really is evidence. This
// is the exploit findings 39 and 59 were about, and the fix must not excuse it.
func TestASessionWithRoutesQueuedAndNothingArrivingIsStillDead(t *testing.T) {
	sums := map[string]bgpSummaryJSON{
		"ATL": summaryWith(map[string]int{"3.153.0.1": 4}),
	}
	sent, known := advertisedTo(sums, "ATL", "3.153.0.1")
	if !known || sent != 4 {
		t.Fatalf("a peer with routes queued was not seen: sent=%d known=%v", sent, known)
	}
}

// A peer whose summary could not be read, or which has no session with us at
// all, yields no count. The caller must not turn that into either verdict: the
// unreadable router is reported on its own account, and the missing session is
// reported from the side that is missing it.
func TestAnUnreadablePeerYieldsNoCount(t *testing.T) {
	sums := map[string]bgpSummaryJSON{
		"ATL": summaryWith(map[string]int{"3.153.0.1": 4}),
	}
	if _, known := advertisedTo(sums, "NYC", "3.153.0.1"); known {
		t.Fatal("a router that was never read produced a count")
	}
	if _, known := advertisedTo(sums, "ATL", "3.199.0.1"); known {
		t.Fatal("a session that does not exist produced a count")
	}
	if _, known := advertisedTo(sums, "ATL", ""); known {
		t.Fatal("a router with no loopback produced a count")
	}
}

func summaryWith(pfxSnt map[string]int) bgpSummaryJSON {
	var s bgpSummaryJSON
	s.IPv4Unicast.Peers = map[string]struct {
		RemoteAs      int    `json:"remoteAs"`
		State         string `json:"state"`
		PfxRcd        int    `json:"pfxRcd"`
		PfxSnt        int    `json:"pfxSnt"`
		PeerUptimeMs  int64  `json:"peerUptimeMsec"`
		ConnectionsEs int    `json:"connectionsEstablished"`
		MsgRcvd       int64  `json:"msgRcvd"`
		MsgSent       int64  `json:"msgSent"`
	}{}
	for addr, n := range pfxSnt {
		p := s.IPv4Unicast.Peers[addr]
		p.RemoteAs = 3
		p.State = "Established"
		p.PfxSnt = n
		s.IPv4Unicast.Peers[addr] = p
	}
	return s
}
