package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/netx"
)

func sweepRequest(remove bool) *http.Request {
	body := `{}`
	if remove {
		body = `{"remove":true}`
	}
	return httptest.NewRequest(http.MethodPost, "/v1/sweep", strings.NewReader(body))
}

func sweepResponse(t *testing.T, server *Server, remove bool) (*httptest.ResponseRecorder, SweepResponse) {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.handleSweep(recorder, sweepRequest(remove))
	var out SweepResponse
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode sweep response: %v", err)
		}
	}
	return recorder, out
}

func sweepRefusal(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode sweep refusal: %v", err)
	}
	return body.Error
}

// A removing sweep is the one destructive path an operator drives by hand.
// Every claim on this node's objects must refuse it, not only a local
// operation lease: recovery rolling a transaction forward, a grading hold, and
// a fenced cluster mutation all own overlays without holding s.ops.
func TestSweepRefusesRemovalWhileAnythingOwnsThisNode(t *testing.T) {
	orphans := []netx.Orphan{{VNI: 4242, Owner: "abandoned"}}
	for _, tc := range []struct {
		name  string
		claim func(*Server, time.Time)
		want  string
	}{
		{
			name: "operation",
			claim: func(s *Server, _ time.Time) {
				s.ops = map[string]*lease{"deploying": {kind: "apply"}}
			},
			want: `operation apply on lab "deploying"`,
		},
		{
			name: "mutation lease",
			claim: func(s *Server, now time.Time) {
				s.mutations["deploying"] = &clusterLease{
					holder: "controller", until: now.Add(time.Minute),
				}
			},
			want: `mutation lease on lab "deploying"`,
		},
		{
			name: "transaction",
			claim: func(s *Server, _ time.Time) {
				s.transactions["recovering"] = applyTransaction{
					Generation: "g2", Phase: transactionPrepared,
				}
			},
			want: `transaction on lab "recovering" in phase prepared`,
		},
		{
			name: "hold",
			claim: func(s *Server, now time.Time) {
				s.holds = map[string]*hold{
					"grading": {holder: "grader", until: now.Add(time.Minute)},
				}
			},
			want: `hold on lab "grading"`,
		},
		{
			name: "prepared generation",
			claim: func(s *Server, _ time.Time) {
				s.generations["deploying"] = generationState{Prepared: "g3"}
			},
			want: `prepared generation "g3" on lab "deploying"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1_700_000_000, 0)
			server := gcFenceServer(&now)
			var removed []uint32
			server.gcFindOrphans = func(map[string]bool) ([]netx.Orphan, error) {
				return orphans, nil
			}
			server.gcRemoveOverlay = func(vni uint32) error {
				removed = append(removed, vni)
				return nil
			}
			tc.claim(server, now)

			recorder, _ := sweepResponse(t, server, true)
			if recorder.Code != http.StatusConflict {
				t.Fatalf("sweep --remove status=%d body=%s, want 409", recorder.Code, recorder.Body.String())
			}
			if refusal := sweepRefusal(t, recorder); !strings.Contains(refusal, tc.want) {
				t.Errorf("refusal does not name the owner %q: %s", tc.want, refusal)
			}
			if len(removed) != 0 {
				t.Errorf("removed %v while %s owned this node", removed, tc.name)
			}

			// Reporting is not destructive and must stay available: it is how
			// an operator finds out what is there while the node is busy.
			report, body := sweepResponse(t, server, false)
			if report.Code != http.StatusOK {
				t.Fatalf("report-only sweep status=%d body=%s", report.Code, report.Body.String())
			}
			if len(body.Orphans) != 1 {
				t.Errorf("report-only sweep found %d orphan(s), want 1", len(body.Orphans))
			}
			if len(removed) != 0 {
				t.Errorf("report-only sweep removed %v", removed)
			}
		})
	}
}

// The scan and the deletion are separate moments. A deployment that claims the
// identifier in between is entitled to it, and the sweep must leave it alone
// and say so rather than delete the cable the new lab was just wired into.
func TestSweepLeavesAnOverlayClaimedBetweenScanAndDeletion(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := gcFenceServer(&now)
	var removed []uint32
	server.gcFindOrphans = func(map[string]bool) ([]netx.Orphan, error) {
		// The claim lands after the list is read, exactly as a real deploy
		// racing an operator's sweep would.
		server.mu.Lock()
		server.overlayClaims[4242] = overlayClaim{Lab: "arriving", Live: true}
		server.mu.Unlock()
		return []netx.Orphan{{VNI: 4242, Owner: "abandoned"}, {VNI: 4243, Owner: "abandoned"}}, nil
	}
	server.gcRemoveOverlay = func(vni uint32) error {
		removed = append(removed, vni)
		return nil
	}

	recorder, body := sweepResponse(t, server, true)
	if recorder.Code != http.StatusOK {
		t.Fatalf("sweep status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(removed) != 1 || removed[0] != 4243 {
		t.Fatalf("removed %v, want only the unclaimed 4243", removed)
	}
	if len(body.Fenced) != 1 || body.Fenced[0].VNI != 4242 {
		t.Fatalf("fenced=%v, want the claimed 4242 reported", body.Fenced)
	}
	if len(body.Removed) != 1 || body.Removed[0] != 4243 {
		t.Fatalf("response removed=%v, want only 4243", body.Removed)
	}
	var named bool
	for _, message := range body.Errs {
		if strings.Contains(message, "vni 4242") && strings.Contains(message, "claimed") {
			named = true
		}
	}
	if !named {
		t.Errorf("sweep did not say why 4242 was left in place: %v", body.Errs)
	}
}

// A quiet node with nothing claiming it still sweeps, or the fence would have
// turned an operator tool into one that never works.
func TestSweepRemovesOrphansOnAnIdleNode(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := gcFenceServer(&now)
	var removed []uint32
	server.gcFindOrphans = func(map[string]bool) ([]netx.Orphan, error) {
		return []netx.Orphan{{VNI: 7000, Owner: "gone"}, {VNI: 7001, Ports: 2, Owner: "busy"}}, nil
	}
	server.gcRemoveOverlay = func(vni uint32) error {
		removed = append(removed, vni)
		return nil
	}

	recorder, body := sweepResponse(t, server, true)
	if recorder.Code != http.StatusOK {
		t.Fatalf("sweep status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(removed) != 1 || removed[0] != 7000 {
		t.Fatalf("removed %v, want only the peerless 7000", removed)
	}
	if len(body.InUse) != 1 || body.InUse[0].VNI != 7001 {
		t.Fatalf("in use=%v, want the overlay that still carries a port", body.InUse)
	}
	if len(body.Fenced) != 0 {
		t.Fatalf("fenced=%v on an idle node", body.Fenced)
	}
}
