package grade

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/svc"
)

// The manifest declares a ROA held by one AS for a prefix inside another's
// space, which makes an announcement of that prefix RPKI-invalid. A ROA on its
// own is half of that: for a while nothing in the lab announced the prefix, so
// no route anywhere was ever invalid, "no invalid route is selected" was true
// of a router that had done nothing, and every submission scored the mark for
// having written a route-map.
//
// A staff AS other than the ROA holder announces it, so it exists for every
// student and no student can withdraw it.
func TestTheInvalidAnnouncementIsActuallyAnnounced(t *testing.T) {
	top := &model.Topology{
		ASes: map[int]*model.AS{
			1:  {ASN: 1, Role: model.RoleStaff, Block: "1.0.0.0/8"},
			2:  {ASN: 2, Role: model.RoleStaff, Block: "2.0.0.0/8"},
			10: {ASN: 10, Role: model.RoleStudent, Block: "10.0.0.0/8"},
		},
		Lab: &model.Lab{RPKI: model.RPKISpec{Invalid: map[int]string{2: "10.128.0.0/9"}}},
	}
	asn, prefix := svc.HijackOrigin(top)
	if prefix != "10.128.0.0/9" {
		t.Fatalf("the declared invalid prefix is not announced by anybody: got %q", prefix)
	}
	if asn == 2 {
		t.Fatal("the ROA holder announces its own prefix, which is valid, not invalid")
	}
	if as, ok := top.ASes[asn]; !ok || as.Role != model.RoleStaff {
		t.Fatalf("AS %d announces the hijack but is not staff-operated, so a student "+
			"can withdraw the very announcement they are marked on rejecting", asn)
	}

	// And with nothing declared, nothing is announced -- a lab that does not
	// pose the question must not have a router quietly announcing a hijack.
	quiet := &model.Topology{ASes: top.ASes, Lab: &model.Lab{}}
	if asn, prefix := svc.HijackOrigin(quiet); asn != 0 || prefix != "" {
		t.Errorf("a lab with no declared invalid prefix announces %q from AS %d", prefix, asn)
	}
}
