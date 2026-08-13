package svc

import (
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// A system may authorise prefixes inside its own allocation and name only
// itself as the origin. Without that, the exercise's deliberate hijack could be
// published away by its victim, and a group could authorise a neighbour's space
// and quietly break their marks.
func TestOnlyYourOwnPrefixAndOnlyYourOwnOrigin(t *testing.T) {
	auth := []Authority{
		{ASN: 3, Blocks: []string{"3.0.0.0/8"}, From: []string{"3.152.0.1", "3.151.0.1"}},
		{ASN: 4, Blocks: []string{"4.0.0.0/8"}, From: []string{"4.152.0.1"}},
	}
	p, err := NewPublisher(filepath.Join(t.TempDir(), "published.json"), auth)
	if err != nil {
		t.Fatal(err)
	}
	from3 := netip.MustParseAddr("3.152.0.1")

	if err := p.Publish(from3, PublishRequest{Prefix: "3.0.0.0/8", ASN: 3}); err != nil {
		t.Fatalf("a system could not authorise its own prefix: %v", err)
	}
	if got := p.Published(); len(got) != 1 || got[0].ASN != 3 || got[0].MaxLength != 8 {
		t.Fatalf("what was published is not what was asked for: %v", got)
	}

	for _, c := range []struct {
		name string
		from netip.Addr
		req  PublishRequest
	}{
		{"somebody else's allocation", from3, PublishRequest{Prefix: "4.0.0.0/8", ASN: 3}},
		{"somebody else as the origin", from3, PublishRequest{Prefix: "3.0.0.0/8", ASN: 4}},
		{"the prefix an exercise deliberately mis-authorises", from3,
			PublishRequest{Prefix: "10.128.0.0/9", ASN: 3}},
		{"an address belonging to no system", netip.MustParseAddr("192.0.2.7"),
			PublishRequest{Prefix: "3.0.0.0/8", ASN: 3}},
	} {
		if err := p.Publish(c.from, c.req); err == nil {
			t.Errorf("%s was accepted, so a group can rewrite another's authorisation "+
				"-- or publish away the hijack the exercise is about", c.name)
		}
	}
}

// A group has to be able to correct a mistake without an operator, and what
// they publish has to survive the validator being restarted.
func TestPublicationIsCorrectableAndSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "published.json")
	auth := []Authority{{ASN: 3, Blocks: []string{"3.0.0.0/8"}, From: []string{"3.152.0.1"}}}
	from := netip.MustParseAddr("3.152.0.1")

	p, err := NewPublisher(path, auth)
	if err != nil {
		t.Fatal(err)
	}
	// A wrong maximum length first, then the correction.
	if err := p.Publish(from, PublishRequest{Prefix: "3.0.0.0/8", ASN: 3, MaxLength: 24}); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(from, PublishRequest{Prefix: "3.0.0.0/8", ASN: 3}); err != nil {
		t.Fatal(err)
	}
	if got := p.Published(); len(got) != 1 || got[0].MaxLength != 8 {
		t.Fatalf("correcting an authorisation left %v", got)
	}

	again, err := NewPublisher(path, auth)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.Published(); len(got) != 1 {
		t.Fatalf("restarting the validator lost what the class had published: %v", got)
	}

	if err := again.Publish(from, PublishRequest{Prefix: "3.0.0.0/8", ASN: 3, Withdraw: true}); err != nil {
		t.Fatal(err)
	}
	if got := again.Published(); len(got) != 0 {
		t.Fatalf("withdrawing left %v", got)
	}
}

// The authority is derived from the topology, so a lab that gains a system
// gains a publisher without anybody editing a second file.
func TestAuthorityComesFromTheTopology(t *testing.T) {
	top := loadLab(t)
	auth := AuthorityFor(top)
	if len(auth) == 0 {
		t.Fatal("no system may publish anything, so the exercise cannot be done at all")
	}
	for _, a := range auth {
		as := top.ASes[a.ASN]
		if as == nil || as.Role != model.RoleStudent {
			t.Errorf("AS %d may publish but is not a student system", a.ASN)
		}
		if len(a.From) == 0 {
			t.Errorf("AS %d may publish but from no address, so it cannot", a.ASN)
		}
	}
}
