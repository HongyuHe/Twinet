package client

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
)

func labWithTwoRouters() *model.Topology {
	a := &model.Device{ID: "as3/ATL", Kind: model.KindRouter, Image: "hyhe/twinet-frr:v1"}
	b := &model.Device{ID: "as3/BOS", Kind: model.KindRouter, Image: "hyhe/twinet-frr:v1"}
	return &model.Topology{
		Name:    "cos461",
		Lab:     &model.Lab{},
		Devices: map[string]*model.Device{a.ID: a, b.ID: b},
	}
}

// Every caller that deploys must arrive at the same container spec hash, or
// each will see the other's containers as out of date and replace all of them.
//
// The hash includes the digest an image reference resolves to. Only the deploy
// command used to resolve it; grading's restore between submissions sent the
// same devices with the field empty. On a three-node lab that recreated 89 of
// 212 containers while grading two submissions, and 172 on the next deploy --
// which empties network namespaces and reverts FRR to the image's own daemons
// file, and was reported both times as students' mistakes.
func TestNodesThatAgreeGiveAnIdentity(t *testing.T) {
	seen, disagree := agreedDigests(map[string]map[string]string{
		"node-0": {"frr:v1": "sha256:aaaaaaaaaaaa", "host:v1": "sha256:bbbbbbbbbbbb"},
		"node-1": {"frr:v1": "sha256:aaaaaaaaaaaa", "host:v1": "sha256:bbbbbbbbbbbb"},
		"node-2": {"frr:v1": "sha256:aaaaaaaaaaaa", "host:v1": "sha256:bbbbbbbbbbbb"},
	})
	if len(disagree) != 0 {
		t.Fatalf("nodes that all said the same thing were reported as disagreeing: %v", disagree)
	}
	if seen["frr:v1"] != "sha256:aaaaaaaaaaaa" || seen["host:v1"] != "sha256:bbbbbbbbbbbb" {
		t.Errorf("the agreed identity was not returned: %v", seen)
	}
}

// A node that has not pulled an image yet has no opinion, and the deployment is
// about to give it one. Treating that as a disagreement would leave the
// identity unresolved on every first deploy, which is the bug again.
func TestANodeThatHasNotPulledYetIsNotADisagreement(t *testing.T) {
	seen, disagree := agreedDigests(map[string]map[string]string{
		"node-0": {"frr:v1": "sha256:aaaaaaaaaaaa"},
		"node-1": {"frr:v1": ""},
		"node-2": {},
	})
	if len(disagree) != 0 {
		t.Fatalf("a node that has not pulled the image was counted as disagreeing: %v", disagree)
	}
	if seen["frr:v1"] != "sha256:aaaaaaaaaaaa" {
		t.Errorf("no identity was returned for an image one node knows: %v", seen)
	}
}

// Nodes that genuinely differ must not have one of their answers picked. A
// mark that depends on which node a student's AS was scheduled onto is not a
// mark, and nothing else in the system would report it.
func TestNodesThatDifferYieldNoIdentity(t *testing.T) {
	seen, disagree := agreedDigests(map[string]map[string]string{
		"node-0": {"frr:v1": "sha256:aaaaaaaaaaaa"},
		"node-1": {"frr:v1": "sha256:cccccccccccc"},
		"node-2": {"frr:v1": "sha256:aaaaaaaaaaaa"},
	})
	if _, ok := seen["frr:v1"]; ok {
		t.Fatalf("one node's answer was chosen for an image the nodes do not agree on (%q). "+
			"Half a class would be marked on a different build from the other half",
			seen["frr:v1"])
	}
	who, ok := disagree["frr:v1"]
	if !ok {
		t.Fatal("the disagreement was not reported at all")
	}
	joined := strings.Join(who, " ")
	for _, want := range []string{"node-0", "node-1", "node-2", "aaaaaaaaaaaa", "cccccccccccc"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the report does not mention %s, so nobody can tell which node to "+
				"fix: %q", want, joined)
		}
	}
}

// An identity the caller already established is not overwritten: the deploy
// command checks that every node agrees on what an image is and refuses when
// they do not, and that answer must survive.
func TestAnIdentityTheCallerEstablishedIsKept(t *testing.T) {
	top := labWithTwoRouters()
	top.Devices["as3/ATL"].ImageID = "sha256:chosen-by-the-caller"
	top.Devices["as3/BOS"].ImageID = "sha256:chosen-by-the-caller"
	before := deploy.SpecHash(top.Devices["as3/ATL"])

	c := &Cluster{}
	c.stampImageIDs(context.Background(), top)

	for _, d := range top.Devices {
		if d.ImageID != "sha256:chosen-by-the-caller" {
			t.Errorf("%s's identity was replaced with %q, discarding the check that "+
				"every node agrees on what this image is", d.ID, d.ImageID)
		}
	}
	if got := deploy.SpecHash(top.Devices["as3/ATL"]); got != before {
		t.Error("the spec hash moved for a device nothing changed about, so every " +
			"container would be destroyed and recreated")
	}
}
