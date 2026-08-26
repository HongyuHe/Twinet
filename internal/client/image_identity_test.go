package client

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
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

func TestPostPullDigestMismatchIsRefused(t *testing.T) {
	ref := "registry.example/router@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	top := &model.Topology{
		Name: "lab",
		Lab:  &model.Lab{Images: model.ImagePolicy{Mode: model.ImageModeRelease}},
		Devices: map[string]*model.Device{
			"as1/R1": {ID: "as1/R1", Node: "node-0", Image: ref},
		},
	}
	err := verifyAppliedImageDigests(top, "node-0", agent.ApplyResponse{
		ImageDigests: map[string]string{
			ref: "registry.example/router@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "not locked digest") {
		t.Fatalf("post-pull mismatch = %v", err)
	}
}

const (
	lockedRouter = "registry.example/router:0.1@sha256:" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	lockedRouterDigest = "sha256:" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	strangerDigest = "sha256:" +
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func labPinnedOnThreeNodes(mode model.ImageMode) *model.Topology {
	devices := map[string]*model.Device{}
	for _, node := range []string{"node-0", "node-1", "node-2"} {
		id := "as1/" + node
		devices[id] = &model.Device{ID: id, Node: node, Image: lockedRouter,
			ImageID: lockedRouterDigest}
	}
	return &model.Topology{
		Name:    "scale",
		Lab:     &model.Lab{Images: model.ImagePolicy{Mode: mode}},
		Devices: devices,
	}
}

// Unequal caches are allowed for a pinned reference because of this: the
// nodes that had to pull are made to state afterwards which manifest they
// have, and the transaction refuses to commit unless every one of them proves
// the locked digest. Verification that only covered the nodes that already
// had the image would be no proof at all.
func TestEveryAssignedNodeProvesTheLockedDigestAfterPulling(t *testing.T) {
	top := labPinnedOnThreeNodes(model.ImageModeRelease)
	answered := agent.ApplyResponse{
		ImageDigests: map[string]string{lockedRouter: lockedRouterDigest},
	}
	for _, node := range []string{"node-0", "node-1", "node-2"} {
		if err := verifyAppliedImageDigests(top, node, answered); err != nil {
			t.Fatalf("%s proved the locked digest and was still refused: %v", node, err)
		}
	}
	// node-0 held the image before the deployment; node-1 has just pulled and
	// says nothing about what it got, and node-2 pulled something else.
	silent := verifyAppliedImageDigests(top, "node-1", agent.ApplyResponse{})
	if silent == nil || !strings.Contains(silent.Error(), "did not report a post-pull digest") {
		t.Fatalf("a node that never proved what it pulled was accepted: %v", silent)
	}
	wrong := verifyAppliedImageDigests(top, "node-2", agent.ApplyResponse{
		ImageDigests: map[string]string{lockedRouter: strangerDigest},
	})
	if wrong == nil || !strings.Contains(wrong.Error(), "not locked digest") {
		t.Fatalf("a node that pulled another manifest was accepted: %v", wrong)
	}
	if !strings.Contains(wrong.Error(), "node-2") || !strings.Contains(wrong.Error(), strangerDigest) {
		t.Errorf("the refusal does not name the node and what it holds: %v", wrong)
	}
}

// A development manifest may pin a digest too, and a pin nobody checks is
// decoration. The unequal-cache allowance follows the reference, so the proof
// must follow it as well.
func TestAPinnedReferenceIsVerifiedInDevelopmentModeToo(t *testing.T) {
	top := labPinnedOnThreeNodes(model.ImageModeDevelopment)
	err := verifyAppliedImageDigests(top, "node-1", agent.ApplyResponse{
		ImageDigests: map[string]string{lockedRouter: strangerDigest},
	})
	if err == nil {
		t.Fatal("a development lab pinned by digest ran an unverified manifest")
	}
	// A tag in a development lab has nothing to prove and is left alone.
	tagged := &model.Topology{
		Name: "dev", Lab: &model.Lab{},
		Devices: map[string]*model.Device{
			"as1/R1": {ID: "as1/R1", Node: "node-0", Image: "hyhe/twinet-router:0.1"},
		},
	}
	if err := verifyAppliedImageDigests(tagged, "node-0", agent.ApplyResponse{}); err != nil {
		t.Fatalf("a development tag was required to prove a digest: %v", err)
	}
}

// Release and grading deploy locked manifests only. A reference that reaches
// the post-pull check without a digest means the lock was not applied, and
// that must stop the transaction rather than pass unnoticed.
func TestReleaseModeRefusesAnUnpinnedReferenceAfterApply(t *testing.T) {
	top := &model.Topology{
		Name: "lab",
		Lab:  &model.Lab{Images: model.ImagePolicy{Mode: model.ImageModeRelease}},
		Devices: map[string]*model.Device{
			"as1/R1": {ID: "as1/R1", Node: "node-0", Image: "hyhe/twinet-router:0.1"},
		},
	}
	err := verifyAppliedImageDigests(top, "node-0", agent.ApplyResponse{
		ImageDigests: map[string]string{"hyhe/twinet-router:0.1": strangerDigest},
	})
	if err == nil || !strings.Contains(err.Error(), "immutable registry digest") {
		t.Fatalf("release mode accepted a mutable reference: %v", err)
	}
}

// Every caller must arrive at the same identity for a pinned reference, and
// the reference states it. Asking a node instead lets a local alias -- a
// repository-qualified spelling, a config ID -- become the spec hash, so the
// next caller sees every container as out of date and recreates it.
func TestAPinnedReferenceIdentityIsNotTakenFromACache(t *testing.T) {
	top := labPinnedOnThreeNodes(model.ImageModeRelease)
	for _, d := range top.Devices {
		d.ImageID = ""
	}
	c := &Cluster{}
	c.stampImageIDs(context.Background(), top)
	for _, d := range top.Devices {
		if d.ImageID != lockedRouterDigest {
			t.Errorf("%s was stamped %q, not the locked manifest %q",
				d.ID, d.ImageID, lockedRouterDigest)
		}
	}
	hashes := map[string]bool{}
	for _, d := range top.Devices {
		hashes[deploy.SpecHash(d)] = true
	}
	if len(hashes) != len(top.Devices) {
		t.Fatalf("devices on different nodes collapsed to %d spec hashes", len(hashes))
	}
}
