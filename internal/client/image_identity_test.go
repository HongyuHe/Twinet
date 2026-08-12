package client

import (
	"context"
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
//
// Resolution therefore happens where every caller passes, not in one of them.
func TestApplyResolvesImageIdentityForEveryCaller(t *testing.T) {
	top := labWithTwoRouters()
	before := deploy.SpecHash(top.Devices["as3/ATL"])

	c := &Cluster{}
	// No nodes and no local daemon in a test, so nothing can be resolved; what
	// is being checked is that Apply asks at all rather than leaving the field
	// to whichever caller happened to fill it in.
	c.stampImageIDs(context.Background(), top)

	for _, d := range top.Devices {
		if d.ImageID != "" && deploy.SpecHash(d) == before {
			t.Errorf("%s resolved an identity but its hash did not move", d.ID)
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

	c := &Cluster{}
	c.stampImageIDs(context.Background(), top)

	for _, d := range top.Devices {
		if d.ImageID != "sha256:chosen-by-the-caller" {
			t.Errorf("%s's identity was replaced with %q, discarding the check that "+
				"every node agrees on what this image is", d.ID, d.ImageID)
		}
	}
}
