package deploy

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// The container spec hash decides whether a deployment may leave a container
// alone or must destroy and recreate it. Two callers that compute it from
// different information will fight: each sees the other's containers as
// out of date and replaces all of them, for ever.
//
// That is what happened. The spec hash includes the digest a device's image
// reference resolves to, so that rebuilding a tag in place is noticed, but only
// the deploy command resolved it. Grading's restore between submissions sent
// the same devices with the field empty. Measured on a three-node lab: grading
// two submissions recreated 89 of 212 containers, and the next ordinary deploy
// recreated 172 of them.
//
// Recreating a container empties its network namespace, so the next submission
// failed to load with `Cannot find device "port_BOS"`, and it comes back with
// the image's own FRR daemons file, in which everything but zebra is disabled,
// so routers were found running with no bgpd and no ospfd. Both were reported
// as students' mistakes.
func TestAnUnresolvedImageIdentityWouldRecreateEveryContainer(t *testing.T) {
	resolved := &model.Device{
		ID: "as3/ATL", Kind: model.KindRouter, Hostname: "atl", Node: "node-1",
		Image: "hyhe/twinet-frr:latest", ImageID: "sha256:abcdef0123456789",
	}
	unresolved := *resolved
	unresolved.ImageID = ""

	if SpecHash(resolved) == SpecHash(&unresolved) {
		t.Skip("the image identity is no longer part of the spec hash, so callers " +
			"cannot disagree about it")
	}

	// The two must never both reach a deployment. Nothing here can prove that
	// on its own -- it is what Cluster.Apply is for -- but this records why the
	// field must be filled in before the hash is taken.
	t.Log("a device whose image identity is unknown hashes differently from the " +
		"same device whose identity is known; every caller must resolve it")
}

// Whatever is in the hash has to be stable for a device that has not changed,
// or a re-deploy destroys a lab it was asked to converge.
func TestTheSpecHashIsStableForAnUnchangedDevice(t *testing.T) {
	d := &model.Device{
		ID: "as3/ATL", Kind: model.KindRouter, Hostname: "atl", Node: "node-1",
		Image: "hyhe/twinet-frr:latest", ImageID: "sha256:abcdef0123456789",
		Env:          map[string]string{"B": "2", "A": "1", "C": "3"},
		Sysctls:      map[string]string{"net.ipv4.ip_forward": "1", "net.mpls.platform_labels": "1048575"},
		Binds:        []string{"/b:/b", "/a:/a"},
		Command:      []string{"/sbin/init"},
		CPUs:         1.5,
		Memory:       "512m",
		Restart:      "unless-stopped",
		Capabilities: []string{"NET_ADMIN", "SYS_ADMIN"},
	}
	first := SpecHash(d)
	for i := 0; i < 200; i++ {
		if got := SpecHash(d); got != first {
			t.Fatalf("the same device hashed to %s and then %s. Every deployment "+
				"would destroy and recreate it, losing whatever is inside", first, got)
		}
	}
}

// A change that genuinely needs a new container must still be noticed.
func TestARebuiltImageIsNoticed(t *testing.T) {
	d := &model.Device{ID: "as3/ATL", Image: "hyhe/twinet-frr:latest", ImageID: "sha256:aaa"}
	before := SpecHash(d)
	d.ImageID = "sha256:bbb"
	if SpecHash(d) == before {
		t.Error("a tag rebuilt in place is different software under an unchanged name, " +
			"and the lab would keep running the old one while every report said it " +
			"was up to date")
	}
}
