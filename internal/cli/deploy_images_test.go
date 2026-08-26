package cli

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/images"
	"github.com/HongyuHe/twinet/internal/model"
)

// A student's devices must not run different software depending on which node
// their autonomous system was scheduled onto.
//
// The image resolver accepted the first node's answer and stopped asking.
// Measured on this cluster: all four images differed between node-0 and the
// other two, while every report said the deployment was current. A mark that
// depends on where a container happened to be placed is not a mark, and nothing
// downstream could have detected it.
func TestADeployRefusesWhenTheNodesDisagreeOnAnImage(t *testing.T) {
	skewed := map[string]map[string]string{
		"hyhe/twinet-router:0.1": {
			"node-0": "sha256:26d10acd7dcc11112222",
			"node-1": "sha256:43372cd01d7c33334444",
			"node-2": "sha256:43372cd01d7c33334444",
		},
	}
	err := sameEverywhere(skewed)
	if err == nil {
		t.Fatal("a deployment was allowed to proceed with different images on different nodes")
	}
	for _, want := range []string{"hyhe/twinet-router:0.1", "node-0", "node-1,node-2", "26d10acd7dcc", "43372cd01d7c"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so the operator cannot act on it:\n%s", want, err)
		}
	}
}

func TestAgreementIsNotMistakenForSkew(t *testing.T) {
	agreed := map[string]map[string]string{
		"hyhe/twinet-router:0.1": {
			"node-0": "sha256:06350bc44aee",
			"node-1": "sha256:06350bc44aee",
			"node-2": "sha256:06350bc44aee",
		},
		// A node that has not pulled an image yet reports nothing and is not
		// recorded, so a first deployment is still possible.
		"hyhe/twinet-host:0.1": {"node-0": "sha256:23b9bb8fea9b"},
	}
	if err := sameEverywhere(agreed); err != nil {
		t.Errorf("a consistent cluster was refused: %v", err)
	}
}

func TestImageCacheCoherenceCoversOnlyAssignedNodes(t *testing.T) {
	required := map[string]map[string]bool{
		"hyhe/twinet-bird:0.1": {"node-0": true},
	}
	present := map[string]map[string]string{
		"hyhe/twinet-bird:0.1": {"node-0": "sha256:06350bc44aee"},
	}
	if err := allOrNoneHaveIt(present, required); err != nil {
		t.Fatalf("an image used only on node-0 required unrelated caches: %v", err)
	}
}

func TestImageCacheCoherenceNamesMissingAssignedNodes(t *testing.T) {
	required := map[string]map[string]bool{
		"hyhe/twinet-router:0.1": {
			"node-0": true, "node-1": true, "node-2": true,
		},
	}
	present := map[string]map[string]string{
		"hyhe/twinet-router:0.1": {
			"node-0": "sha256:06350bc44aee",
		},
	}
	err := allOrNoneHaveIt(present, required)
	if err == nil {
		t.Fatal("a partially cached image was accepted on its assigned nodes")
	}
	for _, want := range []string{
		"node-0", "node-1, node-2", "mutable image tags", "selected runtime", "pin it by digest",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not contain %q:\n%s", want, err)
		}
	}
}

const (
	pinnedRouter = "hyhe/twinet-router:0.1@sha256:" +
		"6d5cd4ae3a199706d0be931b9dd977868a0e717778533fc91e4488173003e17a"
	pinnedRouterDigest = "sha256:" +
		"6d5cd4ae3a199706d0be931b9dd977868a0e717778533fc91e4488173003e17a"
	// A manifest no bundled lock names, so a survey can be corrupted with it
	// whichever image is picked.
	otherManifest = "sha256:" +
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

// A digest-pinned reference names one manifest, so a node that does not have
// it can only pull that manifest or fail. Unequal caches are the ordinary
// state of a cluster after a partial run, and refusing them stopped the
// documented release scale benchmark dead: every reference in the refusal was
// already pinned by a verified lock, and the remedy the message offered --
// pin it by digest -- was the state already in force. The operator's only way
// forward was to preload six images onto two nodes by hand.
func TestPartiallyCachedDigestPinnedImageIsAllowed(t *testing.T) {
	required := map[string]map[string]bool{
		pinnedRouter: {"node-0": true, "node-1": true, "node-2": true},
	}
	present := map[string]map[string]string{
		pinnedRouter: {"node-0": pinnedRouterDigest},
	}
	if err := allOrNoneHaveIt(present, required); err != nil {
		t.Fatalf("a digest-pinned image was refused because only one node had "+
			"pulled it, which is what blocked `make benchmark`: %v", err)
	}
	if err := pinnedCachesMatchTheirDigest(present); err != nil {
		t.Fatalf("the one node that has the pinned manifest was refused: %v", err)
	}
	if err := sameEverywhere(present); err != nil {
		t.Fatalf("a single-node answer was read as disagreement: %v", err)
	}
}

// The refusal exists for tags, and only for tags: a tag rebuilt between one
// node's pull and another's is different software under one name, and nothing
// downstream would say so.
func TestPartiallyCachedMutableTagIsStillRefused(t *testing.T) {
	required := map[string]map[string]bool{
		"hyhe/twinet-host:0.1": {"node-0": true, "node-1": true},
	}
	present := map[string]map[string]string{
		"hyhe/twinet-host:0.1": {"node-0": "sha256:06350bc44aee"},
	}
	err := allOrNoneHaveIt(present, required)
	if err == nil {
		t.Fatal("a partially cached mutable tag was accepted")
	}
	if !strings.Contains(err.Error(), "mutable image tags") {
		t.Errorf("the refusal does not say the reference is a mutable tag, so an "+
			"operator cannot tell it apart from a pinned one:\n%s", err)
	}
}

// A reference that advertises a digest it cannot honour is neither a pin nor
// an honest tag. Deploying it on the strength of matching caches would run
// software nothing can verify afterwards, under a name that claims it can.
func TestMalformedPseudoDigestIsRefused(t *testing.T) {
	for _, ref := range []string{
		"hyhe/twinet-router:0.1@sha256:deadbeef",
		"hyhe/twinet-router:0.1@sha256:" + strings.Repeat("z", 64),
		"hyhe/twinet-router:0.1@sha256:" + strings.Repeat("A", 64),
	} {
		err := refuseMalformedPins([]string{ref})
		if err == nil {
			t.Fatalf("%s was accepted as a digest-pinned reference", ref)
		}
		if !strings.Contains(err.Error(), ref) ||
			!strings.Contains(err.Error(), "64 lower-case hexadecimal") {
			t.Errorf("the refusal does not say what is wrong with %s:\n%s", ref, err)
		}
		// A malformed pin must not fall through to the tag rule either: it is
		// refused whatever the caches look like.
		if images.Digest(ref) != "" {
			t.Errorf("%s parsed as a valid digest", ref)
		}
	}
	if err := refuseMalformedPins([]string{
		pinnedRouter, "hyhe/twinet-host:0.1", "registry.local:5000/twinet-svc:0.1",
	}); err != nil {
		t.Fatalf("well-formed references were refused: %v", err)
	}
}

func TestEveryRequiredNodeHoldingTheExactManifestIsAccepted(t *testing.T) {
	required := map[string]map[string]bool{
		pinnedRouter: {"node-0": true, "node-1": true, "node-2": true},
	}
	present := map[string]map[string]string{
		pinnedRouter: {
			"node-0": pinnedRouterDigest,
			// Docker answers with a repository-qualified digest and containerd
			// with a bare one. The same manifest spelled two ways is not a
			// disagreement.
			"node-1": pinnedRouter,
			"node-2": pinnedRouterDigest,
		},
	}
	if err := pinnedCachesMatchTheirDigest(present); err != nil {
		t.Fatalf("a cluster that all holds the pinned manifest was refused: %v", err)
	}
	if err := sameEverywhere(present); err != nil {
		t.Fatalf("two spellings of one manifest were read as skew: %v", err)
	}
	if err := allOrNoneHaveIt(present, required); err != nil {
		t.Fatalf("a fully cached lab was refused: %v", err)
	}
}

// A node that answers a pinned reference with another manifest is not a tag
// that moved: it is a cache that cannot serve what was asked for. The pull
// would be verified against the same answer, so the transaction is refused
// before anything is touched, and the operator is told which node to clear
// rather than to pin an image that is already pinned.
func TestAPinnedReferenceCachedAsAnotherManifestIsRefused(t *testing.T) {
	err := pinnedCachesMatchTheirDigest(map[string]map[string]string{
		pinnedRouter: {"node-0": pinnedRouterDigest, "node-1": otherManifest},
	})
	if err == nil {
		t.Fatal("a node holding a different manifest under a pinned reference was accepted")
	}
	for _, want := range []string{"node-1", pinnedRouterDigest, otherManifest} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q:\n%s", want, err)
		}
	}
	if strings.Contains(err.Error(), "pin it by digest") {
		t.Errorf("the refusal recommends the pinning that is already in force:\n%s", err)
	}
}

// The preflight survey asks nodes what they hold; it must not let that answer
// overwrite an identity the lock already proved. A stale local alias adopted
// here becomes the container spec hash, so the next caller -- grading's
// restore, a no-op redeploy -- computes a different one and recreates every
// container it was meant to leave alone.
func TestAPinnedReferenceKeepsItsAuthoredIdentity(t *testing.T) {
	surveyed := map[string]string{pinnedRouter: otherManifest}
	if got := stampedImageIdentity(pinnedRouter, surveyed, pinnedRouterDigest); got != pinnedRouterDigest {
		t.Fatalf("the authored digest was replaced with a cached identity %q", got)
	}
	if got := stampedImageIdentity(pinnedRouter, nil, ""); got != pinnedRouterDigest {
		t.Errorf("a pinned reference on a cluster that has never pulled it resolved to %q", got)
	}
	// A mutable tag has no identity of its own, so the survey still supplies it.
	if got := stampedImageIdentity("hyhe/twinet-host:0.1",
		map[string]string{"hyhe/twinet-host:0.1": otherManifest}, ""); got != otherManifest {
		t.Errorf("a tag's surveyed identity was discarded: %q", got)
	}
	if got := stampedImageIdentity("hyhe/twinet-host:0.1", nil, "sha256:already"); got != "sha256:already" {
		t.Errorf("an established identity was erased by an empty survey: %q", got)
	}
}

// The release scale benchmark deploys examples/scale from its shipped lock.
// This is that preflight, with the cluster in the state `make benchmark`
// actually found it in: node-0 had pulled everything during an earlier run and
// node-1/node-2 had not.
func TestScaleBenchmarkPreflightSurvivesUnequalCaches(t *testing.T) {
	root := documentationRepoRoot(t)
	lock, err := images.Load(filepath.Join(root, "examples", "scale", "images.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]map[string]bool{}
	present := map[string]map[string]string{}
	var refs []string
	for _, pinned := range lock.Images {
		refs = append(refs, pinned)
		required[pinned] = map[string]bool{"node-0": true, "node-1": true, "node-2": true}
		present[pinned] = map[string]string{"node-0": images.Digest(pinned)}
	}
	if len(refs) == 0 {
		t.Fatal("the scale lock has no images")
	}
	sort.Strings(refs)
	if err := refuseMalformedPins(refs); err != nil {
		t.Fatalf("the shipped scale lock does not survive its own pin check: %v", err)
	}
	if err := imageCachesAllowDeployment(present, required); err != nil {
		t.Fatalf("`make benchmark` cannot reach deployment from unequal caches: %v", err)
	}
	// The same survey with one node holding a different manifest is still
	// refused, so the allowance is about pinning and not about giving up.
	corrupt := map[string]map[string]string{}
	for ref, perNode := range present {
		corrupt[ref] = map[string]string{"node-0": perNode["node-0"]}
	}
	corrupt[refs[0]]["node-1"] = otherManifest
	if err := imageCachesAllowDeployment(corrupt, required); err == nil {
		t.Fatal("a node holding another manifest under a locked reference was accepted")
	}
}

// The whole preflight, on a clustered release lab whose nodes have not been
// surveyed at all -- the state of a cluster the controller has no token for,
// and of every first deployment. The devices must still carry the locked
// manifest into the container specification, because that is what the agents
// are then held to after they pull.
func TestPreflightStampsTheLockedManifestWithoutASurvey(t *testing.T) {
	t.Setenv("TWINET_TOKEN", "")
	top := &model.Topology{
		Name: "scale",
		Lab: &model.Lab{Placement: model.Placement{Nodes: []model.NodeSpec{
			{Name: "node-0"}, {Name: "node-1"}, {Name: "node-2"},
		}}},
		Devices: map[string]*model.Device{
			"as1/R1": {ID: "as1/R1", Node: "node-0", Image: pinnedRouter, ImageID: pinnedRouterDigest},
			"as2/R2": {ID: "as2/R2", Node: "node-1", Image: pinnedRouter, ImageID: pinnedRouterDigest},
			"as3/R3": {ID: "as3/R3", Node: "node-2", Image: pinnedRouter},
		},
	}
	if !clustered(top) {
		t.Fatal("the lab under test is not clustered, so the preflight path is not exercised")
	}
	if err := resolveImageIDs(t.Context(), top, ""); err != nil {
		t.Fatalf("a digest-pinned lab was refused before any node was asked: %v", err)
	}
	for _, d := range top.SortedDevices() {
		if d.ImageID != pinnedRouterDigest {
			t.Errorf("%s carries identity %q, not the locked manifest %q",
				d.ID, d.ImageID, pinnedRouterDigest)
		}
	}
	top.Devices["as1/R1"].Image = "hyhe/twinet-router:0.1@sha256:deadbeef"
	if err := resolveImageIDs(t.Context(), top, ""); err == nil {
		t.Fatal("a reference claiming a digest it does not carry was deployed")
	}
}

func TestRequiredImageNodesFollowPlacement(t *testing.T) {
	top := &model.Topology{Devices: map[string]*model.Device{
		"as1/A": {ID: "as1/A", Node: "node-0", Image: "router"},
		"as2/B": {ID: "as2/B", Node: "node-1", Image: "router"},
		"as3/C": {ID: "as3/C", Node: "node-0", Image: "bird"},
		"as4/D": {ID: "as4/D", Image: "unplaced"},
	}}
	got := requiredImageNodes(top)
	for image, nodes := range map[string][]string{
		"router": {"node-0", "node-1"},
		"bird":   {"node-0"},
	} {
		for _, node := range nodes {
			if !got[image][node] {
				t.Errorf("%s is not required on %s: %#v", image, node, got)
			}
		}
	}
	if _, ok := got["unplaced"]; ok {
		t.Fatalf("unplaced image entered a node coherence boundary: %#v", got)
	}
}
