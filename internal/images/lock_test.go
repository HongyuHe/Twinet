package images

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

const digestA = "registry.example/twinet-router@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestLockRejectsLocalImageID(t *testing.T) {
	_, err := NewLock("topology", "v1", "abc", map[string]string{
		"registry.example/twinet-router:v1": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err == nil || !strings.Contains(err.Error(), "immutable registry digest") {
		t.Fatalf("local image ID lock error = %v", err)
	}
}

func TestReleaseLockRewritesTopologyToImmutableReferences(t *testing.T) {
	top := &model.Topology{
		Name: "lab", Hash: "topology",
		Lab: &model.Lab{Images: model.ImagePolicy{
			Mode: model.ImageModeRelease, Lock: "missing.json",
		}},
		Devices: map[string]*model.Device{
			"as1/R1": {ID: "as1/R1", Image: "registry.example/twinet-router:v1"},
		},
	}
	if _, err := Apply(top); err == nil || !strings.Contains(err.Error(), "read image lock") {
		t.Fatalf("release policy without a lock file = %v", err)
	}
}

func TestDevelopmentTagsNeedAnExplicitMode(t *testing.T) {
	top := &model.Topology{
		Name: "lab", Hash: "topology", Lab: &model.Lab{},
		Devices: map[string]*model.Device{
			"as1/R1": {ID: "as1/R1", Image: "registry.example/twinet-router:v1"},
		},
	}
	if _, err := Apply(top); err == nil || !strings.Contains(err.Error(), "explicit images.mode") {
		t.Fatalf("implicit mutable development tag = %v", err)
	}
	if !IsImmutable(digestA) || Digest(digestA) == "" {
		t.Fatal("valid immutable digest was not recognized")
	}
}

func TestSameDigestAcceptsContainerdDigestOnlyIdentity(t *testing.T) {
	const bare = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if !SameDigest(digestA, bare) || Digest(bare) != bare {
		t.Fatalf("registry digest %q and runtime identity %q were treated as different",
			digestA, bare)
	}
	for _, invalid := range []string{
		"sha256:short",
		"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		if Digest(invalid) != "" {
			t.Fatalf("invalid digest %q was accepted", invalid)
		}
	}
}

// A reference that advertises a digest and then does not carry one is nobody's
// intent: whoever wrote it believed the deployment was pinned. Telling it
// apart from an honest tag is what lets the deployment refuse it instead of
// quietly treating it as a moving name.
func TestClaimsDigestSeparatesBrokenPinsFromHonestTags(t *testing.T) {
	for _, pretender := range []string{
		"registry.example/twinet-router:v1@sha256:deadbeef",
		"registry.example/twinet-router@sha256:" + strings.Repeat("z", 64),
		"registry.example/twinet-router@sha256:",
	} {
		if !ClaimsDigest(pretender) {
			t.Errorf("%q does not read as a claimed digest", pretender)
		}
		if IsImmutable(pretender) || Digest(pretender) != "" {
			t.Errorf("%q was accepted as an immutable reference", pretender)
		}
	}
	for _, tag := range []string{
		"registry.example/twinet-router:v1",
		"twinet-router",
		"registry.local:5000/twinet-router:0.1",
	} {
		if ClaimsDigest(tag) {
			t.Errorf("mutable tag %q was read as a claimed digest", tag)
		}
	}
	if !ClaimsDigest(digestA) || !IsImmutable(digestA) {
		t.Fatalf("%q is a well-formed pin and was not recognised as one", digestA)
	}
}

func TestApplyRejectsMissingDeviceImageBeforeDeployment(t *testing.T) {
	top := &model.Topology{
		Lab: &model.Lab{Images: model.ImagePolicy{Mode: model.ImageModeDevelopment}},
		Devices: map[string]*model.Device{
			"as42/leaf1": {ID: "as42/leaf1", Kind: model.KindRouter},
		},
	}
	_, err := Apply(top)
	if err == nil || !strings.Contains(err.Error(), "device as42/leaf1 has no image") {
		t.Fatalf("missing device image was accepted: %v", err)
	}
}

func TestLockRoundTripBindsReleaseTopology(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".test-lock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	lock, err := NewLock("topology", "v1.2.3", "abcdef", map[string]string{
		"registry.example/twinet-router:v1": digestA,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "images.lock.json")
	if err := Write(path, lock); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.Images, lock.Images) || loaded.ManifestHash != lock.ManifestHash {
		t.Fatalf("lock round trip = %#v, want %#v", loaded, lock)
	}
	top := &model.Topology{
		Name: "lab", Hash: "topology",
		Lab: &model.Lab{Dir: dir, Images: model.ImagePolicy{
			Mode: model.ImageModeRelease, Lock: "images.lock.json",
		}},
		Devices: map[string]*model.Device{
			"as1/R1": {ID: "as1/R1", Image: "registry.example/twinet-router:v1"},
		},
	}
	if _, err := Apply(top); err != nil {
		t.Fatal(err)
	}
	device := top.Devices["as1/R1"]
	if device.Image != digestA || device.ImageID != Digest(digestA) || top.Lab.Images.LockDigest == "" {
		t.Fatalf("release lock was not applied to topology: %#v / %#v", device, top.Lab.Images)
	}
}
