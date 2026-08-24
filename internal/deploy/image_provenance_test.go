package deploy

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/runtime"
)

type digestRuntime struct {
	runtime.Runtime
	digest string
	err    error
}

func (r digestRuntime) ImageDigest(context.Context, string) (string, error) {
	return r.digest, r.err
}

func TestPostPullDigestMismatchRefusesBeforeContainerCreate(t *testing.T) {
	ref := "registry.example/router@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := &Engine{
		Runtime:                digestRuntime{digest: "registry.example/router@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		RequireImmutableImages: true,
	}
	err := engine.verifyPulledImage(context.Background(), ref)
	if err == nil || !strings.Contains(err.Error(), "runtime reports") {
		t.Fatalf("post-pull digest mismatch = %v", err)
	}
}

func TestPostPullAcceptsContainerdDigestOnlyIdentity(t *testing.T) {
	ref := "registry.example/router@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := &Engine{
		Runtime: digestRuntime{
			digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		RequireImmutableImages: true,
	}
	if err := engine.verifyPulledImage(context.Background(), ref); err != nil {
		t.Fatalf("matching containerd digest-only identity was rejected: %v", err)
	}
}

func TestReleaseModeRefusesMutablePostPullReference(t *testing.T) {
	engine := &Engine{Runtime: digestRuntime{digest: "sha256:local-config"}, RequireImmutableImages: true}
	err := engine.verifyPulledImage(context.Background(), "registry.example/router:dev")
	if err == nil || !strings.Contains(err.Error(), "immutable registry digest") {
		t.Fatalf("mutable release image = %v", err)
	}
}
