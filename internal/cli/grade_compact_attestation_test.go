package cli

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/model"
)

func TestCompactEligibilityFailsClosedWithoutGradingImageLock(t *testing.T) {
	topology := &model.Topology{Hash: "top", Lab: &model.Lab{}}
	ok, hash, why := compactEligibility(topology, &grade.Rubric{}, "", "")
	if ok || hash != "" || why == "" {
		t.Fatalf("development topology enabled unattested compact harness: ok=%v hash=%q why=%q", ok, hash, why)
	}
}

func TestGraderSourceIdentityRequiresSHA256(t *testing.T) {
	original := SourceDigest
	SourceDigest = strings.Repeat("a", 64)
	t.Cleanup(func() { SourceDigest = original })

	got, ok := graderSourceIdentity()
	if !ok || got != SourceDigest {
		t.Fatalf("SHA-256 build-input digest was rejected: digest=%q ok=%v", got, ok)
	}

	SourceDigest = "dirty"
	if _, ok := graderSourceIdentity(); ok {
		t.Fatal("non-SHA-256 source identity was accepted")
	}
}
