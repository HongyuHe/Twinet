package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePub(t *testing.T, dir, name string, pub ed25519.PublicKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, name), blob, 0o644); err != nil {
		t.Fatal(err)
	}
}

func aBundle() Bundle {
	return Bundle{
		Lab: "cos461", AS: 3, Group: "group3", Topology: "b6c08db96552",
		TakenAt: time.Date(2026, 8, 12, 1, 2, 3, 0, time.UTC),
		Files:   map[string]string{"frr.conf": "deadbeef"},
	}
}

// Collection and grading do not have to happen on the same machine, and for a
// class of any size they do not. Trust used to be one machine's private key, so
// the only way to mark work collected elsewhere was to copy that private key --
// the one thing that must never be copied, since it signs anything at all.
func TestAnArchiveCollectedElsewhereCanBeVerifiedFromItsPublicKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TWINET_PKI", home)

	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := aBundle()
	sig := signBundle(b, otherPriv)

	if err := checkBundleSignature(b, sig, false); err == nil {
		t.Fatal("an archive signed by a key this machine has never heard of was accepted")
	}

	writePub(t, filepath.Join(home, trustedSignersDir), "collector.pem", otherPub)

	if err := checkBundleSignature(b, sig, false); err != nil {
		t.Fatalf("an archive signed by a trusted collector was refused: %v", err)
	}
}

// Trusting another machine must not weaken the check it exists to perform.
func TestAnEditedArchiveIsStillRefusedWithTrustedSigners(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TWINET_PKI", home)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writePub(t, filepath.Join(home, trustedSignersDir), "collector.pem", pub)

	b := aBundle()
	sig := signBundle(b, priv)

	// The student rewrites the archive to claim a group that scored better.
	b.Group = "group7"
	err = checkBundleSignature(b, sig, false)
	if err == nil {
		t.Fatal("an archive whose group was rewritten after collection was accepted")
	}
	if !strings.Contains(err.Error(), "group7") {
		t.Errorf("the refusal does not say what the archive claims to be: %v", err)
	}
}

// A key file that was meant to be trusted and cannot be read must not read as a
// tampered archive: that message points at a student for the operator's typo.
func TestAnUnreadableTrustedKeyIsReportedAsSuch(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TWINET_PKI", home)
	dir := filepath.Join(home, trustedSignersDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "typo.pem"), []byte("not a key"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	b := aBundle()
	err := checkBundleSignature(b, signBundle(b, priv), false)
	if err == nil {
		t.Fatal("a broken trusted key file was ignored and the archive accepted")
	}
	if !strings.Contains(err.Error(), "typo.pem") {
		t.Errorf("the failure does not name the file that could not be read, so the "+
			"operator will look at the student instead: %v", err)
	}
}

// Key identifiers are what let a person tell "edited" from "collected on the
// other machine" apart.
func TestKeysHaveDistinctReadableIdentifiers(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	if keyID(a) == keyID(b) {
		t.Fatal("two different keys have the same identifier")
	}
	again := a
	if keyID(a) != keyID(again) {
		t.Fatal("the same key has two identifiers")
	}
	if n := len(keyID(a)); n < 8 || n > 32 {
		t.Errorf("identifier is %d characters, which is not something anyone will compare", n)
	}
	if trustedKeyIDs(nil) != "none" {
		t.Error("an empty trust set does not say so")
	}
}
