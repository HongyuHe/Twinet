package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// A submission archive states which group and which AS it belongs to, and
// carries a checksum for every file. All of it was written by whoever produced
// the archive and stored inside it, so none of it constrained anybody: a
// student editing a configuration recomputes the sha256 sitting next to it, and
// a student wanting a better mark edits the group field.
//
// These tests are about what a forged archive can no longer do.
func TestAnEditedSubmissionIsRefused(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)

	honest := Bundle{
		Lab: "cos461", AS: 3, Group: "group3", Topology: "abc123",
		TakenAt: time.Now().UTC().Truncate(time.Second),
		Files:   map[string]string{"ATL.conf": "aaaa", "MSP.conf": "bbbb"},
	}
	sig := signBundle(honest, key)
	if !verifyBundle(honest, sig, pub) {
		t.Fatal("an honest archive does not verify; nothing else here means anything")
	}

	tampered := []struct {
		what string
		why  string
		with func(*Bundle)
	}{
		{
			what: "claiming another group",
			why:  "this is how one student's work is submitted under another's name",
			with: func(b *Bundle) { b.Group = "group7" },
		},
		{
			what: "claiming another AS",
			why:  "the AS decides which rubric runs and whose topology it is graded on",
			with: func(b *Bundle) { b.AS = 7 },
		},
		{
			what: "swapping a file's checksum",
			why:  "the checksum is the only thing tying the archive to its contents",
			with: func(b *Bundle) { b.Files["ATL.conf"] = "cccc" },
		},
		{
			what: "adding a file",
			why:  "an extra configuration could carry the answer to a question not attempted",
			with: func(b *Bundle) { b.Files["EXTRA.conf"] = "dddd" },
		},
		{
			what: "removing a file",
			why:  "dropping a bad router hides a failing check",
			with: func(b *Bundle) { delete(b.Files, "MSP.conf") },
		},
		{
			what: "claiming a different topology",
			why:  "this is how work is replayed against a lab it was never written for",
			with: func(b *Bundle) { b.Topology = "deadbeef" },
		},
		{
			what: "backdating the collection",
			why:  "a late submission presented as an on-time one",
			with: func(b *Bundle) { b.TakenAt = b.TakenAt.Add(-72 * time.Hour) },
		},
	}

	for _, c := range tampered {
		t.Run(c.what, func(t *testing.T) {
			forged := honest
			forged.Files = map[string]string{}
			for k, v := range honest.Files {
				forged.Files[k] = v
			}
			c.with(&forged)
			if verifyBundle(forged, sig, pub) {
				t.Errorf("an archive %s still verified against the original signature.\n%s.",
					c.what, c.why)
			}
		})
	}
}

// Re-signing with a different key must not help either, or a student who
// generates their own key pair simply signs whatever they like.
func TestASubmissionSignedBySomebodyElseIsRefused(t *testing.T) {
	_, mine, _ := ed25519.GenerateKey(rand.Reader)
	_, theirs, _ := ed25519.GenerateKey(rand.Reader)

	b := Bundle{Lab: "cos461", AS: 3, Group: "group3",
		Files: map[string]string{"ATL.conf": "aaaa"}}

	if verifyBundle(b, signBundle(b, theirs), mine.Public().(ed25519.PublicKey)) {
		t.Error("an archive signed with a key of the student's own choosing was accepted; " +
			"they can then sign any claim they like")
	}
}

// An absent signature must not read as "not signed, carry on", or deleting the
// signature is the whole attack.
func TestAnUnsignedSubmissionIsRefusedByDefault(t *testing.T) {
	b := Bundle{Lab: "cos461", AS: 3, Group: "group3"}

	if err := checkBundleSignature(b, "", false); err == nil {
		t.Error("an unsigned archive was accepted; removing the signature would then be " +
			"enough to submit anything at all")
	}
	// The escape hatch has to exist for archives collected by an older build,
	// but it has to be asked for.
	if err := checkBundleSignature(b, "", true); err != nil {
		t.Errorf("--allow-unsigned did not allow an unsigned archive: %v", err)
	}
}

// The signature must cover the identity, not only the file checksums. Signing
// the checksums alone leaves the group and AS free to be rewritten, which is
// the impersonation this exists to prevent.
func TestTheSignedBytesCoverTheIdentity(t *testing.T) {
	a := Bundle{Lab: "l", AS: 3, Group: "group3", Files: map[string]string{"x": "1"}}
	b := a
	b.Group = "group9"
	if string(bundleBytes(a)) == string(bundleBytes(b)) {
		t.Error("the group is not part of what gets signed, so it can be rewritten freely")
	}
	c := a
	c.AS = 9
	if string(bundleBytes(a)) == string(bundleBytes(c)) {
		t.Error("the AS is not part of what gets signed")
	}
}

// The bytes that get signed must not depend on Go's map iteration order, or the
// same archive verifies on one run and fails on the next.
func TestTheSignedBytesAreStable(t *testing.T) {
	b := Bundle{Lab: "l", AS: 3, Group: "g", Files: map[string]string{}}
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		b.Files[n] = n
	}
	first := string(bundleBytes(b))
	for i := 0; i < 50; i++ {
		if got := string(bundleBytes(b)); got != first {
			t.Fatal("the signed bytes vary between runs, so archives would be rejected at random")
		}
	}
}
