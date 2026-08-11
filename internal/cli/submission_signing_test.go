package cli

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
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

// A signature over a list of files says nothing about a file that is not in
// the list. The archive is read by code that applies every configuration it is
// handed, so an unlisted file travelling alongside a listed one is a way to
// change what gets graded while leaving the signature perfectly valid.
//
// This is the shape of the attack: the manifest lists and signs R.conf, and
// the archive also carries r.conf, which nobody signed. The restore path
// matches configuration names case-insensitively, so the unsigned one wins.
func TestAnArchiveMayContainOnlyWhatItSigned(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TWINET_PKI", t.TempDir())

	honest := map[string]string{"R1.conf": "router bgp 1\n"}
	smuggled := map[string]string{
		"an unlisted file":       "r1.conf",
		"a plausible extra file": "R2.conf",
		"a shell script":         "setup.sh",
	}

	for what, extra := range smuggled {
		t.Run(what, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(what, " ", "_")+".tar.gz")
			writeBundleWithExtra(t, p, honest, extra, "router bgp 666\n")

			_, _, err := readBundle(p)
			if err == nil {
				t.Fatalf("an archive carrying %s alongside its signed files was accepted.\n"+
					"The signature covers the manifest's list, so a file outside that list "+
					"is one nobody vouched for -- and the code that consumes the archive "+
					"applies every configuration it is given.", extra)
			}
			if !strings.Contains(err.Error(), "signed manifest") &&
				!strings.Contains(err.Error(), "name the same file") {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}

	// The same archive without the extra file must still be accepted, or this
	// is a check that refuses everything and proves nothing.
	p := filepath.Join(dir, "clean.tar.gz")
	writeBundleWithExtra(t, p, honest, "", "")
	if _, files, err := readBundle(p); err != nil {
		t.Fatalf("an honest archive was refused, so the check above is worthless: %v", err)
	} else if len(files) != 1 {
		t.Fatalf("expected the one signed file back, got %d", len(files))
	}
}

// writeBundleWithExtra builds a properly signed archive and then adds one
// unsigned member to it, which is exactly what an attacker can do with a
// submission they were legitimately given.
func writeBundleWithExtra(t *testing.T, p string, listed map[string]string, extraName, extraBody string) {
	t.Helper()
	// A real key in a temporary directory, so the archive is signed the way a
	// genuine one is and the signature that survives the tampering is a
	// signature this platform would accept.
	key, err := submissionKey()
	if err != nil {
		t.Fatal(err)
	}

	b := Bundle{
		Lab: "cos461", AS: 3, Group: "group3", Topology: "abc123",
		TakenAt: time.Now().UTC().Truncate(time.Second),
		Files:   map[string]string{},
	}
	for name, body := range listed {
		sum := sha256.Sum256([]byte(body))
		b.Files[name] = hex.EncodeToString(sum[:])
	}
	sig := signBundle(b, key)

	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	add := func(name, body string) {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	mj, err := bundleJSON(b, sig)
	if err != nil {
		t.Fatal(err)
	}
	add("manifest.json", string(mj))
	for name, body := range listed {
		add(name, body)
	}
	if extraName != "" {
		add(extraName, extraBody)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}
