package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// trustedSignersDir holds the public halves of other machines allowed to
// collect submissions for this course.
const trustedSignersDir = "trusted_signers"

// keyID names a signing key in a way a person can compare.
//
// Without one, "this archive's signature does not match" is the same message
// whether the archive was edited, collected on a different machine, or
// collected before the key was rotated. Those need different responses, and an
// operator holding a term's submissions cannot afford to guess between "someone
// tampered with this" and "I graded on the wrong laptop".
func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// trustedSubmissionKeys is every key this machine will accept an archive from:
// its own, and any public key placed in the trusted signers directory.
//
// Collection and grading do not have to happen on the same machine, and for a
// course of any size they usually do not: work is collected wherever the lab
// runs and marked wherever the marker is. Trust tied to one machine's private
// key makes that impossible without copying the private key around, which is
// the one thing that must never be copied -- a private key on a shared machine
// signs anything anybody wants to submit.
//
// Publishing the public half instead costs nothing and can be done in the open.
func trustedSubmissionKeys() ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	seen := map[string]bool{}

	add := func(k ed25519.PublicKey) {
		id := keyID(k)
		if seen[id] {
			return
		}
		seen[id] = true
		keys = append(keys, k)
	}

	if k, err := submissionPublicKey(); err == nil {
		add(k)
	}

	dir, err := credentialDir()
	if err != nil {
		// No credential directory means no extra signers to trust, which is
		// the ordinary single-machine case, not a failure.
		return keys, nil //nolint:nilerr // absence is not an error here
	}
	ents, err := os.ReadDir(filepath.Join(dir, trustedSignersDir))
	if err != nil {
		return keys, nil //nolint:nilerr // no directory means no extra signers
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".pem") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var bad []string
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, trustedSignersDir, n))
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s (%v)", n, err))
			continue
		}
		k, err := parsePublicKey(raw)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s (%v)", n, err))
			continue
		}
		add(k)
	}
	// A key that was meant to be trusted and could not be read is reported
	// rather than skipped. Skipping it turns a typo into "this archive was
	// tampered with", pointed at a student.
	if len(bad) > 0 {
		return keys, fmt.Errorf("%d trusted signer file(s) could not be read: %s",
			len(bad), strings.Join(bad, "; "))
	}
	return keys, nil
}

// trustedKeyIDs lists what this machine will accept, for an error message that
// tells the operator what to do next.
func trustedKeyIDs(keys []ed25519.PublicKey) string {
	if len(keys) == 0 {
		return "none"
	}
	ids := make([]string, len(keys))
	for i, k := range keys {
		ids[i] = keyID(k)
	}
	return strings.Join(ids, ", ")
}
