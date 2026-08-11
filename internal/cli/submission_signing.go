package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// A submission archive says which group and which AS it belongs to, and carries
// a checksum for every file in it. Both were written by whoever produced the
// archive, and stored inside the archive.
//
// That is no protection at all. A student who edits a configuration recomputes
// the checksum -- it is a sha256 of a file sitting next to it. A student who
// wants someone else's mark, or wants their own work attributed to a group that
// did better, edits the group and AS fields. Nothing downstream could tell,
// because there was nothing to check against.
//
// So the archive is signed by the machine that produced it. `twinet save` is a
// staff operation; students never run it. A signature over the manifest binds
// the identity and the checksums together and to the platform, so an edited or
// forged archive is refused rather than graded.
//
// Ed25519, and not an HMAC, because grading does not have to happen on the
// machine that collected the work. The verifier needs only the public half.

const (
	bundleKeyFile = "submission_key.pem"
	bundlePubFile = "submission_pub.pem"
)

// signBundle returns a detached signature over the bundle's identity and file
// checksums.
func signBundle(b Bundle, key ed25519.PrivateKey) string {
	return fmt.Sprintf("%x", ed25519.Sign(key, bundleBytes(b)))
}

// bundleBytes is the exact byte sequence that is signed.
//
// It is built field by field rather than by marshalling the struct, so that
// adding a field cannot silently drop it out of the signature -- and it
// deliberately covers the identity fields as well as the checksums. Signing
// only the checksums would leave the group and AS free to be edited, which is
// the impersonation this exists to stop.
func bundleBytes(b Bundle) []byte {
	var sb strings.Builder
	fmt.Fprintf(&sb, "lab=%s\nas=%d\ngroup=%s\ntopology=%s\ntaken=%s\n",
		b.Lab, b.AS, b.Group, b.Topology, b.TakenAt.UTC().Format("2006-01-02T15:04:05Z"))
	names := make([]string, 0, len(b.Files))
	for n := range b.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&sb, "file=%s=%s\n", n, b.Files[n])
	}
	return []byte(sb.String())
}

// verifyBundle checks the signature against the public key.
func verifyBundle(b Bundle, sig string, pub ed25519.PublicKey) bool {
	raw := make([]byte, 0, len(sig)/2)
	for i := 0; i+1 < len(sig); i += 2 {
		var v int
		if _, err := fmt.Sscanf(sig[i:i+2], "%02x", &v); err != nil {
			return false
		}
		raw = append(raw, byte(v))
	}
	return ed25519.Verify(pub, bundleBytes(b), raw)
}

// submissionKey loads the signing key, creating one on first use.
//
// It lives with the cluster's other credentials rather than in the lab
// directory, because a key kept beside the archives it signs is worth as much
// as no key: anyone who can edit an archive can re-sign it.
func submissionKey() (ed25519.PrivateKey, error) {
	dir, err := credentialDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, bundleKeyFile)
	if raw, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(raw)
		if blk == nil {
			return nil, fmt.Errorf("%s is not a PEM key", path)
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		ed, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s is not an ed25519 key", path)
		}
		return ed, nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	pder, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, bundlePubFile),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pder}), 0o644); err != nil {
		return nil, err
	}
	return priv, nil
}

// submissionPublicKey loads the verifying half.
func submissionPublicKey() (ed25519.PublicKey, error) {
	dir, err := credentialDir()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, bundlePubFile))
	if err != nil {
		// The private key implies the public one, so a machine that signs can
		// always verify even if only the key file was copied.
		if k, kerr := existingSubmissionKey(dir); kerr == nil {
			return k.Public().(ed25519.PublicKey), nil
		}
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, fmt.Errorf("submission public key is not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("submission public key is not ed25519")
	}
	return pub, nil
}

func existingSubmissionKey(dir string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(filepath.Join(dir, bundleKeyFile))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, fmt.Errorf("not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not ed25519")
	}
	return ed, nil
}

func credentialDir() (string, error) {
	if d := os.Getenv("TWINET_PKI"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".twinet", "pki"), nil
}

// checkBundleSignature decides whether an archive may be graded.
//
// It fails closed. An archive with no signature is refused unless the operator
// says explicitly that unsigned archives are acceptable -- if an absent
// signature meant "not signed, carry on", then removing the signature would be
// the whole attack.
func checkBundleSignature(b Bundle, sig string, allowUnsigned bool) error {
	if sig == "" {
		if allowUnsigned {
			return nil
		}
		return fmt.Errorf("this archive is not signed, so nothing shows it was produced by " +
			"`twinet save` rather than written by hand; the group, the AS and every checksum " +
			"in it are whatever its author chose. Re-collect it, or pass --allow-unsigned if " +
			"you know where it came from")
	}
	pub, err := submissionPublicKey()
	if err != nil {
		return fmt.Errorf("this archive is signed but the key to check it against could not "+
			"be read (%w); grading it would be accepting a signature nobody verified", err)
	}
	if !verifyBundle(b, sig, pub) {
		return fmt.Errorf("this archive's signature does not match its contents: it was edited "+
			"after it was collected, or it was not produced by this platform. It claims to be "+
			"AS %d, group %q", b.AS, b.Group)
	}
	return nil
}

// bundleJSON marshals the manifest with its signature attached.
func bundleJSON(b Bundle, sig string) ([]byte, error) {
	type signed struct {
		Bundle
		Signature string `json:"signature,omitempty"`
	}
	return json.MarshalIndent(signed{Bundle: b, Signature: sig}, "", "  ")
}

// allowUnsignedBundles relaxes the signature requirement.
//
// It is a package-level switch rather than a parameter because readBundle is
// called from several commands and threading a flag through all of them would
// make it easy to add a caller that forgot. It defaults to refusing, and only
// an explicit --allow-unsigned turns it off, for the transition period where
// archives collected by an older build have no signature.
var allowUnsignedBundles bool
