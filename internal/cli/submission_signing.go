package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
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
	bundleKeyLock = ".submission_key.lock"
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
//
// `twinet save` runs eight collectors at once, and several machines may collect
// at the same time, so the first-ever use is a load-or-create reached
// concurrently. Done unlocked it is a race: two callers each generate a
// different keypair and overwrite each other's halves, leaving a public key
// that does not verify the private key the archives were signed with. Nothing
// notices until grading, by which time the archives are collected and the cause
// is gone. So the whole load-or-create is serialised by a cross-process file
// lock, and a fresh keypair is installed by renaming temp files into place --
// atomic within a filesystem -- and never overwritten once installed, so the
// two halves are always the matched pair they were generated as.
func submissionKey() (ed25519.PrivateKey, error) {
	dir, err := credentialDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	unlock, err := lockCredentialDir(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	priv, err := loadSubmissionKeyPair(dir)
	if err == nil {
		return priv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		// The private half is present but unreadable, or present and not
		// matching its public half. Regenerating would sign future archives
		// with a key that cannot verify the ones already collected, so the
		// operator is told rather than left with a mismatch nobody can explain.
		return nil, err
	}
	return createSubmissionKeyPair(dir)
}

// loadSubmissionKeyPair reads an existing keypair and checks the halves match.
//
// A public half that does not correspond to the private half is exactly the
// wreckage an earlier unlocked race left behind. It is reported as an error so
// the mismatch is diagnosed here, at save time, rather than surfacing as an
// unverifiable archive at grading time when nothing can be re-collected.
func loadSubmissionKeyPair(dir string) (ed25519.PrivateKey, error) {
	priv, err := existingSubmissionKey(dir)
	if err != nil {
		return nil, err
	}
	derived := priv.Public().(ed25519.PublicKey)
	raw, err := os.ReadFile(filepath.Join(dir, bundlePubFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// The private key implies the public one; install the missing half
			// so a copied-in private key does not stay half a keypair.
			if werr := writeSubmissionPublic(dir, derived); werr != nil {
				return nil, werr
			}
			return priv, nil
		}
		return nil, err
	}
	pub, err := parsePublicKey(raw)
	if err != nil {
		return nil, err
	}
	if !derived.Equal(pub) {
		return nil, fmt.Errorf("%s and %s in %s are not a pair: the stored public key does "+
			"not verify the private key that would sign submissions. A previous unlocked save "+
			"most likely generated two keypairs at once; delete both files and re-run `twinet "+
			"save` to mint a fresh keypair, then re-collect any archives signed in between",
			bundleKeyFile, bundlePubFile, dir)
	}
	return priv, nil
}

// createSubmissionKeyPair mints a keypair and installs both halves atomically.
func createSubmissionKeyPair(dir string) (ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	// The private half is written first, then the public. Either order is a
	// matched pair -- a keypair is never overwritten -- and an unlocked reader
	// that catches the create half-done either finds the matching public key or
	// finds none and derives it from the private key, never a mismatched one.
	if err := writeAtomic(dir, bundleKeyFile,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	if err := writeSubmissionPublic(dir, pub); err != nil {
		return nil, err
	}
	return priv, nil
}

// writeSubmissionPublic installs the verifying half.
func writeSubmissionPublic(dir string, pub ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	return writeAtomic(dir, bundlePubFile,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
}

// lockCredentialDir takes a cross-process exclusive lock over the signing key's
// load-or-create. A flock is held against the open file description, so two
// goroutines in one process that each open the lock file exclude each other
// exactly as two processes do -- which is what makes eight concurrent
// collectors safe as well as two machines.
func lockCredentialDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, bundleKeyLock), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// writeAtomic installs a file by writing a temporary file in the same directory
// and renaming it into place. Rename is atomic within a filesystem, so a reader
// sees either the old file or the whole new one and never a half-written key.
func writeAtomic(dir, name string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(dir, name))
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
	return parsePublicKey(raw)
}

// parsePublicKey decodes a PEM-encoded ed25519 public key.
func parsePublicKey(raw []byte) (ed25519.PublicKey, error) {
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
	keys, err := trustedSubmissionKeys()
	if err != nil {
		return fmt.Errorf("this archive is signed and the keys to check it against could not "+
			"all be read (%w); grading it would be accepting a signature nobody verified", err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("this archive is signed but this machine trusts no signing key, so " +
			"nothing can check it. Copy the public half of the key that collected these " +
			"archives (submission_pub.pem on that machine) into the trusted_signers " +
			"directory beside this machine's own credentials")
	}
	for _, pub := range keys {
		if verifyBundle(b, sig, pub) {
			return nil
		}
	}
	return fmt.Errorf("this archive's signature does not match its contents under any key "+
		"this machine trusts (%s): it was edited after it was collected, or it was collected "+
		"on a machine whose public key is not installed here. It claims to be AS %d, group %q",
		trustedKeyIDs(keys), b.AS, b.Group)
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
