// Package images implements durable image provenance for manifest deployments.
package images

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

const (
	LockAPIVersion = "twinet.dev/v1"
	LockKind       = "ImageLock"
)

// Lock is a machine-readable, manifest-bound set of registry manifest
// digests. Each map key is the authored image reference and each value is the
// immutable reference the runtime must pull.
type Lock struct {
	APIVersion    string            `json:"apiVersion"`
	Kind          string            `json:"kind"`
	ManifestHash  string            `json:"manifest_hash"`
	SourceVersion string            `json:"source_version,omitempty"`
	Commit        string            `json:"commit,omitempty"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Images        map[string]string `json:"images"`
}

// Validate proves a lock can identify actual registry manifests rather than
// local config IDs or mutable tags.
func (l Lock) Validate() error {
	if l.APIVersion != LockAPIVersion {
		return fmt.Errorf("image lock apiVersion %q, want %q", l.APIVersion, LockAPIVersion)
	}
	if l.Kind != LockKind {
		return fmt.Errorf("image lock kind %q, want %q", l.Kind, LockKind)
	}
	if strings.TrimSpace(l.ManifestHash) == "" {
		return errors.New("image lock has no manifest_hash")
	}
	if len(l.Images) == 0 {
		return errors.New("image lock has no images")
	}
	for _, ref := range sortedKeys(l.Images) {
		if strings.TrimSpace(ref) == "" {
			return errors.New("image lock has an empty image reference")
		}
		if !IsImmutable(l.Images[ref]) {
			return fmt.Errorf("image lock entry %q is not an immutable registry digest: %q",
				ref, l.Images[ref])
		}
	}
	return nil
}

// IsImmutable reports whether a reference includes a registry manifest digest.
// A bare sha256 config ID is intentionally not accepted: it is local engine
// metadata and cannot prove a registry image was pushed.
func IsImmutable(ref string) bool {
	_, digest, ok := strings.Cut(strings.TrimSpace(ref), "@sha256:")
	if !ok || len(digest) != 64 {
		return false
	}
	for _, r := range digest {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// Digest returns the sha256 manifest portion of an immutable reference.
func Digest(ref string) string {
	_, digest, ok := strings.Cut(strings.TrimSpace(ref), "@sha256:")
	if !ok || len(digest) != 64 {
		return ""
	}
	return "sha256:" + digest
}

// SameDigest compares registry references without requiring the same registry
// spelling. Runtime APIs may return docker.io/library aliases while the lock
// retains the authored source name.
func SameDigest(a, b string) bool {
	ad, bd := Digest(a), Digest(b)
	return ad != "" && ad == bd
}

// Load reads and validates a lock file.
func Load(path string) (*Lock, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read image lock %s: %w", path, err)
	}
	var lock Lock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse image lock %s: %w", path, err)
	}
	if err := lock.Validate(); err != nil {
		return nil, fmt.Errorf("validate image lock %s: %w", path, err)
	}
	return &lock, nil
}

// Write persists a lock atomically. It only accepts an already valid lock so a
// build script cannot accidentally publish a local image ID as release
// evidence.
func Write(path string, lock Lock) error {
	if err := lock.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err := file.Write(append(raw, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Chmod(file.Name(), 0o640); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// Hash returns a stable content identifier carried into reports and agent
// audit records. It uses canonical JSON so whitespace changes do not create a
// different provenance claim.
func Hash(lock Lock) (string, error) {
	if err := lock.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(lock)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// LockPath resolves a manifest-relative lock path.
func LockPath(lab *model.Lab) string {
	if lab == nil || strings.TrimSpace(lab.Images.Lock) == "" {
		return ""
	}
	if filepath.IsAbs(lab.Images.Lock) {
		return lab.Images.Lock
	}
	return filepath.Join(lab.Dir, lab.Images.Lock)
}

// ValidatePolicy rejects an ambiguous mode before topology expansion. It does
// not read the lock: callers that have an expanded topology use Apply, which
// also verifies the lock's manifest hash and every image entry.
func ValidatePolicy(policy model.ImagePolicy) error {
	switch policy.EffectiveMode() {
	case "", model.ImageModeDevelopment:
		if policy.EffectiveMode() == model.ImageModeDevelopment && strings.TrimSpace(policy.Lock) != "" {
			return fmt.Errorf("development image mode must not set a release image lock")
		}
		return nil
	case model.ImageModeRelease, model.ImageModeGrading:
		if strings.TrimSpace(policy.Lock) == "" {
			return fmt.Errorf("%s image mode requires images.lock", policy.EffectiveMode())
		}
		return nil
	default:
		return fmt.Errorf("unknown images.mode %q (development, release, grading)", policy.Mode)
	}
}

// Apply binds an expanded topology to its configured lock. Development tags
// are accepted only with explicit images.mode: development; release and
// grading modes rewrite each device to the immutable lock reference before
// any runtime plan is built.
func Apply(top *model.Topology) (*Lock, error) {
	if top == nil || top.Lab == nil {
		return nil, errors.New("image provenance needs a topology with a lab")
	}
	policy := top.Lab.Images
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}
	for _, device := range top.SortedDevices() {
		if strings.TrimSpace(device.Image) == "" {
			return nil, fmt.Errorf("device %s has no image; set it under kinds.%s.image",
				device.ID, device.Kind)
		}
	}
	refs := topologyRefs(top)
	if policy.RequiresImmutableImages() {
		lockPath := LockPath(top.Lab)
		lock, err := Load(lockPath)
		if err != nil {
			return nil, err
		}
		if lock.ManifestHash != top.Hash {
			return nil, fmt.Errorf("image lock %s belongs to topology %s, not %s",
				lockPath, lock.ManifestHash, top.Hash)
		}
		for _, device := range top.SortedDevices() {
			pinned, ok := lock.Images[device.Image]
			if !ok && IsImmutable(device.Image) {
				// Re-applying provenance in the same process is idempotent.
				pinned = device.Image
				ok = true
			}
			if !ok {
				return nil, fmt.Errorf("image lock %s has no digest for %s (%s)",
					lockPath, device.ID, device.Image)
			}
			if !IsImmutable(pinned) {
				return nil, fmt.Errorf("image lock %s has an unknown or mutable digest for %s",
					lockPath, device.ID)
			}
			device.Image = pinned
			device.ImageID = Digest(pinned)
		}
		digest, err := Hash(*lock)
		if err != nil {
			return nil, err
		}
		top.Lab.Images.LockDigest = digest
		return lock, nil
	}
	for _, ref := range refs {
		if IsImmutable(ref) {
			continue
		}
		if policy.EffectiveMode() != model.ImageModeDevelopment {
			return nil, fmt.Errorf("mutable image %q requires explicit images.mode: development", ref)
		}
	}
	return nil, nil
}

func topologyRefs(top *model.Topology) []string {
	refs := map[string]bool{}
	for _, device := range top.Devices {
		if device != nil && device.Image != "" {
			refs[device.Image] = true
		}
	}
	return sortedKeys(refs)
}

// NewLock constructs a lock only from verified registry digest references.
// Callers must supply the result of a post-push registry inspection, never a
// local image ID.
func NewLock(manifestHash, sourceVersion, commit string, images map[string]string) (Lock, error) {
	lock := Lock{
		APIVersion: LockAPIVersion, Kind: LockKind, ManifestHash: manifestHash,
		SourceVersion: sourceVersion, Commit: commit, GeneratedAt: time.Now().UTC(),
		Images: make(map[string]string, len(images)),
	}
	for ref, digest := range images {
		lock.Images[ref] = digest
	}
	if err := lock.Validate(); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

func sortedKeys[V any](values map[string]V) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
