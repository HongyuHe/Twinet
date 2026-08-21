package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/images"
	"github.com/HongyuHe/twinet/internal/model"
)

func newImagesCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "images",
		Short: "Create and verify reproducible image locks",
	}
	cmd.AddCommand(newImagesLockCmd(opts), newImagesVerifyCmd(opts))
	return cmd
}

func newImagesLockCmd(opts *Options) *cobra.Command {
	var (
		output string
		token  string
		extra  []string
		pins   []string
	)
	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Write a machine-readable lock from pushed image digests",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			pinned, err := parseImagePins(pins)
			if err != nil {
				return err
			}
			refs := topologyImageRefs(top)
			for _, ref := range extra {
				ref = strings.TrimSpace(ref)
				if ref == "" {
					continue
				}
				refs = append(refs, ref)
			}
			for source := range pinned {
				refs = append(refs, source)
			}
			refs = uniqueSortedRefs(refs)
			if len(refs) == 0 {
				return fmt.Errorf("lab %q uses no images", top.Name)
			}
			observed := make([]string, 0, len(refs))
			for _, ref := range refs {
				if _, isPinned := pinned[ref]; !isPinned {
					observed = append(observed, ref)
				}
			}
			digests := map[string]string{}
			if len(observed) > 0 {
				digests, err = observedImageDigests(cmd.Context(), top, token, observed)
				if err != nil {
					return err
				}
			}
			for source, digest := range pinned {
				digests[source] = digest
			}
			lock, err := images.NewLock(top.Hash, Version, Commit, digests)
			if err != nil {
				return fmt.Errorf("refusing to lock an unpushed or unknown image: %w", err)
			}
			if output == "" {
				output = images.LockPath(top.Lab)
				if output == "" {
					output = filepath.Join(top.Lab.Dir, "images.lock.json")
				}
			} else if !filepath.IsAbs(output) {
				output = filepath.Join(top.Lab.Dir, output)
			}
			if err := images.Write(output, lock); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s for topology %s (%d images)\n",
				output, top.Hash, len(lock.Images))
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "lock path (default images.lock.json or images.lock)")
	cmd.Flags().StringVar(&token, "token", "", "agent token for clustered labs")
	cmd.Flags().StringSliceVar(&extra, "image", nil,
		"additional pushed image reference to include (repeat for every release image)")
	cmd.Flags().StringSliceVar(&pins, "pin", nil,
		"verified source=digest reference; bypasses local inspection after a remote registry check")
	return cmd
}

func newImagesVerifyCmd(opts *Options) *cobra.Command {
	var (
		lockPath string
		token    string
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify locked digests on every node that will run them",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			configuredLock := lockPath == ""
			if configuredLock {
				lockPath = images.LockPath(top.Lab)
			}
			if lockPath == "" {
				return fmt.Errorf("images.verify needs --lock or images.lock in the manifest")
			}
			if !configuredLock && !filepath.IsAbs(lockPath) {
				lockPath = filepath.Join(top.Lab.Dir, lockPath)
			}
			lock, err := images.Load(lockPath)
			if err != nil {
				return err
			}
			if lock.ManifestHash != top.Hash {
				return fmt.Errorf("image lock %s belongs to topology %s, not %s",
					lockPath, lock.ManifestHash, top.Hash)
			}
			if err := verifyLockReferences(top, lock); err != nil {
				return err
			}
			if err := verifyLockedNodes(cmd.Context(), top, token, lock); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "verified %d locked images for %s\n", len(lock.Images), top.Name)
			return nil
		},
	}
	cmd.Flags().StringVar(&lockPath, "lock", "", "path to image lock")
	cmd.Flags().StringVar(&token, "token", "", "agent token for clustered labs")
	return cmd
}

func topologyImageRefs(top *model.Topology) []string {
	seen := map[string]bool{}
	for _, device := range top.Devices {
		if device != nil && device.Image != "" {
			seen[device.Image] = true
		}
	}
	out := make([]string, 0, len(seen))
	for ref := range seen {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedRefs(refs []string) []string {
	seen := map[string]bool{}
	for _, ref := range refs {
		if ref = strings.TrimSpace(ref); ref != "" {
			seen[ref] = true
		}
	}
	out := make([]string, 0, len(seen))
	for ref := range seen {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

func parseImagePins(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, value := range values {
		source, digest, ok := strings.Cut(value, "=")
		source, digest = strings.TrimSpace(source), strings.TrimSpace(digest)
		if !ok || source == "" || !images.IsImmutable(digest) {
			return nil, fmt.Errorf("invalid --pin %q; use source=repository@sha256:<64 hex>", value)
		}
		if previous, exists := out[source]; exists && previous != digest {
			return nil, fmt.Errorf("conflicting --pin values for %s", source)
		}
		out[source] = digest
	}
	return out, nil
}

func observedImageDigests(ctx context.Context, top *model.Topology, token string, refs []string) (map[string]string, error) {
	if !clustered(top) {
		runtime, err := localRuntime(top)
		if err != nil {
			return nil, err
		}
		out := make(map[string]string, len(refs))
		for _, ref := range refs {
			digest, err := runtime.ImageDigest(ctx, ref)
			if err != nil {
				return nil, fmt.Errorf("resolve local image %s: %w", ref, err)
			}
			out[ref] = digest
		}
		return out, nil
	}
	tok, err := tokenFor(token)
	if err != nil {
		return nil, err
	}
	cluster := client.NewCluster(top.Lab, tok)
	answers := map[string]map[string]string{}
	for _, node := range cluster.Nodes {
		got, err := node.ImageDigests(ctx, refs)
		if err != nil {
			return nil, err
		}
		answers[node.Name] = got
	}
	out := make(map[string]string, len(refs))
	for _, ref := range refs {
		var identity string
		for node, response := range answers {
			digest := response[ref]
			if digest == "" {
				continue
			}
			if identity == "" {
				identity = digest
				continue
			}
			if !images.SameDigest(identity, digest) {
				return nil, fmt.Errorf("nodes disagree on image %s: %s has %s, expected %s",
					ref, node, digest, identity)
			}
		}
		if identity == "" {
			return nil, fmt.Errorf("no node has pulled %s; push and pull it before locking", ref)
		}
		out[ref] = identity
	}
	return out, nil
}

func verifyLockReferences(top *model.Topology, lock *images.Lock) error {
	for _, device := range top.SortedDevices() {
		if _, ok := lock.Images[device.Image]; ok {
			continue
		}
		found := false
		for _, locked := range lock.Images {
			if device.Image == locked {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("image lock has no entry for %s (%s)", device.ID, device.Image)
		}
	}
	return nil
}

func verifyLockedNodes(ctx context.Context, top *model.Topology, token string, lock *images.Lock) error {
	expectedFor := func(node string) map[string]string {
		out := map[string]string{}
		for _, device := range top.DevicesOnNode(node) {
			for source, pinned := range lock.Images {
				if device.Image == source || device.Image == pinned {
					// Verify the immutable reference itself, not a mutable
					// authored tag. This makes `images verify` meaningful for
					// a development manifest being prepared for release as
					// well as for a release manifest already rewritten by
					// images.Apply.
					out[pinned] = pinned
				}
			}
		}
		return out
	}
	verify := func(node string, expected, actual map[string]string) error {
		for ref, pinned := range expected {
			got := actual[ref]
			if got == "" {
				return fmt.Errorf("%s has not pulled %s", node, ref)
			}
			if !images.SameDigest(pinned, got) {
				return fmt.Errorf("%s reports %s as %s, not %s", node, ref, got, pinned)
			}
		}
		return nil
	}
	if !clustered(top) {
		runtime, err := localRuntime(top)
		if err != nil {
			return err
		}
		node := localNode(top)
		expected := expectedFor(node)
		actual := map[string]string{}
		for ref := range expected {
			digest, err := runtime.ImageDigest(ctx, ref)
			if err != nil {
				return err
			}
			actual[ref] = digest
		}
		return verify(node, expected, actual)
	}
	tok, err := tokenFor(token)
	if err != nil {
		return err
	}
	cluster := client.NewCluster(top.Lab, tok)
	for _, node := range cluster.Nodes {
		expected := expectedFor(node.Name)
		if len(expected) == 0 {
			continue
		}
		refs := make([]string, 0, len(expected))
		for ref := range expected {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		actual, err := node.ImageDigests(ctx, refs)
		if err != nil {
			return err
		}
		if err := verify(node.Name, expected, actual); err != nil {
			return err
		}
	}
	return nil
}
