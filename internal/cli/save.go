package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// Bundle is the manifest inside a submission archive.
//
// A submission that cannot be tied to the topology it was written against is
// not evidence of anything: addresses move when a lab is edited, and a
// configuration correct for one revision fails against another for reasons the
// student could not have known. The hash is what lets a grader say which of
// those happened.
type Bundle struct {
	Lab        string            `json:"lab"`
	AS         int               `json:"as"`
	Group      string            `json:"group"`
	Topology   string            `json:"topology_hash"`
	Controller string            `json:"controller"`
	TakenAt    time.Time         `json:"taken_at"`
	Files      map[string]string `json:"files"` // path inside the bundle -> sha256
}

func newSaveCmd(opts *Options) *cobra.Command {
	var (
		outDir string
		asList []int
		token  string
	)
	cmd := &cobra.Command{
		Use:   "save",
		Short: "Collect each group's work into a submission archive",
		Long: `Saves what students have configured, as an archive per group.

Every archive carries the hash of the topology it was written against. A
configuration is only meaningful relative to a topology: addresses move when a
lab is edited, and work that was correct for one revision can fail against
another for reasons no student could have known. Recording the hash is what
lets that be told apart from a mistake, months later, in a dispute.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			exec, err := execFunc(cmd.Context(), top, token)
			if err != nil {
				return err
			}
			targets := asList
			if len(targets) == 0 {
				for _, asn := range top.SortedASNs() {
					if top.ASes[asn].Role == model.RoleStudent {
						targets = append(targets, asn)
					}
				}
			}
			if outDir == "" {
				outDir = filepath.Join("submissions", time.Now().UTC().Format("2006-01-02_15-04-05"))
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}

			var (
				wg   sync.WaitGroup
				mu   sync.Mutex
				done int
				bad  []string
			)
			sem := make(chan struct{}, 8)
			for _, asn := range targets {
				wg.Add(1)
				go func(asn int) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					p, err := saveAS(cmd.Context(), top, asn, outDir, exec)
					mu.Lock()
					defer mu.Unlock()
					if err != nil {
						bad = append(bad, fmt.Sprintf("AS %d: %v", asn, err))
						return
					}
					done++
					fmt.Fprintf(cmd.ErrOrStderr(), "  %s\n", p)
				}(asn)
			}
			wg.Wait()

			fmt.Fprintf(cmd.OutOrStdout(), "saved %d of %d submission(s) to %s\n",
				done, len(targets), outDir)
			if len(bad) > 0 {
				sort.Strings(bad)
				for _, b := range bad {
					fmt.Fprintf(cmd.ErrOrStderr(), "  %s\n", b)
				}
				// A save that silently skipped a group is how a student's work
				// disappears between the deadline and the grading run.
				return fmt.Errorf("%d submission(s) could not be saved", len(bad))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&outDir, "out", "o", "", "where to write the archives")
	cmd.Flags().IntSliceVar(&asList, "as", nil, "only these ASes")
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs")
	return cmd
}

// saveAS writes one group's archive.
func saveAS(ctx context.Context, top *model.Topology, asn int, outDir string,
	exec func(context.Context, string, []string) (execResult, error)) (string, error) {

	as, ok := top.ASes[asn]
	if !ok {
		return "", fmt.Errorf("not in this lab")
	}
	group := as.OwnerGroup
	if group == "" {
		group = fmt.Sprintf("as%d", asn)
	}

	b := Bundle{
		Lab: top.Name, AS: asn, Group: group, Topology: top.Hash,
		Controller: Version, TakenAt: time.Now().UTC(),
		Files: map[string]string{},
	}
	contents := map[string][]byte{}

	for _, d := range as.Devices {
		switch d.Kind {
		case model.KindRouter:
			res, err := exec(ctx, d.ID, []string{"vtysh", "-c", "show running-config"})
			if err != nil {
				return "", fmt.Errorf("%s: %w", d.ID, err)
			}
			if res.ExitCode != 0 {
				return "", fmt.Errorf("%s: vtysh exited %d", d.ID, res.ExitCode)
			}
			contents[d.Name+".conf"] = []byte(cleanConfig(res.Stdout))

			// Tunnels and addresses are set with ip(8) and are invisible to
			// FRR, so an archive of frr.conf alone silently loses the answer
			// to any exercise that is not routing configuration.
			if res, err := exec(ctx, d.ID, []string{"sh", "-c",
				"ip -o addr show; echo ---; ip -d tunnel show 2>/dev/null; echo ---; ip -6 route show 2>/dev/null"}); err == nil {
				contents[d.Name+".state"] = []byte(res.Stdout)
			}

		case model.KindSwitch:
			if res, err := exec(ctx, d.ID, []string{"sh", "-c",
				"ovs-vsctl show 2>/dev/null || true"}); err == nil && strings.TrimSpace(res.Stdout) != "" {
				contents[d.Name+".switch"] = []byte(res.Stdout)
			}

		case model.KindHost:
			if res, err := exec(ctx, d.ID, []string{"sh", "-c",
				"ip -o addr show; echo ---; ip -o route show"}); err == nil {
				contents[d.Name+".state"] = []byte(res.Stdout)
			}
		}
	}
	if len(contents) == 0 {
		return "", fmt.Errorf("nothing could be collected")
	}

	for name, body := range contents {
		sum := sha256.Sum256(body)
		b.Files[name] = hex.EncodeToString(sum[:])
	}

	p := filepath.Join(outDir, group+".tar.gz")
	f, err := os.Create(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	meta, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return "", err
	}
	if err := writeTar(tw, "manifest.json", meta); err != nil {
		return "", err
	}
	names := make([]string, 0, len(contents))
	for n := range contents {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := writeTar(tw, n, contents[n]); err != nil {
			return "", err
		}
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return p, nil
}

func writeTar(tw *tar.Writer, name string, body []byte) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o644, Size: int64(len(body)), ModTime: time.Now(),
	}); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

// cleanConfig strips the preamble vtysh prints before a configuration, which it
// then refuses to read back.
func cleanConfig(out string) string {
	lines := strings.Split(out, "\n")
	start := 0
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "Building configuration") ||
			strings.HasPrefix(t, "Current configuration") {
			start = i + 1
			continue
		}
		break
	}
	return strings.TrimRight(strings.Join(lines[start:], "\n"), "\n") + "\n"
}

func newRestoreCmd(opts *Options) *cobra.Command {
	var (
		token string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "restore <archive.tar.gz>...",
		Short: "Load saved submissions back into a running lab",
		Args:  cobra.MinimumNArgs(1),
		Long: `Restores archives produced by twinet save.

An archive written against a different topology is refused rather than loaded.
Addresses move when a lab is edited, so replaying an old configuration produces
a network that is broken in ways the student never wrote, and the report would
blame them for it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			exec, err := execFunc(cmd.Context(), top, token)
			if err != nil {
				return err
			}
			for _, p := range args {
				b, files, err := readBundle(p)
				if err != nil {
					return err
				}
				if b.Topology != top.Hash && !force {
					return fmt.Errorf(
						"%s was written against topology %s but this lab is %s; "+
							"replaying it would produce a network the student never wrote. "+
							"Pass --force if you are certain",
						filepath.Base(p), short(b.Topology), short(top.Hash))
				}
				n, err := restoreBundle(cmd.Context(), top, b, files, exec)
				if err != nil {
					return fmt.Errorf("%s: %w", filepath.Base(p), err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "restored %s into AS %d (%d device(s))\n", b.Group, b.AS, n)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs")
	cmd.Flags().BoolVar(&force, "force", false, "restore even if the topology has changed")
	return cmd
}

func readBundle(p string) (Bundle, map[string][]byte, error) {
	var b Bundle
	f, err := os.Open(p)
	if err != nil {
		return b, nil, err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return b, nil, fmt.Errorf("%s is not a gzip archive: %w", filepath.Base(p), err)
	}
	defer func() { _ = gz.Close() }()

	files := map[string][]byte{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return b, nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		// An archive is student-supplied input. A name that escapes the
		// extraction directory is how a submission becomes a way to write
		// anywhere on the grading machine.
		name := path.Clean(h.Name)
		if strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			return b, nil, fmt.Errorf("archive contains an unsafe path %q", h.Name)
		}
		body, err := io.ReadAll(io.LimitReader(tr, 4<<20))
		if err != nil {
			return b, nil, err
		}
		if name == "manifest.json" {
			if err := json.Unmarshal(body, &b); err != nil {
				return b, nil, fmt.Errorf("manifest: %w", err)
			}
			continue
		}
		files[path.Base(name)] = body
	}

	// A checksum mismatch means the archive was edited after it was taken.
	// Grading it anyway would be grading something nobody submitted.
	for name, want := range b.Files {
		body, ok := files[name]
		if !ok {
			return b, nil, fmt.Errorf("archive is missing %s, which its manifest lists", name)
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != want {
			return b, nil, fmt.Errorf("%s does not match the checksum recorded when it was saved", name)
		}
	}
	return b, files, nil
}

func restoreBundle(ctx context.Context, top *model.Topology, b Bundle,
	files map[string][]byte, exec func(context.Context, string, []string) (execResult, error)) (int, error) {

	as, ok := top.ASes[b.AS]
	if !ok {
		return 0, fmt.Errorf("AS %d is not in this lab", b.AS)
	}
	byName := map[string]*model.Device{}
	for _, d := range as.Devices {
		byName[strings.ToUpper(d.Name)] = d
	}

	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	n := 0
	for _, name := range names {
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		short := strings.TrimSuffix(name, ".conf")
		d, ok := byName[strings.ToUpper(short)]
		if !ok {
			return n, fmt.Errorf("archive names a router %q that AS %d does not have", short, b.AS)
		}
		if err := loadFRRConfig(ctx, exec, d, string(files[name])); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// execResult keeps this file independent of which runtime produced the result.
type execResult = rt.ExecResult
