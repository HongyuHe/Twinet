package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
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
	"github.com/HongyuHe/twinet/internal/svc"
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
				outDir = filepath.Join("submissions", time.Now().UTC().Format("2006-01-02-150405"))
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}

			// The signing key is minted or loaded once, here, before any
			// collector starts. The load-or-create is safe to reach
			// concurrently now, but doing it from eight workers still means
			// eight first-time callers contending over one file; loading it
			// once up front leaves the workers only ever reading a key that
			// already exists, which is both simpler and impossible to race.
			key, err := submissionKey()
			if err != nil {
				return fmt.Errorf("no key to sign submissions with (%w); an unsigned archive "+
					"cannot be told apart from one written by hand", err)
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

					p, err := saveAS(cmd.Context(), top, asn, outDir, exec, key)
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
	exec func(context.Context, string, []string) (execResult, error), key ed25519.PrivateKey) (string, error) {

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
				return "", fmt.Errorf("%s: its routing configuration could not be read: %w; "+
					"re-run save once the device is reachable", d.ID, err)
			}
			if res.ExitCode != 0 {
				return "", fmt.Errorf("%s: its routing configuration could not be read: "+
					"vtysh exited %d: %s; re-run save once the device is reachable",
					d.ID, res.ExitCode, firstLines(res.Stderr, 3))
			}
			contents[d.Name+".conf"] = []byte(cleanConfig(res.Stdout))

			// Everything that is not FRR configuration, captured as the
			// commands that recreate it rather than as a human-readable dump.
			//
			// This was a dump, and a dump cannot be replayed: the archive
			// looked complete, restore silently applied only the routing
			// configuration, and the VLAN, tunnel and addressing answers were
			// gone. A student regraded from their own archive would lose the
			// marks for three of the assignment's questions with nothing
			// anywhere reporting that their work had not been loaded.
			sh, err := captureCommands(ctx, exec, d)
			if err != nil {
				return "", err
			}
			if sh != "" {
				contents[d.Name+".sh"] = []byte(sh)
			}

		case model.KindSwitch:
			sh, err := captureSwitch(ctx, exec, d)
			if err != nil {
				return "", err
			}
			if sh != "" {
				contents[d.Name+".sh"] = []byte(sh)
			}

		case model.KindHost:
			sh, err := captureCommands(ctx, exec, d)
			if err != nil {
				return "", err
			}
			if sh != "" {
				contents[d.Name+".sh"] = []byte(sh)
			}
		}
	}
	// The ROAs this system published.
	//
	// Publishing is a student action, not a line of configuration, so it lives
	// nowhere in a router's running-config. Without it the archive is not what
	// the group did: re-marking one in a private harness, whose trust anchor
	// starts empty, lost the mark for the question about publishing. Measured
	// at 9.70 out of 10 for a submission that had published correctly.
	roas, rerr := publishedROAs(ctx, exec, top, as)
	if rerr != nil {
		return "", fmt.Errorf("what AS %d has published at the trust anchor could not be "+
			"read (%w); an archive without it would lose the mark for publishing when it "+
			"is graded in a lab of its own", as.ASN, rerr)
	}
	if len(roas) > 0 {
		if raw, err := json.MarshalIndent(roas, "", "  "); err == nil {
			contents["roas.json"] = append(raw, '\n')
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

	// The manifest is signed before it is written. Without it, the group, the
	// AS and every checksum are simply whatever the archive says they are: a
	// student who edits a configuration recomputes the sha256 sitting next to
	// it, and one who wants a better mark edits the group field.
	//
	// The key is minted once, before any collector starts, and passed in. A
	// worker that loaded it here would be one of eight racing the first-ever
	// load-or-create, which is how the public and private halves end up from
	// different keypairs and archives verify as untrusted at grading time.
	meta, err := bundleJSON(b, signBundle(b, key))
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

// captureCommands renders a device's non-FRR network state as the commands
// that recreate it.
//
// Addresses, routes and tunnels only. Interface state that the platform owns is
// deliberately excluded: replaying it would fight the deployment rather than
// restore the student's answer, and the two disagreeing is far harder to
// diagnose than either alone.
//
// It returns ("", nil) for a device that genuinely had nothing to capture, and
// ("", error) when the read itself failed. Collapsing the two into a bare ""
// was the defect: a failed read of a host or a router's shell state was dropped
// silently, and the save then checksummed and signed an archive missing the
// student's work while reporting success.
func captureCommands(ctx context.Context, exec func(context.Context, string, []string) (execResult, error),
	d *model.Device) (string, error) {

	// `replace` throughout, not `add`.
	//
	// A restore has to be able to run against a device that already has some of
	// this state, which is the normal case: the deployment configures the
	// planned addresses and the archive carries them too. With `add` those
	// lines fail, and the failures were being swallowed so that a restore in
	// which every line failed still reported success.
	// Order matters, and getting it wrong cost a question.
	//
	// Tunnels are created first, because the routes that follow point at them:
	// a route through a device that does not exist yet cannot be installed.
	// The tunnel's own delete-then-add -- which is how it is made safe to
	// re-run -- takes every route through that device with it, so emitting the
	// routes first meant restoring them and then destroying them a few lines
	// later. The restore reported success and the 6in4 question scored zero.
	script := strings.Join([]string{
		// Tunnels, which is how the 6in4 exercise is answered.
		//
		// These used to be written as comments, prefixed "# tunnel:". The
		// archive recorded that a tunnel had existed and the restore skipped
		// the line, so a student regraded from their own archive lost the 6in4
		// question with nothing reporting that their answer had not been
		// loaded. They are commands now.
		//
		// `ip tunnel add` is not idempotent and the restore runner has no
		// shell to interpret a guard, so the delete before it is marked
		// optional with a leading "-", which the runner understands.
		`ip -d tunnel show 2>/dev/null | while read -r l; do case "$l" in sit0:*) continue;; esac; ` +
			`n=${l%%:*}; r=$(echo "$l" | sed -n 's/.*remote \([^ ]*\).*/\1/p'); ` +
			`o=$(echo "$l" | sed -n 's/.*local \([^ ]*\).*/\1/p'); ` +
			`[ -z "$r" ] || [ -z "$o" ] || [ "$r" = any ] || [ "$o" = any ] && continue; ` +
			`echo "-ip tunnel del $n"; ` +
			`echo "ip tunnel add $n mode sit remote $r local $o ttl 64"; ` +
			`echo "ip link set $n up"; done`,
		// Addresses the student added: anything on an interface beyond what a
		// deployment configures is theirs.
		`ip -o -4 addr show | awk '$2!="lo"{print "ip addr replace "$4" dev "$2}'`,
		`ip -o -6 addr show | awk '$2!="lo" && $4 !~ /^fe80/{print "ip -6 addr replace "$4" dev "$2}'`,
		// Routes the student added by hand, and only those.
		//
		// The filter used to exclude "proto kernel" alone, so every route OSPF
		// and BGP had installed went into the archive. Those cannot be
		// replayed -- iproute2 rejects the nexthop-group syntax it prints --
		// and the restore was swallowing the failures, so an archive of a
		// router was thirty commands that could never work and nobody knew.
		// A manually added route carries no proto at all, which is exactly
		// what distinguishes the student's work from the routing daemon's.
		`ip -o -4 route show | grep -v " proto " | awk '{print "ip route replace "$0}'`,
		`ip -o -6 route show 2>/dev/null | grep -v " proto " | grep -v "^fe80" | awk '{print "ip -6 route replace "$0}'`,
	}, "\n")

	res, err := exec(ctx, d.ID, []string{"sh", "-c", script})
	if err != nil {
		return "", fmt.Errorf("%s: its addresses, routes and tunnels could not be read: %w; "+
			"re-run save once the device is reachable", d.ID, err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%s: its addresses, routes and tunnels could not be read: "+
			"sh exited %d: %s; re-run save once the device is reachable",
			d.ID, res.ExitCode, firstLines(res.Stderr, 3))
	}
	var keep []string
	for _, line := range strings.Split(res.Stdout, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		keep = append(keep, t)
	}
	if len(keep) == 0 {
		return "", nil
	}
	return "# captured from " + d.ID + "\n" + strings.Join(keep, "\n") + "\n", nil
}

// captureSwitch renders a switch's port and VLAN configuration as commands.
//
// Like captureCommands it distinguishes ("", nil) -- a switch with no ports to
// record -- from ("", error), a switch whose ports could not be read. A failed
// read must fail the save rather than vanish into an archive that looks whole.
func captureSwitch(ctx context.Context, exec func(context.Context, string, []string) (execResult, error),
	d *model.Device) (string, error) {

	// The spaces matter. ovs-vsctl prints a trunk list as "[10, 20]", and
	// emitting that verbatim produces "trunks=10, 20" -- which the shell splits
	// on the space, so the port is set to carry VLAN 10 only and the second
	// VLAN is silently dropped. Restoring such an archive left one VLAN
	// unreachable across the trunk, which presents as hosts that cannot see
	// each other for no visible reason. Removing the spaces is the whole fix,
	// and it cost an afternoon to find from the far end.
	script := `for p in $(ovs-vsctl list-ports br0 2>/dev/null); do
  tag=$(ovs-vsctl get port "$p" tag 2>/dev/null | tr -d '[] ')
  trunks=$(ovs-vsctl get port "$p" trunks 2>/dev/null | tr -d '[] ')
  mode=$(ovs-vsctl get port "$p" vlan_mode 2>/dev/null | tr -d '"')
  [ -n "$tag" ] && echo "ovs-vsctl set port $p tag=$tag"
  # vlan_mode is recorded on its own, not only when a trunk list exists.
  #
  # In Open vSwitch a trunk port with no trunks list carries every VLAN, which
  # is a perfectly good answer and one this omitted entirely -- so a submission
  # that used it came back from its own archive carrying nothing.
  [ -n "$mode" ] && [ "$mode" != "[]" ] && echo "ovs-vsctl set port $p vlan_mode=$mode"
  [ -n "$trunks" ] && echo "ovs-vsctl set port $p trunks=$trunks"
done`
	res, err := exec(ctx, d.ID, []string{"sh", "-c", script})
	if err != nil {
		return "", fmt.Errorf("%s: its switch ports could not be read: %w; "+
			"re-run save once the device is reachable", d.ID, err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%s: its switch ports could not be read: sh exited %d: %s; "+
			"re-run save once the device is reachable", d.ID, res.ExitCode, firstLines(res.Stderr, 3))
	}
	if strings.TrimSpace(res.Stdout) == "" {
		return "", nil
	}
	return "# captured from " + d.ID + "\n" + strings.TrimSpace(res.Stdout) + "\n", nil
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
	cmd.Flags().BoolVar(&allowUnsignedBundles, "allow-unsigned", false,
		"grade archives that carry no signature (only for archives collected by an older build)")
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
	var sig string
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
			var sigOnly struct {
				Signature string `json:"signature"`
			}
			_ = json.Unmarshal(body, &sigOnly)
			sig = sigOnly.Signature
			continue
		}
		// Two members whose base names differ only in case, or that differ
		// only by directory, arrive here as one key. Consumers match
		// configuration names case-insensitively, so the second one would
		// quietly replace the first -- which is a way to substitute a file
		// after it was signed.
		key := path.Base(name)
		for existing := range files {
			if strings.EqualFold(existing, key) {
				return b, nil, fmt.Errorf(
					"archive contains both %q and %q, which name the same file; "+
						"one of them would silently replace the other", existing, key)
			}
		}
		files[key] = body
	}

	// The signature is checked before the checksums, because the checksums are
	// only worth anything once it is established that they were written by the
	// platform and not by the person being marked.
	if err := checkBundleSignature(b, sig, allowUnsignedBundles); err != nil {
		return b, nil, fmt.Errorf("%s: %w", filepath.Base(p), err)
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

	// Every listed file has now been verified, but that is only half of what
	// the signature has to mean. The signature covers the list; it does not
	// cover a file that is in the archive and not in the list. Since the
	// consumers apply every configuration they are handed, an unlisted file
	// alongside a listed one is a way to replace a submission's contents after
	// it was signed, without disturbing the signature at all.
	//
	// So the archive has to contain exactly what was signed: no more.
	for name := range files {
		if _, listed := b.Files[name]; !listed {
			return b, nil, fmt.Errorf(
				"archive contains %s, which is not in its signed manifest; "+
					"the signature covers only the files the manifest lists, so an "+
					"unlisted file is one nobody vouched for", name)
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

	// The rest of the answer: VLANs, addresses, routes and tunnels. Applied
	// after the routing configuration, because a tunnel or a host route may
	// depend on an address it has just brought up.
	for _, name := range names {
		if !strings.HasSuffix(name, ".sh") {
			continue
		}
		short := strings.TrimSuffix(name, ".sh")
		d, ok := byName[strings.ToUpper(short)]
		if !ok {
			return n, fmt.Errorf("archive names a device %q that AS %d does not have", short, b.AS)
		}
		body := string(files[name])
		if err := checkSubmittedScript(body); err != nil {
			return n, fmt.Errorf("%s: %w", d.ID, err)
		}
		// Each command runs on its own so one bad line does not lose the rest
		// of the student's work, but the failures are counted and reported
		// rather than discarded. Every command uses `replace` semantics, so a
		// line that is merely redundant succeeds; a line that fails is a line
		// whose effect is missing from the restored device, and reporting the
		// restore as clean would tell the student their work is loaded when
		// part of it is not.
		// A line beginning with "-" may fail without failing the restore. It is
		// how the archive says "remove this if it is there", which cannot be
		// expressed as a command that always succeeds. Everything else must
		// succeed: the alternative is a restore that applied none of a
		// student's work and said so to nobody.
		res, err := exec(ctx, d.ID, []string{"sh", "-c",
			"fail=0\nwhile IFS= read -r c; do case \"$c\" in ''|\\#*) continue;; " +
				"-*) c=${c#-}; $c >/dev/null 2>&1; continue;; esac; " +
				"if ! out=$($c 2>&1); then fail=$((fail+1)); echo \"FAILED: $c: $out\" >&2; fi; " +
				"done <<'TWINET_RESTORE'\n" + body + "\nTWINET_RESTORE\nexit $fail"})
		if err != nil {
			return n, fmt.Errorf("%s: %w", d.ID, err)
		}
		if res.ExitCode != 0 {
			return n, fmt.Errorf("%s: %d command(s) of the saved state could not be applied: %s",
				d.ID, res.ExitCode, strings.TrimSpace(firstLines(res.Stderr, 3)))
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

// firstLines returns at most n lines of output, for an error message that has
// to name what went wrong without reproducing a whole log.
func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = append(lines[:n], fmt.Sprintf("(and %d more)", len(lines)-n))
	}
	return strings.Join(lines, "; ")
}

// publishedROAs reads back what an autonomous system has authorised at the
// lab's trust anchor.
//
// Read from inside the lab, through one of the system's own routers, because
// that is the only place the validator is reachable from -- and because the
// answer is then exactly what the system itself can see.
func publishedROAs(ctx context.Context, exec execFn, top *model.Topology, as *model.AS) ([]svc.VRP, error) {
	addr := svc.RPKIAddrFor(top, as.ASN)
	if addr == "" || len(as.Routers) == 0 {
		return nil, nil
	}
	var last error
	for _, r := range append([]*model.Device{rpkiFacingRouter(as)}, as.Routers...) {
		res, err := exec(ctx, r.ID, []string{"sh", "-c",
			fmt.Sprintf("curl -sf -m 5 http://%s%s/roas", addr, svc.PublishListen)})
		if err != nil {
			last = err
			continue
		}
		if res.ExitCode != 0 {
			last = fmt.Errorf("%s: the trust anchor did not answer", r.ID)
			continue
		}
		var all []svc.VRP
		if err := json.Unmarshal([]byte(res.Stdout), &all); err != nil {
			last = fmt.Errorf("%s: the trust anchor's answer could not be read: %w", r.ID, err)
			continue
		}
		var mine []svc.VRP
		for _, v := range all {
			if v.ASN == as.ASN {
				mine = append(mine, v)
			}
		}
		// An empty list is an answer; nil with no error would be read as "not
		// asked" by a caller that has to tell the two apart.
		return mine, nil
	}
	return nil, last
}

// replayROAs publishes an archive's authorisations into the lab being graded.
func replayROAs(ctx context.Context, exec execFn, top *model.Topology, as *model.AS, body []byte) error {
	var roas []svc.VRP
	if err := json.Unmarshal(body, &roas); err != nil {
		return fmt.Errorf("the archive's published authorisations could not be read: %w", err)
	}
	addr := svc.RPKIAddrFor(top, as.ASN)
	if addr == "" || len(roas) == 0 || len(as.Routers) == 0 {
		return nil
	}
	r := rpkiFacingRouter(as)
	for _, v := range roas {
		body := fmt.Sprintf(`{"prefix":%q,"max_length":%d,"asn":%d}`, v.Prefix, v.MaxLength, v.ASN)
		// Retried, because this runs moments after the lab was built: the
		// validator may still be starting, and the route to it may still be
		// coming up. A single attempt failed on a harness that was working
		// perfectly ten seconds later, and quarantined the submission.
		//
		// The reason is captured on the last attempt so a genuine refusal --
		// a prefix outside the system's allocation, say -- is reported as
		// itself rather than as a timeout.
		script := fmt.Sprintf(
			"for i in 1 2 3 4 5 6 7 8 9 10; do "+
				"out=$(curl -s -m 5 -w ' HTTP %%{http_code}' -X POST http://%s%s/roas -d %s) && "+
				"case \"$out\" in *'HTTP 200'*) exit 0;; esac; sleep 3; done; "+
				"echo \"$out\" >&2; exit 1",
			addr, svc.PublishListen, shellQuote(body))
		res, err := exec(ctx, r.ID, []string{"sh", "-c", script})
		if err != nil {
			return fmt.Errorf("publishing %s: %w", v.Prefix, err)
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("publishing %s: the trust anchor did not accept it: %s",
				v.Prefix, firstLine(res.Stderr+res.Stdout))
		}
	}
	return nil
}

// rpkiFacingRouter returns the router the trust anchor is cabled to.
//
// Any router of the system can reach it once the interior routing is up, and
// publishing happens seconds after a configuration is installed, when it is
// not. Talking to the directly-connected router needs no routing at all, so it
// does not depend on the very thing being marked.
func rpkiFacingRouter(as *model.AS) *model.Device {
	r := as.Routers[0]
	for _, d := range as.Devices {
		if d.Kind != model.KindRouter {
			continue
		}
		for _, i := range d.Ifaces {
			if i.Peer != nil && i.Peer.Device != nil &&
				i.Peer.Device.Kind == model.KindService &&
				strings.Contains(strings.ToLower(i.Peer.Device.Name), "rpki") {
				r = d
			}
		}
	}
	return r
}
