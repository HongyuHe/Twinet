package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// An RCA agent under evaluation runs here: as somebody else, somewhere else.
//
// The ground truth for an episode is a file. Handing the agent the lab
// directory and asking it not to look is not a control, and the earlier
// arrangement -- keep the answer out of stdin, pass TWINET_MANIFEST -- was
// exactly that. An agent that ran "cat $TWINET_MANIFEST/.twinet/injections.json"
// scored a perfect 1.00 without diagnosing anything.
//
// So the agent gets its own copy of the lab directory containing what a
// diagnostician is entitled to -- the topology it is looking at, and where the
// devices live -- and runs as an unprivileged user that cannot read the
// original. The injection ledger, the student credentials, the roster and the
// PKI never enter the copy, and the copy is all the agent can see.
type sandbox struct {
	Dir      string
	Manifest string
	User     string
	UID      int
	GID      int
}

// sandboxUser is the account agents run as. It owns nothing, has no shell, and
// is in no group that can read a lab directory.
const sandboxUser = "twinet-rca"

// newSandbox prepares an isolated working directory for one episode.
//
// The copy is the lab directory with the private state left out: the manifest
// and its templates are public -- a diagnostician is entitled to know how the
// network was meant to be built -- while .twinet holds the injection ledger,
// the student credentials, the roster and the PKI, and none of those are
// anybody's to read but the operator's. The placement record is copied back in
// on its own, because without it the agent cannot find the devices.
func newSandbox(top *model.Topology, manifest, name string) (*sandbox, error) {
	u, err := ensureSandboxUser(sandboxUser)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, fmt.Errorf("uid of %s: %w", u.Username, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, fmt.Errorf("gid of %s: %w", u.Username, err)
	}

	dir, err := os.MkdirTemp("", "twinet-rca-"+sanitiseName(name)+"-")
	if err != nil {
		return nil, err
	}
	sb := &sandbox{Dir: dir, User: u.Username, UID: uid, GID: gid}
	if err := copyPublicTree(top.Lab.Dir, dir); err != nil {
		sb.Remove()
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, ".twinet"), 0o750); err != nil {
		sb.Remove()
		return nil, err
	}
	placement := filepath.Join(top.Lab.Dir, ".twinet", "placement.json")
	if _, err := os.Stat(placement); err == nil {
		if err := copyForSandbox(placement, filepath.Join(dir, ".twinet", "placement.json")); err != nil {
			sb.Remove()
			return nil, err
		}
	}
	// The manifest may have been given as a file inside the lab directory or
	// as the directory itself; either way the agent is pointed at the copy.
	sb.Manifest = dir
	if fi, err := os.Stat(manifest); err == nil && !fi.IsDir() {
		sb.Manifest = filepath.Join(dir, filepath.Base(manifest))
	}
	if err := chownTree(dir, uid, gid); err != nil {
		sb.Remove()
		return nil, err
	}
	return sb, nil
}

// copyPublicTree copies everything in a lab directory that is not private
// state. Irregular files are skipped: a symbolic link out of the lab is a way
// back to the files this copy exists to exclude.
func copyPublicTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		head := strings.Split(rel, string(filepath.Separator))[0]
		if head == ".twinet" || head == "episodes" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o750)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return copyForSandbox(p, filepath.Join(dst, rel))
	})
}

func (s *sandbox) Remove() {
	if s != nil && s.Dir != "" {
		_ = os.RemoveAll(s.Dir)
	}
}

// ensureSandboxUser finds the agent account, creating it if this is the first
// episode on this machine.
func ensureSandboxUser(name string) (*user.User, error) {
	if u, err := user.Lookup(name); err == nil {
		return u, nil
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("no %q account exists and this process is not root, so it "+
			"cannot create one. Create it with: useradd --system --no-create-home "+
			"--shell /usr/sbin/nologin %s", name, name)
	}
	args := []string{"--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name}
	out, err := exec.Command("useradd", args...).CombinedOutput()
	if err != nil {
		if u, err2 := user.Lookup(name); err2 == nil {
			return u, nil
		}
		return nil, fmt.Errorf("creating the %q account: %v: %s", name, err,
			strings.TrimSpace(string(out)))
	}
	return user.Lookup(name)
}

func copyForSandbox(src, dst string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, raw, 0o640)
}

func chownTree(root string, uid, gid int) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(p, uid, gid)
	})
}

func sanitiseName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// sealLabState makes a lab's private state unreadable to anyone but its owner,
// so an agent that guesses the path finds a directory it cannot open. It runs
// every time a ledger is written, because a lab directory created before this
// existed would otherwise stay open for the rest of its life.
func sealLabState(top *model.Topology) {
	dir := filepath.Join(top.Lab.Dir, ".twinet")
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		_ = os.Chmod(dir, 0o700)
	}
}
