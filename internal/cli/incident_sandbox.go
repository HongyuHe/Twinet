package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/pki"
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
	// TLS material the agent presents to the node agents, where the cluster
	// requires it.
	TLSCert string
	TLSKey  string
	TLSCA   string
	// Hide is every path the agent must not be able to open: the lab it is
	// diagnosing, the repository that lab lives in, and any episode record.
	//
	// A copy is not isolation. The agent ran as an unprivileged account in a
	// filtered copy and could still open the original by absolute path, where
	// the scenario file says in plain YAML which fault was injected on which
	// device -- and so does the end-to-end test that exercises it. An agent
	// whose whole strategy is to grep the repository for its brief scored a
	// perfect 1.00.
	Hide []string

	// Net is the network the agent gets: the node agents and nothing else.
	//
	// Hiding the answer on this machine while leaving a route to the internet
	// hid nothing, because the scenarios are published in a public repository.
	Net *agentNetwork
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
func newSandbox(top *model.Topology, manifest, name string, egress []string) (*sandbox, error) {
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

	// A neutral name. Putting the scenario's name in the path told the agent
	// which episode it was in, which is most of the answer for a suite whose
	// scenarios are named after what they do.
	_ = name
	dir, err := os.MkdirTemp("", "twinet-work-")
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
	sb.Hide = pathsToHide(top, manifest)
	// A transport identity of its own, where the cluster wants one.
	//
	// On a cluster with mutual TLS a bearer token is not enough: every
	// observation the agent tried came back "certificate required", so the
	// benchmark could not be run at all -- the failure that looks exactly like
	// an agent finding nothing. It gets a short-lived client certificate of its
	// own rather than the controller's, because transport identity is not
	// authorisation here (the node agents decide what a caller may do from its
	// token, and the agent's is the read-only, single-lab one) and handing the
	// controller's private key to something under evaluation is not a thing to
	// do when issuing another costs nothing.
	if dir := labPKIDir(top); dir != "" {
		m, err := pki.IssueDiagnostic(dir, filepath.Join(sb.Dir, "tls"), top.Name, 6*time.Hour)
		if err != nil {
			sb.Remove()
			return nil, fmt.Errorf("issuing the agent's client certificate: %w", err)
		}
		sb.TLSCert, sb.TLSKey, sb.TLSCA = m.CertPath, m.KeyPath, m.CAPath
		if err := chownTree(filepath.Join(sb.Dir, "tls"), uid, gid); err != nil {
			sb.Remove()
			return nil, err
		}
	}
	// A network with the node agents on it and nothing else.
	//
	// This is the last of the ways the answer used to be readable. The agent
	// could not open the scenario file, and could fetch the repository that
	// contains it from the internet -- so an agent that never looked at a
	// router scored 1.00. See internal/cli/incident_netns.go.
	net, err := newAgentNetwork(top, egress)
	if err != nil {
		sb.Remove()
		return nil, err
	}
	sb.Net = net
	return sb, nil
}

// labPKIDir is the mutual-TLS material for this lab, or "" when the cluster
// does not use any.
func labPKIDir(top *model.Topology) string {
	var dirs []string
	if top.Lab.Dir != "" {
		dirs = append(dirs, filepath.Join(top.Lab.Dir, ".twinet", "pki"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".twinet", "pki"))
	}
	dirs = append(dirs, "/etc/twinet/pki")
	for _, d := range dirs {
		// The authority's key is what says this directory can issue; a
		// directory with only a certificate belongs to somebody else.
		if _, err := os.Stat(filepath.Join(d, "ca_key.pem")); err == nil {
			return d
		}
	}
	return ""
}

// pathsToHide lists the directories an evaluated agent must not be able to
// read: the lab, whatever repository it lives in, and any episode record.
//
// The repository, not only the lab: the scenario files live under the lab, but
// the end-to-end tests that exercise them name the same faults, and so does the
// documentation. Hiding the lab and leaving the tree it sits in is the kind of
// half-measure this whole mechanism exists to stop.
func pathsToHide(top *model.Topology, manifest string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || p == "/" {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil || abs == "/" || seen[abs] {
			return
		}
		if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
			return
		}
		seen[abs] = true
		out = append(out, abs)
	}
	add(top.Lab.Dir)
	if fi, err := os.Stat(manifest); err == nil && fi.IsDir() {
		add(manifest)
	} else {
		add(filepath.Dir(manifest))
	}
	// The repository the lab lives in, found by walking up to a .git.
	if dir, err := filepath.Abs(top.Lab.Dir); err == nil {
		for d := dir; d != "/" && d != "."; d = filepath.Dir(d) {
			if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
				add(d)
				break
			}
		}
	}
	if wd, err := os.Getwd(); err == nil {
		add(filepath.Join(wd, "episodes"))
	}
	// Where this machine keeps the cluster's own secrets.
	//
	// The node agent's systemd unit carried TWINET_TOKEN in an Environment
	// line, and a unit is world-readable: an evaluated agent read the cluster
	// secret out of it, discarded its own read-only credential and could act as
	// the controller across every lab. The token has been moved to a root-only
	// file, and these are masked as well -- one mistake in a unit file should
	// not be the whole of the defence.
	for _, d := range []string{"/etc/systemd", "/etc/twinet", "/run/systemd/system"} {
		add(d)
	}
	sort.Strings(out)
	// Only the outermost of any nested pair.
	//
	// Masking a parent removes the child's mount point, so mounting the
	// repository and then the lab inside it failed with "mount point does not
	// exist" and the agent never started at all -- which the adversarial test
	// would have read as "it could not reach anything" had it not been made to
	// insist the agent ran.
	var outermost []string
	for _, p := range out {
		nested := false
		for _, q := range outermost {
			if p == q || strings.HasPrefix(p, q+string(filepath.Separator)) {
				nested = true
				break
			}
		}
		if !nested {
			outermost = append(outermost, p)
		}
	}
	return outermost
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
		// incidents/ holds the scenario files, each of which names the fault,
		// the device and the interface. Copying them into the agent's own
		// sandbox was handing over the answer with extra steps.
		if head == ".twinet" || head == "episodes" || head == "incidents" {
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
	if s == nil {
		return
	}
	s.Net.Close()
	if s.Dir != "" {
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

// sealLabState makes a lab's private state unreadable to anyone but its owner,
// so an agent that guesses the path finds a directory it cannot open. It runs
// every time a ledger is written, because a lab directory created before this
// existed would otherwise stay open for the rest of its life.
func sealLabState(top *model.Topology) {
	dir := filepath.Join(top.Lab.Dir, ".twinet")
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return
	}
	_ = os.Chmod(dir, 0o700)
	// And it belongs to whoever is running twinet, not to root.
	//
	// Running one command under sudo -- which evaluating an agent now requires
	// -- left the ledger and the directory owned by root and readable by nobody
	// else, so the operator's next ordinary `twinet fault status` in their own
	// lab directory failed with "permission denied". Locking a user out of
	// their own lab is not what sealing it is for.
	if os.Geteuid() != 0 {
		return
	}
	uid, gid := sudoCaller()
	if uid < 0 {
		return
	}
	// Errors are ignored deliberately: this is a courtesy to the operator, and
	// a path that cannot be chowned is not a reason to fail the command that
	// was actually asked for.
	_ = filepath.Walk(dir, func(p string, _ os.FileInfo, walkErr error) error {
		if walkErr == nil {
			_ = os.Chown(p, uid, gid)
		}
		return nil
	})
}

// sudoCaller is the user who invoked sudo, or -1 when this is not a sudo
// session.
func sudoCaller() (uid, gid int) {
	u, uerr := strconv.Atoi(os.Getenv("SUDO_UID"))
	g, gerr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if uerr != nil || gerr != nil || u == 0 {
		return -1, -1
	}
	return u, g
}
