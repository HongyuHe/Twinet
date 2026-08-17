// Package integrity checks that the programs a grading run's evidence comes
// from are the ones the image ships.
//
// Students have root in their own containers, which is the point: the exercise
// is to operate a real router. It also means a student can replace the programs
// the grader runs. Every data-plane question in this system is answered by
// running `ping`, `nc` or `twinet-mcast` inside a student's container and
// reading what it printed, and every configuration question by running `vtysh`
// there. A shell script called `ping` that prints "3 packets transmitted, 3
// received" and exits zero earns the reachability marks on a network that
// forwards nothing, and one called `vtysh` earns the configuration marks for
// configuration that was never written.
//
// So before a grading run believes anything a container told it, the programs
// it is about to run are compared against the image the container was built
// from. The comparison is done here, by the grader, over the container's
// filesystem as the kernel or the container engine sees it -- never by asking
// the container itself, which is the thing under suspicion.
//
// What this does not cover is stated plainly: a shared library replaced
// underneath an untouched program, and a program replaced between the check and
// the run. Both are narrower than what it does cover, and neither is reachable
// by editing a configuration file.
package integrity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// Tools are the programs a mark can depend on.
//
// Every one of these either produces evidence a check reads, or is the shell a
// check's pipeline runs through. A program not on this list cannot be the
// reason a question passed.
var Tools = []string{
	"ping", "ping6", "nc", "ncat", "traceroute", "traceroute6",
	"ip", "cat", "sh", "vtysh", "ovs-ofctl", "ovs-vsctl", "twinet-mcast",
	"iptables", "ss", "awk", "grep",
}

// searchPath is the order a program name is resolved in.
//
// It matters as much as the contents of the files: a student who leaves
// /usr/bin/ping alone and writes /usr/local/bin/ping has replaced the program
// the grader runs without touching the one it would have hashed.
var searchPath = []string{
	"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
}

// Finding is one program that is not what the image ships.
type Finding struct {
	Tool string `json:"tool"`
	Want string `json:"want,omitempty"`
	Got  string `json:"got,omitempty"`
	Why  string `json:"why"`
}

func (f Finding) String() string {
	switch {
	case f.Want == "":
		return fmt.Sprintf("%s: %s (%s)", f.Tool, f.Why, f.Got)
	case f.Got == "":
		return fmt.Sprintf("%s: %s (the image has it at %s)", f.Tool, f.Why, f.Want)
	default:
		return fmt.Sprintf("%s: %s (image %s, container %s)", f.Tool, f.Why, f.Want, f.Got)
	}
}

// Error is what a caller gets when a container's tools are not its image's.
//
// It is deliberately not a verdict about the submission. A grading run that
// meets this must stop and say so, because it cannot tell what the marks would
// have been.
type Error struct {
	Container string
	Findings  []Finding
}

func (e *Error) Error() string {
	parts := make([]string, 0, len(e.Findings))
	for _, f := range e.Findings {
		parts = append(parts, f.String())
	}
	return fmt.Sprintf("the programs %s would be graded with are not the ones its image "+
		"ships, so nothing they print can be believed: %s",
		e.Container, strings.Join(parts, "; "))
}

// source reads files out of one filesystem.
type source interface {
	// read returns a file's contents, or an error if it is not there.
	read(ctx context.Context, p string) ([]byte, error)
}

// procSource reads a running container's filesystem through /proc, which is the
// kernel's view of it and needs nothing from the container itself.
//
// Symbolic links are followed here rather than by the kernel, because an
// absolute link met while walking a path under /proc/<pid>/root is resolved
// against the *caller's* root: reading /proc/<pid>/root/bin/sh straight through
// would hash the node's shell and call every container correct.
type procSource struct{ root string }

func (s procSource) read(_ context.Context, p string) ([]byte, error) {
	cur := p
	for i := 0; i < 16; i++ {
		full := path.Join(s.root, cur)
		fi, err := os.Lstat(full)
		if err != nil {
			return nil, err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			if !fi.Mode().IsRegular() {
				return nil, fmt.Errorf("%s is not a regular file", cur)
			}
			return os.ReadFile(full)
		}
		target, err := os.Readlink(full)
		if err != nil {
			return nil, err
		}
		if path.IsAbs(target) {
			cur = target
		} else {
			cur = path.Join(path.Dir(cur), target)
		}
	}
	return nil, fmt.Errorf("%s: too many levels of symbolic links", p)
}

// copySource reads through the container engine, for callers that are not root
// on the machine the container is running on.
type copySource struct {
	rt   rt.Runtime
	name string
}

// follower is a runtime that can resolve a symbolic link at the end of a path.
type follower interface {
	CopyFromFollow(ctx context.Context, name, src string) ([]byte, error)
}

func (s copySource) read(ctx context.Context, p string) ([]byte, error) {
	if f, ok := s.rt.(follower); ok {
		return f.CopyFromFollow(ctx, s.name, p)
	}
	return s.rt.CopyFrom(ctx, s.name, p)
}

// resolved is where a program was found and what it hashed to.
type resolved struct {
	path string
	sum  string
}

// resolveAll finds each tool the way an exec would: first match along the
// search path.
func resolveAll(ctx context.Context, s source) map[string]resolved {
	out := map[string]resolved{}
	for _, tool := range Tools {
		for _, dir := range searchPath {
			p := path.Join(dir, tool)
			body, err := s.read(ctx, p)
			if err != nil {
				continue
			}
			sum := sha256.Sum256(body)
			out[tool] = resolved{path: p, sum: hex.EncodeToString(sum[:])}
			break
		}
	}
	return out
}

// Checker compares containers against the images they were built from, keeping
// each image's answer so that a lab of two thousand containers pays for it once
// per image.
type Checker struct {
	rt rt.Runtime

	mu       sync.Mutex
	images   map[string]map[string]resolved
	inFlight map[string]chan struct{}
}

// NewChecker returns a checker that reads images through the given runtime.
func NewChecker(r rt.Runtime) *Checker {
	return &Checker{rt: r, images: map[string]map[string]resolved{},
		inFlight: map[string]chan struct{}{}}
}

// Verify reports every tool in a container that is not the one its image ships.
//
// A container whose image cannot be read at all is not a finding: that is the
// grader's own failure, and it comes back as an error so that it is never
// mistaken for a student's.
func (c *Checker) Verify(ctx context.Context, con rt.Container) ([]Finding, error) {
	// The image the container is *running*, not the reference it was created
	// from. A tag moves whenever the images are rebuilt, and a container made
	// before it moved is still correct: comparing it against whatever the tag
	// points at now reports every one of them as tampered with.
	image := con.ImageID
	if image == "" {
		image = con.Image
	}
	if image == "" {
		return nil, fmt.Errorf("container %s reports no image, so there is nothing to "+
			"compare its programs against", con.Name)
	}
	want, err := c.imageTools(ctx, image)
	if err != nil {
		return nil, err
	}
	var src source
	if con.PID > 0 && canReadProc(con.PID) {
		src = procSource{root: fmt.Sprintf("/proc/%d/root", con.PID)}
	} else {
		src = copySource{rt: c.rt, name: con.Name}
	}
	return compare(want, resolveAll(ctx, src)), nil
}

// canReadProc reports whether this process can see into a container's root
// through /proc, which needs root on the machine the container runs on.
func canReadProc(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d/root/.", pid))
	return err == nil
}

// compare turns two resolutions into findings.
func compare(want, got map[string]resolved) []Finding {
	var out []Finding
	for tool, w := range want {
		g, ok := got[tool]
		switch {
		case !ok:
			// The image ships it and the container does not. A tool that
			// cannot be run is not a way to earn marks, and removing one is a
			// thing a student may legitimately do to their own machine, so
			// this is not reported.
			continue
		case g.path != w.path:
			out = append(out, Finding{Tool: tool, Want: w.path, Got: g.path,
				Why: "a program of this name earlier on the search path shadows the image's"})
		case g.sum != w.sum:
			out = append(out, Finding{Tool: tool, Want: w.path, Got: g.path,
				Why: "the file is not the one the image ships"})
		}
	}
	// A tool the image does not have at all, planted in the container, is how
	// a program the grader falls back to gets written.
	for tool, g := range got {
		if _, ok := want[tool]; !ok {
			out = append(out, Finding{Tool: tool, Got: g.path,
				Why: "the image does not ship this program at all"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}

// imageTools resolves the tools in a pristine container of an image.
//
// The container is created and never started, so nothing in it has run and
// nothing could have changed it. One image is read once however many containers
// are built from it, and two callers that want the same image at the same time
// wait for one read rather than making two throwaway containers of the same
// name.
func (c *Checker) imageTools(ctx context.Context, image string) (map[string]resolved, error) {
	for {
		c.mu.Lock()
		if m, ok := c.images[image]; ok {
			c.mu.Unlock()
			return m, nil
		}
		if wait, ok := c.inFlight[image]; ok {
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		done := make(chan struct{})
		c.inFlight[image] = done
		c.mu.Unlock()

		m, err := c.readImage(ctx, image)

		c.mu.Lock()
		delete(c.inFlight, image)
		if err == nil {
			c.images[image] = m
		}
		c.mu.Unlock()
		close(done)
		return m, err
	}
}

func (c *Checker) readImage(ctx context.Context, image string) (map[string]resolved, error) {
	sum := sha256.Sum256([]byte(image))
	name := "twinet-integrity-" + hex.EncodeToString(sum[:8])
	_ = c.rt.Remove(ctx, name, true)
	if _, err := c.rt.Create(ctx, &rt.Spec{Name: name, Image: image,
		Command:     []string{"/bin/true"},
		NetworkMode: "none",
		Labels:      map[string]string{"twinet.integrity": "true"}}); err != nil {
		if strings.Contains(err.Error(), "No such image") {
			// The container is running an image this node no longer has,
			// which happens when the images are rebuilt under a tag that
			// already had containers. Nothing about the student is wrong and
			// nothing about them can be checked either.
			return nil, fmt.Errorf("this container is running an image (%s) that is no "+
				"longer on this node, so the programs in it cannot be compared against "+
				"anything; redeploy the lab so that its containers run the images the "+
				"node actually has", image)
		}
		return nil, fmt.Errorf("a pristine container of %s could not be made to compare "+
			"against: %w", image, err)
	}
	defer func() { _ = c.rt.Remove(context.WithoutCancel(ctx), name, true) }()

	m := resolveAll(ctx, copySource{rt: c.rt, name: name})
	if len(m) == 0 {
		return nil, fmt.Errorf("no program at all could be read out of %s, so no container "+
			"built from it can be checked", image)
	}
	return m, nil
}
