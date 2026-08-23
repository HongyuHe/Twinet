package integrity

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mapSource is a filesystem of known files.
type mapSource map[string]string

func (m mapSource) read(_ context.Context, p string) ([]byte, error) {
	body, ok := m[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(body), nil
}

// The whole point: a program the student wrote is not the image's program.
func TestAReplacedProgramIsFound(t *testing.T) {
	image := mapSource{"/usr/bin/ping": "the real one"}
	container := mapSource{"/usr/bin/ping": "#!/bin/sh\necho '3 packets transmitted, 3 received'"}

	got := compare(resolveAll(context.Background(), image),
		resolveAll(context.Background(), container))
	if len(got) != 1 {
		t.Fatalf("a container whose ping is a shell script was passed as untouched: %+v", got)
	}
	if got[0].Tool != "ping" || !strings.Contains(got[0].Why, "not the one the image ships") {
		t.Errorf("the finding does not say what is wrong: %s", got[0])
	}
}

// A student need not touch the image's copy at all.
//
// Exec resolves a bare name along the search path, so a file earlier on it is
// the program that runs while the one the grader would have hashed sits
// untouched further down.
func TestAShadowingProgramIsFound(t *testing.T) {
	image := mapSource{"/usr/bin/ping": "the real one"}
	container := mapSource{
		"/usr/bin/ping":       "the real one",
		"/usr/local/bin/ping": "#!/bin/sh\nexit 0",
	}

	got := compare(resolveAll(context.Background(), image),
		resolveAll(context.Background(), container))
	if len(got) != 1 {
		t.Fatalf("a ping planted earlier on the search path was not found: %+v", got)
	}
	if got[0].Got != "/usr/local/bin/ping" || got[0].Want != "/usr/bin/ping" {
		t.Errorf("the finding does not name both copies: %s", got[0])
	}
}

// A program the image does not have at all is a plant.
func TestAProgramTheImageDoesNotShipIsFound(t *testing.T) {
	image := mapSource{"/usr/bin/ping": "the real one"}
	container := mapSource{"/usr/bin/ping": "the real one", "/usr/bin/nc": "#!/bin/sh\nexit 0"}

	got := compare(resolveAll(context.Background(), image),
		resolveAll(context.Background(), container))
	if len(got) != 1 || got[0].Tool != "nc" {
		t.Fatalf("a program planted where the image has none was not found: %+v", got)
	}
}

// An untouched container must not cost anybody a mark.
func TestAnUntouchedContainerHasNoFindings(t *testing.T) {
	same := mapSource{
		"/usr/bin/ping": "the real one",
		"/usr/bin/ip":   "iproute2",
		"/bin/sh":       "dash",
	}
	if got := compare(resolveAll(context.Background(), same),
		resolveAll(context.Background(), same)); len(got) != 0 {
		t.Fatalf("a container identical to its image was reported as tampered with: %+v", got)
	}
}

// Removing a program from your own machine is not cheating.
//
// It cannot earn a mark either: a check that cannot run its probe reports that
// it could not, which is not a pass.
func TestAMissingProgramIsNotAFinding(t *testing.T) {
	image := mapSource{"/usr/bin/ping": "the real one", "/usr/bin/nc": "netcat"}
	container := mapSource{"/usr/bin/ping": "the real one"}

	if got := compare(resolveAll(context.Background(), image),
		resolveAll(context.Background(), container)); len(got) != 0 {
		t.Fatalf("a container missing a program was reported as tampered with: %+v", got)
	}
}

// Reading a container's files through /proc must stay inside the container.
//
// An absolute symbolic link met while walking a path under /proc/<pid>/root is
// resolved by the kernel against the caller's root, so following one straight
// through hashes the node's own program and calls every container correct. This
// is the test that the walk is done here instead.
func TestAnAbsoluteSymlinkResolvesInsideTheContainer(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "bin", "dash"),
		[]byte("the container's shell"), 0o755); err != nil {
		t.Fatal(err)
	}
	// /bin/sh -> /usr/bin/dash, written as an absolute path, exactly as a
	// Debian image has it.
	if err := os.Symlink("/usr/bin/dash", filepath.Join(root, "bin", "sh")); err != nil {
		t.Fatal(err)
	}

	body, err := procSource{root: root}.read(context.Background(), "/bin/sh")
	if err != nil {
		t.Fatalf("the container's shell could not be read: %v", err)
	}
	if string(body) != "the container's shell" {
		t.Errorf("reading /bin/sh left the container and hashed something else: %q", body)
	}
}

// A link that points at itself must not hang the grader.
func TestALoopingSymlinkIsAnError(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/ping", filepath.Join(root, "usr", "bin", "ping")); err != nil {
		t.Fatal(err)
	}
	if _, err := (procSource{root: root}).read(context.Background(), "/usr/bin/ping"); err == nil {
		t.Fatal("a symbolic link pointing at itself was followed forever")
	}
}

// The error a grading run meets has to say what was wrong with which container,
// because the only safe response to it is to stop and tell somebody.
func TestTheErrorNamesTheContainerAndTheProgram(t *testing.T) {
	err := &Error{Container: "twinet-cos461-as3-atl", Findings: []Finding{
		{Tool: "ping", Want: "/usr/bin/ping", Got: "/usr/local/bin/ping",
			Why: "a program of this name earlier on the search path shadows the image's"}}}
	msg := err.Error()
	for _, want := range []string{"twinet-cos461-as3-atl", "ping", "/usr/local/bin/ping"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message does not mention %q: %s", want, msg)
		}
	}

}

func TestIntegrityContainerStartRequirement(t *testing.T) {
	for _, runtimeName := range []string{"podman", "containerd"} {
		if !integrityContainerNeedsStart(runtimeName) {
			t.Fatalf("%s pristine container was left unstarted", runtimeName)
		}
	}
	for _, runtimeName := range []string{"docker", "memory"} {
		if integrityContainerNeedsStart(runtimeName) {
			t.Fatalf("%s pristine container was started unnecessarily", runtimeName)
		}
	}
}
