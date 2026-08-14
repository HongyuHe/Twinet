package render

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The watcher is a shell script assembled in Go, so it is checked by a shell.
//
// A quoting mistake here does not fail a build or a test: it produces a script
// that a router runs, fails, and never mentions again, and the symptom is an
// origin-validation question the whole class gets wrong.
func TestTheRPKIWatcherIsValidShell(t *testing.T) {
	body := RPKIRefreshScript
	f, err := os.CreateTemp(t.TempDir(), "rpki-*.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-n", f.Name()).CombinedOutput()
	if err != nil {
		t.Fatalf("the watcher is not valid shell: %v\n%s\n---\n%s", err, out, body)
	}
	// And the inner script, which is written by a heredoc and never seen by
	// the outer parse.
	inner := body
	if i := strings.Index(inner, "<<'TWINET_RPKI'\n"); i >= 0 {
		inner = inner[i+len("<<'TWINET_RPKI'\n"):]
	}
	if i := strings.Index(inner, "\nTWINET_RPKI"); i >= 0 {
		inner = inner[:i]
	}
	g, err := os.CreateTemp(t.TempDir(), "rpki-inner-*.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.WriteString(inner); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("sh", "-n", g.Name()).CombinedOutput(); err != nil {
		t.Fatalf("the watcher's inner script is not valid shell: %v\n%s\n---\n%s",
			err, out, inner)
	}
	// It must actually contain the repair, or it is the version that watched a
	// dead session for ever.
	if !strings.Contains(inner, "No connection") {
		t.Error("the watcher does not look for a disconnected validator session")
	}
}
