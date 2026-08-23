package render

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
)

func TestROAPublicationUsesOneDetachedPublisherPerAS(t *testing.T) {
	loaded, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatal(err)
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	renderer := New(result.Topology, ModeSolve)
	count := func(asn int) (int, string) {
		as := result.Topology.ASes[asn]
		if as == nil {
			t.Fatalf("AS %d is absent", asn)
		}
		total, command := 0, ""
		for _, router := range as.Routers {
			commands, err := renderer.Commands(router)
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range commands {
				if candidate.Describe == "authorise this system's prefix with the lab's trust anchor" {
					total++
					command = candidate.Args[len(candidate.Args)-1]
				}
			}
		}
		return total, command
	}

	total, command := count(3)
	if total != 1 {
		t.Fatalf("AS 3 has %d ROA publishers, want exactly one", total)
	}
	if !strings.Contains(command, "setsid sh /etc/twinet/roa_publish.sh") ||
		!strings.Contains(command, "</dev/null >/tmp/twinet-roa-publish.log 2>&1 &") {
		t.Fatalf("ROA publication retains the deployment transport:\n%s", command)
	}
	script := t.TempDir() + "/publish.sh"
	if err := os.WriteFile(script, []byte(command), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("sh", "-n", script).CombinedOutput(); err != nil {
		t.Fatalf("ROA publisher is not valid shell: %v\n%s\n---\n%s", err, out, command)
	}
	result.Topology.Lab.RPKI.NotFound = append(result.Topology.Lab.RPKI.NotFound, 3)
	if total, _ := count(3); total != 0 {
		t.Fatalf("deliberate not-found AS 3 has %d ROA publishers", total)
	}
}
