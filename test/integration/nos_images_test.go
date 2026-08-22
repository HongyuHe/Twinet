//go:build nosimages

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestNOSImagesStart verifies real daemon readiness for both registered open
// NOS images. make nos-images checks Docker first; this test consequently
// fails rather than silently skipping when an image cannot be exercised.
func TestNOSImagesStart(t *testing.T) {
	docker := os.Getenv("DOCKER")
	if docker == "" {
		docker = "docker"
	}
	registry := os.Getenv("REGISTRY")
	if registry == "" {
		registry = "hyhe"
	}
	tag := os.Getenv("TAG")
	if tag == "" {
		tag = "0.1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	run := func(args ...string) string {
		t.Helper()
		command := exec.CommandContext(ctx, docker, args...)
		body, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%s failed: %v\n%s", docker+" "+strings.Join(args, " "), err, body)
		}
		return strings.TrimSpace(string(body))
	}
	start := func(image string) string {
		id := run("run", "-d", "--rm", "--cap-add", "NET_ADMIN", image)
		t.Cleanup(func() {
			command := exec.Command(docker, "rm", "-f", id)
			_, _ = command.CombinedOutput()
		})
		return id
	}

	frr := start(fmt.Sprintf("%s/twinet-router:%s", registry, tag))
	bird := start(fmt.Sprintf("%s/twinet-bird:%s", registry, tag))
	run("exec", frr, "sh", "-c", "/usr/lib/frr/frrinit.sh start && vtysh -c 'show version' >/dev/null")
	run("exec", bird, "sh", "-c",
		"cat >/etc/bird/bird.conf <<'BIRD'\n"+
			"router id 127.0.0.1;\n"+
			"protocol device {}\n"+
			"protocol static hijack4 { ipv4; route 10.128.0.0/9 reject; }\n"+
			"filter export_reference { if source != RTS_BGP && source != RTS_STATIC then reject; bgp_path.prepend(1); accept; }\n"+
			"protocol bgp reference { local as 1; neighbor 192.0.2.2 as 2; ipv4 { import none; export filter export_reference; }; }\n"+
			"BIRD\n"+
			"bird -c /etc/bird/bird.conf -s /run/bird.ctl && "+
			"birdc -r -s /run/bird.ctl show status >/dev/null")
}
