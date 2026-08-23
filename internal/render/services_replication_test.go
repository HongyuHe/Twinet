package render

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/place"
)

func TestReplicatedDNSAndRTRRenderEquivalentDeclaredData(t *testing.T) {
	loaded, err := manifest.Load("../../examples/scale")
	if err != nil {
		t.Fatal(err)
	}

	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := place.Place(result.Topology, place.Options{}); err != nil {
		t.Fatal(err)
	}
	renderer := New(result.Topology, ModePlatform)
	for _, name := range []string{"dns", "rpki"} {
		service := result.Topology.Services[name]
		if service == nil || len(service.Replicas) < 2 {
			t.Fatalf("%s did not expand into multiple replicas", name)
		}
		var baseline map[string][]byte
		for _, replica := range service.SortedReplicas() {
			files, err := renderer.Files(replica.Device)
			if err != nil {
				t.Fatal(err)
			}
			declared := declaredServiceFiles(files)
			if baseline == nil {
				baseline = declared
				continue
			}
			if !sameFiles(baseline, declared) {
				t.Fatalf("%s replica %s rendered data different from its peers", name, replica.ID)
			}
		}

	}
}

func declaredServiceFiles(files map[string]deploy.FileSpec) map[string][]byte {
	out := map[string][]byte{}
	for path, file := range files {
		if path == "/etc/twinet/device.json" {
			continue
		}
		out[path] = file.Content
	}
	return out
}

func sameFiles(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	keys := make([]string, 0, len(a))
	for key := range a {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !bytes.Equal(a[key], b[key]) {
			return false
		}
	}
	return true
}

func TestDNSDaemonDoesNotRetainExecTransportPipes(t *testing.T) {
	loaded, err := manifest.Load("../../examples/scale")
	if err != nil {
		t.Fatal(err)
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := place.Place(result.Topology, place.Options{}); err != nil {
		t.Fatal(err)
	}
	service := result.Topology.Services["dns"]
	if service == nil || len(service.Replicas) == 0 {
		t.Fatal("scale topology has no DNS replica")
	}
	commands, err := New(result.Topology, ModePlatform).Commands(service.SortedReplicas()[0].Device)
	if err != nil {
		t.Fatal(err)
	}
	var start string
	for _, command := range commands {
		if command.Describe == "start the authoritative resolver" {
			start = strings.Join(command.Args, " ")
			break
		}
	}
	if !strings.Contains(start, "named -g") ||
		!strings.Contains(start, ">/var/log/named/twinet.log 2>&1 &") {
		t.Fatalf("DNS start command does not detach from its exec transport:\n%s", start)
	}
}
