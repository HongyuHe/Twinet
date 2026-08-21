package runtime

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestResolvePodmanHost(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		euid int
		uid  int
		want string
	}{
		{
			name: "explicit unix socket path",
			env:  map[string]string{podmanBackendEnv: "/srv/podman.sock"},
			euid: 1000,
			uid:  1000,
			want: "unix:///srv/podman.sock",
		},
		{
			name: "explicit tcp endpoint",
			env:  map[string]string{podmanBackendEnv: "tcp://podman.example:8080"},
			euid: 1000,
			uid:  1000,
			want: "tcp://podman.example:8080",
		},
		{
			name: "rootful default",
			env:  map[string]string{},
			euid: 0,
			uid:  0,
			want: "unix:///run/podman/podman.sock",
		},
		{
			name: "rootless runtime directory",
			env:  map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"},
			euid: 1000,
			uid:  1000,
			want: "unix:///run/user/1000/podman/podman.sock",
		},
		{
			name: "rootless fallback",
			env:  map[string]string{},
			euid: 1000,
			uid:  1000,
			want: "unix:///run/user/1000/podman/podman.sock",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolvePodmanHost(func(key string) string { return tc.env[key] }, tc.euid, tc.uid)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("host = %q, want %q", got, tc.want)
			}
		})
	}
	for _, host := range []string{"http://127.0.0.1:8080", "ssh://podman.example", "relative.sock"} {
		_, err := resolvePodmanHost(func(key string) string {
			if key == podmanBackendEnv {
				return host
			}
			return ""
		}, 1000, 1000)
		if err == nil || !strings.Contains(err.Error(), podmanBackendEnv) {
			t.Errorf("host %q error = %v, want explicit %s error", host, err, podmanBackendEnv)
		}
	}
}

func TestPodmanRuntimeIsRegistered(t *testing.T) {
	runtime, err := NewRuntime("podman")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Name() != "podman" {
		t.Fatalf("runtime name = %q, want podman", runtime.Name())
	}
	if _, ok := runtime.(EventRuntime); !ok {
		t.Fatalf("podman runtime %T does not implement EventRuntime", runtime)
	}
	capabilities, ok := CapabilitiesFor("podman")
	if !ok || !capabilities.Lifecycle || !capabilities.Exec || !capabilities.Copy ||
		!capabilities.NetworkNamespaces || !capabilities.Events {
		t.Fatalf("podman capabilities = %#v", capabilities)
	}
}

func TestPodmanReportsInvalidHostOnFirstOperation(t *testing.T) {
	t.Setenv(podmanBackendEnv, "http://127.0.0.1:8080")
	podman := NewPodman()
	_, err := podman.Ping(context.Background())
	if err == nil || !strings.Contains(err.Error(), "resolve Podman API host") ||
		!strings.Contains(err.Error(), podmanBackendEnv) {
		t.Fatalf("invalid Podman host error = %v", err)
	}
}

func TestPodmanOperationErrorsIdentifyPodman(t *testing.T) {
	fake := newEngineFake(t, func(w http.ResponseWriter, r *http.Request) {
		path, ok := podmanRequestPath(t, r)
		if !ok {
			return
		}
		if path != "/containers/missing/start" {
			http.Error(w, "unexpected Podman API request", http.StatusNotFound)
			return
		}
		http.Error(w, "no such container", http.StatusNotFound)
	})
	podman := newTestPodman(t, fake)
	err := podman.Start(context.Background(), "missing")
	if err == nil || !strings.Contains(err.Error(), "podman start missing") || strings.Contains(err.Error(), "docker start") {
		t.Fatalf("Podman start error = %v", err)
	}
}

func TestPodmanCompatibilityContract(t *testing.T) {
	var (
		mu         sync.Mutex
		stdin      string
		copyHeader *tar.Header
		copyData   []byte
	)
	fake := newEngineFake(t, func(w http.ResponseWriter, r *http.Request) {
		path, ok := podmanRequestPath(t, r)
		if !ok {
			return
		}
		switch {
		case path == "/version":
			writeDockerJSON(w, http.StatusOK, map[string]any{
				"Version":       "5.4.2",
				"ApiVersion":    podmanCompatAPIVersion,
				"MinAPIVersion": "1.24",
			})
		case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json"):
			image := strings.TrimSuffix(strings.TrimPrefix(path, "/images/"), "/json")
			if image == "missing" {
				writeDockerJSON(w, http.StatusNotFound, map[string]string{"message": "no such image"})
				return
			}
			if image == "digest-only" {
				writeDockerJSON(w, http.StatusOK, map[string]any{
					"Id":     "sha256:podman-image",
					"Digest": "sha256:podman-manifest",
				})
				return
			}
			writeDockerJSON(w, http.StatusOK, map[string]any{
				"Id":          "sha256:podman-image",
				"RepoDigests": []string{"example@sha256:podman-digest"},
			})
		case path == "/images/create":
			if got := r.URL.Query().Get("fromImage"); got != "docker.io/library/example" {
				t.Errorf("Podman pull image = %q, want normalized example", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{\"status\":\"done\"}\n"))
		case path == "/containers/create":
			if got := r.URL.Query().Get("name"); got != "pod" {
				t.Errorf("Podman create name = %q, want pod", got)
			}
			writeDockerJSON(w, http.StatusCreated, map[string]string{"Id": "pod-id"})
		case path == "/containers/pod/start", path == "/containers/pod/pause", path == "/containers/pod/unpause":
			w.WriteHeader(http.StatusNoContent)
		case path == "/containers/pod/stop":
			if got := r.URL.Query().Get("t"); got != "3" {
				t.Errorf("Podman stop timeout = %q, want 3", got)
			}
			w.WriteHeader(http.StatusNoContent)
		case path == "/containers/pod":
			if r.Method != http.MethodDelete {
				http.Error(w, "wrong method", http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case path == "/containers/configured/json":
			writeDockerJSON(w, http.StatusOK, fakePodmanContainer("configured", "configured-id", 0, "configured"))
		case path == "/containers/running/json":
			writeDockerJSON(w, http.StatusOK, fakePodmanContainer("running", "running-id", 419, "running"))
		case path == "/containers/mystery/json":
			writeDockerJSON(w, http.StatusOK, fakePodmanContainer("mystery", "mystery-id", 0, "mystery"))
		case path == "/containers/json":
			if got := r.URL.Query().Get("all"); got != "1" {
				t.Errorf("Podman list all = %q, want 1", got)
			}
			writeDockerJSON(w, http.StatusOK, []map[string]any{
				{"Id": "pod-z"},
				{"Id": "pod-a"},
			})
		case path == "/containers/pod-a/json":
			writeDockerJSON(w, http.StatusOK, fakePodmanContainer("a", "pod-a", 10, "configured"))
		case path == "/containers/pod-z/json":
			writeDockerJSON(w, http.StatusOK, fakePodmanContainer("z", "pod-z", 20, "stopped"))
		case path == "/containers/pod/exec":
			writeDockerJSON(w, http.StatusCreated, map[string]string{"Id": "pod-exec"})
		case path == "/exec/pod-exec/start":
			serveExecStream(t, w, r, &mu, &stdin)
		case path == "/exec/pod-exec/json":
			writeDockerJSON(w, http.StatusOK, map[string]any{
				"ID":       "pod-exec",
				"Running":  false,
				"ExitCode": 7,
			})
		case path == "/containers/pod/archive" && r.Method == http.MethodPut:
			reader := tar.NewReader(r.Body)
			header, err := reader.Next()
			if err != nil {
				t.Errorf("read Podman copy header: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			data, err := io.ReadAll(reader)
			if err != nil {
				t.Errorf("read Podman copy data: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			copyHeader = header
			copyData = data
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case path == "/containers/pod/archive" && r.Method == http.MethodHead:
			link := ""
			if r.URL.Query().Get("path") == "/link" {
				link = "file"
			}
			w.Header().Set("X-Docker-Container-Path-Stat", dockerPathStat(link))
			w.WriteHeader(http.StatusOK)
		case path == "/containers/pod/archive" && r.Method == http.MethodGet:
			switch r.URL.Query().Get("path") {
			case "/file":
				w.Header().Set("X-Docker-Container-Path-Stat", dockerPathStat(""))
				_, _ = w.Write(tarBytes(t, &tar.Header{Name: "file", Mode: 0o644, Size: 4}, []byte("copy")))
			default:
				http.Error(w, "unknown archive path", http.StatusNotFound)
			}
		case path == "/containers/unsupported/archive" && r.Method == http.MethodHead:
			http.Error(w, "archive stat is unsupported", http.StatusNotImplemented)
		case path == "/events":
			w.Header().Set("Content-Type", "application/x-ndjson")
			encoder := json.NewEncoder(w)
			_ = encoder.Encode(map[string]any{
				"Type":   "container",
				"Action": "died",
				"Actor": map[string]any{
					"ID":         "pod-id",
					"Attributes": map[string]string{"name": "pod", "twinet.lab": "lab"},
				},
				"time": 10,
			})
			_ = encoder.Encode(map[string]any{
				"Type":   "container",
				"Action": "remove",
				"Actor": map[string]any{
					"ID":         "pod-id",
					"Attributes": map[string]string{"name": "pod", "twinet.lab": "lab"},
				},
				"time": 11,
			})
		default:
			http.Error(w, "unexpected Podman API request "+path, http.StatusNotFound)
		}
	})
	podman := newTestPodman(t, fake)
	ctx := context.Background()

	if version, err := podman.Ping(ctx); err != nil || version != "5.4.2" {
		t.Fatalf("Podman ping = (%q, %v), want 5.4.2", version, err)
	}
	backend, err := podman.backendFor()
	if err != nil {
		t.Fatal(err)
	}
	api, ok := backend.(*podmanAPI)
	if !ok {
		t.Fatalf("Podman backend = %T, want *podmanAPI", backend)
	}
	if api.host != strings.Replace(fake.server.URL, "http://", "tcp://", 1) {
		t.Fatalf("Podman host = %q, want fake TCP endpoint", api.host)
	}

	exists, err := podman.ImageExists(ctx, "present")
	if err != nil || !exists {
		t.Fatalf("Podman image exists = (%t, %v), want true", exists, err)
	}
	if err := podman.PullImage(ctx, "example:latest", PullAlways); err != nil {
		t.Fatalf("Podman pull image: %v", err)
	}
	if digest, err := podman.ImageDigest(ctx, "present"); err != nil || digest != "example@sha256:podman-digest" {
		t.Fatalf("Podman image digest = (%q, %v)", digest, err)
	}
	if digest, err := podman.ImageDigest(ctx, "digest-only"); err != nil || digest != "sha256:podman-manifest" {
		t.Fatalf("Podman native-style image digest = (%q, %v)", digest, err)
	}

	if id, err := podman.Create(ctx, &Spec{Name: "pod", Image: "present"}); err != nil || id != "pod-id" {
		t.Fatalf("Podman create = (%q, %v)", id, err)
	}
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{"start", func() error { return podman.Start(ctx, "pod") }},
		{"pause", func() error { return podman.Pause(ctx, "pod") }},
		{"unpause", func() error { return podman.Unpause(ctx, "pod") }},
		{"stop", func() error { return podman.Stop(ctx, "pod", 3*time.Second) }},
		{"remove", func() error { return podman.Remove(ctx, "pod", true) }},
	} {
		if err := operation.run(); err != nil {
			t.Errorf("Podman %s: %v", operation.name, err)
		}
	}

	configured, err := podman.Inspect(ctx, "configured")
	if err != nil {
		t.Fatal(err)
	}
	if configured.State != StateCreated {
		t.Errorf("configured Podman state = %q, want created", configured.State)
	}
	if nsPath, err := podman.NSPath(ctx, "running"); err != nil || nsPath != "/proc/419/ns/net" {
		t.Fatalf("Podman namespace path = (%q, %v)", nsPath, err)
	}
	if _, err := podman.Inspect(ctx, "mystery"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown Podman state error = %v, want ErrUnsupported", err)
	}
	listed, err := podman.List(ctx, Filter{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].Name != "a" || listed[0].State != StateCreated ||
		listed[1].Name != "z" || listed[1].State != StateExited {
		t.Errorf("Podman list = %#v", listed)
	}

	execResult, err := podman.Exec(ctx, "pod", ExecCmd{Cmd: []string{"run"}, Stdin: strings.NewReader("input")})
	if err != nil {
		t.Fatal(err)
	}
	if execResult.ExitCode != 7 || execResult.Stdout != "out" || execResult.Stderr != "err" {
		t.Errorf("Podman exec = %#v", execResult)
	}
	mu.Lock()
	gotStdin := stdin
	mu.Unlock()
	if gotStdin != "input" {
		t.Errorf("Podman exec stdin = %q, want input", gotStdin)
	}

	if err := podman.CopyTo(ctx, "pod", "/etc/file", 0o640, []byte("copy")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gotHeader, gotCopy := copyHeader, append([]byte(nil), copyData...)
	mu.Unlock()
	if gotHeader == nil || gotHeader.Name != "file" || gotHeader.Mode != 0o640 || string(gotCopy) != "copy" {
		t.Errorf("Podman copy to = header:%#v content:%q", gotHeader, gotCopy)
	}
	if copied, err := podman.CopyFrom(ctx, "pod", "/file"); err != nil || string(copied) != "copy" {
		t.Fatalf("Podman copy from = (%q, %v)", copied, err)
	}
	if copied, err := podman.CopyFromFollow(ctx, "pod", "/link"); err != nil || string(copied) != "copy" {
		t.Fatalf("Podman copy from link = (%q, %v)", copied, err)
	}
	if _, err := podman.CopyFromFollow(ctx, "unsupported", "/link"); !errors.Is(err, ErrUnsupported) ||
		!strings.Contains(err.Error(), "symlink metadata") {
		t.Fatalf("Podman unsupported copy-follow error = %v", err)
	}

	events, terminal := collectEvents(t, podman.Subscribe(ctx, EventFilter{Labels: map[string]string{"twinet.lab": "lab"}}))
	if !errors.Is(terminal, io.EOF) {
		t.Fatalf("Podman event terminal error = %v, want EOF", terminal)
	}
	if len(events) != 2 {
		t.Fatalf("Podman events = %#v, want died and remove", events)
	}
	if got, want := []EventAction{events[0].Action, events[1].Action}, []EventAction{EventDie, EventDestroy}; !slices.Equal(got, want) {
		t.Errorf("Podman event actions = %#v, want %#v", got, want)
	}
	if events[0].Container != "pod-id" || events[0].Labels["twinet.lab"] != "lab" {
		t.Errorf("Podman event = %#v", events[0])
	}

	_, err = podman.Create(ctx, &Spec{
		Name:        "unsupported",
		Image:       "present",
		MaskedPaths: []string{"/proc/kcore"},
	})
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "MaskedPaths") {
		t.Fatalf("Podman unsupported path hardening error = %v", err)
	}
	if fake.requestCount("/_ping") != 0 {
		t.Fatal("Podman compatibility client unexpectedly negotiated through Docker _ping")
	}
}

func newTestPodman(t *testing.T, fake *engineFake) *Podman {
	t.Helper()
	t.Setenv(podmanBackendEnv, strings.Replace(fake.server.URL, "http://", "tcp://", 1))
	podman := NewPodman()
	t.Cleanup(func() {
		if err := podman.Close(); err != nil {
			t.Errorf("close Podman API client: %v", err)
		}
	})
	return podman
}

func podmanRequestPath(t *testing.T, r *http.Request) (string, bool) {
	t.Helper()
	if r.URL.Path == "/_ping" {
		t.Error("Podman compatibility client must use its fixed compatibility API version, not Docker negotiation")
		return "", false
	}
	const prefix = "/v" + podmanCompatAPIVersion
	if !strings.HasPrefix(r.URL.Path, prefix+"/") {
		t.Errorf("Podman API path = %q, want %s/...", r.URL.Path, prefix)
		return "", false
	}
	return strings.TrimPrefix(r.URL.Path, prefix), true
}

func fakePodmanContainer(name, id string, pid int, state string) map[string]any {
	return map[string]any{
		"Id":    id,
		"Name":  "/" + name,
		"Image": "sha256:podman-image",
		"State": map[string]any{
			"Status": state,
			"Pid":    pid,
		},
		"Config": map[string]any{
			"Image":  "present",
			"Labels": map[string]string{"twinet.lab": "lab"},
		},
	}
}
