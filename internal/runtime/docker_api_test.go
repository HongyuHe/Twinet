package runtime

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type engineFake struct {
	server *httptest.Server

	mu             sync.Mutex
	newConnections int
	requests       []string
}

func newEngineFake(t *testing.T, handler http.HandlerFunc) *engineFake {
	t.Helper()
	fake := &engineFake{}
	fake.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		fake.requests = append(fake.requests, r.Method+" "+enginePath(r))
		fake.mu.Unlock()
		handler(w, r)
	}))
	fake.server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			fake.mu.Lock()
			fake.newConnections++
			fake.mu.Unlock()
		}
	}
	fake.server.Start()
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *engineFake) connectionCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.newConnections
}

func (f *engineFake) requestCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, request := range f.requests {
		if strings.HasSuffix(request, " "+path) {
			count++
		}
	}
	return count
}

func newEngineDocker(t *testing.T, fake *engineFake) *Docker {
	t.Helper()
	t.Setenv(dockerBackendEnv, "")
	t.Setenv("DOCKER_HOST", strings.Replace(fake.server.URL, "http://", "tcp://", 1))
	t.Setenv("DOCKER_API_VERSION", "")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	docker := NewDocker()
	t.Cleanup(func() {
		if err := docker.Close(); err != nil {
			t.Errorf("close Docker API client: %v", err)
		}
	})
	return docker
}

func enginePath(r *http.Request) string {
	path := r.URL.Path
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
	if len(parts) == 2 && strings.HasPrefix(parts[0], "v") {
		return "/" + parts[1]
	}
	return path
}

func servePing(w http.ResponseWriter, r *http.Request) bool {
	if enginePath(r) != "/_ping" {
		return false
	}
	w.Header().Set("API-Version", "1.55")
	w.WriteHeader(http.StatusOK)
	return true
}

func serveVersion(w http.ResponseWriter, r *http.Request) bool {
	if enginePath(r) != "/version" {
		return false
	}
	writeDockerJSON(w, http.StatusOK, map[string]any{
		"Version":       "27.5.1",
		"ApiVersion":    "1.55",
		"MinAPIVersion": "1.44",
	})
	return true
}

func writeDockerJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func TestDockerDefaultUsesEngineAPIAndReusesTransport(t *testing.T) {
	fake := newEngineFake(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case servePing(w, r), serveVersion(w, r):
		default:
			http.Error(w, "unexpected Docker API request", http.StatusNotFound)
		}
	})
	t.Setenv("PATH", "")
	docker := newEngineDocker(t, fake)

	for range 2 {
		version, err := docker.Ping(context.Background())
		if err != nil {
			t.Fatalf("ping Docker API: %v", err)
		}
		if version != "27.5.1" {
			t.Fatalf("version = %q, want 27.5.1", version)
		}
	}

	backend, err := docker.backendFor()
	if err != nil {
		t.Fatalf("initialize backend: %v", err)
	}
	if _, ok := backend.(*dockerAPI); !ok {
		t.Fatalf("default backend = %T, want *dockerAPI", backend)
	}
	if got := fake.connectionCount(); got != 1 {
		t.Fatalf("connections = %d, want one reused API transport", got)
	}
	if got := fake.requestCount("/_ping"); got != 1 {
		t.Fatalf("API version negotiations = %d, want 1", got)
	}
}

func TestDockerCLIIsExplicitCompatibilityMode(t *testing.T) {
	t.Setenv(dockerBackendEnv, "cli")
	docker := NewDocker()

	backend, err := docker.backendFor()
	if err != nil {
		t.Fatalf("initialize CLI backend: %v", err)
	}
	if _, ok := backend.(*dockerCLI); !ok {
		t.Fatalf("explicit CLI backend = %T, want *dockerCLI", backend)
	}
}

func TestDockerCreateConfigLeavesUnspecifiedOptionsUnset(t *testing.T) {
	config, hostConfig, err := dockerCreateConfig(&Spec{Image: "example:latest"})
	if err != nil {
		t.Fatalf("create config: %v", err)
	}
	if config.Env != nil || config.Labels != nil {
		t.Errorf("empty config options = Env:%#v Labels:%#v, want nil", config.Env, config.Labels)
	}
	if hostConfig.Binds != nil || hostConfig.Tmpfs != nil || hostConfig.Sysctls != nil {
		t.Errorf("empty host options = Binds:%#v Tmpfs:%#v Sysctls:%#v, want nil",
			hostConfig.Binds, hostConfig.Tmpfs, hostConfig.Sysctls)
	}
	if hostConfig.CapDrop != nil || hostConfig.SecurityOpt != nil ||
		hostConfig.MaskedPaths != nil || hostConfig.ReadonlyPaths != nil ||
		hostConfig.ReadonlyRootfs || hostConfig.Runtime != "" || hostConfig.UsernsMode != "" {
		t.Errorf("empty hardening options = %#v, want Docker zero values", hostConfig)
	}

	_, explicitlyCleared, err := dockerCreateConfig(&Spec{
		Image:         "example:latest",
		MaskedPaths:   []string{},
		ReadonlyPaths: []string{},
	})
	if err != nil {
		t.Fatalf("create config with cleared system paths: %v", err)
	}
	if explicitlyCleared.MaskedPaths == nil || explicitlyCleared.ReadonlyPaths == nil {
		t.Errorf("explicitly cleared system paths = Masked:%#v Readonly:%#v, want non-nil empty lists",
			explicitlyCleared.MaskedPaths, explicitlyCleared.ReadonlyPaths)
	}
}

func TestDockerAPIHonorsOperationContext(t *testing.T) {
	started := make(chan struct{})
	fake := newEngineFake(t, func(w http.ResponseWriter, r *http.Request) {
		if servePing(w, r) {
			return
		}
		if enginePath(r) != "/containers/blocked/json" {
			http.Error(w, "unexpected Docker API request", http.StatusNotFound)
			return
		}
		close(started)
		<-r.Context().Done()
	})
	docker := newEngineDocker(t, fake)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := docker.Inspect(ctx, "blocked")
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Docker API request did not reach the fake")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("inspect cancellation error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Docker API operation did not stop after context cancellation")
	}
}

func TestDockerAPIHardeningCreateRequest(t *testing.T) {
	var (
		mu       sync.Mutex
		captured struct {
			HostConfig struct {
				SecurityOpt    []string
				ReadonlyRootfs bool
				Runtime        string
				UsernsMode     string
				CapDrop        []string
				MaskedPaths    []string
				ReadonlyPaths  []string
			}
		}
	)
	fake := newEngineFake(t, func(w http.ResponseWriter, r *http.Request) {
		if servePing(w, r) {
			return
		}
		if enginePath(r) != "/containers/create" {
			http.Error(w, "unexpected Docker API request", http.StatusNotFound)
			return
		}
		var request struct {
			HostConfig struct {
				SecurityOpt    []string
				ReadonlyRootfs bool
				Runtime        string
				UsernsMode     string
				CapDrop        []string
				MaskedPaths    []string
				ReadonlyPaths  []string
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode hardening create request: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		captured = request
		mu.Unlock()
		writeDockerJSON(w, http.StatusCreated, map[string]string{"Id": "hardened-id"})
	})
	docker := newEngineDocker(t, fake)

	_, err := docker.Create(context.Background(), &Spec{
		Name:           "hardened",
		Image:          "example:latest",
		SecurityOpt:    []string{"no-new-privileges", "seccomp=unconfined", "apparmor=twinet"},
		ReadOnlyRootfs: true,
		RuntimeClass:   "runsc",
		UsernsMode:     "host",
		CapDrop:        []string{"CAP_NET_RAW", "CAP_SYS_ADMIN"},
		MaskedPaths:    []string{"/proc/kcore", "/proc/keys"},
		ReadonlyPaths:  []string{"/proc/sys", "/proc/irq"},
	})
	if err != nil {
		t.Fatalf("create hardened container: %v", err)
	}

	mu.Lock()
	got := captured.HostConfig
	mu.Unlock()
	if !slices.Equal(got.SecurityOpt, []string{"no-new-privileges", "seccomp=unconfined", "apparmor=twinet"}) {
		t.Errorf("SecurityOpt = %#v", got.SecurityOpt)
	}
	if !got.ReadonlyRootfs || got.Runtime != "runsc" || got.UsernsMode != "host" {
		t.Errorf("rootfs/runtime/userns = %#v", got)
	}
	if !slices.Equal(got.CapDrop, []string{"CAP_NET_RAW", "CAP_SYS_ADMIN"}) {
		t.Errorf("CapDrop = %#v", got.CapDrop)
	}
	if !slices.Equal(got.MaskedPaths, []string{"/proc/kcore", "/proc/keys"}) {
		t.Errorf("MaskedPaths = %#v", got.MaskedPaths)
	}
	if !slices.Equal(got.ReadonlyPaths, []string{"/proc/sys", "/proc/irq"}) {
		t.Errorf("ReadonlyPaths = %#v", got.ReadonlyPaths)
	}
}

func TestDockerCLIHardeningArguments(t *testing.T) {
	args, err := dockerCLICreateArgs(&Spec{
		Name:           "hardened",
		Image:          "example:latest",
		SecurityOpt:    []string{"no-new-privileges", "seccomp=unconfined", "apparmor=twinet"},
		ReadOnlyRootfs: true,
		RuntimeClass:   "runsc",
		UsernsMode:     "host",
		CapDrop:        []string{"NET_RAW", "SYS_ADMIN"},
	})
	if err != nil {
		t.Fatalf("build CLI arguments: %v", err)
	}
	want := []string{
		"create", "--name", "hardened", "--network", "none",
		"--cap-drop", "NET_RAW", "--cap-drop", "SYS_ADMIN",
		"--security-opt", "no-new-privileges",
		"--security-opt", "seccomp=unconfined",
		"--security-opt", "apparmor=twinet",
		"--read-only", "--runtime", "runsc", "--userns", "host",
		"example:latest",
	}
	if !slices.Equal(args, want) {
		t.Errorf("CLI arguments = %#v, want %#v", args, want)
	}
}

func TestDockerCLIHardeningSystemPaths(t *testing.T) {
	args, err := dockerCLICreateArgs(&Spec{
		Name:          "clear-system-paths",
		Image:         "example:latest",
		MaskedPaths:   []string{},
		ReadonlyPaths: []string{},
	})
	if err != nil {
		t.Fatalf("build CLI arguments for cleared system paths: %v", err)
	}
	want := []string{
		"create", "--name", "clear-system-paths", "--network", "none",
		"--security-opt", "systempaths=unconfined", "example:latest",
	}
	if !slices.Equal(args, want) {
		t.Errorf("CLI system-path arguments = %#v, want %#v", args, want)
	}

	for _, spec := range []*Spec{
		{
			Name:        "custom-masked-paths",
			Image:       "example:latest",
			MaskedPaths: []string{"/proc/kcore"},
		},
		{
			Name:          "custom-readonly-paths",
			Image:         "example:latest",
			ReadonlyPaths: []string{"/proc/sys"},
		},
	} {
		_, err = dockerCLICreateArgs(spec)
		if err == nil || !strings.Contains(err.Error(), "cannot represent MaskedPaths or ReadonlyPaths") {
			t.Fatalf("%s error = %v, want clear CLI compatibility error", spec.Name, err)
		}
	}
}

func TestDockerAPILifecycleCreateInspectAndList(t *testing.T) {
	var create struct {
		Env         []string
		Entrypoint  []string
		Cmd         []string
		StopTimeout *int
		Healthcheck *struct {
			Test []string
		}
		HostConfig struct {
			NetworkMode   string
			NanoCPUs      int64
			Memory        int64
			PidsLimit     *int64
			RestartPolicy struct {
				Name              string
				MaximumRetryCount int
			}
			Init *bool
		}
	}
	var createMu sync.Mutex
	fake := newEngineFake(t, func(w http.ResponseWriter, r *http.Request) {
		if servePing(w, r) {
			return
		}
		switch enginePath(r) {
		case "/containers/create":
			if r.Method != http.MethodPost {
				http.Error(w, "wrong method", http.StatusMethodNotAllowed)
				return
			}
			if got := r.URL.Query().Get("name"); got != "node" {
				t.Errorf("create name = %q, want node", got)
			}
			var request struct {
				Env         []string
				Entrypoint  []string
				Cmd         []string
				StopTimeout *int
				Healthcheck *struct {
					Test []string
				}
				HostConfig struct {
					NetworkMode   string
					NanoCPUs      int64
					Memory        int64
					PidsLimit     *int64
					RestartPolicy struct {
						Name              string
						MaximumRetryCount int
					}
					Init *bool
				}
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode create request: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			createMu.Lock()
			create = request
			createMu.Unlock()
			writeDockerJSON(w, http.StatusCreated, map[string]string{"Id": "created-id"})
		case "/containers/node/start", "/containers/node/pause", "/containers/node/unpause":
			w.WriteHeader(http.StatusNoContent)
		case "/containers/node/stop":
			if got := r.URL.Query().Get("t"); got != "7" {
				t.Errorf("stop timeout = %q, want 7", got)
			}
			w.WriteHeader(http.StatusNoContent)
		case "/containers/node":
			if r.Method != http.MethodDelete {
				http.Error(w, "wrong method", http.StatusMethodNotAllowed)
				return
			}
			if got := r.URL.Query().Get("v"); got != "1" {
				t.Errorf("remove volumes = %q, want 1", got)
			}
			if got := r.URL.Query().Get("force"); got != "1" {
				t.Errorf("remove force = %q, want 1", got)
			}
			w.WriteHeader(http.StatusNoContent)
		case "/containers/missing":
			writeDockerJSON(w, http.StatusNotFound, map[string]string{"message": "No such container"})
		case "/containers/node/json":
			writeDockerJSON(w, http.StatusOK, fakeContainer("node", "node-id", 314, "running"))
		case "/containers/missing/json":
			writeDockerJSON(w, http.StatusNotFound, map[string]string{"message": "No such container"})
		case "/containers/json":
			if got := r.URL.Query().Get("all"); got != "1" {
				t.Errorf("list all = %q, want 1", got)
			}
			var filters map[string]map[string]bool
			if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil {
				t.Errorf("decode list filters: %v", err)
			} else if !filters["label"]["twinet=lab"] {
				t.Errorf("list filters = %#v, want twinet=lab", filters)
			}
			writeDockerJSON(w, http.StatusOK, []map[string]any{
				{"Id": "id-z"},
				{"Id": "id-a"},
			})
		case "/containers/id-a/json":
			writeDockerJSON(w, http.StatusOK, fakeContainer("a", "id-a", 10, "paused"))
		case "/containers/id-z/json":
			writeDockerJSON(w, http.StatusOK, fakeContainer("z", "id-z", 20, "exited"))
		default:
			http.Error(w, "unexpected Docker API request "+enginePath(r), http.StatusNotFound)
		}
	})
	docker := newEngineDocker(t, fake)

	stopTimeout := 11
	id, err := docker.Create(context.Background(), &Spec{
		Name:        "node",
		Image:       "example:latest",
		Command:     []string{"command"},
		Entrypoint:  []string{"entrypoint", "argument"},
		Env:         map[string]string{"Z": "last", "A": "first"},
		CPUs:        1.5,
		Memory:      "64Mi",
		PidsLimit:   42,
		Restart:     "on-failure:3",
		DNS:         []string{"1.1.1.1"},
		NetworkMode: "",
		StopTimeout: &stopTimeout,
		Init:        true,
		Health:      &Health{Test: []string{"echo", "healthy"}},
	})
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	if id != "created-id" {
		t.Fatalf("created ID = %q, want created-id", id)
	}

	createMu.Lock()
	gotCreate := create
	createMu.Unlock()
	if got, want := strings.Join(gotCreate.Env, ","), "A=first,Z=last"; got != want {
		t.Errorf("create env = %q, want %q", got, want)
	}
	if got, want := strings.Join(gotCreate.Entrypoint, ","), "entrypoint"; got != want {
		t.Errorf("entrypoint = %q, want %q", got, want)
	}
	if got, want := strings.Join(gotCreate.Cmd, ","), "argument,command"; got != want {
		t.Errorf("command = %q, want %q", got, want)
	}
	if gotCreate.StopTimeout == nil || *gotCreate.StopTimeout != stopTimeout {
		t.Errorf("stop timeout = %#v, want %d", gotCreate.StopTimeout, stopTimeout)
	}
	if gotCreate.Healthcheck == nil || strings.Join(gotCreate.Healthcheck.Test, ",") != "CMD-SHELL,echo healthy" {
		t.Errorf("healthcheck = %#v, want CMD-SHELL echo healthy", gotCreate.Healthcheck)
	}
	if got, want := gotCreate.HostConfig.NetworkMode, "none"; got != want {
		t.Errorf("network mode = %q, want %q", got, want)
	}
	if got, want := gotCreate.HostConfig.NanoCPUs, int64(1_500_000_000); got != want {
		t.Errorf("NanoCPUs = %d, want %d", got, want)
	}
	if got, want := gotCreate.HostConfig.Memory, int64(64<<20); got != want {
		t.Errorf("memory = %d, want %d", got, want)
	}
	if gotCreate.HostConfig.PidsLimit == nil || *gotCreate.HostConfig.PidsLimit != 42 {
		t.Errorf("PidsLimit = %#v, want 42", gotCreate.HostConfig.PidsLimit)
	}
	if got := gotCreate.HostConfig.RestartPolicy; got.Name != "on-failure" || got.MaximumRetryCount != 3 {
		t.Errorf("restart policy = %#v, want on-failure:3", got)
	}
	if gotCreate.HostConfig.Init == nil || !*gotCreate.HostConfig.Init {
		t.Errorf("init = %#v, want true", gotCreate.HostConfig.Init)
	}

	ctx := context.Background()
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{"start", func() error { return docker.Start(ctx, "node") }},
		{"pause", func() error { return docker.Pause(ctx, "node") }},
		{"unpause", func() error { return docker.Unpause(ctx, "node") }},
		{"stop", func() error { return docker.Stop(ctx, "node", 7*time.Second) }},
		{"remove", func() error { return docker.Remove(ctx, "node", true) }},
		{"remove missing", func() error { return docker.Remove(ctx, "missing", false) }},
	} {
		if err := operation.run(); err != nil {
			t.Errorf("%s container: %v", operation.name, err)
		}
	}

	inspected, err := docker.Inspect(ctx, "node")
	if err != nil {
		t.Fatalf("inspect container: %v", err)
	}
	if inspected.State != StateRunning || inspected.PID != 314 || inspected.Health != "healthy" {
		t.Errorf("inspect = %#v, want running container with PID and health", inspected)
	}
	absent, err := docker.Inspect(ctx, "missing")
	if err != nil {
		t.Fatalf("inspect missing container: %v", err)
	}
	if absent.State != StateAbsent || absent.Name != "missing" {
		t.Errorf("missing inspect = %#v, want absent missing container", absent)
	}
	nsPath, err := docker.NSPath(ctx, "node")
	if err != nil {
		t.Fatalf("network namespace path: %v", err)
	}
	if nsPath != "/proc/314/ns/net" {
		t.Errorf("network namespace path = %q, want /proc/314/ns/net", nsPath)
	}
	listed, err := docker.List(ctx, Filter{All: true, Labels: map[string]string{"twinet": "lab"}})
	if err != nil {
		t.Fatalf("list containers: %v", err)
	}
	if got, want := len(listed), 2; got != want {
		t.Fatalf("listed %d containers, want %d", got, want)
	}
	if listed[0].Name != "a" || listed[0].PID != 10 || listed[1].Name != "z" || listed[1].PID != 20 {
		t.Errorf("listed containers = %#v, want deterministically sorted inspected results", listed)
	}
	if got := fake.requestCount("/containers/json"); got != 1 {
		t.Errorf("list requests = %d, want one batched list request", got)
	}
}

func TestDockerAPIImagesExecAndCopy(t *testing.T) {
	var (
		mu         sync.Mutex
		stdin      string
		copyHeader *tar.Header
		copyData   []byte
	)
	fake := newEngineFake(t, func(w http.ResponseWriter, r *http.Request) {
		if servePing(w, r) {
			return
		}
		path := enginePath(r)
		switch {
		case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json"):
			image := strings.TrimSuffix(strings.TrimPrefix(path, "/images/"), "/json")
			if image == "missing" {
				writeDockerJSON(w, http.StatusNotFound, map[string]string{"message": "No such image"})
				return
			}
			writeDockerJSON(w, http.StatusOK, map[string]any{
				"Id":          "sha256:image",
				"RepoDigests": []string{"example@sha256:digest"},
			})
		case path == "/images/create":
			if r.URL.Query().Get("fromImage") != "docker.io/library/example" || r.URL.Query().Get("tag") != "latest" {
				t.Errorf("pull query = %q, want docker.io/library/example:latest", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{"status":"done"}`)
		case path == "/containers/node/exec":
			var request struct {
				Cmd []string
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode exec request: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			id := "exec-run"
			if len(request.Cmd) > 0 && request.Cmd[0] == "detached" {
				id = "exec-detached"
			}
			writeDockerJSON(w, http.StatusCreated, map[string]string{"Id": id})
		case path == "/exec/exec-run/start":
			serveExecStream(t, w, r, &mu, &stdin)
		case path == "/exec/exec-detached/start":
			w.WriteHeader(http.StatusOK)
		case path == "/exec/exec-run/json":
			writeDockerJSON(w, http.StatusOK, map[string]any{
				"ID":       "exec-run",
				"Running":  false,
				"ExitCode": 7,
			})
		case path == "/containers/node/archive" && r.Method == http.MethodPut:
			if got := r.URL.Query().Get("path"); got != "/etc" {
				t.Errorf("copy destination = %q, want /etc", got)
			}
			reader := tar.NewReader(r.Body)
			header, err := reader.Next()
			if err != nil {
				t.Errorf("read copied archive header: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			data, err := io.ReadAll(reader)
			if err != nil {
				t.Errorf("read copied archive: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			copyHeader = header
			copyData = data
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case path == "/containers/node/archive" && r.Method == http.MethodHead:
			target := ""
			if r.URL.Query().Get("path") == "/link" {
				target = "target"
			}
			w.Header().Set("X-Docker-Container-Path-Stat", dockerPathStat(target))
			w.WriteHeader(http.StatusOK)
		case path == "/containers/node/archive" && r.Method == http.MethodGet:
			source := r.URL.Query().Get("path")
			w.Header().Set("X-Docker-Container-Path-Stat", dockerPathStat(map[string]string{"/link": "target"}[source]))
			switch source {
			case "/link":
				_, _ = w.Write(tarBytes(t, &tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "target"}, nil))
			case "/target":
				_, _ = w.Write(tarBytes(t, &tar.Header{Name: "target", Mode: 0o644, Size: int64(len("followed"))}, []byte("followed")))
			default:
				http.Error(w, "unknown source", http.StatusNotFound)
			}
		default:
			http.Error(w, "unexpected Docker API request "+path, http.StatusNotFound)
		}
	})
	docker := newEngineDocker(t, fake)
	ctx := context.Background()

	exists, err := docker.ImageExists(ctx, "present")
	if err != nil || !exists {
		t.Fatalf("present image = (%t, %v), want (true, nil)", exists, err)
	}
	exists, err = docker.ImageExists(ctx, "missing")
	if err != nil || exists {
		t.Fatalf("missing image = (%t, %v), want (false, nil)", exists, err)
	}
	if err := docker.PullImage(ctx, "example:latest", PullAlways); err != nil {
		t.Fatalf("pull image: %v", err)
	}
	digest, err := docker.ImageDigest(ctx, "present")
	if err != nil {
		t.Fatalf("image digest: %v", err)
	}
	if digest != "example@sha256:digest" {
		t.Errorf("image digest = %q, want example@sha256:digest", digest)
	}

	result, err := docker.Exec(ctx, "node", ExecCmd{Cmd: []string{"run"}, Stdin: strings.NewReader("input")})
	if err != nil {
		t.Fatalf("exec command: %v", err)
	}
	if result.ExitCode != 7 || result.Stdout != "out" || result.Stderr != "err" {
		t.Errorf("exec result = %#v, want stdout/stderr and nonzero exit data", result)
	}
	mu.Lock()
	gotStdin := stdin
	mu.Unlock()
	if gotStdin != "input" {
		t.Errorf("exec stdin = %q, want input", gotStdin)
	}
	detached, err := docker.Exec(ctx, "node", ExecCmd{Cmd: []string{"detached"}, Detach: true})
	if err != nil {
		t.Fatalf("detach exec: %v", err)
	}
	if detached.Stdout != "exec-detached\n" || detached.ExitCode != 0 {
		t.Errorf("detached result = %#v, want exec ID output", detached)
	}

	if err := docker.CopyTo(ctx, "node", "/etc/hosts", 0o640, []byte("hosts")); err != nil {
		t.Fatalf("copy into container: %v", err)
	}
	mu.Lock()
	gotHeader, gotCopy := copyHeader, append([]byte(nil), copyData...)
	mu.Unlock()
	if gotHeader == nil || gotHeader.Name != "hosts" || gotHeader.Mode != 0o640 || !gotHeader.ModTime.Equal(time.Unix(0, 0)) {
		t.Errorf("copied header = %#v, want deterministic hosts archive", gotHeader)
	}
	if string(gotCopy) != "hosts" {
		t.Errorf("copied data = %q, want hosts", gotCopy)
	}

	if _, err := docker.CopyFrom(ctx, "node", "/link"); err == nil {
		t.Fatal("copying an unfollowed symlink succeeded, want archive lookup error")
	}
	followed, err := docker.CopyFromFollow(ctx, "node", "/link")
	if err != nil {
		t.Fatalf("copy following symlink: %v", err)
	}
	if string(followed) != "followed" {
		t.Errorf("followed copy = %q, want followed", followed)
	}
}

func fakeContainer(name, id string, pid int, state string) map[string]any {
	return map[string]any{
		"Id":    id,
		"Name":  "/" + name,
		"Image": "sha256:image",
		"State": map[string]any{
			"Status": state,
			"Pid":    pid,
			"Health": map[string]string{"Status": "healthy"},
		},
		"Config": map[string]any{
			"Image":  "example:latest",
			"Labels": map[string]string{"twinet": "lab"},
		},
	}
}

func serveExecStream(t *testing.T, w http.ResponseWriter, r *http.Request, mu *sync.Mutex, stdin *string) {
	t.Helper()
	if _, err := io.ReadAll(r.Body); err != nil {
		t.Errorf("read exec start request: %v", err)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		t.Error("Docker fake response does not support hijacking")
		return
	}
	conn, response, err := hijacker.Hijack()
	if err != nil {
		t.Errorf("hijack exec stream: %v", err)
		return
	}
	defer conn.Close()
	_, _ = fmt.Fprint(response, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\n\r\n")
	if err := response.Flush(); err != nil {
		t.Errorf("flush exec stream response: %v", err)
		return
	}
	input, err := io.ReadAll(conn)
	if err != nil {
		t.Errorf("read exec stdin: %v", err)
		return
	}
	mu.Lock()
	*stdin = string(input)
	mu.Unlock()
	_, _ = conn.Write(dockerStream(1, "out"))
	_, _ = conn.Write(dockerStream(2, "err"))
}

func dockerStream(stream byte, text string) []byte {
	out := make([]byte, 8+len(text))
	out[0] = stream
	binary.BigEndian.PutUint32(out[4:], uint32(len(text)))
	copy(out[8:], text)
	return out
}

func dockerPathStat(linkTarget string) string {
	value, err := json.Marshal(map[string]any{
		"name":       "file",
		"size":       0,
		"mode":       0,
		"mtime":      time.Unix(0, 0),
		"linkTarget": linkTarget,
	})
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(value)
}

func tarBytes(t *testing.T, header *tar.Header, content []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(header); err != nil {
		t.Fatalf("write fake archive header: %v", err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatalf("write fake archive content: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close fake archive: %v", err)
	}
	return archive.Bytes()
}
