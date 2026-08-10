// Package agent implements the Twinet node agent, twinetd.
//
// The agent is the only long-running privileged component. It owns the
// containers, network namespaces, veths, VXLAN tunnels and traffic shaping on
// one machine, and exposes them to the control plane over an authenticated
// HTTP API.
//
// The control plane stays stateless: it sends each node the slice of the
// topology that belongs to it and asks the node to converge. Because every
// allocated resource is derived by hashing rather than handed out by a
// registry, two agents independently compute the same VXLAN identifier for a
// link they share and need no coordination whatsoever.
package agent

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// Version is stamped at build time.
var Version = "dev"

// maxRequestBytes bounds a request body. A full topology for a large class is a
// few megabytes; anything far beyond that is a mistake or an attack.
const maxRequestBytes = 128 << 20

// Config is the agent's runtime configuration.
type Config struct {
	Node        string
	Listen      string
	Token       string
	UnderlayIP  string
	UnderlayDev string
	// StateDir holds student-owned configuration snapshots. It must survive
	// container replacement and node reboots, because it is the only copy of
	// work a class cannot recreate.
	StateDir string
	TLSCert  string
	TLSKey   string
	ClientCA string
}

// Main is the agent entry point.
func Main(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("twinetd", flag.ContinueOnError)
	var (
		node    = fs.String("node", hostShortName(), "this node's name, as used in the manifest")
		listen  = fs.String("listen", ":7200", "address to serve the agent API on")
		token   = fs.String("token", os.Getenv("TWINET_TOKEN"), "shared secret the control plane must present")
		uip     = fs.String("underlay-ip", "", "VTEP source address for cross-node links")
		udev    = fs.String("underlay-dev", "", "interface to source tunnels from")
		sdir    = fs.String("state-dir", "/var/lib/twinet/state", "where student configuration snapshots are kept")
		cert    = fs.String("tls-cert", os.Getenv("TWINET_TLS_CERT"), "server certificate (enables TLS)")
		key     = fs.String("tls-key", os.Getenv("TWINET_TLS_KEY"), "server private key")
		cacert  = fs.String("client-ca", os.Getenv("TWINET_CLIENT_CA"), "CA that signs permitted client certificates (enables mutual TLS)")
		verbose = fs.Bool("verbose", false, "debug logging")
		version = fs.Bool("version", false, "print the version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version {
		fmt.Printf("twinetd %s\n", Version)
		return nil
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if *token == "" {
		return errors.New("a token is required: pass -token or set TWINET_TOKEN. " +
			"The agent can create privileged containers and rewire the host's networking, " +
			"so it must never be reachable unauthenticated")
	}

	s, err := New(Config{
		Node: *node, Listen: *listen, Token: *token,
		UnderlayIP: *uip, UnderlayDev: *udev, StateDir: *sdir,
		TLSCert: *cert, TLSKey: *key, ClientCA: *cacert,
	})
	if err != nil {
		return err
	}
	return s.Serve(ctx)
}

// Server is the agent.
type Server struct {
	cfg     Config
	rt      rt.Runtime
	store   *state.Store
	started time.Time

	mu sync.Mutex
	// current is the last topology applied, per lab. One node may host several
	// labs at once -- a class lab beside a harness per submission being graded
	// -- and a single slot would make each new deployment forget the previous
	// one, so a later destroy could no longer capture the work it holds.
	current map[string]*model.Topology

	// ops holds one lease per lab. Docker inspect-then-create and netlink
	// lookup-then-add are check-then-act sequences, so two overlapping applies
	// to the same lab can wire a container another request has just replaced.
	//
	// The lease is per lab rather than per node because that is the true scope
	// of the race: container names and overlay device names are both derived
	// from the lab name, so operations on different labs touch disjoint
	// objects. A node-wide lease would be correct but would also serialise the
	// whole cluster, which is exactly what makes grading a class one submission
	// at a time instead of many.
	ops map[string]*lease
}

// lease records an in-flight mutating operation on one lab.
type lease struct {
	kind string
	at   time.Time
}

// New constructs an agent.
func New(cfg Config) (*Server, error) {
	if cfg.Node == "" {
		return nil, errors.New("the node name must not be empty")
	}
	engine := rt.NewDocker()
	if _, err := engine.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("cannot reach the container engine: %w", err)
	}
	srv := &Server{
		cfg: cfg, rt: engine, started: time.Now(),
		current: map[string]*model.Topology{},
		ops:     map[string]*lease{},
	}
	if cfg.StateDir != "" {
		st, err := state.Open(cfg.StateDir)
		if err != nil {
			return nil, fmt.Errorf("state directory: %w", err)
		}
		srv.store = st
	}
	return srv, nil
}

// renderer builds the configuration renderer for one apply.
func renderer(top *model.Topology, mode render.Mode, ungraded int) *render.Renderer {
	if ungraded != 0 {
		return render.NewHarness(top, ungraded)
	}
	return render.New(top, mode)
}

// acquire takes the operation lease for one lab, refusing rather than queueing
// so a caller learns immediately that something else is mid-flight on that lab.
// Operations on other labs are unaffected.
func (s *Server) acquire(lab, kind string) error {
	if lab == "" {
		return errors.New("an operation must name the lab it acts on")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if held, ok := s.ops[lab]; ok {
		return fmt.Errorf("another operation is already running on lab %q: %s, started %s ago",
			lab, held.kind, time.Since(held.at).Round(time.Second))
	}
	s.ops[lab] = &lease{kind: kind, at: time.Now()}
	return nil
}

func (s *Server) release(lab string) {
	s.mu.Lock()
	delete(s.ops, lab)
	s.mu.Unlock()
}

// Serve runs the HTTP API until the context is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	if err := s.tuneKernel(); err != nil {
		slog.Warn("kernel tuning incomplete", "err", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.auth(s.handleStatus))
	mux.HandleFunc("GET /v1/containers", s.auth(s.handleContainers))
	mux.HandleFunc("POST /v1/apply", s.auth(s.handleApply))
	mux.HandleFunc("POST /v1/destroy", s.auth(s.handleDestroy))
	mux.HandleFunc("POST /v1/exec", s.auth(s.handleExec))
	mux.HandleFunc("GET /v1/underlay", s.auth(s.handleUnderlay))

	srv := &http.Server{
		Addr:    s.cfg.Listen,
		Handler: http.MaxBytesHandler(mux, maxRequestBytes),
		// An agent that can create privileged containers must not be held open
		// by a stalled or malicious peer.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Minute,
		WriteTimeout:      35 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	tlsMode := "disabled"
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		cfg := &tls.Config{MinVersion: tls.VersionTLS13}
		tlsMode = "server"
		if s.cfg.ClientCA != "" {
			pool := x509.NewCertPool()
			pem, err := os.ReadFile(s.cfg.ClientCA)
			if err != nil {
				return fmt.Errorf("read client CA: %w", err)
			}
			if !pool.AppendCertsFromPEM(pem) {
				return fmt.Errorf("client CA %s contains no certificates", s.cfg.ClientCA)
			}
			cfg.ClientCAs = pool
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
			tlsMode = "mutual"
		}
		srv.TLSConfig = cfg
	} else {
		slog.Warn("the agent is serving plain HTTP with only a bearer token; " +
			"pass -tls-cert, -tls-key and -client-ca for mutual TLS before exposing it beyond a trusted network")
	}

	errc := make(chan error, 1)
	go func() {
		slog.Info("agent listening", "node", s.cfg.Node, "addr", s.cfg.Listen,
			"underlay", s.cfg.UnderlayIP, "tls", tlsMode, "state", s.cfg.StateDir)
		if srv.TLSConfig != nil {
			errc <- srv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
			return
		}
		errc <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// auth enforces the shared secret with a constant-time comparison.
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	want := []byte("Bearer " + s.cfg.Token)
	return func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// StatusResponse describes the agent and its host.
type StatusResponse struct {
	Node        string `json:"node"`
	Version     string `json:"version"`
	Uptime      string `json:"uptime"`
	Runtime     string `json:"runtime"`
	RuntimeVer  string `json:"runtime_version"`
	CPUs        int    `json:"cpus"`
	UnderlayIP  string `json:"underlay_ip,omitempty"`
	UnderlayDev string `json:"underlay_dev,omitempty"`
	Containers  int    `json:"containers"`
	Lab         string `json:"lab,omitempty"`
	Hash        string `json:"topology_hash,omitempty"`
	// Labs is every lab this node currently hosts, and Busy every lab with an
	// operation in flight. A node that hosts a class lab and a dozen grading
	// harnesses at once cannot be described by a single name.
	Labs []string `json:"labs,omitempty"`
	Busy []string `json:"busy,omitempty"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ver, err := s.rt.Ping(r.Context())
	if err != nil {
		httpError(w, http.StatusServiceUnavailable, err)
		return
	}
	cs, _ := s.rt.List(r.Context(), rt.Filter{All: true,
		Labels: map[string]string{deploy.LabelManaged: "true"}})

	resp := StatusResponse{
		Node: s.cfg.Node, Version: Version,
		Uptime:  time.Since(s.started).Round(time.Second).String(),
		Runtime: s.rt.Name(), RuntimeVer: ver,
		CPUs:        runtime.NumCPU(),
		UnderlayIP:  s.cfg.UnderlayIP,
		UnderlayDev: s.cfg.UnderlayDev,
		Containers:  len(cs),
	}
	s.mu.Lock()
	labs := make([]string, 0, len(s.current))
	for name := range s.current {
		labs = append(labs, name)
	}
	sort.Strings(labs)
	if len(labs) > 0 {
		resp.Lab = strings.Join(labs, ",")
		resp.Hash = s.current[labs[0]].Hash
	}
	resp.Labs = labs
	busy := make([]string, 0, len(s.ops))
	for lab, l := range s.ops {
		busy = append(busy, fmt.Sprintf("%s:%s", lab, l.kind))
	}
	sort.Strings(busy)
	resp.Busy = busy
	s.mu.Unlock()
	writeJSON(w, resp)
}

func (s *Server) handleContainers(w http.ResponseWriter, r *http.Request) {
	lab := r.URL.Query().Get("lab")
	f := rt.Filter{All: true, Labels: map[string]string{deploy.LabelManaged: "true"}}
	if lab != "" {
		f.Labels[deploy.LabelLab] = lab
	}
	cs, err := s.rt.List(r.Context(), f)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, cs)
}

// ApplyRequest carries the slice of a topology this node is responsible for.
type ApplyRequest struct {
	Topology     *Wire             `json:"topology"`
	Mode         string            `json:"mode"`
	PullPolicy   string            `json:"pull_policy"`
	// Ungraded names the one AS that keeps platform mode while the rest of the
	// lab is rendered with the reference solution. It is how a grading harness
	// surrounds a submission with a correct internet without also configuring
	// the work being marked.
	Ungraded int `json:"ungraded_as,omitempty"`
	Workers      int               `json:"workers"`
	DryRun       bool              `json:"dry_run"`
	PeerUnderlay map[string]string `json:"peer_underlay"`
	// Prune removes containers and overlays this node holds that the topology
	// no longer wants. Only safe when the topology is complete.
	Prune bool `json:"prune"`
	// Generation identifies this deployment in logs and labels.
	Generation string `json:"generation"`
	// OnlySteps, when non-empty, restricts the plan to these step IDs. This is
	// how a scoped repair is expressed: the topology stays whole so every
	// cross-reference still resolves, and only the work is narrowed.
	OnlySteps []string `json:"only_steps,omitempty"`
}

// ApplyResponse reports the outcome.
type ApplyResponse struct {
	Node       string              `json:"node"`
	Steps      int                 `json:"steps"`
	DurationMS int64               `json:"duration_ms"`
	Failures   map[string][]string `json:"failures,omitempty"`
	Pruned     []string            `json:"pruned,omitempty"`
	Snapshots  int                 `json:"snapshots,omitempty"`
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var req ApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}
	if req.Topology == nil {
		httpError(w, http.StatusBadRequest, errors.New("no topology supplied"))
		return
	}
	top, err := req.Topology.Rehydrate()
	if err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("rehydrate topology: %w", err))
		return
	}
	if err := s.acquire(top.Name, "apply"); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	defer s.release(top.Name)

	mode := render.Mode(req.Mode)
	if mode == "" {
		mode = render.ModePlatform
	}
	eng := &deploy.Engine{
		Runtime:      s.rt,
		Node:         s.cfg.Node,
		PullPolicy:   rt.PullPolicy(req.PullPolicy),
		Renderer:     renderer(top, mode, req.Ungraded),
		UnderlayIP:   s.cfg.UnderlayIP,
		UnderlayDev:  s.cfg.UnderlayDev,
		PeerUnderlay: req.PeerUnderlay,
		State:        s.store,
		Prune:        req.Prune,
		Generation:   req.Generation,
	}
	p, err := eng.Build(top)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.OnlySteps) > 0 {
		want := map[string]bool{}
		for _, sc := range req.OnlySteps {
			want[sc] = true
		}
		p = p.Restrict(func(st *plan.Step) bool { return want[st.Scope] })
	}
	rep, err := p.Execute(r.Context(), plan.Options{
		Workers:         req.Workers,
		ContinueOnError: true,
		DryRun:          req.DryRun,
	})
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}

	s.mu.Lock()
	s.current[top.Name] = top
	s.mu.Unlock()

	resp := ApplyResponse{
		Node: s.cfg.Node, Steps: p.Len(),
		DurationMS: rep.Duration.Milliseconds(),
	}

	// Pruning happens only after a clean run and only when asked, so a partial
	// topology or a half-failed deployment can never be read as "remove
	// everything else".
	if req.Prune && !req.DryRun && !rep.Failed() {
		gone, err := eng.PruneOrphans(r.Context(), top)
		if err != nil {
			slog.Warn("pruning containers", "err", err)
		}
		resp.Pruned = gone
		if overlays, err := eng.PruneOverlays(top); err != nil {
			slog.Warn("pruning overlays", "err", err)
		} else {
			resp.Pruned = append(resp.Pruned, overlays...)
		}
	}

	// Snapshot student work at the end of every successful apply, so the most
	// recent copy is never older than the last time anyone touched the lab.
	if s.store != nil && !req.DryRun {
		if n, err := eng.CaptureAll(r.Context(), top, s.store); err != nil {
			slog.Warn("capturing student configuration", "err", err, "saved", n)
		} else if n > 0 {
			resp.Snapshots = n
		}
	}
	if rep.Failed() {
		resp.Failures = map[string][]string{}
		for _, scope := range rep.FailedScopes() {
			for _, e := range rep.ScopeErrors[scope] {
				resp.Failures[scope] = append(resp.Failures[scope], e.Error())
			}
		}
	}
	writeJSON(w, resp)
}

// DestroyRequest asks the node to remove a lab.
type DestroyRequest struct {
	Lab  string   `json:"lab"`
	VNIs []uint32 `json:"vnis,omitempty"`
	// Force skips the pre-destroy snapshot of student work.
	Force bool `json:"force,omitempty"`
	// AllOverlays removes every Twinet overlay on the node, which is how a lab
	// is cleaned up when its manifest is no longer available.
	AllOverlays bool `json:"all_overlays,omitempty"`
	// Ephemeral marks a lab whose state is worthless and must not outlive it,
	// such as a grading harness. Snapshots are discarded rather than kept, so
	// a later lab of the same name starts from the manifest and not from
	// whatever the previous run happened to leave behind.
	Ephemeral bool `json:"ephemeral,omitempty"`
}

func (s *Server) handleDestroy(w http.ResponseWriter, r *http.Request) {
	var req DestroyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Lab == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab name is required"))
		return
	}
	if err := s.acquire(req.Lab, "destroy"); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	defer s.release(req.Lab)

	eng := &deploy.Engine{Runtime: s.rt, Node: s.cfg.Node, State: s.store}

	// Destroying a lab must not lose a class's work: everything is captured
	// first, and refusing is better than proceeding blind.
	if s.store != nil && !req.Force && !req.Ephemeral {
		s.mu.Lock()
		top := s.current[req.Lab]
		s.mu.Unlock()
		if top != nil {
			if n, err := eng.CaptureAll(r.Context(), top, s.store); err != nil {
				httpError(w, http.StatusConflict, fmt.Errorf(
					"refusing to destroy %s: student configuration could not be captured (%w); "+
						"pass force to override", req.Lab, err))
				return
			} else if n > 0 {
				slog.Info("captured before destroy", "lab", req.Lab, "snapshots", n)
			}
		}
	}
	if err := eng.Destroy(r.Context(), req.Lab); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	switch {
	case req.AllOverlays:
		// Without a manifest there is no VNI list, so cleanup works from what
		// is actually on the host. This is what makes `destroy --lab NAME`
		// able to clean up after a topology nobody has a copy of any more.
		vnis, err := netx.ListOverlays()
		if err != nil {
			slog.Warn("listing overlays", "err", err)
		} else if err := eng.DestroyOverlays(vnis); err != nil {
			slog.Warn("overlay cleanup incomplete", "err", err)
		}
	case len(req.VNIs) > 0:
		if err := eng.DestroyOverlays(req.VNIs); err != nil {
			slog.Warn("overlay cleanup incomplete", "err", err)
		}
	}
	if req.Ephemeral && s.store != nil {
		if err := s.store.Forget(req.Lab); err != nil {
			slog.Warn("discarding ephemeral lab state", "lab", req.Lab, "err", err)
		}
	}
	s.mu.Lock()
	delete(s.current, req.Lab)
	s.mu.Unlock()
	writeJSON(w, map[string]string{"status": "destroyed", "lab": req.Lab})
}

// ExecRequest runs a command inside a container on this node.
type ExecRequest struct {
	Container string   `json:"container"`
	Cmd       []string `json:"cmd"`
	// Owner, when set, must match the container's twinet.owner label. This is
	// how a student session is confined to their own AS: authorisation is
	// enforced here, beside the container, not by network segmentation.
	Owner string `json:"owner,omitempty"`
}

// ExecResponse carries the result.
type ExecResponse struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	var req ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Container == "" || len(req.Cmd) == 0 {
		httpError(w, http.StatusBadRequest, errors.New("container and cmd are both required"))
		return
	}
	c, err := s.rt.Inspect(r.Context(), req.Container)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if c.State == rt.StateAbsent {
		httpError(w, http.StatusNotFound, fmt.Errorf("no container %q on %s", req.Container, s.cfg.Node))
		return
	}
	if c.Labels[deploy.LabelManaged] != "true" {
		httpError(w, http.StatusForbidden, errors.New("that container is not managed by twinet"))
		return
	}
	if req.Owner != "" && c.Labels[deploy.LabelOwner] != req.Owner {
		httpError(w, http.StatusForbidden,
			fmt.Errorf("%s belongs to %q, not %q", req.Container, c.Labels[deploy.LabelOwner], req.Owner))
		return
	}
	res, err := s.rt.Exec(r.Context(), req.Container, rt.ExecCmd{Cmd: req.Cmd})
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, ExecResponse{ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr})
}

// UnderlayResponse reports what the fabric can carry.
type UnderlayResponse struct {
	Node   string `json:"node"`
	IP     string `json:"ip,omitempty"`
	Dev    string `json:"dev,omitempty"`
	MTU    int    `json:"mtu,omitempty"`
	Probed string `json:"probed,omitempty"`
}

// handleUnderlay reports the MTU toward a peer, so the control plane can refuse
// a lab whose links would not fit once VXLAN encapsulation is added, rather
// than letting it manifest as unexplained packet loss inside a student's AS.
func (s *Server) handleUnderlay(w http.ResponseWriter, r *http.Request) {
	peer := r.URL.Query().Get("peer")
	resp := UnderlayResponse{Node: s.cfg.Node, IP: s.cfg.UnderlayIP, Dev: s.cfg.UnderlayDev}
	if peer != "" {
		mtu, dev, err := netx.UnderlayMTU(peer)
		if err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
		resp.MTU, resp.Dev, resp.Probed = mtu, dev, peer
	}
	writeJSON(w, resp)
}

// tuneKernel raises the limits a dense lab needs.
//
// The legacy platform documented these as prerequisites the operator had to
// remember to apply by hand; forgetting them produced neighbour-table overflows
// and fork failures under load. Applying them from the agent means a node is
// correct simply by virtue of running the agent.
func (s *Server) tuneKernel() error {
	settings := map[string]string{
		// A dense lab has tens of thousands of neighbours across namespaces.
		"/proc/sys/net/ipv4/neigh/default/gc_thresh1": "16384",
		"/proc/sys/net/ipv4/neigh/default/gc_thresh2": "32768",
		"/proc/sys/net/ipv4/neigh/default/gc_thresh3": "131072",
		"/proc/sys/net/ipv6/neigh/default/gc_thresh1": "16384",
		"/proc/sys/net/ipv6/neigh/default/gc_thresh2": "32768",
		"/proc/sys/net/ipv6/neigh/default/gc_thresh3": "131072",
		// Thousands of containers, each with several processes.
		"/proc/sys/kernel/pid_max": "4194304",
		// Container tooling watches a great many paths.
		"/proc/sys/fs/inotify/max_user_instances": "8192",
		"/proc/sys/fs/inotify/max_user_watches":   "524288",
	}
	var failed []string
	for path, val := range settings {
		if err := os.WriteFile(path, []byte(val), 0o644); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", path, err))
		}
	}
	// MPLS is needed by the advanced-course exercises; absence is not fatal.
	for _, m := range []string{"mpls_router", "mpls_gso", "mpls_iptunnel", "vxlan", "8021q"} {
		if err := exec.Command("modprobe", m).Run(); err != nil {
			slog.Debug("module not loaded", "module", m, "err", err)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%s", strings.Join(failed, "; "))
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("write response", "err", err)
	}
}

func httpError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func hostShortName() string {
	h, err := os.Hostname()
	if err != nil {
		return "local"
	}
	if i := strings.IndexByte(h, '.'); i > 0 {
		return h[:i]
	}
	return h
}

// LocalAddrs returns this host's IPv4 addresses, used to auto-detect a VTEP.
func LocalAddrs() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
				out = append(out, ipn.IP.String())
			}
		}
	}
	return out
}
