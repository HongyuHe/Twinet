// Package agent implements the Twinet node agent, twinetd.
//
// The agent is the only long-running privileged component. It owns the
// containers, network namespaces, veths, VXLAN tunnels and traffic shaping on
// one machine, and exposes them to the control plane over an authenticated
// HTTP API.
//
// The control plane sends each node the topology it needs to converge. A
// short-lived fenced lease orders mutations across nodes, and node-local VNI
// reservations make deterministic overlay identifiers safe when independent
// labs happen to derive the same value.
package agent

import (
	"context"
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

	"github.com/HongyuHe/twinet/internal/authz"
	"github.com/HongyuHe/twinet/internal/contract"
	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/integrity"
	"github.com/HongyuHe/twinet/internal/limiter"
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
	Node   string
	Listen string
	Token  string
	// Runtime is the registered container backend this agent owns. Empty is
	// Docker for compatibility with agents configured before runtime selection.
	Runtime string
	// RuntimeSocket optionally binds the selected backend to a particular
	// local Engine API endpoint rather than relying on process environment.
	RuntimeSocket string
	// RuntimeNamespace isolates containerd metadata from Docker's moby
	// namespace and from any other agent sharing the daemon.
	RuntimeNamespace string
	UnderlayIP       string
	UnderlayDev      string
	// StateDir holds student-owned configuration snapshots. It must survive
	// container replacement and node reboots, because it is the only copy of
	// work a class cannot recreate.
	StateDir string
	// Insecure allows the agent to serve without mutual TLS on an address
	// other than loopback. It exists so a development cluster is possible, and
	// it must be asked for: the failure mode of a warning is that everything
	// works and nobody ever revisits it.
	Insecure bool
	TLSCert  string
	TLSKey   string
	ClientCA string
	// PeerTLSCert and PeerTLSKey are the node's replication-only client
	// identity. They must not be the listener certificate in a new
	// installation: server keys authenticate a node to callers, peer keys
	// authenticate the node only to the peer-state API.
	PeerTLSCert string
	PeerTLSKey  string
	// LegacyPeerCertUntil is a one-way, time-bounded migration window for
	// clusters issued before peer keys were split from listener keys. A zero
	// value never enables fallback.
	LegacyPeerCertUntil time.Time
	// GCGrace and GCInterval bound automatic removal of abandoned host
	// objects and stale local records. A zero value selects conservative
	// defaults, which keeps callers written before automatic collection safe.
	GCGrace    time.Duration
	GCInterval time.Duration
	// EventCapacity bounds in-memory and persisted node event history.
	EventCapacity int
	// WorkLimits optionally overrides host-sized node-wide backpressure.
	// Non-positive fields retain limiter.DefaultConfig.
	WorkLimits limiter.Config
	// RecoveryMaxTimeout caps workload-derived rollback transactions. Zero
	// uses the two-hour default; values above the hard two-hour client/server
	// contract are clamped.
	RecoveryMaxTimeout time.Duration
}

// Main is the agent entry point.
func Main(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("twinetd", flag.ContinueOnError)
	defaultLimits := limiter.DefaultConfig()
	var (
		node        = fs.String("node", hostShortName(), "this node's name, as used in the manifest")
		listen      = fs.String("listen", ":7200", "address to serve the agent API on")
		token       = fs.String("token", os.Getenv("TWINET_TOKEN"), "shared secret the control plane must present")
		runtimeName = fs.String("runtime", os.Getenv("TWINET_RUNTIME"),
			"registered container runtime (docker, podman, or containerd; default docker)")
		runtimeSocket = fs.String("runtime-socket", os.Getenv("TWINET_RUNTIME_SOCKET"),
			"optional Unix socket or TCP endpoint for the selected runtime")
		runtimeNamespace = fs.String("runtime-namespace", os.Getenv("TWINET_RUNTIME_NAMESPACE"),
			"containerd metadata namespace (default twinet-<node>)")
		uip      = fs.String("underlay-ip", "", "VTEP source address for cross-node links")
		udev     = fs.String("underlay-dev", "", "interface to source tunnels from")
		sdir     = fs.String("state-dir", "/var/lib/twinet/state", "where student configuration snapshots are kept")
		cert     = fs.String("tls-cert", os.Getenv("TWINET_TLS_CERT"), "server certificate (enables TLS)")
		key      = fs.String("tls-key", os.Getenv("TWINET_TLS_KEY"), "server private key")
		cacert   = fs.String("client-ca", os.Getenv("TWINET_CLIENT_CA"), "CA that signs permitted client certificates (enables mutual TLS)")
		peerCert = fs.String("peer-tls-cert", os.Getenv("TWINET_PEER_TLS_CERT"),
			"peer-state-only client certificate for durable replication")
		peerKey = fs.String("peer-tls-key", os.Getenv("TWINET_PEER_TLS_KEY"),
			"peer-state-only private key for durable replication")
		legacyPeerUntil = fs.String("legacy-peer-cert-until", os.Getenv("TWINET_LEGACY_PEER_CERT_UNTIL"),
			"RFC3339 deadline for explicit legacy listener-certificate peer migration")
		insec = fs.Bool("insecure", os.Getenv("TWINET_INSECURE") == "1",
			"serve without mutual TLS on a non-loopback address (development only)")
		gcGrace = fs.Duration("gc-grace", 15*time.Minute,
			"minimum age before automatic garbage collection removes an abandoned object")
		gcInterval = fs.Duration("gc-interval", 5*time.Minute,
			"how often to scan safely collectible abandoned objects")
		eventCapacity = fs.Int("event-capacity", defaultEventCapacity,
			"maximum structured events retained locally")
		applyLimit = fs.Int("limit-apply", 0,
			"node-wide apply concurrency (0 selects the runtime default)")
		lifecycleLimit = fs.Int("limit-lifecycle", 0,
			"node-wide container lifecycle concurrency (0 selects the runtime default)")
		containerCreateLimit = fs.Int("limit-container-create", 0,
			"concurrent container creates (0 selects measured runtime default: Docker 4, Podman 8)")
		containerStartLimit = fs.Int("limit-container-start", 0,
			"concurrent container starts (0 selects measured runtime default: Docker 4, Podman 8)")
		execProbeLimit = fs.Int("limit-exec-probe", 0,
			"node-wide exec and probe concurrency (0 selects the runtime default)")
		netlinkLimit = fs.Int("limit-netlink", 0,
			"node-wide netlink mutation concurrency (0 selects the runtime default)")
		imagePullLimit = fs.Int("limit-image-pull", defaultLimits.ImagePull,
			"node-wide image pull concurrency")
		captureLimit = fs.Int("limit-capture", defaultLimits.Capture,
			"node-wide state capture concurrency")
		convergenceLimit = fs.Int("limit-convergence", 0,
			"node-wide routing convergence concurrency (0 selects the measured runtime default)")
		recoveryMaxTimeout = fs.Duration("recovery-max-timeout", MaximumRecoveryTotalTimeout,
			"maximum workload-derived recovery duration (hard cap 2h)")
		hostLockDir = fs.String("host-lock-dir", os.Getenv("TWINET_HOST_LOCK_DIR"),
			"directory holding the per-network-namespace agent lock (default /run/twinet)")
		legacyHostLock = fs.String("host-lock", "",
			"removed: the lock is named after this host's network namespace and cannot be chosen")
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
	var peerMigrationUntil time.Time
	if *legacyPeerUntil != "" {
		parsed, err := time.Parse(time.RFC3339, *legacyPeerUntil)
		if err != nil {
			return fmt.Errorf("parse -legacy-peer-cert-until: %w", err)
		}
		peerMigrationUntil = parsed.UTC()
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
	// An arbitrary lock path never isolated anything: two agents pointed at
	// different files still shared one root network namespace, and both
	// rewired its veths, bridges and VXLANs. Refuse the old override loudly
	// rather than accept a value that no longer means what it used to, and
	// refuse its environment form too, which would otherwise be ignored in
	// silence by an operator who believed it was in force.
	if strings.TrimSpace(*legacyHostLock) != "" || os.Getenv("TWINET_HOST_LOCK") != "" {
		return errors.New("-host-lock and TWINET_HOST_LOCK have been removed: the agent's lock is " +
			"named after the inode of the network namespace it is in, so two agents in one namespace " +
			"always contend and two agents in genuinely separate namespaces never do. " +
			"A network-namespace-isolated test agent needs no override. Use -host-lock-dir only to " +
			"move the lock directory off /run/twinet")
	}
	hostLease, err := acquireHostAgentLock(*hostLockDir, *node, *listen, *runtimeNamespace)
	if err != nil {
		return err
	}
	defer func() { _ = hostLease.Close() }()

	s, err := New(Config{
		Node: *node, Listen: *listen, Token: *token,
		Runtime: *runtimeName, RuntimeSocket: *runtimeSocket,
		RuntimeNamespace: *runtimeNamespace,
		UnderlayIP:       *uip, UnderlayDev: *udev, StateDir: *sdir, Insecure: *insec,
		TLSCert: *cert, TLSKey: *key, ClientCA: *cacert, GCGrace: *gcGrace,
		PeerTLSCert: *peerCert, PeerTLSKey: *peerKey, LegacyPeerCertUntil: peerMigrationUntil,
		GCInterval: *gcInterval, EventCapacity: *eventCapacity,
		WorkLimits: limiter.Config{
			Apply: *applyLimit, Lifecycle: *lifecycleLimit,
			ContainerCreate: *containerCreateLimit, ContainerStart: *containerStartLimit,
			ExecProbe: *execProbeLimit,
			Netlink:   *netlinkLimit, ImagePull: *imagePullLimit, Capture: *captureLimit,
			Convergence: *convergenceLimit,
		},
		RecoveryMaxTimeout: *recoveryMaxTimeout,
	})
	if err != nil {
		return err
	}
	return s.Serve(ctx)
}

// Server is the agent.
type Server struct {
	cfg         Config
	rt          rt.Runtime
	eventSource rt.EventSource
	store       *state.Store
	started     time.Time

	metrics *agentMetrics
	eventMu sync.Mutex
	events  *eventRing

	// hostNetns is the agent's own network namespace, resolved once. A device
	// container never shares it, so it is the reference a namespace proof uses
	// to reject an identity that came from a recycled pid.
	hostNetnsOnce sync.Once
	hostNetns     rt.NetnsIdentity
	hostNetnsErr  error

	reconcileMu          sync.Mutex
	reconcileQueue       chan reconcileRequest
	reconcilePending     map[string]bool
	reconcileWorkersOnce sync.Once
	reconcileContext     context.Context
	health               map[string]deviceObservation
	// repairHook is test-only seam for proving event delivery reaches a
	// targeted repair without invoking host networking.
	repairHook func(context.Context, *model.Topology, []*model.Device)

	gcMu                   sync.Mutex
	gcSeen                 map[string]time.Time
	gcFindOrphans          func(map[string]bool) ([]netx.Orphan, error)
	gcRemoveOverlay        func(uint32) error
	gcDeleteHostLink       func(string) error
	gcListMultiplex        func(string) ([]netx.MultiplexOverlay, error)
	gcRemoveEmptyMultiplex func(string) ([]string, error)
	gcFindOrphanBridges    func(map[string]bool) ([]netx.OrphanBridge, error)
	gcRemoveOrphanBridge   func(string) error
	gcLabRuntimeActive     func(context.Context, string) (bool, error)

	// tools compares a container's programs against its image's, so that a
	// mark never rests on a program the student under examination wrote. It is
	// a field rather than a call so that a test can put a container in front
	// of it without an image to build one from.
	tools     func(context.Context, rt.Container) ([]integrity.Finding, error)
	toolsMu   sync.Mutex
	toolsSeen map[string]toolsVerdict

	inventoryMu sync.Mutex
	inventory   *hostInventoryObserver
	workMu      sync.Mutex
	work        *limiter.Limiter

	mu sync.Mutex
	// current is the last topology applied, per lab. One node may host several
	// labs at once -- a class lab beside a harness per submission being graded
	// -- and a single slot would make each new deployment forget the previous
	// one, so a later destroy could no longer capture the work it holds.
	current map[string]*model.Topology
	// modes records what each lab was applied as, so a repair rebuilds what
	// the lab is rather than what it started as.
	modes map[string]string

	// ungraded is the AS each lab exempted from the reference solution, if any.
	ungraded map[string]int
	// peers records the VTEP address of every other node, per lab, so that a
	// cross-node link can be rebuilt without waiting for the controller to
	// send the map again.
	peers map[string]map[string]string

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

	// mutations are fenced, cluster-scoped operation leases. Unlike ops,
	// which only serialise work inside this process, these leases are issued
	// to the controller and survive every handler boundary.
	mutations      map[string]*clusterLease
	fenceHighWater map[string]uint64
	overlayClaims  map[uint32]overlayClaim
	generations    map[string]generationState
	transactions   map[string]applyTransaction
	inventories    map[string]transactionInventory
	overlayLineage map[string]map[uint32]string
	// ephemeral holds the bounded lifetime of every disposable lab this node
	// is carrying. A lab absent from this map is durable and is never
	// reclaimed automatically.
	ephemeral map[string]ephemeralLease
	// gcCollecting fences objects a collection pass has decided to remove.
	// Reservation refuses a VNI listed here, so a deploy arriving mid-pass is
	// told to retry instead of racing the deletion of the object it just
	// claimed.
	gcCollecting    map[uint32]bool
	now             func() time.Time
	overlayOwners   func() (map[uint32]string, error)
	overlayAdopter  func(uint32, string) error
	overlayReverter func(uint32, string) error
	// Transaction seams let focused tests force failures at destructive
	// boundaries without touching a host runtime or netlink namespace.
	transactionFailpoint     func(string) error
	recoveryContainers       func(context.Context, string) ([]rt.Container, error)
	recoveryOverlays         func(string) ([]uint32, error)
	recoveryOverlayInventory func(string) (netx.OverlayInventory, error)
	recoveryRollback         func(context.Context, string, Fence, applyTransaction) error
	recoveryForward          func(context.Context, string, Fence, applyTransaction) error
	recoveryRestore          func(context.Context, string, applyTransaction) error
	recoveryVerify           func(context.Context, applyTransaction) error
	recoveryReplicate        func(context.Context, applyTransaction) error
	ephemeralDestroy         func(context.Context, string) error
	recoveryPhaseTimeout     time.Duration
	recoveryTotalTimeout     time.Duration
	recoveryLeaseTTL         time.Duration
	recoveryStatusTimeout    time.Duration
	recoveryHeartbeat        time.Duration
	opSequence               uint64

	// holds are labs an external operation has asked this node to leave alone.
	holds map[string]*hold

	// repairFails counts consecutive failed repairs, keyed by lab and device.
	repairFails map[string]int
	// repairNext is the earliest time a failed repair may be retried. It keeps
	// an abandoned device from consuming a permanent share of the node while
	// still allowing a later healthy observation or bounded retry to recover.
	repairNext map[string]time.Time
	// semanticCycles counts the complete local repair cycles a semantically
	// drifted device has already been given, and repairTerminal records why
	// one was abandoned. Together they make distributed repair either
	// converge or stop and say so, rather than retry for ever.
	semanticCycles map[string]int
	repairTerminal map[string]string
	// semanticGraceUntil prevents ordinary distributed routing convergence
	// from being mistaken for locally repairable drift immediately after a
	// commit or agent restart. Local interface/address defects remain
	// actionable during this window.
	semanticGraceUntil map[string]time.Time
	// overlayBindingRepair is a test-only seam for the cross-node binding
	// half of a semantic repair, which otherwise needs host netlink.
	overlayBindingRepair func(context.Context, *model.Topology, *model.Device) (deploy.OverlayRepairReport, error)

	// exempt records, per lab, the devices that are broken on purpose.
	exempt map[string]*exemptions

	// partial counts consecutive surveys in which a device has been missing
	// some, but not all, of its interfaces.
	partial map[string]int

	// durability serialises periodic and destructive-boundary captures per
	// lab. It is separate from ops: a capture may run while the ordinary
	// repair survey reads another lab, but two captures of the same lab must
	// not race their current pointers or replica acknowledgements.
	durabilityMu   sync.Mutex
	lastCapture    map[string]time.Time
	durabilityBusy map[string]bool
	// durabilityCancel holds only periodic work. Transaction-bound capture is
	// deliberately not cancellable through this map: it is part of the
	// fenced operation that owns recovery.
	durabilityCancel map[string]context.CancelFunc
	peerDial         peerDialer
	peerHealthMu     sync.Mutex
	peerHealth       map[string]PeerReplicationStatus
}

func (s *Server) workLimiter() *limiter.Limiter {
	s.workMu.Lock()
	defer s.workMu.Unlock()
	if s.work == nil {
		s.work = limiter.New(limiter.WithDefaultsForRuntime(s.cfg.WorkLimits, s.cfg.Runtime))
	}
	return s.work
}

// lease records an in-flight mutating operation on one lab.
type lease struct {
	id       uint64
	kind     string
	at       time.Time
	deadline time.Time
	cancel   context.CancelFunc
	done     chan struct{}
}

// New constructs an agent.
func New(cfg Config) (*Server, error) {
	if cfg.Node == "" {
		return nil, errors.New("the node name must not be empty")
	}
	runtimeName := strings.TrimSpace(cfg.Runtime)
	if runtimeName == "" {
		runtimeName = model.DefaultRuntime
	}
	if err := rt.RequireRoutedLabCapabilities(runtimeName); err != nil {
		return nil, fmt.Errorf("validate selected runtime before starting agent: %w", err)
	}
	engine, err := rt.NewRuntime(runtimeName)
	if err != nil {
		return nil, fmt.Errorf("select runtime %q: %w", runtimeName, err)
	}
	if err := rt.ConfigureEndpoint(engine, cfg.RuntimeSocket); err != nil {
		return nil, fmt.Errorf("configure %s runtime socket: %w", runtimeName, err)
	}
	if runtimeName == "containerd" && strings.TrimSpace(cfg.RuntimeNamespace) == "" {
		cfg.RuntimeNamespace = "twinet-" + cfg.Node
	}
	if err := rt.ConfigureNamespace(engine, cfg.RuntimeNamespace); err != nil {
		return nil, fmt.Errorf("configure %s runtime namespace: %w", runtimeName, err)
	}
	if _, err := engine.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("cannot reach selected %s container engine: %w", runtimeName, err)
	}
	cfg.Runtime = runtimeName
	srv := &Server{
		cfg: cfg, started: time.Now(), metrics: newAgentMetrics(),
		current: map[string]*model.Topology{},
		ops:     map[string]*lease{},
		holds:   map[string]*hold{},

		tools:     integrity.NewChecker(engine).Verify,
		toolsSeen: map[string]toolsVerdict{},

		repairFails:        map[string]int{},
		repairNext:         map[string]time.Time{},
		semanticCycles:     map[string]int{},
		repairTerminal:     map[string]string{},
		semanticGraceUntil: map[string]time.Time{},
		exempt:             map[string]*exemptions{},
		partial:            map[string]int{},
		lastCapture:        map[string]time.Time{},
		durabilityBusy:     map[string]bool{},
		durabilityCancel:   map[string]context.CancelFunc{},
		peerHealth:         map[string]PeerReplicationStatus{},
	}
	if source, ok := interface{}(engine).(rt.EventSource); ok {
		srv.eventSource = source
	}
	srv.rt = &observedRuntime{runtime: engine, metrics: srv.metrics, limiter: srv.workLimiter()}
	srv.initCoordination()
	if cfg.StateDir != "" {
		st, err := state.Open(cfg.StateDir)
		if err != nil {
			return nil, fmt.Errorf("state directory: %w", err)
		}
		srv.store = st
		srv.loadCoordination()
		srv.rehydrate()
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

// rehydrate reloads the labs this node was hosting before the agent restarted.
//
// Without it, an upgrade or a reboot leaves the agent believing the node is
// empty. Nothing looks wrong -- the containers are still running -- until a
// destroy arrives and skips the capture of student work it no longer knows
// exists.
func (s *Server) rehydrate() {
	restoredLifetimes := false
	labs, err := s.store.Labs()
	if err != nil {
		slog.Warn("reloading known labs", "err", err)
		return
	}
	for _, lab := range labs {
		raw, err := s.store.Topology(lab)
		if err != nil {
			continue
		}
		var wt Wire
		if err := json.Unmarshal(raw, &wt); err != nil {
			slog.Warn("reloading a lab", "lab", lab, "err", err)
			continue
		}
		mode, modeErr := requiredTransactionMode(wt.Mode)
		if modeErr != nil {
			if strings.TrimSpace(wt.Mode) != "" {
				slog.Error("AUDIT: persisted topology has invalid mode", "lab", lab, "mode", wt.Mode, "err", modeErr)
				continue
			}
			// The only committed-topology compatibility bridge: records
			// predating the required field are explicitly migrated and
			// rewritten, never silently defaulted in a later apply path.
			mode = render.ModePlatform
			wt.Mode, wt.Ungraded = string(mode), 0
			migrated, marshalErr := json.Marshal(&wt)
			if marshalErr != nil {
				slog.Error("AUDIT: encode legacy topology mode migration failed", "lab", lab, "err", marshalErr)
				continue
			}
			if storeErr := s.store.PutTopology(lab, migrated); storeErr != nil {
				slog.Error("AUDIT: persist legacy topology mode migration failed", "lab", lab, "err", storeErr)
				continue
			}
			slog.Warn("AUDIT: migrated legacy persisted topology mode to platform", "lab", lab)
		}
		top, err := wt.Rehydrate()
		if err != nil {
			slog.Warn("rehydrating a lab", "lab", lab, "err", err)
			continue
		}
		s.current[top.Name] = top
		s.beginSemanticConvergenceGrace(top)
		state := s.generations[top.Name]
		if wt.Generation != "" {
			// topology.json is atomically written with its generation, so it
			// is the authority if a crash landed between that write and the
			// separate coordination journal update.
			state.Committed = wt.Generation
		} else if state.Committed == "" {
			state.Committed = top.Hash
		}
		s.generations[top.Name] = state
		if wt.Ephemeral {
			// The persisted topology is the authority on whether a lab is
			// disposable. Its deadline lives in the coordination journal; if
			// only one of the two survived a crash, a bounded restart grace is
			// substituted rather than an unbounded lifetime.
			if s.restoreEphemeralLeaseLocked(top.Name, wt.EphemeralTTLSeconds, wt.Generation) {
				restoredLifetimes = true
			}
		}
		s.rememberHow(top.Name, string(mode), wt.Ungraded)
		s.loadExemptions(top.Name)
		s.loadHolds(top.Name)
		if wt.PeerUnderlay != nil {
			if s.peers == nil {
				s.peers = map[string]map[string]string{}
			}
			s.peers[top.Name] = wt.PeerUnderlay
		}
		s.loadPersistedPeerReplicationHealth(top)
	}
	if restoredLifetimes {
		// Persisted immediately so a crash-looping agent cannot keep granting
		// itself a fresh restart grace for the same abandoned harness.
		if err := s.saveCoordinationLocked(); err != nil {
			slog.Error("AUDIT: persisting restored ephemeral lab deadlines", "err", err)
		}
	}
	if len(s.current) > 0 {
		slog.Info("reloaded labs from the state store", "count", len(s.current))
	}
}

// loopbackOnly reports whether an address is reachable only from this machine.
func loopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func insecureReason(cfg Config) string {
	if cfg.Insecure {
		return "-insecure was passed"
	}
	return "listening on loopback only"
}

// acquire takes the operation lease for one lab, refusing rather than queueing
// so a caller learns immediately that something else is mid-flight on that lab.
// Operations on other labs are unaffected.
func (s *Server) acquire(lab, kind string) error {
	_, _, err := s.acquireOperation(lab, kind, nil)
	return err
}

// acquireOperation records a cancellable local operation. Recovery may
// preempt apply or reconciliation, but must wait for its done channel before
// publishing a new owner. The returned ID prevents an old goroutine from
// deleting a newer operation while it unwinds.
func (s *Server) acquireOperation(lab, kind string, cancel context.CancelFunc) (uint64, chan struct{}, error) {
	if lab == "" {
		return 0, nil, errors.New("an operation must name the lab it acts on")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ops == nil {
		s.ops = map[string]*lease{}
	}
	if held, ok := s.ops[lab]; ok {
		return 0, nil, fmt.Errorf("another operation is already running on lab %q: %s, started %s ago",
			lab, held.kind, time.Since(held.at).Round(time.Second))
	}
	s.opSequence++
	id := s.opSequence
	var done chan struct{}
	if cancel != nil {
		done = make(chan struct{})
	}
	s.ops[lab] = &lease{id: id, kind: kind, at: time.Now(), cancel: cancel, done: done}
	return id, done, nil
}

func (s *Server) acquireDestroyOperation(
	ctx context.Context,
	lab string,
	force bool,
) (uint64, chan struct{}, error) {
	if !force {
		return s.acquireOperation(lab, "destroy", nil)
	}
	return s.acquireForcedOperation(ctx, lab, "destroy", false)
}

// acquireForcedOperation takes a lab's operation lease, cancelling whatever
// cancellable work already holds it.
//
// preemptStaleRecovery additionally displaces a recovery that has already
// passed its own persisted deadline. Only automatic reclamation asks for that:
// an operator's forced destroy still waits for recovery, because recovery is
// the thing protecting student state, whereas a lab that a node has decided to
// reclaim has no state to protect and must not be blocked indefinitely by a
// recovery that is itself stuck.
func (s *Server) acquireForcedOperation(
	ctx context.Context,
	lab, kind string,
	preemptStaleRecovery bool,
) (uint64, chan struct{}, error) {
	if lab == "" {
		return 0, nil, errors.New("an operation must name the lab it acts on")
	}
	for {
		s.mu.Lock()
		if s.ops == nil {
			s.ops = map[string]*lease{}
		}
		held := s.ops[lab]
		if held == nil {
			s.opSequence++
			id := s.opSequence
			s.ops[lab] = &lease{id: id, kind: kind, at: s.nowTime()}
			s.mu.Unlock()
			return id, nil, nil
		}
		staleRecovery := preemptStaleRecovery && held.kind == "recovery" &&
			!held.deadline.IsZero() && !s.nowTime().Before(held.deadline)
		preemptible := held.cancel != nil && held.done != nil &&
			(held.kind == "reconcile" || held.kind == "apply" || staleRecovery)
		if !preemptible {
			s.mu.Unlock()
			return 0, nil, fmt.Errorf("another operation is already running on lab %q: %s, started %s ago",
				lab, held.kind, s.nowTime().Sub(held.at).Round(time.Second))
		}
		held.cancel()
		done := held.done
		heldKind := held.kind
		s.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return 0, nil, fmt.Errorf("%s did not yield to %s: %w", heldKind, kind, ctx.Err())
		}
	}
}

// acquireRecoveryOperation gives durable recovery priority over cancellable
// apply/reconciliation work, and permits a newer fence to cancel only a
// recovery whose persisted deadline has expired. It does not publish the new
// recovery owner until the previous operation has fully unwound.
func (s *Server) acquireRecoveryOperation(ctx context.Context, lab string, deadline time.Time,
	cancel context.CancelFunc, takeover bool,
) (uint64, chan struct{}, error) {
	if lab == "" {
		return 0, nil, errors.New("a recovery must name the lab it acts on")
	}
	for {
		s.mu.Lock()
		if s.ops == nil {
			s.ops = map[string]*lease{}
		}
		held := s.ops[lab]
		if held == nil {
			s.opSequence++
			id := s.opSequence
			done := make(chan struct{})
			s.ops[lab] = &lease{
				id: id, kind: "recovery", at: s.nowTime(), deadline: deadline,
				cancel: cancel, done: done,
			}
			s.mu.Unlock()
			return id, done, nil
		}
		staleRecovery := held.kind == "recovery" && !held.deadline.IsZero() &&
			!s.nowTime().Before(held.deadline)
		preemptible := held.cancel != nil && held.done != nil &&
			(held.kind == "reconcile" || held.kind == "apply" || (staleRecovery && takeover))
		if !preemptible {
			s.mu.Unlock()
			return 0, nil, fmt.Errorf("another operation is already running on lab %q: %s, started %s ago",
				lab, held.kind, s.nowTime().Sub(held.at).Round(time.Second))
		}
		held.cancel()
		done := held.done
		kind := held.kind
		s.mu.Unlock()

		select {
		case <-done:
			// Recheck under the lock. Another caller may have acquired the
			// lab after the old owner released it.
		case <-ctx.Done():
			return 0, nil, fmt.Errorf("%s did not yield to durable recovery: %w", kind, ctx.Err())
		}
	}
}

func (s *Server) releaseRecoveryOperation(lab string, id uint64, done chan struct{}) {
	s.mu.Lock()
	if held := s.ops[lab]; held != nil && held.id == id {
		delete(s.ops, lab)
	}
	s.mu.Unlock()
	if done != nil {
		close(done)
	}
}

func (s *Server) releaseOperation(lab string, id uint64, done chan struct{}) {
	s.mu.Lock()
	if held := s.ops[lab]; held != nil && held.id == id {
		delete(s.ops, lab)
	}
	s.mu.Unlock()
	if done != nil {
		close(done)
	}
}

// rememberHow records how a lab was deployed, so a repair rebuilds what the lab
// is rather than what the software would build from scratch.
//
// Both halves are needed and they are recorded together. A private grading
// harness is deployed solved except for the one system being marked; replaying
// only the mode rebuilds that system with the reference answer on it, for the
// student whose work is being marked against it. Recording them in one place
// means a caller cannot record half of it.
//
// The caller holds s.mu.
func (s *Server) rememberHow(lab, mode string, ungraded int) {
	if s.modes == nil {
		s.modes = map[string]string{}
	}
	if s.ungraded == nil {
		s.ungraded = map[string]int{}
	}
	s.modes[lab] = mode
	s.ungraded[lab] = ungraded
}

// modeToPersist decides what mode is written to disk for a lab.
//
// Only an apply entitled to say how the lab was built writes it. A scoped or
// failed one keeps whatever was already recorded, because the alternative is a
// restarted agent believing a lab is at the reference when only one AS of it
// ever was -- and a lab believed to be at the reference has its snapshotting
// suppressed, so every student's work stops being preserved.
func modeToPersist(authoritative bool, mode string, ungraded int,
	prevMode string, prevUngraded int) (string, int) {
	if authoritative {
		return mode, ungraded
	}

	return prevMode, prevUngraded
}

func canonicalMode(mode string) string {
	if mode == "" {
		return string(render.ModePlatform)
	}
	return mode
}

// RequireTransactionMode validates the explicit desired mode carried by every
// clustered transaction request. Unlike canonicalMode it never treats an
// omitted field as platform: that silent default can turn a solve no-change
// rollback into a solve->platform restore path.
func RequireTransactionMode(mode string) (string, error) {
	switch render.Mode(strings.ToLower(strings.TrimSpace(mode))) {
	case render.ModePlatform:
		return string(render.ModePlatform), nil
	case render.ModeSolve:
		return string(render.ModeSolve), nil
	default:
		return "", fmt.Errorf("transaction mode must be %q or %q, got %q",
			render.ModePlatform, render.ModeSolve, mode)
	}
}

func requiredTransactionMode(mode string) (render.Mode, error) {
	value, err := RequireTransactionMode(mode)
	return render.Mode(value), err
}

func needsStudentReset(previous string, desired render.Mode) bool {
	return canonicalMode(previous) == string(render.ModeSolve) && desired != render.ModeSolve
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
	// Every route names an action and resolves a lab before its handler runs.
	// A future endpoint therefore cannot inherit controller access merely by
	// being wrapped in a broad "authenticated" middleware.
	mux.HandleFunc("GET /metrics", s.authorize(endpointPolicy{
		Action: authz.ActionObserve, AllowCluster: true, ResolveRequest: scopeCluster(authz.ActionObserve),
	}, s.observedHandler("metrics", s.handleMetrics)))
	mux.HandleFunc("GET /v1/status", s.authorize(endpointPolicy{
		Action: authz.ActionObserve, AllowCluster: true, ResolveRequest: scopeFromQuery(authz.ActionObserve, true),
	}, s.observedHandler("status", s.handleStatus)))
	mux.HandleFunc("POST /v1/plan", s.authorize(endpointPolicy{
		Action: authz.ActionDeploy, ResolveRequest: scopeFromJSONLab(authz.ActionDeploy),
	}, s.observedHandler("plan", s.handlePlan)))
	mux.HandleFunc("POST /v1/plan/verify", s.authorize(endpointPolicy{
		Action: authz.ActionDeploy, ResolveRequest: scopeFromJSONLab(authz.ActionDeploy),
	}, s.observedHandler("plan_verify", s.handlePlanVerify)))
	mux.HandleFunc("GET /v1/containers", s.authorize(endpointPolicy{
		Action: authz.ActionObserve, AllowCluster: true, ResolveRequest: scopeFromQuery(authz.ActionObserve, true),
	}, s.handleContainers))
	mux.HandleFunc("GET /v1/controls", s.authorize(endpointPolicy{
		Action: authz.ActionObserve, AllowCluster: true, ResolveRequest: scopeFromQuery(authz.ActionObserve, true),
	}, s.observedHandler("controls", s.handleControls)))
	mux.HandleFunc("POST /v1/controls/reconcile", s.authorize(endpointPolicy{
		Action: authz.ActionAdmin, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionAdmin),
	}, s.observedHandler("controls_reconcile", s.handleControlReconcile)))
	mux.HandleFunc("POST /v1/reconcile", s.authorize(endpointPolicy{
		Action: authz.ActionAdmin, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionAdmin),
	}, s.observedHandler("reconcile", s.handleReconcile)))
	mux.HandleFunc("GET /v1/events", s.authorize(endpointPolicy{
		Action: authz.ActionObserve, AllowCluster: true, ResolveRequest: scopeFromQuery(authz.ActionObserve, true),
	}, s.observedHandler("events", s.handleEvents)))
	mux.HandleFunc("POST /v1/apply", s.authorize(endpointPolicy{
		Action: authz.ActionDeploy, Mutation: true, ResolveRequest: scopeForApply,
	}, s.observedHandler("apply", s.handleApply)))
	mux.HandleFunc("POST /v1/destroy", s.authorize(endpointPolicy{
		Action: authz.ActionDestroy, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionDestroy),
	}, s.observedHandler("destroy", s.handleDestroy)))
	mux.HandleFunc("POST /v1/lease/acquire", s.authorize(endpointPolicy{
		Action: authz.ActionDeploy, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionDeploy),
	}, s.handleLeaseAcquire))
	mux.HandleFunc("POST /v1/lease/renew", s.authorize(endpointPolicy{
		Action: authz.ActionDeploy, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionDeploy),
	}, s.handleLeaseRenew))
	mux.HandleFunc("POST /v1/lease/release", s.authorize(endpointPolicy{
		Action: authz.ActionDeploy, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionDeploy),
	}, s.handleLeaseRelease))
	mux.HandleFunc("POST /v1/overlay/reserve", s.authorize(endpointPolicy{
		Action: authz.ActionDeploy, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionDeploy),
	}, s.handleOverlayReserve))
	// A heartbeat is deploy authority over one lab: it can only extend the
	// lifetime of a lab that a deployment already declared disposable, and it
	// can never create one.
	mux.HandleFunc("POST /v1/ephemeral", s.authorize(endpointPolicy{
		Action: authz.ActionDeploy, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionDeploy),
	}, s.observedHandler("ephemeral", s.handleEphemeral)))
	mux.HandleFunc("GET /v1/recovery", s.authorize(endpointPolicy{
		Action: authz.ActionObserve, AllowCluster: true, ResolveRequest: scopeFromQuery(authz.ActionObserve, false),
	}, s.observedHandler("recovery", s.handleRecoveryStatus)))
	mux.HandleFunc("POST /v1/recover", s.authorize(endpointPolicy{
		Action: authz.ActionDeploy, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionDeploy),
	}, s.observedHandler("recover", s.handleRecovery)))
	mux.HandleFunc("POST /v1/exec", s.authorize(endpointPolicy{
		Action: authz.ActionExec, Mutation: true, ResolveRequest: scopeForContainer(authz.ActionExec),
	}, s.observedHandler("exec", s.handleExec)))
	mux.HandleFunc("POST /v1/exec/batch", s.authorize(endpointPolicy{
		Action: authz.ActionExec, Mutation: true, ResolveRequest: scopeForExecBatch(authz.ActionExec),
	}, s.observedHandler("exec_batch", s.handleExecBatch)))
	mux.HandleFunc("POST /v1/hold", s.authorize(endpointPolicy{
		Action: authz.ActionLifecycle, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionLifecycle),
	}, s.observedHandler("hold", s.handleHold)))
	mux.HandleFunc("POST /v1/exempt", s.authorize(endpointPolicy{
		Action: authz.ActionFault, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionFault),
	}, s.observedHandler("exempt", s.handleExempt)))
	mux.HandleFunc("POST /v1/lifecycle", s.authorize(endpointPolicy{
		Action: authz.ActionLifecycle, Mutation: true, ResolveRequest: scopeForContainer(authz.ActionLifecycle),
	}, s.observedHandler("lifecycle", s.handleLifecycle)))
	mux.HandleFunc("POST /v1/reshape", s.authorize(endpointPolicy{
		Action: authz.ActionFault, Mutation: true, ResolveRequest: scopeForContainer(authz.ActionFault),
	}, s.observedHandler("reshape", s.handleReshape)))
	mux.HandleFunc("POST /v1/mpls-label-space", s.authorize(endpointPolicy{
		Action: authz.ActionFault, Mutation: true, ResolveRequest: scopeForContainer(authz.ActionFault),
	}, s.observedHandler("mpls_label_space", s.handleMPLSLabelSpace)))
	mux.HandleFunc("GET /v1/images", s.authorize(endpointPolicy{
		Action: authz.ActionObserve, AllowCluster: true, ResolveRequest: scopeCluster(authz.ActionObserve),
	}, s.handleImages))
	mux.HandleFunc("GET /v1/attach", s.authorize(endpointPolicy{
		Action: authz.ActionExec, Mutation: true, ResolveRequest: scopeForAttach,
	}, s.handleAttach))
	mux.HandleFunc("GET /v1/underlay", s.authorize(endpointPolicy{
		Action: authz.ActionObserve, AllowCluster: true, ResolveRequest: scopeCluster(authz.ActionObserve),
	}, s.observedHandler("underlay", s.handleUnderlay)))
	mux.HandleFunc("GET /v1/state", s.authorize(endpointPolicy{
		Action: authz.ActionState, Mutation: true, ResolveRequest: scopeFromQuery(authz.ActionState, false),
	}, s.observedHandler("state", s.handleStateExport)))
	mux.HandleFunc("POST /v1/state", s.authorize(endpointPolicy{
		Action: authz.ActionState, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionState),
	}, s.observedHandler("state", s.handleStateImport)))
	mux.HandleFunc("POST /v1/state/verify", s.authorize(endpointPolicy{
		Action: authz.ActionState, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionState),
	}, s.observedHandler("state", s.handleStateVerify)))
	// The peer routes are intentionally separate from controller routes and
	// accept only a node certificate with peer-state scope. A node key is not
	// a controller key.
	mux.HandleFunc("GET /v1/peer/state/inventory", s.peerAuth(s.handlePeerStateInventory))
	mux.HandleFunc("GET /v1/peer/state", s.peerAuth(s.handlePeerStateRead))
	mux.HandleFunc("POST /v1/peer/state", s.peerAuth(s.handlePeerStateImport))
	mux.HandleFunc("POST /v1/sweep", s.authorize(endpointPolicy{
		Action: authz.ActionAdmin, Mutation: true, AllowCluster: true,
		ResolveRequest: func(_ *Server, _ *http.Request) (requestScope, error) {
			return requestScope{Action: authz.ActionAdmin, Target: "overlays"}, nil
		},
	}, s.observedHandler("sweep", s.handleSweep)))

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

	// A partial TLS configuration is refused rather than served.
	//
	// -tls-cert and -tls-key without -client-ca gives server-only TLS: the
	// traffic is encrypted and the caller is not verified at all, so anyone who
	// can reach the port and holds the bearer token is admitted. The token is
	// the same on every node, so one leak takes the cluster. The operator who
	// left out one flag has no way to tell: the agent starts, the deploy works,
	// and everything looks exactly as it does when it is configured correctly.
	given := 0
	for _, v := range []string{s.cfg.TLSCert, s.cfg.TLSKey, s.cfg.ClientCA} {
		if v != "" {
			given++
		}
	}
	if given > 0 && given < 3 {
		return fmt.Errorf(
			"mutual TLS needs -tls-cert, -tls-key and -client-ca together; %s given.\n"+
				"Without -client-ca the agent would encrypt the connection but verify\n"+
				"nothing about the caller, which looks identical to a correct setup and\n"+
				"is not one. Issue all three with `twinet node pki`, or pass -insecure\n"+
				"to accept a bearer token over plain HTTP on a network you control",
			describeTLSInputs(s.cfg))
	}
	peerGiven := 0
	for _, v := range []string{s.cfg.PeerTLSCert, s.cfg.PeerTLSKey} {
		if v != "" {
			peerGiven++
		}
	}
	if peerGiven == 1 {
		return errors.New("peer replication needs -peer-tls-cert and -peer-tls-key together")
	}
	if given == 0 && peerGiven > 0 {
		return errors.New("peer replication credentials require mutual TLS on the agent listener")
	}

	tlsMode := "disabled"
	if given == 3 {
		if peerGiven == 0 {
			if s.cfg.LegacyPeerCertUntil.IsZero() || !time.Now().Before(s.cfg.LegacyPeerCertUntil) {
				return errors.New(
					"mutual TLS requires a separate -peer-tls-cert and -peer-tls-key for replication. " +
						"Legacy listener certificates are accepted only with a future explicit " +
						"-legacy-peer-cert-until migration deadline; issue replacement material with `twinet node pki`")
			}
			slog.Warn("AUDIT: using an expiring legacy listener certificate for peer replication",
				"until", s.cfg.LegacyPeerCertUntil.Format(time.RFC3339))
		} else if err := validatePeerTLSIdentity(s.cfg.Node, s.cfg.PeerTLSCert,
			s.cfg.PeerTLSKey, s.cfg.ClientCA); err != nil {
			return fmt.Errorf("validate replication-only peer credential: %w", err)
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS13}
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
		srv.TLSConfig = cfg
	} else {
		// Refusing rather than warning. This API creates containers and
		// rewires hosts, and a bearer token over plain HTTP is replayable by
		// anyone who sees one request, identical on every node so one leak
		// takes the cluster, and leaves the agent unauthenticated to the
		// caller -- so anything that can occupy the port collects tokens.
		//
		// A warning does not survive contact with a working cluster: it scrolls
		// past once, everything functions, and the insecure configuration
		// becomes permanent because nothing ever forces the question again.
		if !s.insecureLoopbackMode() {
			return fmt.Errorf(
				"refusing to serve %s without mutual TLS.\n"+
					"This API can create privileged containers and rewire hosts.\n"+
					"Issue credentials with `twinet node pki` and pass -tls-cert, -tls-key\n"+
					"and -client-ca. Development HTTP is available only with -insecure on\n"+
					"a loopback listener", s.cfg.Listen)
		}
		slog.Warn("serving plain HTTP with only a bearer token",
			"listen", s.cfg.Listen, "reason", insecureReason(s.cfg))
	}

	// Repair devices whose network namespace has been emptied. Without this a
	// container that restarts on its own is running, healthy and connected to
	// nothing until somebody happens to redeploy.
	go s.reconcileLoop(ctx)
	// Garbage collection is deliberately separate from repair: a runtime
	// event needs a prompt response, whereas absence needs a grace window and
	// a generation/operation safety proof before anything is removed.
	go s.gcLoop(ctx)
	// Capturing and replicating state belongs to the long-running agent, not
	// the CLI invocation that happened to deploy the lab.
	go s.durabilityLoop(ctx)
	// Peer quorum health is a live authenticated handshake, not a side effect
	// of periodic state mutation. It remains active while recovery suppresses
	// periodic capture so simultaneously restarted nodes can bootstrap safely.
	go s.peerHealthLoop(ctx)
	// Interrupted transactions are durable recovery work, not abandoned
	// partial applies. The loop obtains a new internal fence only after a
	// controller lease lapses and keeps retrying rollback after node recovery.
	go s.recoveryLoop(ctx)
	// A disposable lab belongs to a controller that is still running. This is
	// the only thing on the node that can tell the difference between a
	// grading harness whose controller was killed and a lab a course needs.
	go s.ephemeralLoop(ctx)

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

// auth remains for narrow internal compatibility call sites. New routes must
// use authorize with their own action and resolver; treating this as a generic
// authenticated wrapper would recreate the broad authority boundary O12
// removes.
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return s.authorize(endpointPolicy{
		Action: authz.ActionAdmin, Mutation: true, AllowCluster: true,
		ResolveRequest: func(_ *Server, _ *http.Request) (requestScope, error) {
			return requestScope{Action: authz.ActionAdmin}, nil
		},
	}, h)
}

// StatusResponse describes the agent and its host.
type StatusResponse struct {
	Node string `json:"node"`
	// Version is the exact source build. It is audit evidence, not a rolling
	// upgrade gate; Compatibility below names the contracts that can block a
	// mutation safely.
	Version       string       `json:"version"`
	Compatibility contract.Set `json:"compatibility"`
	Uptime        string       `json:"uptime"`
	Runtime       string       `json:"runtime"`
	RuntimeVer    string       `json:"runtime_version"`
	// RuntimeSocket is the endpoint actually bound by this agent, allowing a
	// controller to distinguish a Podman selection from a Docker-compatible
	// socket accidentally pointed at a different daemon.
	RuntimeSocket string `json:"runtime_socket,omitempty"`
	// RuntimeNamespace identifies the isolated containerd metadata namespace.
	RuntimeNamespace string `json:"runtime_namespace,omitempty"`
	CPUs             int    `json:"cpus"`
	UnderlayIP       string `json:"underlay_ip,omitempty"`
	UnderlayDev      string `json:"underlay_dev,omitempty"`
	UnderlayMTU      int    `json:"underlay_mtu,omitempty"`
	Containers       int    `json:"containers"`
	// PrimaryContainers deliberately excludes internal FRR control sidecars;
	// it is the topology-device count operators compare with placement.
	PrimaryContainers int `json:"primary_containers"`
	// ControlContainers reports the private sidecars separately so 81
	// routers plus 24 FRR controls never looks like an unexplained inventory
	// mismatch.
	ControlContainers int `json:"control_containers"`
	// ManagedContainers is the physical runtime count including controls.
	ManagedContainers int `json:"managed_containers"`
	// ContainerCount is nil when the runtime list could not be read. Containers
	// is retained for older clients, but must not make an unreadable runtime
	// look like an empty node.
	ContainerCount     *int   `json:"container_count,omitempty"`
	ContainerListError string `json:"container_list_error,omitempty"`
	Lab                string `json:"lab,omitempty"`
	Hash               string `json:"topology_hash,omitempty"`
	// Labs is every lab this node currently hosts, and Busy every lab with an
	// operation in flight. A node that hosts a class lab and a dozen grading
	// harnesses at once cannot be described by a single name.
	Labs []string `json:"labs,omitempty"`
	Busy []string `json:"busy,omitempty"`
	// Overlays maps each VXLAN identifier in use on this node to the lab that
	// owns it, so an orchestrator can avoid handing a second lab an identifier
	// the first is already using.
	Overlays map[uint32]string `json:"overlays,omitempty"`
	// LogicalOverlayBindings counts VNI/VLAN mappings; PhysicalOverlayTrunks
	// counts bridge/VXLAN carriers. They intentionally diverge under
	// multiplexing.
	LogicalOverlayBindings int `json:"logical_overlay_bindings"`
	PhysicalOverlayTrunks  int `json:"physical_overlay_trunks"`
	// Generations are the only committed deployment generations. A prepared
	// transaction is deliberately absent: it is not a cluster commit.
	Generations map[string]string `json:"generations,omitempty"`
	// Modes exposes the committed renderer contract per lab so a node that
	// reports a healthy inventory cannot hide a platform/solve drift.
	Modes map[string]LabModeStatus `json:"modes,omitempty"`
	// Recoveries exposes durable transaction state and inventory verification.
	// A controller must not read an HTTP 200 status as proof that a failed
	// apply preserved services; Consistent is the proof boundary.
	Recoveries map[string]RecoveryStatus `json:"recoveries,omitempty"`
	// Ephemeral names every disposable lab this node holds and when its
	// lifetime ends. It is how an operator sees that a harness is still
	// consuming the cluster and exactly how long that can continue.
	Ephemeral []EphemeralStatus `json:"ephemeral,omitempty"`
	// Inventory distinguishes observed physical and allocatable capacity from
	// Twinet's own reservations. Unknown values are nil and named explicitly
	// in Inventory.Unknown; they are never reported as zero capacity.
	Inventory HostInventory `json:"inventory"`
	// Backpressure exposes node-wide queue depth and wait time by work class.
	Backpressure map[string]limiter.Stats `json:"backpressure"`
	// ActiveWork is the in-flight portion of each shared limiter. It is a
	// concise status surface for schedulers; Backpressure keeps queue/wait
	// detail for operators.
	ActiveWork map[string]int `json:"active_work"`
	// Convergence is the latest observed device-health classification. Unknown
	// is explicitly distinct from healthy and never folded into zero.
	Convergence map[string]int `json:"convergence"`
	// SemanticHealth keeps the same health facts per lab so an operator can
	// see that an otherwise idle recovery is degraded by one missing host
	// address instead of reading an aggregate node count as success.
	SemanticHealth map[string]SemanticHealth `json:"semantic_health,omitempty"`
	// Unknown names status dimensions that could not be observed.
	Unknown []string `json:"unknown,omitempty"`
	// StateStoreHealthy is nil for an older agent that cannot report it.
	// Explicit false lets a controller treat a surviving runtime with a lost
	// state disk as unavailable for durable placement.
	StateStoreHealthy *bool `json:"state_store_healthy,omitempty"`
	// PeerReplication exposes whether every recently contacted durability
	// peer acknowledged state. Keys are stable "lab/peer" tuples so an
	// operator can correlate failure-domain quorum loss without state data.
	PeerReplication map[string]PeerReplicationStatus `json:"peer_replication,omitempty"`
}

type LabModeStatus struct {
	Mode     string `json:"mode"`
	Ungraded int    `json:"ungraded_as,omitempty"`
}

type SemanticHealth struct {
	Healthy int `json:"healthy"`
	Broken  int `json:"broken"`
	Unknown int `json:"unknown"`
	Partial int `json:"partial"`
	// Terminal counts devices whose bounded distributed repair was abandoned.
	// They are a subset of Broken: the node has proven it cannot repair them
	// locally and has stopped retrying, so an operator has to look.
	Terminal int `json:"terminal,omitempty"`
	// Reasons names each currently non-healthy device and its bounded last
	// observation, so an idle node status cannot hide a sidecar/reachability
	// failure behind aggregate counts.
	Reasons map[string]string `json:"reasons,omitempty"`
}

// Degraded counts devices this node has observed and proven are not what the
// topology says they should be. Unknown is deliberately excluded: it is an
// absence of evidence, not evidence of drift.
func (h SemanticHealth) Degraded() int { return h.Broken + h.Partial }

// Drift names one device and its reason, for a caller that has to explain a
// refusal in one line. It is deterministic and prefers a terminal device,
// because that is the one nothing else is going to repair.
func (h SemanticHealth) Drift() string {
	devices := make([]string, 0, len(h.Reasons))
	for device := range h.Reasons {
		devices = append(devices, device)
	}
	sort.Strings(devices)
	for _, device := range devices {
		if strings.HasPrefix(h.Reasons[device], terminalReasonPrefix) {
			return device + ": " + h.Reasons[device]
		}
	}
	if len(devices) > 0 {
		return devices[0] + ": " + h.Reasons[devices[0]]
	}
	return ""
}

// terminalReasonPrefix marks a reason an operator must act on. It is part of
// the wire format so that a controller can distinguish "still converging"
// from "this node has given up" without a second request.
const terminalReasonPrefix = "terminal: "

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ver, err := s.rt.Ping(r.Context())
	if err != nil {
		httpError(w, http.StatusServiceUnavailable, err)
		return
	}
	cs, listErr := s.rt.List(r.Context(), rt.Filter{All: true,
		Labels: map[string]string{deploy.LabelManaged: "true"}})
	if listErr != nil {
		// Docker list can race a daemon reconnect. One immediate retry avoids
		// reporting a healthy 105-container node as unknown/zero because of a
		// transient client socket reset; a persistent error is retained in
		// both status and the structured log rather than silently folded into
		// an empty inventory.
		retry, retryErr := s.rt.List(r.Context(), rt.Filter{All: true,
			Labels: map[string]string{deploy.LabelManaged: "true"}})
		if retryErr == nil {
			cs, listErr = retry, nil
		} else {
			slog.Error("managed container inventory is unavailable", "node", s.cfg.Node,
				"err", listErr, "retry_err", retryErr)
		}
	}
	visibleCount := 0
	controlCount := 0
	for _, container := range cs {
		if !isInternalControlContainer(container) {
			visibleCount++
		} else {
			controlCount++
		}
	}

	resp := StatusResponse{
		Node: s.cfg.Node, Version: Version, Compatibility: Compatibility(),
		Uptime:  time.Since(s.started).Round(time.Second).String(),
		Runtime: s.rt.Name(), RuntimeVer: ver, RuntimeSocket: rt.Endpoint(s.rt),
		RuntimeNamespace:  rt.Namespace(s.rt),
		CPUs:              runtime.NumCPU(),
		UnderlayIP:        s.cfg.UnderlayIP,
		UnderlayDev:       s.cfg.UnderlayDev,
		UnderlayMTU:       s.configuredUnderlayMTU(),
		Containers:        visibleCount,
		PrimaryContainers: visibleCount,
		ControlContainers: controlCount,
		ManagedContainers: len(cs),
	}
	resp.Inventory = s.observeHostInventory(cs, listErr)
	resp.Backpressure = s.workLimiter().Snapshot()
	resp.ActiveWork = map[string]int{}
	for kind, stats := range resp.Backpressure {
		resp.ActiveWork[kind] = stats.InFlight
	}
	if listErr == nil {
		count := visibleCount
		resp.ContainerCount = &count
	} else {
		resp.Unknown = append(resp.Unknown, "containers")
		resp.ContainerListError = listErr.Error()
	}
	for _, unknown := range resp.Inventory.Unknown {
		resp.Unknown = append(resp.Unknown, "inventory."+unknown)
	}
	stateHealthy := s.store != nil
	if stateHealthy && s.store.Healthy() != nil {
		stateHealthy = false
	}
	resp.StateStoreHealthy = &stateHealthy
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
	// Both views are derived from the same filtered observations. A count
	// that disagreed with the per-device reasons -- or with what the plan
	// endpoint publishes -- would put the contradiction this removes straight
	// back into node status.
	resp.SemanticHealth = semanticHealthLocked(s.health, s.repairTerminal, s.current, s.cfg.Node, "")
	resp.Convergence = convergenceCounts(resp.SemanticHealth)
	s.mu.Unlock()
	resp.Generations = s.committedGenerations()
	resp.Modes = s.committedModes()
	resp.Recoveries = s.recoveryStatuses(r.Context())
	resp.Ephemeral = s.ephemeralStatuses()
	resp.PeerReplication = s.peerReplicationStatuses()

	if owners, err := netx.OverlayOwners(); err == nil {
		resp.Overlays = owners
	}
	if overlays, err := netx.InspectOverlayInventory(""); err == nil {
		resp.LogicalOverlayBindings = len(overlays.Bindings)
		resp.PhysicalOverlayTrunks = len(overlays.Trunks)
	}
	// A lab-scoped operator or diagnostic caller is told about the node it is
	// looking at and nothing about the rest of the cluster's business. The
	// request authorization context, not a query parameter the caller can
	// rewrite later, is the authority for this filter.
	scope, limited := scopedRequestOf(r)
	if !limited {
		if lab, diagnostic := diagScopeOf(r); diagnostic {
			scope, limited = requestScope{Lab: lab}, true
		}
	}
	if limited && scope.Lab != "" && scope.Lab != "*" {
		resp.Overlays = nil
		resp.Busy = nil
		resp.Labs = nil
		resp.Hash = ""
		resp.Lab = ""
		resp.Generations = nil
		resp.Modes = nil
		resp.Recoveries = nil
		resp.Ephemeral = nil
		resp.PeerReplication = nil
		resp.SemanticHealth = nil
		// Aggregates carry no tenant identifiers and remain useful to a
		// diagnostic caller, but a count of every active lab is not needed.
		// Reservations name other labs, which is cluster business a
		// diagnostic credential is not entitled to enumerate.
		if own, found := resp.Inventory.Reservations[scope.Lab]; found {
			resp.Inventory.Reservations = map[string]ResourceInventory{scope.Lab: own}
			resp.Inventory.Reserved = own
		} else {
			resp.Inventory.Reservations = nil
			resp.Inventory.Reserved = ResourceInventory{}
		}
		for _, l := range labs {
			if l == scope.Lab {
				resp.Lab, resp.Labs = scope.Lab, []string{scope.Lab}
			}
		}
		ownContainers := 0
		ownControls := 0
		for _, container := range cs {
			if container.Labels[deploy.LabelLab] == scope.Lab {
				if isInternalControlContainer(container) {
					ownControls++
				} else {
					ownContainers++
				}
			}
		}
		resp.Containers = ownContainers
		resp.PrimaryContainers = ownContainers
		resp.ControlContainers = ownControls
		resp.ManagedContainers = ownContainers + ownControls
		if resp.ContainerCount != nil {
			resp.ContainerCount = &ownContainers
		}
	}
	sort.Strings(resp.Unknown)
	writeJSON(w, resp)
}

func (s *Server) configuredUnderlayMTU() int {
	if s.cfg.UnderlayDev != "" {
		if iface, err := net.InterfaceByName(s.cfg.UnderlayDev); err == nil {
			return iface.MTU
		}
	}
	if s.cfg.UnderlayIP == "" {
		return 0
	}
	for _, iface := range rangeInterfaces() {
		for _, address := range iface.addrs {
			host, _, err := net.ParseCIDR(address)
			if err == nil && host.String() == s.cfg.UnderlayIP {
				return iface.mtu
			}
		}
	}
	return 0
}

type interfaceMTU struct {
	mtu   int
	addrs []string
}

func rangeInterfaces() []interfaceMTU {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]interfaceMTU, 0, len(interfaces))
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		values := make([]string, 0, len(addrs))
		for _, address := range addrs {
			values = append(values, address.String())
		}
		out = append(out, interfaceMTU{mtu: iface.MTU, addrs: values})
	}
	return out
}

func (s *Server) handleContainers(w http.ResponseWriter, r *http.Request) {
	lab := r.URL.Query().Get("lab")
	// A scoped certificate sees its own lab and no other, whatever query was
	// supplied. Listing an entire node would reveal other students' labs and
	// internal grading harnesses.
	if scope, ok := scopedRequestOf(r); ok && scope.Lab != "" && scope.Lab != "*" {
		lab = scope.Lab
	} else if scope, diagnostic := diagScopeOf(r); diagnostic {
		lab = scope
	}
	f := rt.Filter{All: true, Labels: map[string]string{deploy.LabelManaged: "true"}}
	if lab != "" {
		f.Labels[deploy.LabelLab] = lab
	}
	cs, err := s.rt.List(r.Context(), f)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	visible := cs[:0]
	for _, c := range cs {
		if !isInternalControlContainer(c) {
			visible = append(visible, c)
		}
	}
	writeJSON(w, visible)
}

// ApplyRequest carries the complete topology plus an explicit witness of the
// subset this node is responsible for.
type ApplyRequest struct {
	// ControllerVersion is the exact source build that requested the mutation.
	// It is audit provenance only; Compatibility is checked by the client
	// before any node mutates.
	ControllerVersion string `json:"controller_version,omitempty"`
	// Hold is the caller's grading-hold token, if it has one. A lab that is
	// held refuses changes from anybody else.
	Hold string `json:"hold,omitempty"`
	// Fence proves that this controller owns the cluster mutation lease.
	Fence Fence `json:"fence"`
	// Phase participates in the cluster prepare/apply/commit protocol. Empty
	// is retained for dry-run compatibility; mutating cluster applies must use
	// prepare, apply, commit, finalize, or abort.
	Phase string `json:"phase,omitempty"`
	// Lab is used by commit and abort, whose request need not repeat a large
	// topology payload.
	Lab string `json:"lab,omitempty"`
	// TargetNode and AssignedDevices are the controller's explicit placement
	// witness for this request. New agents reject a payload whose serialized
	// Device.Node fields disagree, rather than silently applying another
	// node's subset. AssignmentKnown distinguishes an intentional empty subset
	// from requests made by older controllers.
	TargetNode      string   `json:"target_node,omitempty"`
	AssignedDevices []string `json:"assigned_devices,omitempty"`
	AssignmentKnown bool     `json:"assignment_known,omitempty"`
	// ExpectedGeneration is the compare-and-swap value observed before
	// prepare. Generation is committed only after every node applied.
	ExpectedGeneration string `json:"expected_generation,omitempty"`

	Topology   *Wire  `json:"topology"`
	Mode       string `json:"mode"`
	PullPolicy string `json:"pull_policy"`
	// Ungraded names the one AS that keeps platform mode while the rest of the
	// lab is rendered with the reference solution. It is how a grading harness
	// surrounds a submission with a correct internet without also configuring
	// the work being marked.
	Ungraded int `json:"ungraded_as,omitempty"`
	// Ephemeral asks the node to hold this lab under a bounded, renewable
	// lifetime instead of indefinitely. It is how a controller says "this lab
	// exists only while I do", and it is the only thing that lets a node
	// reclaim a grading harness whose controller was killed.
	//
	// EphemeralTTLSeconds is the requested lifetime between heartbeats; the
	// node clamps it to its own safe bounds and never grants more than its
	// absolute lifetime ceiling from first deployment.
	Ephemeral           bool   `json:"ephemeral,omitempty"`
	EphemeralTTLSeconds int    `json:"ephemeral_ttl_seconds,omitempty"`
	EphemeralOwner      string `json:"ephemeral_owner,omitempty"`
	Workers             int    `json:"workers"`
	DryRun              bool   `json:"dry_run"`
	// StrictAdmission makes the controller verify live inventory before any
	// cluster mutation. It is set by deploy and grading; low-level callers
	// retain their explicit compatibility behavior.
	StrictAdmission bool `json:"strict_admission,omitempty"`
	// Overcommit is the explicit, audited exception to strict admission.
	Overcommit   bool              `json:"overcommit,omitempty"`
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
	// StateProofs are freshly captured source snapshots that a destination
	// must verify after restore and before any source placement is pruned.
	StateProofs []StateProof `json:"state_proofs,omitempty"`
}

// ApplyResponse reports the outcome.
type ApplyResponse struct {
	Node              string `json:"node"`
	AgentVersion      string `json:"agent_version,omitempty"`
	ControllerVersion string `json:"controller_version,omitempty"`
	// ImageDigests is observed after image pulls and before this response
	// allows a cluster transaction to commit. Keys are pull references and
	// values are runtime-reported identities.
	ImageDigests map[string]string `json:"image_digests,omitempty"`
	Generation   string            `json:"generation,omitempty"`
	Phase        string            `json:"phase,omitempty"`
	// Steps is how many steps ran and succeeded, and Planned how many the
	// plan held. They differ on a dry run, on an --only, and on a deploy that
	// failed part way, which are exactly the runs whose summary must not read
	// like a complete one.
	Steps   int `json:"steps"`
	Planned int `json:"planned,omitempty"`
	Devices int `json:"devices"`
	Links   int `json:"links"`
	// CrossLinkEndpoints counts completed/planned wire endpoints belonging to
	// cross-node links. The controller derives logical links from this actual
	// count; it must never subtract manifest cross-links from zero work.
	CrossLinkEndpoints     int   `json:"cross_link_endpoints,omitempty"`
	WantCrossLinkEndpoints int   `json:"want_cross_link_endpoints,omitempty"`
	WantDevice             int   `json:"want_devices,omitempty"`
	WantLinks              int   `json:"want_links,omitempty"`
	DryRun                 bool  `json:"dry_run,omitempty"`
	DurationMS             int64 `json:"duration_ms"`
	// PhaseMS separates bounded observation/diff/capture work from executable
	// plan time, so a no-change regression names its actual bottleneck.
	PhaseMS   map[string]int64    `json:"phase_ms,omitempty"`
	Dirty     map[string]int      `json:"dirty,omitempty"`
	Mutations map[string]int      `json:"mutations,omitempty"`
	Failures  map[string][]string `json:"failures,omitempty"`
	Pruned    []string            `json:"pruned,omitempty"`
	Snapshots int                 `json:"snapshots,omitempty"`
	// SemanticHealth is this node's audited convergence state for the lab
	// after the response was produced. A controller uses it to refuse a
	// zero-change success that contradicts the node it just deployed to.
	SemanticHealth SemanticHealth `json:"semantic_health"`
	// UnprovenNamespaces names the devices whose network namespace this pass
	// could neither prove continuous with the state they are supposed to hold
	// nor repair, with the reason for each.
	//
	// These devices are running, and their audited health may well say they
	// are fine -- the audit does not look at what a student owns. What is
	// wrong with them is invisible from outside: their saved addressing,
	// tunnels and bridge ports are being withheld from the state store,
	// because writing what is in their namespace now could overwrite the only
	// copy of the work. A lab that has quietly stopped being backed up is not
	// something an operator can be expected to infer.
	UnprovenNamespaces map[string]string `json:"unproven_namespaces,omitempty"`
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var req ApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}
	switch req.Phase {
	case "prepare":
		s.handleApplyPrepare(w, r, req)
		return
	case "commit":
		s.handleApplyCommit(w, r, req)
		return
	case "finalize":
		s.handleApplyFinalize(w, r, req)
		return
	case "abort":
		s.handleApplyAbort(w, r, req)
		return
	case "", "apply":
		// A dry run has no mutation to fence. Every real cluster apply is
		// deliberately the apply phase of a prepared transaction.
	default:
		httpError(w, http.StatusBadRequest, fmt.Errorf("unknown apply phase %q", req.Phase))
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
	if err := validateApplyAssignment(req, top, s.cfg.Node); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	if !req.DryRun && req.Phase == "apply" {
		s.auditDevelopmentHardeningOverrides(r, top, req.Generation, req.Fence.Generation)
	}
	s.recordEvent(top.Name, req.Generation, "deploy", s.requestCorrelation(r), "apply_requested", "scheduled",
		"phase="+req.Phase+" controller_source="+req.ControllerVersion)
	if why := s.refuseMutationIfHeld(top.Name, req.Hold, "this deployment"); why != "" {
		httpError(w, http.StatusConflict, errors.New(why))
		return
	}
	if !req.DryRun {
		if req.Phase != "apply" {
			httpError(w, http.StatusConflict, errors.New(
				"a mutating apply must be part of a prepared cluster transaction"))
			return
		}
		if err := s.requireMutationFence(top.Name, req.Fence); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		if err := s.checkPreparedGeneration(top.Name, req.Fence, req.Generation); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		if err := s.requireOverlayReservations(top, req.Fence); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		if req.Overcommit {
			// The controller records this in placement.json as well. Keep a
			// node-local audit trail because this agent is where pressure and
			// any resulting eviction are observed.
			slog.Warn("applying deployment under audited overcommit override",
				"lab", top.Name, "generation", req.Generation, "node", s.cfg.Node)
		}
	}
	operationCtx, cancelOperation := context.WithCancel(r.Context())
	opID, opDone, err := s.acquireOperation(top.Name, "apply", cancelOperation)
	if err != nil {
		cancelOperation()
		httpError(w, http.StatusConflict, err)
		return
	}
	defer func() {
		cancelOperation()
		s.releaseOperation(top.Name, opID, opDone)
	}()

	requestedMode, modeErr := requiredTransactionMode(req.Mode)
	if modeErr != nil {
		httpError(w, http.StatusBadRequest, modeErr)
		return
	}
	mode, ungraded := requestedMode, req.Ungraded
	previousMode, previousUngraded := "", 0
	peerUnderlay, prune, onlySteps := req.PeerUnderlay, req.Prune, req.OnlySteps
	if !req.DryRun && req.Phase == "apply" {
		tx, err := s.transactionForApply(top.Name, req.Fence, req.Generation)
		if err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		if err := validatePreparedPlacement(tx, top); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		persistedMode, err := requiredTransactionMode(tx.Mode)
		if err != nil {
			httpError(w, http.StatusConflict, fmt.Errorf("prepared desired mode: %w", err))
			return
		}
		if requestedMode != persistedMode || req.Ungraded != tx.Ungraded {
			httpError(w, http.StatusConflict, fmt.Errorf(
				"apply mode %s/%d does not match prepared desired mode %s/%d",
				requestedMode, req.Ungraded, persistedMode, tx.Ungraded))
			return
		}
		mode, ungraded = persistedMode, tx.Ungraded
		previousMode, previousUngraded = tx.PreviousMode, tx.PreviousUngraded
		peerUnderlay, prune, onlySteps = tx.PeerUnderlay, tx.Prune, tx.OnlySteps
	}
	if previousMode != "" {
		if _, err := requiredTransactionMode(previousMode); err != nil {
			httpError(w, http.StatusConflict, fmt.Errorf("prepared previous mode: %w", err))
			return
		}
	}
	forceStudentReset := needsStudentReset(previousMode, mode)
	eng := &deploy.Engine{
		Runtime:         s.rt,
		Node:            s.cfg.Node,
		Limiter:         s.workLimiter(),
		PullPolicy:      rt.PullPolicy(req.PullPolicy),
		Renderer:        renderer(top, mode, ungraded),
		WritesReference: mode == render.ModeSolve,
		// Solve mode installs the reference solution, which is the one case
		// where the rendered configuration must overwrite what is there.
		Authoritative:          mode == render.ModeSolve && ungraded == 0,
		UnderlayIP:             s.cfg.UnderlayIP,
		UnderlayDev:            s.cfg.UnderlayDev,
		PeerUnderlay:           peerUnderlay,
		State:                  s.store,
		Prune:                  prune,
		Generation:             req.Generation,
		ModeKey:                rendererModeKey(mode, ungraded),
		ForceStudentReset:      forceStudentReset,
		RestoreStudentState:    forceStudentReset,
		PreviousMode:           previousMode,
		PreviousUngraded:       previousUngraded,
		RequireImmutableImages: top.Lab.Images.RequiresImmutableImages(),
		RetainLegacyOverlays:   req.Phase == "apply",
		SemanticProbe: func(ctx context.Context, device *model.Device) error {
			if s.isExempt(top.Name, device.ID) {
				return nil
			}
			if err := s.semanticProbe(ctx, top, mode, ungraded, device); err != nil {
				return err
			}
			return auditedDriftError(s.auditedDriftReason(ctx, top.Name, device))
		},
	}
	if !req.DryRun && req.Phase == "apply" {
		if err := s.markGenerationApplying(top.Name, req.Fence, req.Generation); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		if err := s.transactionFail("apply"); err != nil {
			_ = s.markTransactionPhase(top.Name, req.Fence, req.Generation,
				transactionRollbackNeeded, err.Error())
			httpError(w, http.StatusConflict, err)
			return
		}
	}
	p, err := eng.BuildContext(operationCtx, top)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if len(onlySteps) > 0 {
		want := map[string]bool{}
		for _, sc := range onlySteps {
			want[sc] = true
		}
		p = p.Restrict(func(st *plan.Step) bool { return want[st.Scope] })
	}
	if req.Phase == "apply" {
		s.transactionFailpoints(p)
	}
	if req.Phase == "apply" && !req.DryRun {
		// Persist the exact create/recreate and cross-node binding set before
		// executing destructive steps. A restart during execution must not
		// infer object lineage from mutable labels.
		if err := s.recordGenerationTouched(top.Name, req.Fence, req.Generation,
			eng.DirtyCreateDevices(), eng.DirtyOverlayVNIs(top), true); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
	}
	execCtx := operationCtx
	stopFence := func() {}
	if req.Phase == "apply" {
		execCtx, stopFence = s.fencedContext(execCtx, top.Name, req.Fence)
	}
	defer stopFence()
	rep, err := p.Execute(execCtx, plan.Options{
		Workers:         s.workLimiter().ClampWorkers(limiter.Apply, req.Workers),
		ContinueOnError: true,
		DryRun:          req.DryRun,
	})
	s.recordPlanMetrics(rep)
	deploymentStats := eng.DeploymentStats(rep)
	s.recordDeploymentStats(deploymentStats, rep)
	crossDone := wireCrossEndpoints(rep.Results, top, false)
	crossWant := plannedCrossEndpoints(p, top)
	if err != nil {
		if req.Phase == "apply" && !req.DryRun {
			_ = s.markTransactionPhase(top.Name, req.Fence, req.Generation,
				transactionRollbackNeeded, "forward apply execution failed: "+err.Error())
		}
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	imageDigests := map[string]string(nil)
	if !req.DryRun {
		imageDigests, err = s.pulledImageDigests(operationCtx, top)
		if err != nil {
			if req.Phase == "apply" {
				_ = s.markTransactionPhase(top.Name, req.Fence, req.Generation,
					transactionRollbackNeeded, "post-apply image verification failed: "+err.Error())
			}
			httpError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if !req.DryRun && !rep.Failed() {
		s.refreshRepairedHealth(operationCtx, top, eng.DirtyNamespaceStateDevices())
	}
	if req.Phase == "apply" {
		resp := ApplyResponse{
			Node: s.cfg.Node, AgentVersion: Version, ControllerVersion: req.ControllerVersion,
			ImageDigests: imageDigests,
			Steps:        rep.Done(), Planned: p.Len(),
			Devices:                rep.Completed(plan.StageCreate),
			Links:                  rep.Completed(plan.StageWire),
			CrossLinkEndpoints:     crossDone,
			WantCrossLinkEndpoints: crossWant,
			WantDevice:             rep.Planned(plan.StageCreate),
			WantLinks:              rep.Planned(plan.StageWire),
			DurationMS:             rep.Duration.Milliseconds(),
			SemanticHealth:         s.labSemanticHealth(top.Name),
		}
		attachDeploymentStats(&resp, deploymentStats, rep)
		attachUnprovenNamespaces(&resp, eng.UnprovenNamespaceDevices())
		recordStart := time.Now()
		if err := s.recordGenerationDirtyCapture(top.Name, req.Fence, req.Generation, eng.DirtyCaptureDevices()); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		if err := s.recordGenerationSemantic(top.Name, req.Fence, req.Generation, eng.DirtySemanticDevices()); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		if rep.Failed() {
			resp.Failures = reportFailures(rep)
			slog.Error("apply plan reported degraded scopes",
				"lab", top.Name, "generation", req.Generation, "node", s.cfg.Node,
				"failures", resp.Failures)
			_ = s.markTransactionPhase(top.Name, req.Fence, req.Generation,
				transactionRollbackNeeded, fmt.Sprintf("forward apply failed: %v", rep.Err()))
			s.recordEvent(top.Name, req.Generation, "deploy", s.requestCorrelation(r),
				"apply", "error", fmt.Sprintf("%d degraded scope(s)", len(resp.Failures)))
			writeJSON(w, resp)
			return
		}
		if err := s.markGenerationApplied(top.Name, req.Fence, req.Generation); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		addPhaseTiming(&resp, "record", time.Since(recordStart))
		s.recordEvent(top.Name, req.Generation, "deploy", s.requestCorrelation(r),
			"apply", "success", fmt.Sprintf("steps=%d", resp.Steps))
		writeJSON(w, resp)
		return
	}

	// Whether this apply is entitled to say how the lab was built.
	//
	// The same condition guards the in-memory record and the one on disk. It
	// used to guard only the first, so a scoped or failed `--solve --only
	// as=3` left "solve" on disk with the in-memory record correctly untouched
	// -- and an agent restart read the disk copy back, so the node came up
	// believing an unsolved lab was the reference and stopped preserving
	// anybody's work.
	recordStart := time.Now()
	authoritative := len(req.OnlySteps) == 0 && !rep.Failed()

	s.mu.Lock()
	// A dry run changed nothing on this node, so it must not become what the
	// node believes it is hosting. Recording it made the agent claim a lab it
	// had never built: `node status` reported its hash, and a later destroy
	// would try to capture student work from containers that did not exist.
	if !req.DryRun {
		s.current[top.Name] = top
		// Only a complete, successful solve makes the whole lab solved.
		//
		// `--solve --only as=3` restricts what runs and then recorded the
		// entire lab as solved, so a later destroy skipped capturing every
		// other system's work. A partial failure did the same. The record is
		// what tells destroy whose configuration is whose, and it has to mean
		// what it says.
		if authoritative {
			s.rememberHow(top.Name, req.Mode, req.Ungraded)
		}
	}
	if s.peers == nil {
		s.peers = map[string]map[string]string{}
	}
	// Kept so a cross-node link can be rebuilt on this node's own initiative,
	// without waiting for the controller to send the map again.
	s.peers[top.Name] = req.PeerUnderlay
	s.mu.Unlock()

	// Recorded on disk as well as in memory. An agent restarted for any reason
	// would otherwise come back believing the node is empty, and the next
	// destroy would take a class's work with it without noticing there was
	// anything to capture.
	// A dry run changed nothing, so recording it would make the node claim to
	// host a lab that was never built.
	var recordFailure string
	if s.store != nil && !req.DryRun {
		// The peer map travels with the lab so a node that restarts can rebuild
		// a cross-node link without the controller.
		wt := req.Topology
		wt.PeerUnderlay = req.PeerUnderlay
		s.mu.Lock()
		prevMode, prevUngraded := s.modes[top.Name], s.ungraded[top.Name]
		s.mu.Unlock()
		wt.Mode, wt.Ungraded = modeToPersist(authoritative,
			req.Mode, req.Ungraded, prevMode, prevUngraded)
		raw, err := json.Marshal(wt)
		if err == nil {
			err = s.store.PutTopology(top.Name, raw)
		}
		if err != nil {
			// Reported to the caller, not merely journaled.
			//
			// This is the record that tells a restarted agent the node hosts
			// anything at all. Without it the node comes back believing it is
			// empty: nothing is repaired, and the next destroy removes a
			// class's work without capturing it, because there is no topology
			// saying there was anything to capture. An operator who is told
			// the deploy succeeded has no reason to look in the journal.
			slog.Error("recording the applied topology", "lab", top.Name, "err", err)
			recordFailure = fmt.Sprintf("the deployment was applied but this node could "+
				"not record it (%v); if this agent restarts it will believe the node is "+
				"empty, and nothing here will be repaired or preserved", err)
		}
	}

	resp := ApplyResponse{
		Node: s.cfg.Node, AgentVersion: Version, ControllerVersion: req.ControllerVersion,
		ImageDigests: imageDigests,
		Steps:        rep.Done(), Planned: p.Len(),
		Devices:                rep.Completed(plan.StageCreate),
		Links:                  rep.Completed(plan.StageWire),
		CrossLinkEndpoints:     crossDone,
		WantCrossLinkEndpoints: crossWant,
		WantDevice:             rep.Planned(plan.StageCreate),
		WantLinks:              rep.Planned(plan.StageWire),
		DryRun:                 req.DryRun,
		DurationMS:             rep.Duration.Milliseconds(),
		SemanticHealth:         s.labSemanticHealth(top.Name),
	}
	attachDeploymentStats(&resp, deploymentStats, rep)
	attachUnprovenNamespaces(&resp, eng.UnprovenNamespaceDevices())
	addPhaseTiming(&resp, "record", time.Since(recordStart))
	if recordFailure != "" {
		resp.Failures = map[string][]string{"state": {recordFailure}}
	}

	// Pruning happens only after a clean run and only when asked, so a partial
	// topology or a half-failed deployment can never be read as "remove
	// everything else".
	if req.Prune && !req.DryRun && !rep.Failed() {
		gone, err := eng.PruneOrphans(r.Context(), top)
		if err != nil {
			// Surfaced to the caller, not just logged. A prune that refused to
			// remove a container because it could not capture what was inside
			// is exactly the thing an operator has to see: the lab is fine, and
			// something is holding work nobody can account for. A warning in
			// the agent's journal is not seen by the person running the deploy.
			slog.Warn("pruning containers", "err", err)
			if resp.Failures == nil {
				resp.Failures = map[string][]string{}
			}
			resp.Failures["prune"] = append(resp.Failures["prune"], err.Error())
		}
		resp.Pruned = gone
		if overlays, err := eng.PruneOverlays(top); err != nil {
			slog.Warn("pruning overlays", "err", err)
			if resp.Failures == nil {
				resp.Failures = map[string][]string{}
			}
			resp.Failures["prune"] = append(resp.Failures["prune"], err.Error())
		} else {
			resp.Pruned = append(resp.Pruned, overlays...)
		}
	}

	// A completed apply is a destructive boundary too: it may have replaced
	// containers or made a new topology/mode record current. Capture and
	// replicate before reporting it as healthy. Solve mode is handled inside
	// captureAndReplicate, which still copies the repair records but never
	// files the reference answer as student work.
	if s.store != nil && !req.DryRun && !rep.Failed() {
		captureStart := time.Now()
		if n, err := s.captureAndReplicateDirty(r.Context(), top, eng.DirtyCaptureDevices()); err != nil {
			if boundaryErr := s.durableBoundary(top, "completing this deployment", err); boundaryErr != nil {
				if resp.Failures == nil {
					resp.Failures = map[string][]string{}
				}
				resp.Failures["durability"] = append(resp.Failures["durability"], boundaryErr.Error())
			}
		} else {
			resp.Snapshots = n
		}
		captureElapsed := time.Since(captureStart)
		addCaptureTiming(&resp, captureElapsed)
		s.metricRegistry().observePhase("capture", captureElapsed, "success")
	}
	if rep.Failed() {
		resp.Failures = reportFailures(rep)
	}
	writeJSON(w, resp)
}

func (s *Server) pulledImageDigests(ctx context.Context, top *model.Topology) (map[string]string, error) {
	refs := map[string]bool{}
	for _, device := range top.DevicesOnNode(s.cfg.Node) {
		if device.Image != "" {
			refs[device.Image] = true
		}
	}
	if len(refs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(refs))
	for _, ref := range sortedSetKeys(refs) {
		digest, err := s.rt.ImageDigest(ctx, ref)
		if err != nil || strings.TrimSpace(digest) == "" {
			if err == nil {
				err = errors.New("runtime returned an empty image identity")
			}
			return nil, fmt.Errorf("verify pulled image %s: %w", ref, err)
		}
		out[ref] = digest
	}
	return out, nil
}

func (s *Server) auditDevelopmentHardeningOverrides(r *http.Request, top *model.Topology,
	generation string, fence uint64,
) {
	if top == nil {
		return
	}
	principal, _ := principalOf(r)
	for _, device := range top.SortedDevices() {
		if !device.Hardening.DevelopmentOverrideActive() {
			continue
		}
		s.recordAuthorizationAudit(r, requestScope{
			Lab: top.Name, Action: authz.ActionDeploy, Target: device.ID,
			Generation: generation, FenceGeneration: fence,
		}, principal, "scheduled", "development hardening override: "+device.Hardening.DevelopmentOverride)
	}
}

// DestroyRequest asks the node to remove a lab.
type DestroyRequest struct {
	// Hold is the caller's grading-hold token, if it has one.
	Hold string `json:"hold,omitempty"`
	// Fence identifies the cluster mutation lease that may remove this lab.
	Fence Fence `json:"fence"`

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
	// WorkItems is a controller-side timeout hint derived from observed or
	// expected inventory. The agent never trusts it for authorization or
	// correctness.
	WorkItems int `json:"work_items,omitempty"`
}

// DestroyResponse reports what was removed and what could not be.
//
// Problems is the important field. A destroy that says "destroyed" while
// leaving overlays behind keeps their identifiers allocated, and the next lab
// to derive the same one finds it occupied -- which joins two labs' traffic
// together with nothing to indicate it happened.
type DestroyResponse struct {
	Status   string   `json:"status"`
	Lab      string   `json:"lab"`
	Problems []string `json:"problems,omitempty"`
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
	s.recordEvent(req.Lab, "", "deploy", s.requestCorrelation(r), "destroy_requested", "scheduled", "")
	if err := s.requireMutationFence(req.Lab, req.Fence); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	if why := s.destroyRecoveryRefusal(req); why != "" {
		httpError(w, http.StatusConflict, errors.New(why))
		return
	}
	if why := s.refuseMutationIfHeld(req.Lab, req.Hold, "removing it"); why != "" {
		httpError(w, http.StatusConflict, errors.New(why))
		return
	}
	opID, opDone, err := s.acquireDestroyOperation(r.Context(), req.Lab, req.Force)
	if err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	defer s.releaseOperation(req.Lab, opID, opDone)
	fenced, stopFence := s.fencedContext(r.Context(), req.Lab, req.Fence)
	defer stopFence()
	r = r.WithContext(fenced)

	eng := &deploy.Engine{Runtime: s.rt, Node: s.cfg.Node, State: s.store, Limiter: s.workLimiter()}

	// Destroying a lab must not lose a class's work: everything is captured
	// first, and refusing is better than proceeding blind.
	if s.store != nil && !req.Force && !req.Ephemeral {
		if err := s.captureBeforeDestroy(r.Context(), eng, req.Lab); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
	}
	s.destroyLab(w, r, eng, req)
}

func (s *Server) destroyRecoveryRefusal(req DestroyRequest) string {
	if req.Force {
		return ""
	}
	return s.recoveryMutationRefusal(req.Lab)
}

// captureBeforeDestroy saves what the students have on this node, and refuses
// when it cannot tell whether there is anything to save.
func (s *Server) captureBeforeDestroy(ctx context.Context, eng *deploy.Engine, lab string) error {
	{
		s.mu.Lock()
		top := s.current[lab]
		mode := render.Mode(s.modes[lab])
		ungraded := s.ungraded[lab]
		s.mu.Unlock()
		// Not while the reference solution is what is on the devices.
		//
		// Capture was stopped on the apply path and not here, so destroying a
		// solved grading lab -- which is every lab a class run touches -- still
		// filed the answer as each student's saved configuration, to be
		// replayed the next time anything recreated their container.
		switch {
		case top == nil && mode == render.ModeSolve:
			// Compatibility for an already-solved legacy harness whose
			// topology record was deliberately absent: no device-specific
			// ungraded exception can be inferred, so never file the reference
			// answer as student state.
		case top != nil && !hasCapturableStudentDevice(top, mode, ungraded, s.cfg.Node):
			// Nothing of anybody's to save: the reference answer is what is on
			// the devices.
		case top == nil:
			// This node does not know what the lab is, so it cannot read
			// anybody's work out of it -- and it used to destroy it anyway.
			//
			// The topology is held in memory and on disk, and the disk copy is
			// what an agent reads after a restart. If that read fails, or the
			// record was never written, the node comes up hosting a class's
			// containers with no idea what they are, and this branch quietly
			// skipped straight to removing them. A term's work, deleted, with
			// the destroy reporting success.
			cs, err := s.rt.List(ctx, rt.Filter{All: true, Labels: map[string]string{
				deploy.LabelManaged: "true", deploy.LabelLab: lab}})
			if err != nil {
				return fmt.Errorf(
					"refusing to destroy %s: this node has no record of the lab and its "+
						"containers could not be listed either (%w), so there is no way to "+
						"tell whether anybody's work is about to be deleted; pass force to "+
						"override", lab, err)
			}
			if len(cs) > 0 {
				return fmt.Errorf(
					"refusing to destroy %s: this node is running %d container(s) of it but "+
						"has no record of what the lab is, so their configuration cannot be "+
						"captured. Apply the lab first so the node knows what it is holding, "+
						"or pass force to destroy it and lose whatever is inside",
					lab, len(cs))
			}
		default:
			if n, err := s.captureAndReplicate(ctx, top); err != nil {
				if boundaryErr := s.durableBoundary(top, "destroy", err); boundaryErr != nil {
					return fmt.Errorf(
						"refusing to destroy %s: student configuration could not be captured and durably replicated (%w); "+
							"pass force to override", lab, boundaryErr)
				}
			} else if n > 0 {
				slog.Info("captured before destroy with durable replicas", "lab", lab, "snapshots", n)
			}
		}
	}
	return nil
}

// destroyLab removes the lab from this node and reports what it could not
// clean up.
func (s *Server) destroyLab(w http.ResponseWriter, r *http.Request,
	eng *deploy.Engine, req DestroyRequest) {
	if err := eng.Destroy(r.Context(), req.Lab); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	// Overlays are removed by ownership, never by the identifiers the caller
	// computed. Two reasons. A lab whose identifiers were moved to avoid a
	// collision no longer matches what its manifest derives, so a
	// manifest-driven list would leak the tunnels it actually has and delete
	// the ones it does not -- which belong to the lab it collided with. And a
	// lab whose manifest is gone entirely can still be cleaned up, because the
	// node knows what it owns without being told.
	// Cleanup failures are collected and returned, not just logged.
	//
	// A destroy that reports "destroyed" while leaving tunnels behind is worse
	// than one that fails: the VNIs stay allocated, and the next lab to derive
	// the same identifier finds them occupied and silently joins two labs'
	// traffic. The caller has to be told, and a warning in this node's log is
	// not telling the caller.
	var problems []string
	owned, err := netx.ListOverlaysOfLab(req.Lab)
	if err != nil {
		slog.Warn("listing this lab's overlays", "lab", req.Lab, "err", err)
		problems = append(problems, fmt.Sprintf("%s: could not list overlays: %v", s.cfg.Node, err))
	}
	if len(owned) > 0 {
		if err := eng.DestroyOverlays(owned); err != nil {
			slog.Warn("overlay cleanup incomplete", "lab", req.Lab, "err", err)
			problems = append(problems, fmt.Sprintf("%s: %d overlay(s) left behind: %v",
				s.cfg.Node, len(owned), err))
		}
	}
	// Identifiers the caller supplied are honoured only where they are
	// unowned, which cleans up a tunnel created before ownership was recorded
	// without ever touching one that belongs to somebody else.
	if len(req.VNIs) > 0 {
		owners, err := netx.OverlayOwners()
		if err == nil {
			var safeVNIs []uint32
			for _, v := range req.VNIs {
				if owner, ok := owners[v]; ok && owner == "" {
					safeVNIs = append(safeVNIs, v)
				}
			}
			if len(safeVNIs) > 0 {
				if err := eng.DestroyOverlays(safeVNIs); err != nil {
					slog.Warn("overlay cleanup incomplete", "lab", req.Lab, "err", err)
					problems = append(problems, fmt.Sprintf("%s: %d unowned overlay(s) left behind: %v",
						s.cfg.Node, len(safeVNIs), err))
				}
			}
		}
	}

	if s.store != nil {
		if req.Ephemeral {
			if err := s.store.Forget(req.Lab); err != nil {
				problems = append(problems, fmt.Sprintf("%s: discard ephemeral lab state: %v",
					s.cfg.Node, err))
			}
		} else if err := s.store.ForgetTopology(req.Lab); err != nil {
			// The snapshots of student work are kept; only the record that
			// this node hosts the lab is dropped, or a restart would resurrect
			// a lab that no longer exists.
			problems = append(problems, fmt.Sprintf("%s: clear lab topology record: %v",
				s.cfg.Node, err))
		}
	}
	status := "destroyed"
	if len(problems) > 0 {
		status = "incomplete"
	} else if err := s.finishDestroyedLab(req.Lab, req.Fence); err != nil {
		status = "incomplete"
		problems = append(problems, fmt.Sprintf("%s: could not commit empty destroyed state: %v",
			s.cfg.Node, err))
	}
	result := "success"
	if status != "destroyed" {
		result = "error"
	}
	s.recordEvent(req.Lab, "", "deploy", s.requestCorrelation(r), "destroy", result,
		strings.Join(problems, "; "))
	writeJSON(w, DestroyResponse{Status: status, Lab: req.Lab, Problems: problems})
}

// ExecRequest runs a command inside a container on this node.
type ExecRequest struct {
	// Hold is the caller's grading-hold token, if it has one. A lab that is
	// held refuses commands from anybody else.
	Hold string `json:"hold,omitempty"`

	Container string   `json:"container"`
	Cmd       []string `json:"cmd"`
	// Owner, when set, must match the container's twinet.owner label. This is
	// how a student session is confined to their own AS: authorisation is
	// enforced here, beside the container, not by network segmentation.
	Owner string `json:"owner,omitempty"`
	// Grading marks a command whose output will become a mark.
	//
	// A student has root in their own containers, so the programs the grader
	// runs there are the student's to replace. Before one of these runs, the
	// container's programs are compared against the image it was built from,
	// and a command that would have been answered by a program that is not the
	// image's comes back as a failure of the machinery rather than as evidence.
	Grading bool `json:"grading,omitempty"`
}

// ExecResponse carries the result.
type ExecResponse struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// ExecBatchRequest groups several read-only grading observations for devices
// on this node. Authorization requires every container to belong to one lab;
// individual results retain an error rather than making an absent device look
// like a negative network fact.
type ExecBatchRequest struct {
	Requests []ExecRequest `json:"requests"`
}

type ExecBatchResult struct {
	Response ExecResponse `json:"response"`
	Error    string       `json:"error,omitempty"`
}

type ExecBatchResponse struct {
	Results []ExecBatchResult `json:"results"`
}

// handleImages reports the digest behind every image this node has, so a
// grading report can name the exact software a mark was produced against.
func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	refs := r.URL.Query()["ref"]
	out := map[string]string{}
	for _, ref := range refs {
		if d, err := s.rt.ImageDigest(r.Context(), ref); err == nil {
			out[ref] = d
		}
	}
	writeJSON(w, out)
}

// ReshapeRequest asks the agent to put an interface back to a declared shaping.
//
// It exists so that undoing a traffic-control fault produces byte-identical
// state to a deployment. Reproducing the deployer's arithmetic with tc's
// command line does not: a burst asked for in bits is converted differently
// from one computed in scheduler ticks, so a "restored" link ends up with a
// different queue from the one the topology describes, and every later
// measurement on it is quietly wrong.
type ReshapeRequest struct {
	// Hold is the caller's grading-hold token, if it has one.
	Hold string `json:"hold,omitempty"`
	// Fence identifies the cluster mutation lease that may change shaping.
	Fence Fence `json:"fence"`

	Container string       `json:"container"`
	Iface     string       `json:"iface"`
	Shaping   netx.Shaping `json:"shaping"`
	MTU       int          `json:"mtu,omitempty"`
}

// MPLSLabelSpaceRequest is the narrow privileged operation used by the
// label-limit incident. The container itself never receives a writable sysctl:
// net.mpls.platform_labels is namespace-owned kernel state and must be fenced
// by the node agent.
type MPLSLabelSpaceRequest struct {
	Hold  string `json:"hold,omitempty"`
	Fence Fence  `json:"fence"`

	Container string `json:"container"`
	Action    string `json:"action"`
	Limit     int    `json:"limit,omitempty"`
	Labels    []int  `json:"labels,omitempty"`
}

// MPLSLabelSpaceResponse reports the observed kernel allocator state.
type MPLSLabelSpaceResponse struct {
	Limit     int    `json:"limit"`
	Allocated int    `json:"allocated"`
	Labels    []int  `json:"labels,omitempty"`
	Exhausted bool   `json:"exhausted"`
	Detail    string `json:"detail,omitempty"`
}

func (s *Server) handleMPLSLabelSpace(w http.ResponseWriter, r *http.Request) {
	var req MPLSLabelSpaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Container == "" || req.Action == "" {
		httpError(w, http.StatusBadRequest, errors.New("container and action are both required"))
		return
	}
	if why := s.refuseMutationIfHeld(s.labOfContainer(req.Container), req.Hold,
		"changing MPLS label space"); why != "" {
		httpError(w, http.StatusConflict, errors.New(why))
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
	if isInternalControlContainer(c) {
		httpError(w, http.StatusForbidden, errors.New("that container is an internal control sidecar"))
		return
	}
	if req.Action != "snapshot" {
		if err := s.requireMutationFence(c.Labels[deploy.LabelLab], req.Fence); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		if err := s.acquire(c.Labels[deploy.LabelLab], "mpls_label_space"); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		defer s.release(c.Labels[deploy.LabelLab])
	}
	ns, err := s.rt.NSPath(r.Context(), req.Container)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	var (
		snapshot netx.MPLSLabelSnapshot
		labels   []int
	)
	err = s.workLimiter().Run(r.Context(), []limiter.Kind{limiter.Netlink}, func() error {
		switch req.Action {
		case "snapshot":
			var inner error
			snapshot, inner = netx.SnapshotMPLSLabelsInNS(ns)
			return inner
		case "probe":
			var inner error
			snapshot, inner = netx.ProbeMPLSLabelExhaustionInNS(ns)
			return inner
		case "exhaust":
			var inner error
			snapshot, labels, inner = netx.ExhaustMPLSLabelsInNS(ns, req.Limit)
			return inner
		case "restore":
			if err := netx.RestoreMPLSLabelsInNS(ns, req.Limit, req.Labels); err != nil {
				return err
			}
			var inner error
			snapshot, inner = netx.SnapshotMPLSLabelsInNS(ns)
			return inner
		default:
			return fmt.Errorf("unknown MPLS label-space action %q", req.Action)
		}
	})
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	responseLabels := snapshot.Labels
	if req.Action == "exhaust" {
		// The fault owns only the routes it allocated, not pre-existing LDP
		// routes visible in the post-exhaustion snapshot.
		responseLabels = labels
	}
	writeJSON(w, MPLSLabelSpaceResponse{
		Limit: snapshot.Limit, Allocated: snapshot.Allocated, Labels: responseLabels,
		Exhausted: snapshot.Exhausted, Detail: snapshot.Detail,
	})
}

func (s *Server) handleReshape(w http.ResponseWriter, r *http.Request) {
	var req ReshapeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Container == "" || req.Iface == "" {
		httpError(w, http.StatusBadRequest, errors.New("container and iface are both required"))
		return
	}
	// Changing a link's delay or bandwidth during a class run changes the
	// marks on the traffic-engineering question, and nothing in the report
	// would say the network had been reshaped underneath it.
	if why := s.refuseMutationIfHeld(s.labOfContainer(req.Container), req.Hold,
		"reshaping a link"); why != "" {
		httpError(w, http.StatusConflict, errors.New(why))
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
	if isInternalControlContainer(c) {
		httpError(w, http.StatusForbidden, errors.New("that container is an internal control sidecar"))
		return
	}
	if err := s.requireMutationFence(c.Labels[deploy.LabelLab], req.Fence); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	if err := s.acquire(c.Labels[deploy.LabelLab], "reshape"); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	defer s.release(c.Labels[deploy.LabelLab])
	ns, err := s.rt.NSPath(r.Context(), req.Container)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.workLimiter().Run(r.Context(), []limiter.Kind{limiter.Netlink}, func() error {
		return netx.ReshapeInNS(ns, req.Iface, req.Shaping, req.MTU)
	}); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "iface": req.Iface})
}

// LifecycleRequest asks the agent to change a container's run state.
type LifecycleRequest struct {
	// Hold is the caller's grading-hold token, if it has one.
	Hold string `json:"hold,omitempty"`
	// Fence identifies the cluster mutation lease that may change lifecycle.
	Fence Fence `json:"fence"`

	Container string `json:"container"`
	// Action is one of state, pause, unpause, stop, start or restart.
	Action string `json:"action"`
	Owner  string `json:"owner,omitempty"`
}

func (s *Server) handleLifecycle(w http.ResponseWriter, r *http.Request) {
	var req LifecycleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Container == "" || req.Action == "" {
		httpError(w, http.StatusBadRequest, errors.New("container and action are both required"))
		return
	}
	// Stopping or restarting a container of a lab somebody is grading changes
	// the marks: a restarted router loses its namespace and comes back with
	// nothing, and the submission that was about to be measured is gone.
	if why := s.refuseMutationIfHeld(s.labOfContainer(req.Container), req.Hold,
		"changing a container's run state"); why != "" {
		httpError(w, http.StatusConflict, errors.New(why))
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
	// The same authorisation as exec. Pausing a container is at least as
	// disruptive as running a command in it, so it cannot be the weaker door.
	if c.Labels[deploy.LabelManaged] != "true" {
		httpError(w, http.StatusForbidden, errors.New("that container is not managed by twinet"))
		return
	}
	if isInternalControlContainer(c) {
		httpError(w, http.StatusForbidden, errors.New("that container is an internal control sidecar"))
		return
	}
	if req.Owner != "" && c.Labels[deploy.LabelOwner] != req.Owner {
		httpError(w, http.StatusForbidden,
			fmt.Errorf("%s belongs to %q, not %q", req.Container, c.Labels[deploy.LabelOwner], req.Owner))
		return
	}

	switch req.Action {
	case "state":
		writeJSON(w, map[string]string{"status": "ok", "state": string(c.State)})
		return
	}
	if err := s.requireMutationFence(c.Labels[deploy.LabelLab], req.Fence); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	if err := s.acquire(c.Labels[deploy.LabelLab], "lifecycle"); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	defer s.release(c.Labels[deploy.LabelLab])

	err = s.workLimiter().Run(r.Context(), []limiter.Kind{limiter.Lifecycle}, func() error {
		control := ""
		if c.Labels[deploy.LabelKind] == string(model.KindRouter) &&
			c.Labels[deploy.LabelNOS] != "bird" && c.Labels[deploy.LabelFRRControl] != "true" {
			name := req.Container + "-frr"
			if sidecar, inspectErr := s.rt.Inspect(r.Context(), name); inspectErr == nil && sidecar.State != rt.StateAbsent {
				control = name
			}
		}
		apply := func(container string) error {
			switch req.Action {
			case "pause":
				return s.rt.Pause(r.Context(), container)
			case "unpause":
				return s.rt.Unpause(r.Context(), container)
			case "stop":
				return s.rt.Stop(r.Context(), container, 10*time.Second)
			case "start":
				return s.rt.Start(r.Context(), container)
			case "restart":
				if err := s.rt.Stop(r.Context(), container, 10*time.Second); err != nil {
					return err
				}
				return s.rt.Start(r.Context(), container)
			default:
				return fmt.Errorf("unknown action %q", req.Action)
			}
		}
		if control == "" {
			return apply(req.Container)
		}
		switch req.Action {
		case "pause":
			if err := apply(control); err != nil {
				return err
			}
			return apply(req.Container)
		case "unpause":
			if err := apply(req.Container); err != nil {
				return err
			}
			return apply(control)
		case "stop":
			if err := apply(control); err != nil {
				return err
			}
			return apply(req.Container)
		case "start":
			if err := apply(req.Container); err != nil {
				return err
			}
			return apply(control)
		case "restart":
			if err := s.rt.Stop(r.Context(), control, 10*time.Second); err != nil {
				return err
			}
			if err := s.rt.Stop(r.Context(), req.Container, 10*time.Second); err != nil {
				return err
			}
			if err := s.rt.Start(r.Context(), req.Container); err != nil {
				return err
			}
			return s.rt.Start(r.Context(), control)
		default:
			return fmt.Errorf("unknown action %q", req.Action)
		}
	})
	if err != nil {
		s.recordEvent(c.Labels[deploy.LabelLab], "", "api", s.requestCorrelation(r),
			"container_"+req.Action, "error", err.Error())
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordEvent(c.Labels[deploy.LabelLab], "", "api", s.requestCorrelation(r),
		"container_"+req.Action, "success", req.Container)
	writeJSON(w, map[string]string{"status": "ok", "action": req.Action})
}

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	var req ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	res, status, err := s.executeExecRequest(r, req)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, res)
}

func (s *Server) handleExecBatch(w http.ResponseWriter, r *http.Request) {
	var req ExecBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Requests) == 0 || len(req.Requests) > 128 {
		httpError(w, http.StatusBadRequest, errors.New("batch must contain 1 through 128 exec requests"))
		return
	}
	workers := s.workLimiter().ClampWorkers(limiter.ExecProbe, 8)
	results := make([]ExecBatchResult, len(req.Requests))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for index, one := range req.Requests {
		index, one := index, one
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-r.Context().Done():
				results[index].Error = r.Context().Err().Error()
				return
			}
			defer func() { <-sem }()
			response, _, err := s.executeExecRequest(r, one)
			if err != nil {
				results[index].Error = err.Error()
				return
			}
			results[index].Response = response
		}()
	}
	wg.Wait()
	writeJSON(w, ExecBatchResponse{Results: results})
}

func (s *Server) executeExecRequest(r *http.Request, req ExecRequest) (ExecResponse, int, error) {
	if req.Container == "" || len(req.Cmd) == 0 {
		return ExecResponse{}, http.StatusBadRequest, errors.New("container and cmd are both required")
	}
	// A diagnostic caller is something under evaluation. It may look at one
	// lab, and it may only look: the hold token, other labs, and every command
	// that could change a device are refused here rather than trusted to the
	// caller's good manners.
	diagLab, diagnostic := diagScopeOf(r)
	if diagnostic {
		if req.Hold != "" {
			return ExecResponse{}, http.StatusForbidden,
				errors.New("a diagnostic session may not present a grading hold")
		}
		if err := ReadOnlyCommand(req.Cmd); err != nil {
			return ExecResponse{}, http.StatusForbidden, err
		}
	}
	// Running a command inside a lab somebody is grading would land in
	// somebody's marks. The grader passes its own hold token and is admitted.
	if why := s.refuseIfHeldByAnother(req.Container, req.Hold); why != "" {
		return ExecResponse{}, http.StatusConflict, errors.New(why)
	}
	c, err := s.rt.Inspect(r.Context(), req.Container)
	if err != nil {
		return ExecResponse{}, http.StatusInternalServerError, err
	}
	if c.State == rt.StateAbsent {
		return ExecResponse{}, http.StatusNotFound, fmt.Errorf("no container %q on %s", req.Container, s.cfg.Node)
	}
	if c.Labels[deploy.LabelManaged] != "true" {
		return ExecResponse{}, http.StatusForbidden, errors.New("that container is not managed by twinet")
	}
	if isInternalControlContainer(c) {
		return ExecResponse{}, http.StatusForbidden, errors.New("that container is an internal control sidecar")
	}
	if req.Owner != "" && c.Labels[deploy.LabelOwner] != req.Owner {
		return ExecResponse{}, http.StatusForbidden,
			fmt.Errorf("%s belongs to %q, not %q", req.Container, c.Labels[deploy.LabelOwner], req.Owner)
	}
	if diagnostic && c.Labels[deploy.LabelLab] != diagLab {
		return ExecResponse{}, http.StatusForbidden,
			fmt.Errorf("this diagnostic session is scoped to lab %q; %s belongs to %q",
				diagLab, req.Container, c.Labels[deploy.LabelLab])
	}
	// Nothing a container says can be believed until the programs saying it
	// are the ones its image ships.
	var res rt.ExecResult
	err = s.workLimiter().Run(r.Context(), []limiter.Kind{limiter.ExecProbe}, func() error {
		if req.Grading {
			if err := s.verifyTools(r.Context(), c); err != nil {
				return err
			}
		}
		var execErr error
		res, execErr = s.rt.Exec(r.Context(), req.Container, rt.ExecCmd{Cmd: req.Cmd})
		return execErr
	})
	if err != nil {
		if req.Grading {
			s.metricRegistry().observeGrading(metricResult(err))
			s.recordEvent(c.Labels[deploy.LabelLab], "", "grading", s.requestCorrelation(r),
				"grading_exec", "error", err.Error())
		}
		return ExecResponse{}, http.StatusInternalServerError, err
	}
	if req.Grading {
		result := "success"
		if res.ExitCode != 0 {
			result = "error"
		}
		s.metricRegistry().observeGrading(result)
		s.recordEvent(c.Labels[deploy.LabelLab], "", "grading", s.requestCorrelation(r),
			"grading_exec", result, "")
	}
	return ExecResponse{ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr}, http.StatusOK, nil
}

// verifyTools compares a container's programs against its image's, at most once
// every few seconds per container.
//
// A grading run makes hundreds of calls into one container, and reading the
// programs on every one of them would cost more than the checks do. The answer
// is not kept for longer than that, though: it was originally kept for the life
// of the container, and a program planted after one run was then believed by
// every run that followed, which is precisely the thing this exists to stop.
func (s *Server) verifyTools(ctx context.Context, c rt.Container) error {
	key := fmt.Sprintf("%s/%d", c.ID, c.PID)
	now := time.Now()
	s.toolsMu.Lock()
	cached, ok := s.toolsSeen[key]
	s.toolsMu.Unlock()
	if ok && now.Sub(cached.at) < toolsCheckEvery {
		return cached.err
	}
	findings, err := s.tools(ctx, c)
	if err != nil {
		// The grader could not read the image. That is the machinery's
		// failure, and it is not remembered: the next call tries again.
		return fmt.Errorf("the programs in %s could not be checked against %s, so the "+
			"evidence they produce cannot be relied on: %w", c.Name, c.Image, err)
	}
	var result error
	if len(findings) > 0 {
		result = &integrity.Error{Container: c.Name, Findings: findings}
	}
	s.toolsMu.Lock()
	s.toolsSeen[key] = toolsVerdict{err: result, at: now}
	s.toolsMu.Unlock()
	return result
}

// toolsCheckEvery is how stale a container's tool check may be.
//
// Short enough that a grading run re-reads the programs several times while it
// is running, and long enough that a run making hundreds of calls into thirty
// containers does not spend its time hashing the same files.
const toolsCheckEvery = 20 * time.Second

// toolsVerdict is what the last check of a container found, and when.
type toolsVerdict struct {
	err error
	at  time.Time
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
		var (
			mtu int
			dev string
		)
		err := s.workLimiter().Run(r.Context(), []limiter.Kind{limiter.Netlink}, func() error {
			var probeErr error
			mtu, dev, probeErr = netx.UnderlayMTU(peer)
			return probeErr
		})
		if err != nil {
			s.metricRegistry().observeUnderlay(metricResult(err))
			s.recordEvent("", "", "underlay", s.requestCorrelation(r), "underlay_probe", "error", err.Error())
			httpError(w, http.StatusBadRequest, err)
			return
		}
		resp.MTU, resp.Dev, resp.Probed = mtu, dev, peer
	}
	s.metricRegistry().observeUnderlay("success")
	s.recordEvent("", "", "underlay", s.requestCorrelation(r), "underlay_probe", "success", resp.Probed)
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

// describeTLSInputs names which of the three credentials were supplied, so the
// operator is told what is missing rather than that something is.
func describeTLSInputs(c Config) string {
	var have []string
	for _, f := range []struct {
		flag, val string
	}{
		{"-tls-cert", c.TLSCert},
		{"-tls-key", c.TLSKey},
		{"-client-ca", c.ClientCA},
	} {
		if f.val != "" {
			have = append(have, f.flag)
		}
	}
	return strings.Join(have, " and ") + " only"
}

// SweepRequest asks a node to report, and optionally remove, the overlays it is
// carrying for nobody.
type SweepRequest struct {
	// Remove actually deletes them; without it the node only reports.
	Remove bool `json:"remove,omitempty"`
}

// SweepResponse is what the node found.
type SweepResponse struct {
	Node    string        `json:"node"`
	Orphans []netx.Orphan `json:"orphans,omitempty"`
	Removed []uint32      `json:"removed,omitempty"`
	InUse   []netx.Orphan `json:"in_use,omitempty"`
	// Fenced are the orphans a removing sweep declined to delete because the
	// object, or its owner, became claimed between the scan and the deletion.
	// They are reported rather than dropped: an operator who asked for a
	// removal is entitled to know which ones did not happen and why.
	Fenced          []netx.Orphan `json:"fenced,omitempty"`
	LogicalBindings int           `json:"logical_bindings"`
	PhysicalTrunks  int           `json:"physical_trunks"`
	Errs            []string      `json:"errors,omitempty"`
}

// sweepFencesLocked names every reason this node must not delete an overlay
// right now. The caller holds s.mu.
//
// An operation lease is only one of them. A fenced cluster mutation, a
// half-applied transaction being rolled forward or back by recovery, a grading
// hold, and a prepared generation each mean something is entitled to the
// objects on this host even though no local lease is open at this instant --
// recovery in particular reconstructs overlays from a transaction record
// without ever taking s.ops.
func (s *Server) sweepFencesLocked(now time.Time) []string {
	var out []string
	for lab, l := range s.ops {
		out = append(out, fmt.Sprintf("operation %s on lab %q", l.kind, lab))
	}
	for lab, lease := range s.mutations {
		if now.Before(lease.until) {
			out = append(out, fmt.Sprintf("mutation lease on lab %q held by %s", lab, lease.holder))
		}
	}
	for lab, tx := range s.transactions {
		out = append(out, fmt.Sprintf("transaction on lab %q in phase %s", lab, tx.Phase))
	}
	for lab, h := range s.holds {
		if h != nil && now.Before(h.until) {
			out = append(out, fmt.Sprintf("hold on lab %q held by %s", lab, h.holder))
		}
	}
	for lab, gen := range s.generations {
		if gen.Prepared != "" {
			out = append(out, fmt.Sprintf("prepared generation %q on lab %q", gen.Prepared, lab))
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) sweepFences() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	now := s.nowTime()
	if s.expireCoordinationLocked(now) {
		if err := s.saveCoordinationLocked(); err != nil {
			slog.Warn("persist expired coordination before sweep", "err", err)
		}
	}
	return s.sweepFencesLocked(now)
}

func sweepConflict(fences []string) error {
	return fmt.Errorf("this node is not idle, so sweeping now could remove an overlay that is "+
		"being built or recovered: %s. Wait for it to finish, or run the sweep without --remove "+
		"to report only", strings.Join(fences, "; "))
}

// handleSweep finds overlays belonging to no lab this node hosts.
//
// A destroyed lab whose teardown was interrupted leaves its tunnels and bridges
// behind. They cost a VNI each out of a finite space, and the deconfliction
// that stops two labs choosing the same identifier reads the very ownership
// record they are missing. A hundred were found on one node of this cluster
// against forty-four in use, left by labs destroyed weeks earlier, and nothing
// had ever reported them.
//
// Sweeping is the one destructive path an operator drives by hand, against a
// list that was true when it was read. Between the scan and the deletion a
// deploy can claim the identifier, recovery can start rebuilding the very
// overlay the scan called abandoned, and a grading hold can be taken. So the
// node-wide fence is re-proved immediately before each removal, and each
// object is additionally claimed through the same lock the reservation path
// takes -- the fence that already protects garbage collection.
func (s *Server) handleSweep(w http.ResponseWriter, r *http.Request) {
	var req SweepRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	s.mu.Lock()
	live := map[string]bool{}
	for name := range s.current {
		live[name] = true
	}
	s.mu.Unlock()
	if req.Remove {
		if fences := s.sweepFences(); len(fences) > 0 {
			httpError(w, http.StatusConflict, sweepConflict(fences))
			return
		}
	}

	// The same discovery and removal seams garbage collection uses, so both
	// destructive paths agree about what an orphan is and a test can exercise
	// the fence without host netlink.
	s.gcMu.Lock()
	findOrphans, removeOverlay := s.gcFindOrphans, s.gcRemoveOverlay
	s.gcMu.Unlock()
	if findOrphans == nil {
		findOrphans = netx.FindOrphans
	}
	if removeOverlay == nil {
		removeOverlay = netx.RemoveOverlay
	}

	var found []netx.Orphan
	err := s.workLimiter().Run(r.Context(), []limiter.Kind{limiter.Netlink}, func() error {
		var findErr error
		found, findErr = findOrphans(live)
		return findErr
	})
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	resp := SweepResponse{Node: s.cfg.Node}
	if inventory, err := netx.InspectOverlayInventory(""); err == nil {
		resp.LogicalBindings = len(inventory.Bindings)
		resp.PhysicalTrunks = len(inventory.Trunks)
	} else {
		resp.Errs = append(resp.Errs, "inspect overlay inventory: "+err.Error())
	}
	for _, o := range found {
		if o.Ports > 0 {
			resp.InUse = append(resp.InUse, o)
			continue
		}
		resp.Orphans = append(resp.Orphans, o)
		if !req.Remove {
			continue
		}
		// Re-prove the node-wide fence for every object, not once for the
		// batch. A sweep of a hundred overlays is not instantaneous, and the
		// deploy or recovery that starts halfway through it is exactly the one
		// this refusal exists for.
		if fences := s.sweepFences(); len(fences) > 0 {
			resp.Fenced = append(resp.Fenced, o)
			resp.Errs = append(resp.Errs, fmt.Sprintf("vni %d: %v", o.VNI, sweepConflict(fences)))
			continue
		}
		if !s.beginOverlayCollection(o.VNI, o.Owner) {
			resp.Fenced = append(resp.Fenced, o)
			resp.Errs = append(resp.Errs, fmt.Sprintf(
				"vni %d: claimed by a deployment or another collection since the scan; left in place", o.VNI))
			continue
		}
		removeErr := s.workLimiter().Run(r.Context(), []limiter.Kind{limiter.Netlink}, func() error {
			return removeOverlay(o.VNI)
		})
		s.endOverlayCollection(o.VNI, o.Owner)
		if removeErr != nil {
			resp.Errs = append(resp.Errs, fmt.Sprintf("vni %d: %v", o.VNI, removeErr))
			continue
		}
		resp.Removed = append(resp.Removed, o.VNI)
	}
	writeJSON(w, resp)
}
