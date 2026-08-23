// Package client talks to Twinet node agents.
//
// The control plane fans out after obtaining a short-lived fenced lease from
// every participating node. It computes the whole topology, slices it by node,
// and uses prepare/apply/commit so a failed controller never claims a partial
// cluster deployment.
package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/contract"
	"github.com/HongyuHe/twinet/internal/images"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type correlationContextKey struct{}

var correlationSequence atomic.Uint64

// WithCorrelation lets an outer controller retain one trace identifier across
// every node request in a cluster operation.
func WithCorrelation(ctx context.Context, correlation string) context.Context {
	if strings.TrimSpace(correlation) == "" {
		return ctx
	}
	return context.WithValue(ctx, correlationContextKey{}, correlation)
}

func operationContext(ctx context.Context) context.Context {
	if existing, ok := ctx.Value(correlationContextKey{}).(string); ok && existing != "" {
		return ctx
	}
	return WithCorrelation(ctx, fmt.Sprintf("controller-%x", correlationSequence.Add(1)))
}

func correlationFromContext(ctx context.Context) string {
	value, _ := ctx.Value(correlationContextKey{}).(string)
	return value
}

// Node is a handle on one agent.
type Node struct {
	Name  string
	Addr  string
	Token string

	http *http.Client
	// tls is the client configuration the raw attach stream reuses, so the
	// streaming path cannot end up weaker than the request path.
	tls *tls.Config
	// cfgErr is a credential that could not be loaded, surfaced on first use
	// rather than swallowed at construction.
	cfgErr         error
	requestTimeout time.Duration
}

const (
	defaultNodeRequestTimeout = 2 * time.Minute
	mutationRequestBase       = 10 * time.Minute
	mutationRequestPerBatch   = 2 * time.Minute
	maxMutationRequestTimeout = agent.MaximumRecoveryTotalTimeout
	mutationRequestWorkers    = 48
)

// TLS carries the client's mutual-TLS material.
type TLS struct {
	Cert string
	Key  string
	CA   string
}

// NewNode constructs a node client.
func NewNode(name, addr, token string) *Node { return NewNodeTLS(name, addr, token, TLS{}) }

// NewNodeTLS constructs a node client, optionally with mutual TLS.
func NewNodeTLS(name, addr, token string, t TLS) *Node {
	scheme := "http://"
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		MaxIdleConnsPerHost: 8,
	}
	var (
		streamCfg *tls.Config
		cfgErr    error
	)
	if t.Cert != "" && t.Key != "" {
		scheme = "https://"
		cfg := &tls.Config{MinVersion: tls.VersionTLS13}

		// A certificate that will not load is recorded, not ignored. Silently
		// continuing without it produces a handshake the far side rejects for
		// reasons that look like a network problem, and the operator's actual
		// mistake -- a path, a permission -- is nowhere in the message. Worse,
		// swallowing it is how a cluster ends up believing it is authenticated
		// when it is not.
		cert, err := tls.LoadX509KeyPair(t.Cert, t.Key)
		if err != nil {
			cfgErr = fmt.Errorf("client certificate %s: %w", t.Cert, err)
		} else {
			cfg.Certificates = []tls.Certificate{cert}
		}
		if t.CA != "" && cfgErr == nil {
			pem, err := os.ReadFile(t.CA)
			switch {
			case err != nil:
				cfgErr = fmt.Errorf("cluster CA %s: %w", t.CA, err)
			default:
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pem) {
					cfgErr = fmt.Errorf("cluster CA %s contains no usable certificate", t.CA)
				} else {
					cfg.RootCAs = pool
				}
			}
		}
		tr.TLSClientConfig = cfg
		streamCfg = cfg
	}
	if !strings.Contains(addr, "://") {
		addr = scheme + addr
	}
	return &Node{
		Name: name, Addr: strings.TrimRight(addr, "/"), Token: token,
		tls: streamCfg, cfgErr: cfgErr, requestTimeout: defaultNodeRequestTimeout,
		http: &http.Client{Transport: tr},
	}
}

func (n *Node) do(ctx context.Context, method, path string, body, out any) error {
	timeout := n.requestTimeout
	if timeout <= 0 {
		timeout = defaultNodeRequestTimeout
	}
	return n.doWithTimeout(ctx, method, path, body, out, timeout)
}

func (n *Node) doWithTimeout(ctx context.Context, method, path string, body, out any,
	timeout time.Duration,
) error {
	if n.cfgErr != nil {
		return fmt.Errorf("node %s: %w", n.Name, n.cfgErr)
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, n.Addr+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	if correlation := correlationFromContext(ctx); correlation != "" {
		req.Header.Set("X-Twinet-Correlation-ID", correlation)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := n.http.Do(req)
	if err != nil {
		return fmt.Errorf("node %s: %w", n.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = json.Unmarshal(raw, &e)
		msg := e.Error
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("node %s: %s: %s", n.Name, resp.Status, msg)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func workloadRequestTimeout(items, workers int) time.Duration {
	if workers <= 0 {
		workers = mutationRequestWorkers
	}
	if workers > mutationRequestWorkers {
		workers = mutationRequestWorkers
	}
	if items < 1 {
		items = 1
	}
	timeout := mutationRequestBase +
		time.Duration((items+workers-1)/workers)*mutationRequestPerBatch
	if timeout > maxMutationRequestTimeout {
		return maxMutationRequestTimeout
	}
	return timeout
}

func applyRequestTimeout(req agent.ApplyRequest) time.Duration {
	items := len(req.AssignedDevices)
	if !req.AssignmentKnown && req.Topology != nil {
		items = len(req.Topology.Devices)
	}
	return workloadRequestTimeout(items, req.Workers)
}

// Status queries the agent.
func (n *Node) Status(ctx context.Context) (agent.StatusResponse, error) {
	var s agent.StatusResponse
	err := n.do(ctx, http.MethodGet, "/v1/status", nil, &s)
	return s, err
}

// Containers lists managed containers on the node.
func (n *Node) Containers(ctx context.Context, lab string) ([]rt.Container, error) {
	var cs []rt.Container
	p := "/v1/containers"
	if lab != "" {
		p += "?lab=" + url.QueryEscape(lab)
	}
	err := n.do(ctx, http.MethodGet, p, nil, &cs)
	return cs, err
}

// Controls audits private FRR control sidecars without exposing them through
// the ordinary user-facing container list.
func (n *Node) Controls(ctx context.Context, lab string) (agent.ControlAuditResponse, error) {
	var out agent.ControlAuditResponse
	path := "/v1/controls"
	if lab != "" {
		path += "?lab=" + url.QueryEscape(lab)
	}
	err := n.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

// ReconcileControls asks one node to enqueue bounded automatic sidecar repair.
// Holds, mutation fences, and normal exponential retry still apply at the
// agent; this is an audit trigger, not a bypass.
func (n *Node) ReconcileControls(ctx context.Context, lab string) ([]string, error) {
	var out struct {
		Scheduled []string `json:"scheduled"`
	}
	err := n.do(ctx, http.MethodPost, "/v1/controls/reconcile",
		agent.ControlReconcileRequest{Lab: lab}, &out)
	return out.Scheduled, err
}

// Reconcile queues desired/observed repair checks without bypassing the
// agent's hold, fence, or bounded-backoff rules.
func (n *Node) Reconcile(ctx context.Context, req agent.ReconcileRequest) (agent.ReconcileResponse, error) {
	var out agent.ReconcileResponse
	err := n.do(ctx, http.MethodPost, "/v1/reconcile", req, &out)
	return out, err
}

// Events reads a bounded page from the node's structured event ring. The
// cursor is node-local; ClusterEvents merges pages deterministically.
func (n *Node) Events(ctx context.Context, lab string, after uint64, limit int) (agent.EventsResponse, error) {
	values := url.Values{}
	if lab != "" {
		values.Set("lab", lab)
	}
	if after > 0 {
		values.Set("after", strconv.FormatUint(after, 10))
	}
	if limit > 0 {
		values.Set("limit", strconv.Itoa(limit))
	}
	var out agent.EventsResponse
	path := "/v1/events"
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	err := n.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

// WatchEvents follows one node's event stream. Closing ctx cancels the HTTP
// request and closes both channels; the caller owns reconnection policy so it
// can merge node streams without duplicating cursor decisions.
func (n *Node) WatchEvents(ctx context.Context, lab string, after uint64) (<-chan agent.Event, <-chan error) {
	events := make(chan agent.Event, 128)
	errs := make(chan error, 1)
	go func() {
		defer close(events)
		defer close(errs)
		if n.cfgErr != nil {
			errs <- fmt.Errorf("node %s: %w", n.Name, n.cfgErr)
			return
		}
		values := url.Values{"follow": []string{"true"}}
		if lab != "" {
			values.Set("lab", lab)
		}
		if after > 0 {
			values.Set("after", strconv.FormatUint(after, 10))
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			n.Addr+"/v1/events?"+values.Encode(), nil)
		if err != nil {
			errs <- err
			return
		}
		req.Header.Set("Authorization", "Bearer "+n.Token)
		resp, err := n.http.Do(req)
		if err != nil {
			if ctx.Err() == nil {
				errs <- fmt.Errorf("node %s: %w", n.Name, err)
			}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode >= http.StatusBadRequest {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			errs <- fmt.Errorf("node %s: %s: %s", n.Name, resp.Status, strings.TrimSpace(string(raw)))
			return
		}
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
		for scanner.Scan() {
			var event agent.Event
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				errs <- fmt.Errorf("node %s: decode event stream: %w", n.Name, err)
				return
			}
			select {
			case events <- event:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil && ctx.Err() == nil {
			errs <- fmt.Errorf("node %s: read event stream: %w", n.Name, err)
		}
	}()
	return events, errs
}

// Apply asks the node to converge its slice of the topology.
func (n *Node) Apply(ctx context.Context, req agent.ApplyRequest) (agent.ApplyResponse, error) {
	var resp agent.ApplyResponse
	err := n.doWithTimeout(ctx, http.MethodPost, "/v1/apply", req, &resp,
		applyRequestTimeout(req))
	return resp, err
}

// Plan performs a read-only desired/observed no-op preflight.
func (n *Node) Plan(ctx context.Context, req agent.PlanRequest) (agent.PlanResponse, error) {
	var resp agent.PlanResponse
	err := n.do(ctx, http.MethodPost, "/v1/plan", req, &resp)
	return resp, err
}

// PlanVerify checks a read-only no-op witness immediately before the
// controller returns without acquiring a mutation lease.
func (n *Node) PlanVerify(ctx context.Context, req agent.PlanVerifyRequest) (agent.PlanVerifyResponse, error) {
	var resp agent.PlanVerifyResponse
	err := n.do(ctx, http.MethodPost, "/v1/plan/verify", req, &resp)
	return resp, err
}

// Destroy removes a lab from the node.
func (n *Node) Destroy(ctx context.Context, lab string, vnis []uint32) error {
	return n.destroy(ctx, agent.DestroyRequest{Lab: lab, VNIs: vnis})
}

// DestroyEphemeral removes a disposable lab and discards its saved state.
func (n *Node) DestroyEphemeral(ctx context.Context, lab string, vnis []uint32) error {
	return n.destroy(ctx, agent.DestroyRequest{Lab: lab, VNIs: vnis, Ephemeral: true})
}

// destroy sends the request and turns a partial cleanup into an error.
//
// The agent used to answer "destroyed" whatever happened to the overlays, so a
// node that could not remove a tunnel logged a warning locally and told the
// controller everything was fine. The identifiers stayed allocated, and the
// next lab deriving the same one joined its traffic to a lab that was supposed
// to be gone.
func (n *Node) destroy(ctx context.Context, req agent.DestroyRequest) error {
	var resp agent.DestroyResponse
	if err := n.doWithTimeout(ctx, http.MethodPost, "/v1/destroy", req, &resp,
		workloadRequestTimeout(req.WorkItems, mutationRequestWorkers)); err != nil {
		return err
	}
	if len(resp.Problems) > 0 {
		return fmt.Errorf("%s was only partially removed, so its network identifiers are "+
			"still in use and a later lab could collide with them: %s",
			req.Lab, strings.Join(resp.Problems, "; "))
	}
	return nil
}

// Hold asks the node's repair loop to leave a lab alone for a while. Seconds of
// zero drops the hold.
func (n *Node) Hold(ctx context.Context, lab, holder, token string, seconds int) error {
	var resp struct{}
	return n.do(ctx, http.MethodPost, "/v1/hold",
		agent.HoldRequest{Lab: lab, Holder: holder, Token: token, Seconds: seconds}, &resp)
}

// Exempt tells the node to leave a device alone, or to look after it again.
func (n *Node) Exempt(ctx context.Context, lab, device, id string, on bool) error {
	return n.exempt(ctx, agent.ExemptRequest{Lab: lab, Device: device, ID: id, On: on})
}

func (n *Node) exempt(ctx context.Context, req agent.ExemptRequest) error {
	var resp struct{}
	return n.do(ctx, http.MethodPost, "/v1/exempt", req, &resp)
}

// Exec runs a command in a container on the node.
func (n *Node) Exec(ctx context.Context, req agent.ExecRequest) (agent.ExecResponse, error) {
	var resp agent.ExecResponse
	err := n.do(ctx, http.MethodPost, "/v1/exec", req, &resp)
	return resp, err
}

// ExecBatch groups same-lab device observations into one authenticated HTTP
// request. Per-device failures stay explicit in the response so a grader can
// classify them as infrastructure errors rather than false network facts.
func (n *Node) ExecBatch(ctx context.Context, req agent.ExecBatchRequest) (agent.ExecBatchResponse, error) {
	var resp agent.ExecBatchResponse
	err := n.do(ctx, http.MethodPost, "/v1/exec/batch", req, &resp)
	return resp, err
}

// Lifecycle changes a container's run state on this node.
func (n *Node) Lifecycle(ctx context.Context, req agent.LifecycleRequest) error {
	return n.do(ctx, http.MethodPost, "/v1/lifecycle", req, nil)
}

// ImageDigests resolves image references to the digests in use on this node.
func (n *Node) ImageDigests(ctx context.Context, refs []string) (map[string]string, error) {
	q := url.Values{}
	for _, r := range refs {
		q.Add("ref", r)
	}
	var out map[string]string
	err := n.do(ctx, http.MethodGet, "/v1/images?"+q.Encode(), nil, &out)
	return out, err
}

// ContainerState reports a container's run state on this node.
func (n *Node) ContainerState(ctx context.Context, container string) (string, error) {
	var resp struct {
		State string `json:"state"`
	}
	err := n.do(ctx, http.MethodPost, "/v1/lifecycle",
		agent.LifecycleRequest{Container: container, Action: "state"}, &resp)
	return resp.State, err
}

// OverlaysInUse maps every VXLAN identifier deployed anywhere in the cluster to
// the lab that owns it. A node that cannot be reached contributes nothing,
// which is deliberate: refusing to deploy because one node is down would be a
// worse failure than the collision this avoids, and the collision is caught
// again at the node itself.
func (c *Cluster) OverlaysInUse(ctx context.Context) map[uint32]string {
	out := map[uint32]string{}
	for _, r := range c.Status(ctx) {
		if r.Err != nil {
			continue
		}
		for vni, lab := range r.Value.Overlays {
			if lab != "" {
				out[vni] = lab
			}
		}
	}
	return out
}

// Reshape puts an interface back to a declared shaping using the same code the
// deployer uses, so an undo cannot drift from a deployment.
func (n *Node) Reshape(ctx context.Context, req agent.ReshapeRequest) error {
	return n.do(ctx, http.MethodPost, "/v1/reshape", req, nil)
}

// MPLSLabelSpace executes the fenced namespace-side label allocator operation.
func (n *Node) MPLSLabelSpace(ctx context.Context, req agent.MPLSLabelSpaceRequest) (agent.MPLSLabelSpaceResponse, error) {
	var resp agent.MPLSLabelSpaceResponse
	err := n.do(ctx, http.MethodPost, "/v1/mpls-label-space", req, &resp)
	return resp, err
}

// Underlay probes the fabric MTU toward a peer.
func (n *Node) Underlay(ctx context.Context, peer string) (agent.UnderlayResponse, error) {
	var resp agent.UnderlayResponse
	p := "/v1/underlay"
	if peer != "" {
		p += "?peer=" + url.QueryEscape(peer)
	}
	err := n.do(ctx, http.MethodGet, p, nil, &resp)
	return resp, err
}

// Cluster is the set of agents backing one lab.
type Cluster struct {
	Nodes []*Node

	// RequestedRuntimes maps each placement node to the backend the manifest
	// selected for it. It is intentionally carried by the client, not inferred
	// from a status response: a daemon answering from the wrong socket must not
	// get to choose what the lab means.
	RequestedRuntimes map[string]string

	// RequireVersion is the exact controller source build retained in audit
	// messages. It deliberately does not gate a rolling upgrade: source SHAs
	// can differ while the protocol, renderer, and state contracts remain
	// compatible.
	RequireVersion string
	// RequireCompatibility is the controller contract accepted for a rolling
	// deployment. Empty keeps narrow tests and deliberately local callers
	// unchecked; normal CLI construction always supplies it.
	RequireCompatibility contract.Set
}

// VersionSkew reports a protocol, renderer, or state incompatibility. The
// historical name remains for callers, but source build IDs are evidence only:
// compatible bug-fix agents may roll one node at a time.
func (c *Cluster) VersionSkew(ctx context.Context) error {
	expected := c.RequireCompatibility
	if expected.Empty() && c.RequireVersion != "" {
		// Compatibility for callers compiled before RequireCompatibility was
		// added. It intentionally does not compare the supplied source build.
		expected = agent.Compatibility()
	}
	if expected.Empty() {
		return nil
	}
	var odd []string
	for _, r := range c.Status(ctx) {
		switch {
		case r.Err != nil:
			odd = append(odd, fmt.Sprintf("%s could not report compatibility (%v)", r.Node, r.Err))
		case r.Value.Compatibility.Empty():
			odd = append(odd, fmt.Sprintf("%s (%s) does not advertise protocol, renderer, and state contracts",
				r.Node, sourceVersion(r.Value.Version)))
		default:
			if err := expected.Compatible(r.Value.Compatibility); err != nil {
				odd = append(odd, fmt.Sprintf("%s (%s): %v", r.Node, sourceVersion(r.Value.Version), err))
			}
		}
	}
	if len(odd) == 0 {
		return nil
	}
	sort.Strings(odd)
	return fmt.Errorf("rolling upgrade contracts are incompatible before mutation: controller source %s; %s.\n"+
		"Exact source builds are retained for audit, but a renderer or state contract "+
		"mismatch can make the same manifest produce different configuration or unreadable state.",
		sourceVersion(c.RequireVersion), strings.Join(odd, ", "))
}

func sourceVersion(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown-source"
	}
	return value
}

// ExpectVersion is retained as the exact source build stamped into controller
// audit records. ExpectCompatibility is the independent rolling-upgrade gate.
var (
	ExpectVersion       string
	ExpectCompatibility contract.Set
)

// NewCluster builds a cluster client from a lab's placement configuration.
func NewCluster(lab *model.Lab, token string) *Cluster {
	t := TLS{
		Cert: os.Getenv("TWINET_TLS_CERT"),
		Key:  os.Getenv("TWINET_TLS_KEY"),
		CA:   os.Getenv("TWINET_CA"),
	}
	// Fall back to material issued for the lab, and then to material issued for
	// the cluster. Requiring an operator to export three environment variables
	// before anything works is how a cluster ends up running without them: the
	// insecure path is the one that needs no setup, so it becomes the path
	// everyone uses.
	//
	// The cluster-wide location matters as much as the per-lab one. A node
	// agent trusts one certificate authority, so a second lab on the same
	// cluster has no way to be trusted unless its own directory happens to
	// contain a copy -- and until somebody copies the files by hand, every
	// command against that lab fails with "client sent an HTTP request to an
	// HTTPS server", which names neither the cause nor the cure.
	if t.Cert == "" {
		for _, dir := range pkiSearchPath(lab) {
			cert := filepath.Join(dir, "controller_cert.pem")
			key := filepath.Join(dir, "controller_key.pem")
			ca := filepath.Join(dir, "ca_cert.pem")
			if fileExists(cert) && fileExists(key) && fileExists(ca) {
				t = TLS{Cert: cert, Key: key, CA: ca}
				break
			}
		}
	}
	return NewClusterTLS(lab, token, t)
}

// pkiSearchPath lists where mutual-TLS material may live, nearest first.
//
// The lab's own directory wins, so a lab issued its own authority keeps using
// it. After that comes the cluster's, because the certificate authority is a
// property of the cluster the agents run on and not of any one lab.
func pkiSearchPath(lab *model.Lab) []string {
	var dirs []string
	if lab != nil && lab.Dir != "" {
		dirs = append(dirs, filepath.Join(lab.Dir, ".twinet", "pki"))
	}
	if d := os.Getenv("TWINET_PKI"); d != "" {
		dirs = append(dirs, d)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs, filepath.Join(home, ".twinet", "pki"))
	}
	dirs = append(dirs, "/etc/twinet/pki")
	return dirs
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// NewClusterTLS builds a cluster client with explicit TLS material.
func NewClusterTLS(lab *model.Lab, token string, t TLS) *Cluster {
	c := &Cluster{RequireVersion: ExpectVersion, RequireCompatibility: ExpectCompatibility}
	if lab != nil {
		c.RequestedRuntimes = make(map[string]string, len(lab.Placement.Nodes))
	}
	if lab == nil {
		return c
	}
	for _, n := range lab.Placement.Nodes {
		addr := n.Addr
		if addr == "" {
			addr = n.Name + ":7200"
		}
		c.Nodes = append(c.Nodes, NewNodeTLS(n.Name, addr, token, t))
		c.RequestedRuntimes[n.Name] = lab.RuntimeForNode(n.Name)
	}
	return c
}

// Node returns the named node.
func (c *Cluster) Node(name string) (*Node, bool) {
	for _, n := range c.Nodes {
		if n.Name == name {
			return n, true
		}
	}
	return nil, false
}

// Without returns a shallow cluster view excluding named nodes. It is used to
// obtain placement inventory from survivors during a drain or node-loss
// recovery; mutation of a live drain still uses the full cluster so the source
// remains fenced until restore verification succeeds.
func (c *Cluster) Without(names ...string) *Cluster {
	skip := map[string]bool{}
	for _, name := range names {
		skip[name] = true
	}
	out := &Cluster{
		RequireVersion:       c.RequireVersion,
		RequireCompatibility: c.RequireCompatibility,
	}
	if len(c.RequestedRuntimes) > 0 {
		out.RequestedRuntimes = make(map[string]string, len(c.RequestedRuntimes))
	}
	for _, node := range c.Nodes {
		if !skip[node.Name] {
			out.Nodes = append(out.Nodes, node)
			if c.RequestedRuntimes != nil {
				out.RequestedRuntimes[node.Name] = c.RequestedRuntimes[node.Name]
			}
		}
	}
	return out
}

// NodeResult pairs a node with the outcome of an operation on it.
type NodeResult[T any] struct {
	Node  string
	Value T
	Err   error
}

// fanOut runs fn against every node concurrently and collects the results in
// node-name order, so output is stable regardless of who finishes first.
func fanOut[T any](ctx context.Context, nodes []*Node, fn func(context.Context, *Node) (T, error)) []NodeResult[T] {
	out := make([]NodeResult[T], len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n *Node) {
			defer wg.Done()
			v, err := fn(ctx, n)
			out[i] = NodeResult[T]{Node: n.Name, Value: v, Err: err}
		}(i, n)
	}
	wg.Wait()
	sort.Slice(out, func(a, b int) bool { return out[a].Node < out[b].Node })
	return out
}

// Status queries every node.
func (c *Cluster) Status(ctx context.Context) []NodeResult[agent.StatusResponse] {
	return fanOut(ctx, c.Nodes, func(ctx context.Context, n *Node) (agent.StatusResponse, error) {
		return n.Status(ctx)
	})
}

// Controls audits private control sidecars on every node in stable node order.
func (c *Cluster) Controls(ctx context.Context, lab string) []NodeResult[agent.ControlAuditResponse] {
	return fanOut(ctx, c.Nodes, func(ctx context.Context, n *Node) (agent.ControlAuditResponse, error) {
		return n.Controls(ctx, lab)
	})
}

// ReconcileControls queues bounded automatic repair on every node that hosts
// the lab. A controller operation correlation is shared by the fan-out.
func (c *Cluster) ReconcileControls(ctx context.Context, lab string) []NodeResult[[]string] {
	ctx = operationContext(ctx)
	return fanOut(ctx, c.Nodes, func(ctx context.Context, n *Node) ([]string, error) {
		return n.ReconcileControls(ctx, lab)
	})
}

// Reconcile asks every node that hosts a lab to enqueue bounded checks.
func (c *Cluster) Reconcile(ctx context.Context, lab string, devices []string, force bool) []NodeResult[agent.ReconcileResponse] {
	return c.ReconcileWithOverlay(ctx, lab, devices, force, false)
}

// ReconcileWithOverlay additionally repairs missing/mismatched logical
// VNI/VLAN bindings. It does not recreate endpoint containers.
func (c *Cluster) ReconcileWithOverlay(ctx context.Context, lab string, devices []string, force, overlay bool) []NodeResult[agent.ReconcileResponse] {
	ctx = operationContext(ctx)
	return fanOut(ctx, c.Nodes, func(ctx context.Context, n *Node) (agent.ReconcileResponse, error) {
		return n.Reconcile(ctx, agent.ReconcileRequest{Lab: lab, Devices: devices, Force: force, Overlay: overlay})
	})
}

// Events obtains finite event pages from every node. Results remain paired
// with errors so a caller cannot mistake an unreachable node for an empty
// event history.
func (c *Cluster) Events(ctx context.Context, lab string, after uint64, limit int) []NodeResult[agent.EventsResponse] {
	return fanOut(ctx, c.Nodes, func(ctx context.Context, n *Node) (agent.EventsResponse, error) {
		return n.Events(ctx, lab, after, limit)
	})
}

// MergeEvents combines successful node pages into the stable order used by
// both JSON and terminal output.
func MergeEvents(results []NodeResult[agent.EventsResponse]) []agent.Event {
	var events []agent.Event
	for _, result := range results {
		if result.Err == nil {
			events = append(events, result.Value.Events...)
		}
	}
	agent.SortEvents(events)
	return events
}

// HealthCheck proves every declared agent responds before placement or a
// migration changes any record. A partial survey is not a healthy cluster:
// the missing node may be the only owner of state about to be moved.
func (c *Cluster) HealthCheck(ctx context.Context) error {
	var problems []string
	for _, result := range c.Status(ctx) {
		if result.Err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", result.Node, result.Err))
			continue
		}
		if result.Value.StateStoreHealthy != nil && !*result.Value.StateStoreHealthy {
			problems = append(problems, fmt.Sprintf("%s: durable state store is unavailable", result.Node))
		}
		for _, peer := range result.Value.PeerReplication {
			if !peer.Healthy {
				problems = append(problems, fmt.Sprintf("%s: durability peer %s is unhealthy (%s)",
					result.Node, peer.Peer, peer.Error))
			}
		}
	}
	if len(problems) == 0 {
		if err := c.RuntimeCompatibility(ctx); err != nil {
			return err
		}
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("cluster health check failed before placement: %s", strings.Join(problems, "; "))
}

// RuntimeCompatibility proves every responding agent is attached to the
// backend requested by the manifest. It deliberately runs before a mutation
// lease, image pull, overlay reservation, or placement record write: an agent
// pointed at Docker when the lab requests Podman is a different substrate, not
// a harmless status detail.
func (c *Cluster) RuntimeCompatibility(ctx context.Context) error {
	if len(c.RequestedRuntimes) == 0 {
		return nil
	}
	var problems []string
	for _, result := range c.Status(ctx) {
		want, configured := c.RequestedRuntimes[result.Node]
		if !configured {
			continue
		}
		switch {
		case result.Err != nil:
			problems = append(problems, fmt.Sprintf("%s could not report its selected runtime (%v)",
				result.Node, result.Err))
		case result.Value.Runtime == "":
			problems = append(problems, fmt.Sprintf("%s does not report a runtime backend", result.Node))
		case !strings.EqualFold(strings.TrimSpace(result.Value.Runtime), strings.TrimSpace(want)):
			problems = append(problems, fmt.Sprintf("%s runs %s but the manifest requests %s",
				result.Node, result.Value.Runtime, want))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("runtime selection does not match the lab before mutation: %s",
		strings.Join(problems, "; "))
}

// Inventories obtains a complete live reservation view from every node. A
// missing response is an admission error rather than an empty node: treating
// an unreachable host as zero or unlimited capacity would make either answer
// silently unsafe.
func (c *Cluster) Inventories(ctx context.Context) ([]place.NodeInventory, error) {
	results := c.Status(ctx)
	out := make([]place.NodeInventory, 0, len(results))
	var problems []string
	for _, result := range results {
		if result.Err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", result.Node, result.Err))
			continue
		}
		out = append(out, placementInventory(result.Node, result.Value.Inventory))
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("could not obtain live inventory from every node: %s", strings.Join(problems, "; "))
	}
	return out, nil
}

func placementInventory(name string, in agent.HostInventory) place.NodeInventory {
	out := place.NodeInventory{
		Name:          name,
		Allocatable:   placementCapacity(in.Allocatable),
		Reserved:      placementResources(in.Reserved),
		ReservedByLab: map[string]place.Resources{},
		Unknown:       append([]string(nil), in.Unknown...),
	}
	for lab, reservation := range in.Reservations {
		out.ReservedByLab[lab] = placementResources(reservation)
	}
	return out
}

func placementCapacity(in agent.ResourceInventory) place.Capacity {
	return place.Capacity{
		Containers:      in.Containers,
		CPUs:            in.CPUs,
		MemoryBytes:     in.MemoryBytes,
		DiskBytes:       in.DiskBytes,
		Pids:            in.Pids,
		FileDescriptors: in.FileDescriptors,
		NetDevices:      in.NetDevices,
	}
}

func placementResources(in agent.ResourceInventory) place.Resources {
	var out place.Resources
	if in.Containers != nil {
		out.Containers = *in.Containers
	}
	if in.CPUs != nil {
		out.CPUs = *in.CPUs
	}
	if in.MemoryBytes != nil {
		out.MemoryBytes, out.MemBytes = *in.MemoryBytes, *in.MemoryBytes
	}
	if in.DiskBytes != nil {
		out.DiskBytes = *in.DiskBytes
	}
	if in.Pids != nil {
		out.Pids = *in.Pids
	}
	if in.FileDescriptors != nil {
		out.FileDescriptors = *in.FileDescriptors
	}
	if in.NetDevices != nil {
		out.NetDevices = *in.NetDevices
	}
	return out
}

// Admit checks a fully placed topology against fresh host inventory. The
// deploy command also feeds the same inventory into Place; this second check
// closes the gap between placement and the fenced mutation transaction so a
// recorded or pinned assignment cannot bypass admission.
func (c *Cluster) Admit(ctx context.Context, top *model.Topology, strict, overcommit bool) error {
	if !strict {
		return nil
	}
	inventory, err := c.Inventories(ctx)
	if err != nil {
		if overcommit {
			slog.Warn("audited overcommit bypassed unavailable live inventory", "lab", top.Name, "err", err)
			return nil
		}
		return err
	}
	if err := place.AdmitPlaced(top, inventory, true, overcommit); err != nil {
		return err
	}
	if overcommit {
		slog.Warn("audited overcommit accepted a deployment despite capacity constraints", "lab", top.Name)
	}
	return nil
}

// Apply converges the whole cluster.
//
// Every node receives the *entire* topology, not just its own devices: an agent
// needs to know where the far end of a cross-node link lives in order to derive
// the same VXLAN identifier and address the right peer. It then acts only on
// what is placed on itself.
func (c *Cluster) Apply(ctx context.Context, top *model.Topology, req agent.ApplyRequest) []NodeResult[agent.ApplyResponse] {
	ctx = operationContext(ctx)
	if req.ControllerVersion == "" {
		req.ControllerVersion = c.RequireVersion
	}
	if err := c.RuntimeCompatibility(ctx); err != nil {
		out := make([]NodeResult[agent.ApplyResponse], 0, len(c.Nodes))
		for _, n := range c.Nodes {
			out = append(out, NodeResult[agent.ApplyResponse]{Node: n.Name, Err: err})
		}
		return out
	}
	if err := c.VersionSkew(ctx); err != nil {
		out := make([]NodeResult[agent.ApplyResponse], 0, len(c.Nodes))
		for _, n := range c.Nodes {
			out = append(out, NodeResult[agent.ApplyResponse]{Node: n.Name, Err: err})
		}
		return out
	}
	mode, err := agent.RequireTransactionMode(req.Mode)
	if err != nil {
		out := make([]NodeResult[agent.ApplyResponse], 0, len(c.Nodes))
		for _, n := range c.Nodes {
			out = append(out, NodeResult[agent.ApplyResponse]{Node: n.Name, Err: err})
		}
		return out
	}
	req.Mode = mode
	if req.StrictAdmission {
		if err := c.Admit(ctx, top, true, req.Overcommit); err != nil {
			out := make([]NodeResult[agent.ApplyResponse], 0, len(c.Nodes))
			for _, n := range c.Nodes {
				out = append(out, NodeResult[agent.ApplyResponse]{Node: n.Name, Err: err})
			}
			return out
		}
	}
	// Stamp the image identities before serialising, if the caller has not.
	//
	// The container spec hash includes the digest a device's image reference
	// resolves to, so that rebuilding a tag in place is noticed. Only the
	// deploy command used to resolve it. Every other caller -- and there are
	// three, grading's restore between submissions among them -- sent a
	// topology with the field empty, computed a different hash for containers
	// that had not changed at all, and so destroyed and recreated every
	// container in scope.
	//
	// Measured on a three-node lab: grading two submissions recreated 89 of
	// 212 containers, and the next ordinary deploy recreated 172 of them,
	// because the two callers disagreed permanently. Recreating a container
	// empties its network namespace, which is why submissions failed to load
	// with "Cannot find device port_BOS", and leaves it with the image's own
	// FRR daemons file, which is why routers were found with no bgpd and no
	// ospfd. Both were blamed on students.
	//
	// It is resolved here because this is the one door every deployment goes
	// through, which is the same reason the version check lives here.
	c.stampImageIDs(ctx, top)
	return c.coordinatedApply(ctx, top, req)
}

func verifyAppliedImageDigests(top *model.Topology, node string, response agent.ApplyResponse) error {
	if top == nil || top.Lab == nil || !top.Lab.Images.RequiresImmutableImages() {
		return nil
	}
	refs := map[string]bool{}
	for _, device := range top.DevicesOnNode(node) {
		if device.Image != "" {
			refs[device.Image] = true
		}
	}
	for ref := range refs {
		actual := response.ImageDigests[ref]
		if actual == "" {
			return fmt.Errorf("%s did not report a post-pull digest for %s", node, ref)
		}
		if !images.SameDigest(ref, actual) {
			return fmt.Errorf("%s pulled %s as %s, not locked digest %s", node, ref, actual, images.Digest(ref))
		}
	}
	return nil
}

// unfencedApply is only for a dry run or an empty local cluster. All
// mutating multi-node deployments go through coordinatedApply, which supplies
// a prepared generation and a node-specific fence.
func (c *Cluster) unfencedApply(ctx context.Context, top *model.Topology,
	req agent.ApplyRequest,
) []NodeResult[agent.ApplyResponse] {
	wire := agent.Serialise(top)
	wire.Mode, wire.Ungraded = req.Mode, req.Ungraded
	peers := map[string]string{}
	if top.Lab != nil {
		for _, n := range top.Lab.Placement.Nodes {
			if n.UnderlayIP != "" {
				peers[n.Name] = n.UnderlayIP
			}
		}
	}
	return fanOut(ctx, c.Nodes, func(ctx context.Context, n *Node) (agent.ApplyResponse, error) {
		r := applyRequestForNode(req, wire, peers, nil, n.Name, "", "", req.Generation)
		return n.Apply(ctx, r)
	})
}

// stampImageIDs fills in the digest each image reference resolves to, for any
// device whose identity the caller has not already established.
//
// Best effort by design: an image nobody has pulled yet has no digest, and a
// first deployment must still be possible. What matters is that every caller
// arrives at the same answer, not that the answer is always known.
func (c *Cluster) stampImageIDs(ctx context.Context, top *model.Topology) {
	refs := map[string]bool{}
	for _, d := range top.Devices {
		if d.Image != "" && d.ImageID == "" {
			refs[d.Image] = true
		}
	}
	if len(refs) == 0 {
		return
	}
	list := make([]string, 0, len(refs))
	for r := range refs {
		list = append(list, r)
	}
	sort.Strings(list)

	// Nodes are asked in a fixed order, and they must agree.
	//
	// Taking the first answer and moving on is how a lab ends up running two
	// different builds at once: one node is rebuilt, a push half-succeeds, a
	// pull is interrupted, and from then on a student's routers run whichever
	// image landed on whichever node their AS was placed on. That was measured
	// on this cluster -- all four images differed between node-0 and the other
	// two -- while every report said the deployment was current. A mark that
	// depends on where a container was scheduled is not a mark.
	//
	// A node that has not pulled an image yet is not a disagreement: it has no
	// opinion, and the deployment is about to give it one.
	answers := map[string]map[string]string{}
	if len(c.Nodes) == 0 {
		// A lab that runs on this machine alone. Asking the local daemon is
		// the same question; leaving the field empty here would recreate every
		// container of a single-node lab on the next deploy, which is the bug
		// this exists to stop, just on one machine instead of a cluster.
		local := map[string]string{}
		if d, err := localTopologyRuntime(top); err == nil {
			for _, ref := range list {
				if id, err := d.ImageDigest(ctx, ref); err == nil {
					local[ref] = id
				}
			}
		}
		answers["local"] = local
	}

	for _, n := range c.Nodes {
		got, err := n.ImageDigests(ctx, list)
		if err != nil {
			continue
		}
		answers[n.Name] = got
	}

	seen, disagree := agreedDigests(answers)
	for ref, who := range disagree {
		slog.Warn("nodes do not agree on what an image is, so its identity is not being "+
			"used; deploy will refuse until they match",
			"image", ref, "disagreement", strings.Join(who, ", "))
	}
	for _, d := range top.Devices {
		if d.ImageID == "" {
			d.ImageID = seen[d.Image]
		}
	}
}

func localTopologyRuntime(top *model.Topology) (rt.Runtime, error) {
	name, socket := model.DefaultRuntime, ""
	if top != nil && top.Lab != nil {
		node := top.Lab.FrontNode()
		for _, device := range top.Devices {
			if device != nil && device.Node != "" {
				node = device.Node
				break
			}
		}
		name = top.Lab.RuntimeForNode(node)
		socket = top.Lab.RuntimeSocketForNode(node)
	}
	if err := rt.ValidateSelection(name, socket); err != nil {
		return nil, err
	}
	selected, err := rt.NewRuntime(name)
	if err != nil {
		return nil, err
	}
	if err := rt.ConfigureEndpoint(selected, socket); err != nil {
		return nil, err
	}
	return selected, nil
}

// agreedDigests reduces each node's answer to the identity they all give, and
// reports the images they do not agree on.
//
// Where the nodes disagree, no identity is returned for that image. Picking one
// node's answer is how half a class ends up marked on a different build from
// the other half, with every report saying the deployment is current; leaving
// it out instead makes the spec hash omit it, so the containers are left alone.
// The deploy command checks the same thing and refuses outright, which is the
// better answer when there is a person present to hear it.
//
// A node that has not pulled an image yet is not a disagreement: it has no
// opinion, and the deployment is about to give it one.
func agreedDigests(answers map[string]map[string]string) (map[string]string, map[string][]string) {
	byRef := map[string]map[string]string{} // image -> node -> digest
	for node, got := range answers {
		for ref, id := range got {
			if id == "" {
				continue
			}
			if byRef[ref] == nil {
				byRef[ref] = map[string]string{}
			}
			byRef[ref][node] = id
		}
	}

	seen := map[string]string{}
	disagree := map[string][]string{}
	for ref, byNode := range byRef {
		nodes := make([]string, 0, len(byNode))
		for n := range byNode {
			nodes = append(nodes, n)
		}
		sort.Strings(nodes)

		first := byNode[nodes[0]]
		agreed := true
		var who []string
		for _, n := range nodes {
			who = append(who, fmt.Sprintf("%s has %s", n, short(byNode[n])))
			if byNode[n] != first {
				agreed = false
			}
		}
		if agreed {
			seen[ref] = first
			continue
		}
		disagree[ref] = who
	}
	return seen, disagree
}

// short abbreviates a digest for a message a person has to read.
func short(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// Destroy removes the lab from every node.
func (c *Cluster) Destroy(ctx context.Context, lab string, vnis []uint32) []NodeResult[struct{}] {
	return c.coordinatedDestroy(ctx, lab, vnis, false)
}

// DestroyEphemeral removes a disposable lab from every node and discards its
// saved state, so a lab of the same name later starts from the manifest.
func (c *Cluster) DestroyEphemeral(ctx context.Context, lab string, vnis []uint32) []NodeResult[struct{}] {
	return c.coordinatedDestroy(ctx, lab, vnis, true)
}

// Hold asks every node to leave a lab alone. Failures are returned per node so
// a caller can decide whether to go ahead without one.
func (c *Cluster) Hold(ctx context.Context, lab, holder, token string, seconds int) []NodeResult[struct{}] {
	return fanOut(ctx, c.Nodes, func(ctx context.Context, n *Node) (struct{}, error) {
		return struct{}{}, n.Hold(ctx, lab, holder, token, seconds)
	})
}

// Containers lists managed containers across the cluster.
func (c *Cluster) Containers(ctx context.Context, lab string) ([]rt.Container, []error) {
	res := fanOut(ctx, c.Nodes, func(ctx context.Context, n *Node) ([]rt.Container, error) {
		return n.Containers(ctx, lab)
	})
	var all []rt.Container
	var errs []error
	for _, r := range res {
		if r.Err != nil {
			errs = append(errs, r.Err)
			continue
		}
		all = append(all, r.Value...)
	}
	rt.SortContainers(all)
	return all, errs
}

// CheckUnderlay verifies that every pair of nodes can carry the lab's MTU once
// VXLAN encapsulation is added.
//
// Doing this before deploying turns an invisible failure mode, where large
// packets vanish inside a student's AS for no discoverable reason, into a
// refusal with a specific instruction.
func (c *Cluster) CheckUnderlay(ctx context.Context, top *model.Topology) []string {
	const vxlanOverhead = 50
	want := 1500
	if top.Lab.LinkDefaults.MTU != nil {
		want = *top.Lab.LinkDefaults.MTU
	}
	need := want + vxlanOverhead

	var problems []string
	for _, from := range top.Lab.Placement.Nodes {
		n, ok := c.Node(from.Name)
		if !ok {
			continue
		}
		for _, to := range top.Lab.Placement.Nodes {
			if to.Name == from.Name || to.UnderlayIP == "" {
				continue
			}
			r, err := n.Underlay(ctx, to.UnderlayIP)
			if err != nil {
				problems = append(problems,
					fmt.Sprintf("%s cannot probe the path to %s (%s): %v",
						from.Name, to.Name, to.UnderlayIP, err))
				continue
			}
			if r.MTU > 0 && r.MTU < need {
				problems = append(problems, fmt.Sprintf(
					"%s reaches %s over %s with MTU %d, but carrying a %d byte lab link needs %d. "+
						"Either raise the underlay MTU or set link_defaults.mtu to %d",
					from.Name, to.Name, r.Dev, r.MTU, want, need, r.MTU-vxlanOverhead))
			}
		}
	}
	return problems
}

// ExportState fetches a node's preserved snapshots for the named devices.
func (n *Node) ExportState(ctx context.Context, lab string, devices []string) (agent.StateExportResponse, error) {
	return n.exportState(ctx, lab, devices, true)
}

// ExportStoredState reads verified stored replicas without asking the remote
// node to capture a running container. It is used only after a source is
// unavailable; normal migration always calls ExportState and requires a fresh
// capture boundary.
func (n *Node) ExportStoredState(ctx context.Context, lab string, devices []string) (agent.StateExportResponse, error) {
	return n.exportState(ctx, lab, devices, false)
}

func (n *Node) exportState(ctx context.Context, lab string, devices []string, fresh bool) (agent.StateExportResponse, error) {
	q := url.Values{}
	q.Set("lab", lab)
	if !fresh {
		q.Set("fresh", "false")
	}
	for _, d := range devices {
		q.Add("device", d)
	}
	var resp agent.StateExportResponse
	err := n.do(ctx, http.MethodGet, "/v1/state?"+q.Encode(), nil, &resp)
	return resp, err
}

// ImportState installs snapshots taken on another node.
func (n *Node) ImportState(ctx context.Context, req agent.StateImportRequest) (int, error) {
	resp, err := n.ImportStateDetailed(ctx, req)
	return resp.Stored, err
}

// ImportStateDetailed returns the receiver's digest acknowledgements as well
// as its count. Durable migration must check those acknowledgements before it
// can regard replication or destination import as complete.
func (n *Node) ImportStateDetailed(ctx context.Context, req agent.StateImportRequest) (agent.StateImportResponse, error) {
	var resp agent.StateImportResponse
	err := n.do(ctx, http.MethodPost, "/v1/state", req, &resp)
	return resp, err
}

// VerifyStateRestore proves the destination restored every fresh source
// snapshot persisted in its prepared transaction before source placement may
// be pruned.
func (n *Node) VerifyStateRestore(ctx context.Context, req agent.StateVerifyRequest) (agent.StateVerifyResponse, error) {
	var resp agent.StateVerifyResponse
	err := n.do(ctx, http.MethodPost, "/v1/state/verify", req, &resp)
	return resp, err
}

// MigrateState is retained for source compatibility but intentionally refuses
// to move data by itself. A standalone transfer cannot prove destination
// restore before source pruning; callers must use ApplyDurable, which keeps
// capture, quorum, restore verification, and pruning under one fence.
func (c *Cluster) MigrateState(ctx context.Context, top *model.Topology) (moved int, problems []string) {
	_ = ctx
	if top == nil {
		return 0, []string{"refusing standalone state migration without a topology"}
	}
	return 0, []string{"refusing standalone state migration; use ApplyDurable so source state is verified after destination restore before any prune"}
}

// node returns the client for a named node, or nil.
func (c *Cluster) node(name string) *Node {
	for _, n := range c.Nodes {
		if n.Name == name {
			return n
		}
	}
	return nil
}

// Sweep asks a node about the overlays it is carrying for no lab it hosts, and
// optionally removes them.
func (n *Node) Sweep(ctx context.Context, remove bool) (agent.SweepResponse, error) {
	var resp agent.SweepResponse
	err := n.do(ctx, http.MethodPost, "/v1/sweep", agent.SweepRequest{Remove: remove}, &resp)
	return resp, err
}

// Sweep asks every node.
func (c *Cluster) Sweep(ctx context.Context, remove bool) []NodeResult[agent.SweepResponse] {
	return fanOut(ctx, c.Nodes, func(ctx context.Context, n *Node) (agent.SweepResponse, error) {
		return n.Sweep(ctx, remove)
	})
}
