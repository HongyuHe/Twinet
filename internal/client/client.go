// Package client talks to Twinet node agents.
//
// The control plane is stateless and fans out: it computes the whole topology,
// slices it by node, and asks every agent to converge its slice concurrently.
// Nothing is stored between invocations, so a control plane that crashes
// mid-deployment leaves nothing to repair; re-running converges.
package client

import (
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
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

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
	cfgErr error
}

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
		tls: streamCfg, cfgErr: cfgErr,
		http: &http.Client{
			Timeout:   30 * time.Minute, // a large apply legitimately takes a while
			Transport: tr,
		},
	}
}

func (n *Node) do(ctx context.Context, method, path string, body, out any) error {
	if n.cfgErr != nil {
		return fmt.Errorf("node %s: %w", n.Name, n.cfgErr)
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

// Apply asks the node to converge its slice of the topology.
func (n *Node) Apply(ctx context.Context, req agent.ApplyRequest) (agent.ApplyResponse, error) {
	var resp agent.ApplyResponse
	err := n.do(ctx, http.MethodPost, "/v1/apply", req, &resp)
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
	if err := n.do(ctx, http.MethodPost, "/v1/destroy", req, &resp); err != nil {
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
	var resp struct{}
	return n.do(ctx, http.MethodPost, "/v1/exempt",
		agent.ExemptRequest{Lab: lab, Device: device, ID: id, On: on}, &resp)
}

// Exec runs a command in a container on the node.
func (n *Node) Exec(ctx context.Context, req agent.ExecRequest) (agent.ExecResponse, error) {
	var resp agent.ExecResponse
	err := n.do(ctx, http.MethodPost, "/v1/exec", req, &resp)
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

	// RequireVersion is the build every node must be running.
	//
	// It is checked inside Apply rather than by the callers, because it was
	// checked by one caller and there turned out to be three. Grading called
	// Apply directly and so ran happily against a cluster of mixed binaries --
	// which is the one place it matters most, since the output is somebody's
	// mark and cannot be attributed to any particular version of the software
	// that produced it.
	//
	// Empty means unchecked, which is what tests and single-node use want.
	RequireVersion string
}

// VersionSkew reports the nodes not running the expected build.
func (c *Cluster) VersionSkew(ctx context.Context) error {
	if c.RequireVersion == "" {
		return nil
	}
	// A node that cannot be asked, and a node that answers without naming a
	// build, both used to pass. Both are exactly the node this check exists to
	// catch: an agent too old to report its version is by definition not the
	// version this controller is, and a node that is unreachable now is a node
	// whose configuration nobody has checked. Failing open here means the
	// check reports agreement it never established.
	var odd []string
	for _, r := range c.Status(ctx) {
		switch {
		case r.Err != nil:
			odd = append(odd, fmt.Sprintf("%s could not be asked which build it runs (%v)",
				r.Node, r.Err))
		case r.Value.Version == "":
			odd = append(odd, fmt.Sprintf("%s does not report a build, so it is older "+
				"than the agent that started reporting one", r.Node))
		case r.Value.Version != c.RequireVersion:
			odd = append(odd, fmt.Sprintf("%s runs %s", r.Node, r.Value.Version))
		}
	}
	if len(odd) == 0 {
		return nil
	}
	sort.Strings(odd)
	return fmt.Errorf("this controller is %s but %s.\n"+
		"The node agent renders the device configuration, so a node running a "+
		"different build produces different configuration from the same manifest, "+
		"and nothing downstream reports it.\n"+
		"Run scripts/deploy_agents.sh, or set TWINET_ALLOW_VERSION_SKEW=1 if you "+
		"are certain the difference does not matter",
		c.RequireVersion, strings.Join(odd, ", "))
}

// ExpectVersion is the build every agent is expected to be running.
//
// It is a package variable set once at start-up rather than a parameter,
// because every cluster must carry it and there are eight places that build
// one. A parameter is a thing the ninth caller forgets, and forgetting it
// yields a cluster that silently accepts mixed builds -- which is how grading
// came to run without the check while deployment had it.
var ExpectVersion string

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
	c := &Cluster{RequireVersion: ExpectVersion}
	for _, n := range lab.Placement.Nodes {
		addr := n.Addr
		if addr == "" {
			addr = n.Name + ":7200"
		}
		c.Nodes = append(c.Nodes, NewNodeTLS(n.Name, addr, token, t))
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

// Apply converges the whole cluster.
//
// Every node receives the *entire* topology, not just its own devices: an agent
// needs to know where the far end of a cross-node link lives in order to derive
// the same VXLAN identifier and address the right peer. It then acts only on
// what is placed on itself.
func (c *Cluster) Apply(ctx context.Context, top *model.Topology, req agent.ApplyRequest) []NodeResult[agent.ApplyResponse] {
	if err := c.VersionSkew(ctx); err != nil && os.Getenv("TWINET_ALLOW_VERSION_SKEW") == "" {
		out := make([]NodeResult[agent.ApplyResponse], 0, len(c.Nodes))
		for _, n := range c.Nodes {
			out = append(out, NodeResult[agent.ApplyResponse]{Node: n.Name, Err: err})
		}
		return out
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

	wire := agent.Serialise(top)
	peers := map[string]string{}
	for _, n := range top.Lab.Placement.Nodes {
		if n.UnderlayIP != "" {
			peers[n.Name] = n.UnderlayIP
		}
	}
	return fanOut(ctx, c.Nodes, func(ctx context.Context, n *Node) (agent.ApplyResponse, error) {
		r := req
		r.Topology = wire
		r.PeerUnderlay = peers
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
		d := rt.NewDocker()
		for _, ref := range list {
			if id, err := d.ImageDigest(ctx, ref); err == nil {
				local[ref] = id
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
	return fanOut(ctx, c.Nodes, func(ctx context.Context, n *Node) (struct{}, error) {
		return struct{}{}, n.Destroy(ctx, lab, vnis)
	})
}

// DestroyEphemeral removes a disposable lab from every node and discards its
// saved state, so a lab of the same name later starts from the manifest.
func (c *Cluster) DestroyEphemeral(ctx context.Context, lab string, vnis []uint32) []NodeResult[struct{}] {
	return fanOut(ctx, c.Nodes, func(ctx context.Context, n *Node) (struct{}, error) {
		return struct{}{}, n.DestroyEphemeral(ctx, lab, vnis)
	})
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
	q := url.Values{}
	q.Set("lab", lab)
	for _, d := range devices {
		q.Add("device", d)
	}
	var resp agent.StateExportResponse
	err := n.do(ctx, http.MethodGet, "/v1/state?"+q.Encode(), nil, &resp)
	return resp, err
}

// ImportState installs snapshots taken on another node.
func (n *Node) ImportState(ctx context.Context, req agent.StateImportRequest) (int, error) {
	var resp agent.StateImportResponse
	err := n.do(ctx, http.MethodPost, "/v1/state", req, &resp)
	return resp.Stored, err
}

// MigrateState carries preserved work to the nodes that will run each device.
//
// Placement is not fixed. Adding a machine, or a manifest that grows,
// re-partitions the lab and moves autonomous systems between nodes. The node
// losing a device captures its configuration before removing it, which is
// right; the node gaining it then builds from the manifest, because the
// snapshot is in a directory on a machine it never asks. Both report success,
// and a class's work is stranded on a node that no longer runs it -- which is
// indistinguishable from lost to anyone who does not know to go looking.
//
// This runs before apply, so the work is already on the destination when the
// device is built and the ordinary restore path picks it up.
//
// It is deliberately not fatal. A node that cannot be reached for an export
// leaves that device's work where it is rather than stopping the deployment:
// the snapshot is still safe on the source node, and refusing to deploy would
// turn a recoverable situation into an outage for every other student in the
// lab. What it must not do is proceed quietly, so every device it could not
// carry is named in the returned report.
func (c *Cluster) MigrateState(ctx context.Context, top *model.Topology) (moved int, problems []string) {
	// Where each device is *now*, asked of the cluster rather than read from
	// the placement record.
	//
	// The record says where the last deploy intended to put things, which is
	// the same as where they are in the ordinary case and therefore detects
	// nothing. A device moves precisely when those two disagree -- after
	// --rebalance, after a record was lost and re-adopted, after a node was
	// added. Asking the containers is the only source that is right in all of
	// those, and it is the same authority adoptRunningPlacement uses for the
	// same reason.
	cs, errs := c.Containers(ctx, top.Name)
	if len(errs) > 0 {
		// A node that cannot be asked may be the one holding the work. Moving
		// what the reachable nodes have while believing the rest is absent
		// would be worse than not moving anything.
		return 0, []string{fmt.Sprintf(
			"could not read the running placement from every node (%v), so preserved "+
				"work was not moved; a device that changes node in this deploy will be "+
				"rebuilt from the manifest", errs[0])}
	}
	previous := map[string]string{}
	for _, ct := range cs {
		if id := ct.Label(deploy.LabelDeviceID); id != "" {
			if node := ct.Label(deploy.LabelNode); node != "" {
				previous[id] = node
			}
		}
	}

	// device -> node it is moving from
	from := map[string][]string{}
	for _, d := range top.SortedDevices() {
		was, ok := previous[d.ID]
		if !ok || was == "" || was == d.Node {
			continue
		}
		from[was] = append(from[was], d.ID)
	}
	if len(from) == 0 {
		return 0, nil
	}

	for src, devices := range from {
		srcNode := c.node(src)
		if srcNode == nil {
			problems = append(problems, fmt.Sprintf(
				"%d device(s) moved off %s, which is not in this cluster; their saved work "+
					"is still on that machine", len(devices), src))
			continue
		}
		exp, err := srcNode.ExportState(ctx, top.Name, devices)
		if err != nil {
			problems = append(problems, fmt.Sprintf(
				"could not collect saved work from %s (%v); %d device(s) will be rebuilt "+
					"from the manifest and their configuration is still on %s",
				src, err, len(devices), src))
			continue
		}
		// A device the source had nothing for is reported, not ignored. Most
		// of the time it means what it says -- an untouched device, a staff
		// machine, a lab that was only just deployed -- but it is also exactly
		// what a failed capture looks like from here, and the two are worth
		// distinguishing before a container is rebuilt from the manifest.
		if len(exp.Missing) > 0 {
			sort.Strings(exp.Missing)
			problems = append(problems, fmt.Sprintf(
				"%s had no saved work for %s; if those devices were configured, that "+
					"configuration is not being carried and will be lost when they are "+
					"rebuilt from the manifest",
				src, strings.Join(exp.Missing, ", ")))
		}

		// Group by destination, because devices leaving one node need not all
		// arrive at the same one.
		byDest := map[string][]agent.WireSnapshot{}
		for _, s := range exp.Snapshots {
			d, ok := top.Device(s.Device)
			if !ok {
				problems = append(problems, fmt.Sprintf(
					"%s sent saved work for %s, which is not in this lab; it is being "+
						"dropped rather than placed somewhere it does not belong",
					src, s.Device))
				continue
			}
			byDest[d.Node] = append(byDest[d.Node], s)
		}
		for dest, snaps := range byDest {
			destNode := c.node(dest)
			if destNode == nil {
				problems = append(problems, fmt.Sprintf(
					"%s is not in this cluster, so work for %d device(s) cannot be placed there",
					dest, len(snaps)))
				continue
			}
			n, err := destNode.ImportState(ctx, agent.StateImportRequest{
				Lab: top.Name, Snapshots: snaps})
			if err != nil {
				problems = append(problems, fmt.Sprintf(
					"could not place saved work on %s (%v); those devices will be rebuilt "+
						"from the manifest", dest, err))
				continue
			}
			moved += n
		}
	}
	sort.Strings(problems)
	return moved, problems
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
