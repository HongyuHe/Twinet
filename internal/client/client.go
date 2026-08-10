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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// Node is a handle on one agent.
type Node struct {
	Name  string
	Addr  string
	Token string

	http *http.Client
}

// NewNode constructs a node client.
func NewNode(name, addr, token string) *Node {
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	return &Node{
		Name: name, Addr: strings.TrimRight(addr, "/"), Token: token,
		http: &http.Client{
			Timeout: 30 * time.Minute, // a large apply legitimately takes a while
			Transport: &http.Transport{
				DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				MaxIdleConnsPerHost: 8,
			},
		},
	}
}

func (n *Node) do(ctx context.Context, method, path string, body, out any) error {
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
	defer resp.Body.Close()

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
	return n.do(ctx, http.MethodPost, "/v1/destroy",
		agent.DestroyRequest{Lab: lab, VNIs: vnis}, nil)
}

// Exec runs a command in a container on the node.
func (n *Node) Exec(ctx context.Context, req agent.ExecRequest) (agent.ExecResponse, error) {
	var resp agent.ExecResponse
	err := n.do(ctx, http.MethodPost, "/v1/exec", req, &resp)
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
}

// NewCluster builds a cluster client from a lab's placement configuration.
func NewCluster(lab *model.Lab, token string) *Cluster {
	c := &Cluster{}
	for _, n := range lab.Placement.Nodes {
		addr := n.Addr
		if addr == "" {
			addr = n.Name + ":7200"
		}
		c.Nodes = append(c.Nodes, NewNode(n.Name, addr, token))
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

// Destroy removes the lab from every node.
func (c *Cluster) Destroy(ctx context.Context, lab string, vnis []uint32) []NodeResult[struct{}] {
	return fanOut(ctx, c.Nodes, func(ctx context.Context, n *Node) (struct{}, error) {
		return struct{}{}, n.Destroy(ctx, lab, vnis)
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
