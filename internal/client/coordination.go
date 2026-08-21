package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/model"
)

const (
	mutationLeaseSeconds = 90
	mutationRenewEvery   = 25 * time.Second
)

// MutationLease is a cluster-wide collection of node-local fences. It is
// acquired in node-name order and released in reverse order, so two controllers
// racing for overlapping clusters cannot deadlock by each holding a different
// prefix of nodes.
type MutationLease struct {
	cluster *Cluster
	lab     string
	fences  map[string]agent.Fence

	ctx    context.Context
	cancel context.CancelFunc
	stop   chan struct{}
	done   chan struct{}

	mu       sync.RWMutex
	renewErr error
	once     sync.Once
}

// Context is cancelled when a lease renewal fails. A long operation must use
// it, because success after losing the fence would be a false commit claim.
func (l *MutationLease) Context() context.Context { return l.ctx }

// Fence returns the node-specific opaque fencing identity.
func (l *MutationLease) Fence(node string) (agent.Fence, bool) {
	fence, ok := l.fences[node]
	return fence, ok
}

// Err reports a renewal failure, if any.
func (l *MutationLease) Err() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.renewErr
}

func (l *MutationLease) lose(err error) {
	l.mu.Lock()
	if l.renewErr == nil {
		l.renewErr = err
		l.cancel()
	}
	l.mu.Unlock()
}

// Release drops every acquired node lease in reverse name order.
func (l *MutationLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		close(l.stop)
		<-l.done
		l.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		nodes := l.cluster.sortedNodes()
		for i := len(nodes) - 1; i >= 0; i-- {
			node := nodes[i]
			fence, ok := l.fences[node.Name]
			if !ok {
				continue
			}
			if err := node.ReleaseMutationLease(ctx, l.lab, fence); err != nil {
				// The TTL is the safe fallback. Do not replace a real operation
				// failure with cleanup noise, but retain it for callers that
				// ask whether the lease was fully released.
				l.mu.Lock()
				if l.renewErr == nil {
					l.renewErr = fmt.Errorf("release mutation lease on %s: %w", node.Name, err)
				}
				l.mu.Unlock()
			}
		}
	})
}

func (c *Cluster) sortedNodes() []*Node {
	nodes := append([]*Node(nil), c.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	return nodes
}

func newMutationHolder() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return "controller-" + hex.EncodeToString(raw[:])
	}
	return fmt.Sprintf("controller-%d", time.Now().UnixNano())
}

// AcquireMutationLease obtains every node fence in one deterministic order.
// Any failed acquisition releases the already acquired prefix before returning.
func (c *Cluster) AcquireMutationLease(ctx context.Context, lab string) (*MutationLease, error) {
	if lab == "" {
		return nil, errors.New("a mutation lease needs a lab name")
	}
	nodes := c.sortedNodes()
	if len(nodes) == 0 {
		return nil, nil
	}
	holder := newMutationHolder()
	fences := make(map[string]agent.Fence, len(nodes))
	for _, node := range nodes {
		resp, err := node.AcquireMutationLease(ctx, agent.LeaseAcquireRequest{
			Lab: lab, Holder: holder, TTLSeconds: mutationLeaseSeconds,
		})
		if err != nil {
			rollback, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			for i := len(nodes) - 1; i >= 0; i-- {
				acquired := nodes[i]
				fence, ok := fences[acquired.Name]
				if !ok {
					continue
				}
				_ = acquired.ReleaseMutationLease(rollback, lab, fence)
			}
			cancel()
			return nil, fmt.Errorf("acquire mutation lease for lab %q on %s: %w", lab, node.Name, err)
		}
		fences[node.Name] = resp.Fence
	}

	opctx, opcancel := context.WithCancel(ctx)
	lease := &MutationLease{
		cluster: c, lab: lab, fences: fences, ctx: opctx, cancel: opcancel,
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go lease.renew()
	return lease, nil
}

func (l *MutationLease) renew() {
	defer close(l.done)
	ticker := time.NewTicker(mutationRenewEvery)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			var renewErr error
			for _, node := range l.cluster.sortedNodes() {
				fence, ok := l.fences[node.Name]
				if !ok {
					continue
				}
				if _, err := node.RenewMutationLease(ctx, l.lab, fence, mutationLeaseSeconds); err != nil {
					renewErr = fmt.Errorf("renew mutation lease on %s: %w", node.Name, err)
					break
				}
			}
			cancel()
			if renewErr != nil {
				l.lose(renewErr)
				return
			}
		}
	}
}

func (c *Cluster) withMutationLease(ctx context.Context, lab string,
	fn func(*MutationLease) error,
) error {
	ctx = operationContext(ctx)
	lease, err := c.AcquireMutationLease(ctx, lab)
	if err != nil {
		return err
	}
	if lease == nil {
		return fn(nil)
	}
	defer lease.Release()
	err = fn(lease)
	if renewErr := lease.Err(); renewErr != nil && err == nil {
		err = renewErr
	}
	return err
}

// AcquireMutationLease asks one agent for a fenced lease.
func (n *Node) AcquireMutationLease(ctx context.Context,
	req agent.LeaseAcquireRequest,
) (agent.LeaseResponse, error) {
	var resp agent.LeaseResponse
	err := n.do(ctx, "POST", "/v1/lease/acquire", req, &resp)
	return resp, err
}

// RenewMutationLease extends one agent lease and any reservations tied to it.
func (n *Node) RenewMutationLease(ctx context.Context, lab string, fence agent.Fence,
	seconds int,
) (agent.LeaseResponse, error) {
	var resp agent.LeaseResponse
	err := n.do(ctx, "POST", "/v1/lease/renew", agent.LeaseRenewRequest{
		Lab: lab, Fence: fence, TTLSeconds: seconds,
	}, &resp)
	return resp, err
}

// ReleaseMutationLease drops one agent lease.
func (n *Node) ReleaseMutationLease(ctx context.Context, lab string, fence agent.Fence) error {
	return n.do(ctx, "POST", "/v1/lease/release", agent.LeaseReleaseRequest{
		Lab: lab, Fence: fence,
	}, nil)
}

// ReserveOverlays atomically reserves every supplied VNI on one node.
func (n *Node) ReserveOverlays(ctx context.Context,
	req agent.OverlayReservationRequest,
) (agent.OverlayReservationResponse, error) {
	var resp agent.OverlayReservationResponse
	err := n.do(ctx, "POST", "/v1/overlay/reserve", req, &resp)
	return resp, err
}

func overlayReservations(top *model.Topology) map[string][]uint32 {
	byNode := map[string]map[uint32]bool{}
	for _, link := range top.Links {
		if link.VNI == 0 || link.A == nil || link.B == nil ||
			link.A.Device == nil || link.B.Device == nil ||
			link.A.Device.Node == link.B.Device.Node {
			continue
		}
		for _, node := range []string{link.A.Device.Node, link.B.Device.Node} {
			if byNode[node] == nil {
				byNode[node] = map[uint32]bool{}
			}
			byNode[node][link.VNI] = true
		}
	}
	out := make(map[string][]uint32, len(byNode))
	for node, set := range byNode {
		for vni := range set {
			out[node] = append(out[node], vni)
		}
		sort.Slice(out[node], func(i, j int) bool { return out[node][i] < out[node][j] })
	}
	return out
}

func (c *Cluster) reserveOverlays(ctx context.Context, lease *MutationLease,
	top *model.Topology, hold string,
) error {
	if lease == nil {
		return nil
	}
	byNode := overlayReservations(top)
	for _, node := range c.sortedNodes() {
		vnis := byNode[node.Name]
		if len(vnis) == 0 {
			continue
		}
		fence, ok := lease.Fence(node.Name)
		if !ok {
			return fmt.Errorf("no mutation fence for node %s", node.Name)
		}
		if _, err := node.ReserveOverlays(ctx, agent.OverlayReservationRequest{
			Lab: top.Name, Hold: hold, Fence: fence, VNIs: vnis,
		}); err != nil {
			return fmt.Errorf("reserve overlays on %s: %w", node.Name, err)
		}
	}
	return nil
}

func (c *Cluster) clusterGeneration(ctx context.Context, lab string) (string, error) {
	results := c.Status(ctx)
	var (
		have bool
		want string
		errs []string
	)
	for _, result := range results {
		if result.Err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", result.Node, result.Err))
			continue
		}
		got := result.Value.Generations[lab]
		if !have {
			want, have = got, true
			continue
		}
		if got != want {
			errs = append(errs, fmt.Sprintf("%s records generation %q, not %q",
				result.Node, got, want))
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return "", fmt.Errorf("cluster generation for lab %q is not a single compare-and-swap value: %s",
			lab, strings.Join(errs, "; "))
	}
	return want, nil
}

func generatedGeneration(top *model.Topology, req agent.ApplyRequest, current string) string {
	if len(req.OnlySteps) > 0 && current != "" {
		return current
	}
	if req.Generation != "" {
		return req.Generation
	}
	if top.Hash != "" {
		return top.Hash
	}
	raw, _ := json.Marshal(agent.Serialise(top))
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func applyRequestForNode(req agent.ApplyRequest, wire *agent.Wire, peers map[string]string,
	lease *MutationLease, node string, phase, expected, generation string,
) agent.ApplyRequest {
	out := req
	out.Topology = wire
	out.PeerUnderlay = peers
	out.Lab = wire.Lab
	out.Phase = phase
	out.ExpectedGeneration = expected
	out.Generation = generation
	if lease != nil {
		out.Fence, _ = lease.Fence(node)
	}
	return out
}

func (c *Cluster) abortApply(ctx context.Context, lease *MutationLease, wire *agent.Wire,
	peers map[string]string, generation string, req agent.ApplyRequest,
) []error {
	if lease == nil {
		return nil
	}
	var errs []error
	nodes := c.sortedNodes()
	for i := len(nodes) - 1; i >= 0; i-- {
		node := nodes[i]
		abort := applyRequestForNode(req, wire, peers, lease, node.Name, "abort", "", generation)
		abort.Topology = nil
		if _, err := node.Apply(ctx, abort); err != nil {
			errs = append(errs, fmt.Errorf("%s rollback: %w", node.Name, err))
		}
	}
	return errs
}

func transactionFailure(nodes []*Node, values map[string]agent.ApplyResponse, cause error,
) []NodeResult[agent.ApplyResponse] {
	out := make([]NodeResult[agent.ApplyResponse], 0, len(nodes))
	for _, node := range nodes {
		out = append(out, NodeResult[agent.ApplyResponse]{
			Node: node.Name, Value: values[node.Name],
			Err: fmt.Errorf("cluster mutation did not commit: %w", cause),
		})
	}
	return out
}

func responseFailure(resp agent.ApplyResponse) error {
	if len(resp.Failures) == 0 {
		return nil
	}
	var parts []string
	for scope, messages := range resp.Failures {
		for _, message := range messages {
			parts = append(parts, scope+": "+message)
		}
	}
	sort.Strings(parts)
	return errors.New(strings.Join(parts, "; "))
}

func (c *Cluster) coordinatedApply(ctx context.Context, top *model.Topology,
	req agent.ApplyRequest,
) []NodeResult[agent.ApplyResponse] {
	nodes := c.sortedNodes()
	if req.DryRun || len(nodes) == 0 {
		return c.unfencedApply(ctx, top, req)
	}
	lease, err := c.AcquireMutationLease(ctx, top.Name)
	if err != nil {
		return transactionFailure(nodes, nil, err)
	}
	defer lease.Release()
	return c.coordinatedApplyWithLease(lease.Context(), top, req, lease, nil)
}

// coordinatedApplyWithLease runs a prepared apply under a caller-owned fence.
// Durable migration uses this form so fresh capture, replication, restore
// verification, and source pruning are one fenced mutation rather than three
// independently successful-looking operations.
func (c *Cluster) coordinatedApplyWithLease(ctx context.Context, top *model.Topology,
	req agent.ApplyRequest, lease *MutationLease, proofs map[string][]agent.StateProof,
) []NodeResult[agent.ApplyResponse] {
	nodes := c.sortedNodes()
	if lease == nil {
		return transactionFailure(nodes, nil, errors.New("a coordinated apply needs a mutation lease"))
	}
	expected, err := c.clusterGeneration(lease.Context(), top.Name)
	if err != nil {
		return transactionFailure(nodes, nil, err)
	}
	generation := generatedGeneration(top, req, expected)
	if generation == "" {
		return transactionFailure(nodes, nil, errors.New("could not derive a deployment generation"))
	}
	wire := agent.Serialise(top)
	peers := map[string]string{}
	if top.Lab != nil {
		for _, node := range top.Lab.Placement.Nodes {
			if node.UnderlayIP != "" {
				peers[node.Name] = node.UnderlayIP
			}
		}
	}
	if err := c.reserveOverlays(lease.Context(), lease, top, req.Hold); err != nil {
		return transactionFailure(nodes, nil, err)
	}

	for _, node := range nodes {
		prepare := applyRequestForNode(req, wire, peers, lease, node.Name,
			"prepare", expected, generation)
		if proofs != nil {
			prepare.StateProofs = append([]agent.StateProof(nil), proofs[node.Name]...)
		}
		if _, err := node.Apply(lease.Context(), prepare); err != nil {
			rollbackErrs := c.abortApply(context.WithoutCancel(ctx), lease, wire, peers, generation, req)
			if len(rollbackErrs) > 0 {
				err = fmt.Errorf("%w; rollback: %v", err, rollbackErrs[0])
			}
			return transactionFailure(nodes, nil, fmt.Errorf("prepare %s: %w", node.Name, err))
		}
	}

	values := map[string]agent.ApplyResponse{}
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		applyErr error
	)
	for _, node := range nodes {
		wg.Add(1)
		go func(node *Node) {
			defer wg.Done()
			apply := applyRequestForNode(req, wire, peers, lease, node.Name,
				"apply", expected, generation)
			resp, err := node.Apply(lease.Context(), apply)
			if err == nil {
				err = responseFailure(resp)
			}
			mu.Lock()
			values[node.Name] = resp
			if err != nil && applyErr == nil {
				applyErr = fmt.Errorf("apply %s: %w", node.Name, err)
			}
			mu.Unlock()
		}(node)
	}
	wg.Wait()
	if applyErr == nil {
		applyErr = lease.Err()
	}
	if applyErr != nil {
		rollbackErrs := c.abortApply(context.WithoutCancel(ctx), lease, wire, peers, generation, req)
		if len(rollbackErrs) > 0 {
			applyErr = fmt.Errorf("%w; rollback: %v", applyErr, rollbackErrs[0])
		}
		return transactionFailure(nodes, values, applyErr)
	}

	// Restore proof happens while the source placement is still running. A
	// commit below is the first path that can prune it, and transactions with
	// proofs refuse to commit until this endpoint persisted verification.
	for _, node := range nodes {
		if len(proofs[node.Name]) == 0 {
			continue
		}
		fence, ok := lease.Fence(node.Name)
		if !ok {
			return transactionFailure(nodes, values, fmt.Errorf("no mutation fence for node %s", node.Name))
		}
		if _, err := node.VerifyStateRestore(lease.Context(), agent.StateVerifyRequest{
			Lab: top.Name, Fence: fence, Generation: generation,
		}); err != nil {
			rollbackErrs := c.abortApply(context.WithoutCancel(ctx), lease, wire, peers, generation, req)
			if len(rollbackErrs) > 0 {
				err = fmt.Errorf("%w; rollback: %v", err, rollbackErrs[0])
			}
			return transactionFailure(nodes, values, fmt.Errorf("verify restored state on %s: %w", node.Name, err))
		}
	}

	for _, node := range nodes {
		commit := applyRequestForNode(req, wire, peers, lease, node.Name,
			"commit", expected, generation)
		commit.Topology = nil
		resp, err := node.Apply(lease.Context(), commit)
		if err == nil {
			err = responseFailure(resp)
		}
		if err != nil {
			rollbackErrs := c.abortApply(context.WithoutCancel(ctx), lease, wire, peers, generation, req)
			if len(rollbackErrs) > 0 {
				err = fmt.Errorf("%w; rollback: %v", err, rollbackErrs[0])
			}
			return transactionFailure(nodes, values, fmt.Errorf("commit %s: %w", node.Name, err))
		}
		if applied, ok := values[node.Name]; ok {
			resp.Steps, resp.Planned = applied.Steps, applied.Planned
			resp.Devices, resp.Links = applied.Devices, applied.Links
			resp.WantDevice, resp.WantLinks = applied.WantDevice, applied.WantLinks
			resp.DurationMS = applied.DurationMS
		}
		values[node.Name] = resp
	}
	for _, node := range nodes {
		finalize := applyRequestForNode(req, wire, peers, lease, node.Name,
			"finalize", expected, generation)
		finalize.Topology = nil
		if _, err := node.Apply(lease.Context(), finalize); err != nil {
			// Every node acknowledged commit before finalization begins. Do
			// not roll that complete generation back merely because cleanup
			// failed; report the failure and leave the retained transaction
			// fail-closed until it can be finalized or deliberately recovered.
			return transactionFailure(nodes, values,
				fmt.Errorf("finalize %s: %w", node.Name, err))
		}
	}
	if err := lease.Err(); err != nil {
		rollbackErrs := c.abortApply(context.WithoutCancel(ctx), lease, wire, peers, generation, req)
		if len(rollbackErrs) > 0 {
			err = fmt.Errorf("%w; rollback: %v", err, rollbackErrs[0])
		}
		return transactionFailure(nodes, values, err)
	}

	out := make([]NodeResult[agent.ApplyResponse], 0, len(nodes))
	for _, node := range nodes {
		out = append(out, NodeResult[agent.ApplyResponse]{Node: node.Name, Value: values[node.Name]})
	}
	return out
}

func mutationFailure[T any](nodes []*Node, values map[string]T, cause error) []NodeResult[T] {
	out := make([]NodeResult[T], 0, len(nodes))
	for _, node := range nodes {
		out = append(out, NodeResult[T]{
			Node: node.Name, Value: values[node.Name],
			Err: fmt.Errorf("cluster mutation did not complete on every node: %w", cause),
		})
	}
	return out
}

func (c *Cluster) coordinatedDestroy(ctx context.Context, lab string, vnis []uint32,
	ephemeral bool,
) []NodeResult[struct{}] {
	ctx = operationContext(ctx)
	nodes := c.sortedNodes()
	if len(nodes) == 0 {
		return nil
	}
	lease, err := c.AcquireMutationLease(ctx, lab)
	if err != nil {
		return mutationFailure[struct{}](nodes, nil, err)
	}
	defer lease.Release()

	values := map[string]struct{}{}
	results := fanOut(lease.Context(), nodes, func(ctx context.Context, node *Node) (struct{}, error) {
		fence, ok := lease.Fence(node.Name)
		if !ok {
			return struct{}{}, fmt.Errorf("no mutation fence for node %s", node.Name)
		}
		return struct{}{}, node.destroy(ctx, agent.DestroyRequest{
			Lab: lab, VNIs: vnis, Ephemeral: ephemeral, Fence: fence,
		})
	})
	var failure error
	for _, result := range results {
		values[result.Node] = result.Value
		if result.Err != nil && failure == nil {
			failure = fmt.Errorf("%s: %w", result.Node, result.Err)
		}
	}
	if failure == nil {
		failure = lease.Err()
	}
	if failure != nil {
		return mutationFailure(nodes, values, failure)
	}
	return results
}

// Lifecycle changes one container under a cluster-wide lab fence.
func (c *Cluster) Lifecycle(ctx context.Context, lab, nodeName string,
	req agent.LifecycleRequest,
) error {
	ctx = operationContext(ctx)
	return c.withMutationLease(ctx, lab, func(lease *MutationLease) error {
		node := c.node(nodeName)
		if node == nil {
			return fmt.Errorf("node %q is not in this cluster", nodeName)
		}
		if lease != nil {
			req.Fence, _ = lease.Fence(nodeName)
			return node.Lifecycle(lease.Context(), req)
		}
		return node.Lifecycle(ctx, req)
	})
}

// Reshape restores shaping under a cluster-wide lab fence.
func (c *Cluster) Reshape(ctx context.Context, lab, nodeName string,
	req agent.ReshapeRequest,
) error {
	return c.withMutationLease(ctx, lab, func(lease *MutationLease) error {
		node := c.node(nodeName)
		if node == nil {
			return fmt.Errorf("node %q is not in this cluster", nodeName)
		}

		if lease != nil {
			req.Fence, _ = lease.Fence(nodeName)
			return node.Reshape(lease.Context(), req)
		}
		return node.Reshape(ctx, req)
	})
}

// MPLSLabelSpace runs a namespace-side allocation operation under the same
// cluster mutation lease as lifecycle and shaping. Label exhaustion changes
// forwarding state and must not race a deploy or another incident.
func (c *Cluster) MPLSLabelSpace(ctx context.Context, lab, nodeName string,
	req agent.MPLSLabelSpaceRequest,
) (agent.MPLSLabelSpaceResponse, error) {
	var out agent.MPLSLabelSpaceResponse
	err := c.withMutationLease(ctx, lab, func(lease *MutationLease) error {
		node := c.node(nodeName)
		if node == nil {
			return fmt.Errorf("node %q is not in this cluster", nodeName)
		}
		if lease != nil {
			req.Fence, _ = lease.Fence(nodeName)
			var err error
			out, err = node.MPLSLabelSpace(lease.Context(), req)
			return err
		}
		var err error
		out, err = node.MPLSLabelSpace(ctx, req)
		return err
	})
	return out, err
}

// Exempt changes a repair exemption under a cluster-wide lab fence.
func (c *Cluster) Exempt(ctx context.Context, nodeName string,
	req agent.ExemptRequest,
) error {
	return c.withMutationLease(ctx, req.Lab, func(lease *MutationLease) error {
		node := c.node(nodeName)
		if node == nil {
			return fmt.Errorf("node %q is not in this cluster", nodeName)
		}
		if lease != nil {
			req.Fence, _ = lease.Fence(nodeName)
			return node.exempt(lease.Context(), req)
		}
		return node.exempt(ctx, req)
	})
}
