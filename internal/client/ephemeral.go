package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
)

// A grading run is the only thing that wants a grading harness, and it is
// mortal. Ctrl-C, an OOM kill, a dropped SSH session and a panic all end it
// without running its teardown, and what it leaves behind is a lab that looks
// exactly like a course's lab to every node holding it.
//
// The heartbeat below is the difference. A controller that deploys a
// disposable lab keeps saying so; a controller that is gone stops, and the
// nodes reclaim what it was holding on their own. Nothing here can extend a
// lab past the ceiling the node applies, and nothing here can mark a lab
// disposable that was not deployed as one.

const (
	// DefaultEphemeralTTL is what a controller asks for when it does not
	// choose. It is comfortably longer than the interval below, so several
	// consecutive heartbeats can fail without a live run losing its lab.
	DefaultEphemeralTTL = 15 * time.Minute
	// minEphemeralHeartbeat bounds how often the cluster is contacted no
	// matter how short a TTL a caller asks for.
	minEphemeralHeartbeat = 5 * time.Second
)

// RenewEphemeral extends one node's lifetime for a disposable lab.
func (n *Node) RenewEphemeral(ctx context.Context, req agent.EphemeralRequest) (
	agent.EphemeralResponse, error,
) {
	var resp agent.EphemeralResponse
	err := n.do(ctx, "POST", "/v1/ephemeral", req, &resp)
	return resp, err
}

// RenewEphemeral extends the lifetime of a disposable lab on every node.
func (c *Cluster) RenewEphemeral(ctx context.Context, lab, owner string, ttl time.Duration) error {
	seconds := int(ttl.Round(time.Second).Seconds())
	results := fanOut(ctx, c.sortedNodes(), func(ctx context.Context, node *Node) (struct{}, error) {
		_, err := node.RenewEphemeral(ctx, agent.EphemeralRequest{
			Lab: lab, Owner: owner, TTLSeconds: seconds,
		})
		return struct{}{}, err
	})
	var problems []string
	for _, result := range results {
		if result.Err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", result.Node, result.Err))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("renewing the lifetime of ephemeral lab %q: %s", lab, strings.Join(problems, "; "))
}

// ReleaseEphemeral ends a disposable lab's lifetime on every node. A node that
// does not know the lab is not an error: an orderly teardown releases what it
// can and destroys the rest.
func (c *Cluster) ReleaseEphemeral(ctx context.Context, lab, owner string) {
	_ = fanOut(ctx, c.sortedNodes(), func(ctx context.Context, node *Node) (struct{}, error) {
		_, err := node.RenewEphemeral(ctx, agent.EphemeralRequest{
			Lab: lab, Owner: owner, Release: true,
		})
		return struct{}{}, err
	})
}

// EphemeralOwnerName identifies the controller process to the nodes it is
// asking to hold a lab. It is provenance for an operator reading node status,
// not an authorization token.
func EphemeralOwnerName(what string) string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	if what == "" {
		what = "controller"
	}
	return fmt.Sprintf("%s@%s/%d", what, host, os.Getpid())
}

// EphemeralHeartbeat keeps a disposable lab alive for as long as it runs.
type EphemeralHeartbeat struct {
	lab   string
	owner string
	ttl   time.Duration
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once
}

// Owner reports the identity this heartbeat renews under, which is the value
// the deployment must have used.
func (h *EphemeralHeartbeat) Owner() string {
	if h == nil {
		return ""
	}
	return h.owner
}

// Stop ends the heartbeat. It does not release the lease: a caller that is
// about to destroy the lab wants the lease to outlive the last heartbeat by
// its full TTL, so a teardown that fails still ends in reclamation rather than
// in an immortal lab.
func (h *EphemeralHeartbeat) Stop() {
	if h == nil {
		return
	}
	h.once.Do(func() {
		close(h.stop)
		<-h.done
	})
}

// KeepEphemeralAlive renews a disposable lab's lifetime until the returned
// heartbeat is stopped or ctx ends.
//
// Failures are logged rather than returned. A heartbeat that cannot reach one
// node must not abort a grading run: the lab is reclaimed if the controller
// really is gone, and a transient failure is covered by the TTL being several
// times the interval.
func (c *Cluster) KeepEphemeralAlive(ctx context.Context, lab, owner string,
	ttl time.Duration,
) *EphemeralHeartbeat {
	if ttl <= 0 {
		ttl = DefaultEphemeralTTL
	}
	heartbeat := &EphemeralHeartbeat{
		lab: lab, owner: owner, ttl: ttl,
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	interval := ttl / 3
	if interval < minEphemeralHeartbeat {
		interval = minEphemeralHeartbeat
	}
	go func() {
		defer close(heartbeat.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeat.stop:
				return
			case <-ticker.C:
			}
			renewCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), interval)
			err := c.RenewEphemeral(renewCtx, lab, owner, ttl)
			cancel()
			if err != nil && !errors.Is(err, context.Canceled) {
				slog.Warn("could not renew the lifetime of an ephemeral lab; "+
					"it will be reclaimed automatically if this controller has stopped",
					"lab", lab, "err", err)
			}
		}
	}()
	return heartbeat
}
