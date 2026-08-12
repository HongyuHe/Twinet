package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/model"
)

// holdRenewEvery is how often the hold is pushed forward, and holdSeconds how
// long each one lasts. The gap between them is the margin: a renewal can be
// late, or fail twice, without the hold lapsing mid-run.
const (
	holdSeconds    = 180
	holdRenewEvery = 45 * time.Second
)

// labHold is a hold on a lab, held for as long as grading needs it.
type labHold struct {
	// Lost is closed if the hold could not be kept. Grading watches it and
	// stops, because from that moment the nodes may be repairing devices
	// underneath it and no mark produced afterwards can be trusted.
	Lost   <-chan struct{}
	Reason func() string

	release func()
}

// Release hands the lab back.
func (h *labHold) Release() {
	if h != nil && h.release != nil {
		h.release()
	}
}

// holdLab asks every node to leave this lab to us until Release is called, and
// keeps asking in the background.
//
// Grading and the nodes' repair loop have opposite ideas about what a device
// should look like, and both are right. Grading blanks an autonomous system
// back to the state its owner started from and then loads somebody's work onto
// it; while it is doing that, a device is legitimately missing addresses,
// interfaces and routing configuration. The repair loop sees a device missing
// those things and puts them back -- rewiring it, and in a lab deployed at the
// reference re-rendering the reference solution over the submission.
//
// The observed consequence was a class run in which seven of eight submissions
// were quarantined with "Cannot find device port_BOS": the repair loop had
// rewired thirteen devices of the lab being graded, and loading a submission
// caught an interface during the moment it was removed and re-added. The marks
// that survive that are worse than the ones that do not, because a submission
// graded while the reference was being written back over it looks like a good
// submission.
//
// Every node must agree. A hold on two nodes out of three is not a hold: the
// devices of any lab of this size are spread across all of them, and the third
// node's repair loop will happily rewire its share. This used to warn and carry
// on, which is the failure mode the hold exists to prevent, reintroduced in the
// mechanism meant to prevent it.
//
// The hold is a lease, so it cannot fail unsafely in the other direction: if
// grading dies, nothing renews it, and every node resumes looking after the lab
// within three minutes without anyone being told to switch repairs back on.
func holdLab(ctx context.Context, top *model.Topology, token string, out io.Writer) (*labHold, error) {
	tok, err := tokenFor(token)
	if err != nil {
		return nil, err
	}
	c := client.NewCluster(top.Lab, tok)
	if len(c.Nodes) == 0 {
		// A lab on this machine alone has no agent repair loop to hold off.
		return &labHold{Lost: make(chan struct{}), Reason: func() string { return "" }}, nil
	}

	var idBytes [8]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idBytes[:])
	// Recorded where the exec path can find it: a lab this process is holding
	// must still admit this process's own commands.
	setHoldToken(id)
	holder := fmt.Sprintf("grading (pid %d)", os.Getpid())

	ask := func(ctx context.Context, secs int) error {
		var bad []string
		for _, r := range c.Hold(ctx, top.Name, holder, id, secs) {
			if r.Err != nil {
				bad = append(bad, fmt.Sprintf("%s (%v)", r.Node, r.Err))
			}
		}
		if len(bad) > 0 {
			return fmt.Errorf("%d of %d node(s) would not hold the lab: %v",
				len(bad), len(c.Nodes), bad)
		}
		return nil
	}

	if err := ask(ctx, holdSeconds); err != nil {
		return nil, fmt.Errorf("%w.\nWhile a node is repairing devices by itself, a "+
			"submission can be loaded onto a device that is being rewired, and in a lab "+
			"deployed at the reference a repair writes the model answer over a student's "+
			"work. Neither is visible in the marks. Fix the node, or upgrade its agent if "+
			"it does not recognise the request, and grade again", err)
	}

	lost := make(chan struct{})
	stop := make(chan struct{})
	done := make(chan struct{})
	var reason atomic.Pointer[string]

	go func() {
		defer close(done)
		t := time.NewTicker(holdRenewEvery)
		defer t.Stop()
		fails := 0
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if err := ask(ctx, holdSeconds); err != nil {
					// One missed renewal is a blip; the lease outlives it by
					// well over two intervals. Two in a row means the lab is
					// about to be looked after by somebody else.
					fails++
					if fails >= 2 {
						msg := err.Error()
						reason.Store(&msg)
						close(lost)
						return
					}
					continue
				}
				fails = 0
			}
		}
	}()

	return &labHold{
		Lost: lost,
		Reason: func() string {
			if p := reason.Load(); p != nil {
				return *p
			}
			return ""
		},
		release: func() {
			close(stop)
			<-done
			setHoldToken("")
			// Hand the lab back rather than waiting for the lease to lapse, so
			// a device that breaks a second after grading ends is repaired
			// then and not three minutes later.
			rel, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			_ = ask(rel, 0)
		},
	}, nil
}

// The grading hold token of this process, if it holds one.
//
// A package-level value rather than a parameter threaded through every call:
// the exec function is built once and handed to two dozen checks, and a token
// that has to be passed by hand is one a future caller forgets, at which point
// grading locks itself out of the lab it is grading.
var (
	holdTokenMu sync.RWMutex
	holdToken   string
)

func setHoldToken(t string) {
	holdTokenMu.Lock()
	holdToken = t
	holdTokenMu.Unlock()
}

// currentHoldToken returns this process's hold token, or "".
func currentHoldToken() string {
	holdTokenMu.RLock()
	defer holdTokenMu.RUnlock()
	return holdToken
}
