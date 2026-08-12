package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/model"
)

// holdRenewEvery is how often the hold is pushed forward, and holdSeconds how
// long each one lasts. The gap between them is the margin: a renewal can be
// late, or fail once, without the hold lapsing mid-run.
const (
	holdSeconds    = 180
	holdRenewEvery = 45 * time.Second
)

// holdLab asks every node to leave this lab to us until the returned function
// is called, and keeps asking in the background.
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
// The hold is a lease, so this cannot fail unsafely: if grading dies, nothing
// renews it, and every node resumes looking after the lab within three minutes
// without anyone being told to go and switch repairs back on.
func holdLab(ctx context.Context, top *model.Topology, token string, out io.Writer) (func(), error) {
	tok, err := tokenFor(token)
	if err != nil {
		return nil, err
	}
	c := client.NewCluster(top.Lab, tok)
	holder := fmt.Sprintf("grading (pid %d)", os.Getpid())

	ask := func(ctx context.Context, secs int) []string {
		var bad []string
		for _, r := range c.Hold(ctx, top.Name, holder, secs) {
			if r.Err != nil {
				bad = append(bad, fmt.Sprintf("%s (%v)", r.Node, r.Err))
			}
		}
		return bad
	}

	// A node that will not hold is reported and grading goes on. Refusing to
	// grade would be worse: the hold is a protection against a rare race, and
	// an old agent that does not know the call at all would otherwise make the
	// whole command unusable until every node is upgraded.
	if bad := ask(ctx, holdSeconds); len(bad) > 0 {
		fmt.Fprintf(out, "note: %d node(s) would not hold off automatic repairs during "+
			"grading: %v.\nGrading will go ahead. If submissions are quarantined for "+
			"missing interfaces, this is the first thing to look at.\n", len(bad), bad)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(holdRenewEvery)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				ask(ctx, holdSeconds)
			}
		}
	}()

	return func() {
		close(stop)
		<-done
		// Hand the lab back rather than waiting for the lease to lapse, so a
		// device that breaks a second after grading ends is repaired then and
		// not three minutes later.
		rel, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		ask(rel, 0)
	}, nil
}
