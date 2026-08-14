package grade

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// Every host has to be tested as a receiver, and as somebody who did not ask.
//
// One round covered every host but the source, and the source was always the
// same host, so that one site was never tested as a receiver at all: blocking
// the group at its own router kept full marks. The no-flooding half had the
// same hole in the other direction -- the source and the one receiver were
// never bystanders, so a submission flooding to exactly those two passed.
//
// This is a property of the rounds themselves, so it is pinned here rather than
// left to an end-to-end run that would only notice if a mutation happened to
// land on the untested host.
func TestEveryHostIsTestedAsAReceiverAndAsABystander(t *testing.T) {
	for _, n := range []int{2, 3, 4, 5, 6, 9} {
		hosts := make([]*model.Device, n)
		for i := range hosts {
			hosts[i] = &model.Device{Name: string(rune('A' + i))}
		}

		asReceiver := map[string]bool{}
		for _, c := range deliveryCasts(hosts) {
			for _, h := range c.recv {
				asReceiver[h.Name] = true
			}
		}
		for _, h := range hosts {
			if !asReceiver[h.Name] {
				t.Errorf("with %d hosts, %s is never a receiver, so multicast could be "+
					"blocked to that site for full marks", n, h.Name)
			}
		}

		if n < 3 {
			continue
		}
		asBystander := map[string]bool{}
		for _, c := range floodingCasts(hosts) {
			for _, h := range c.bystanders {
				asBystander[h.Name] = true
			}
			if len(c.recv) != 1 {
				t.Errorf("with %d hosts, a flooding round has %d receivers; the check reads "+
					"the first and would ignore the rest", n, len(c.recv))
			}
		}
		if n == 3 {
			// Three hosts leave exactly one to overhear, and moving the source
			// would leave the round with no bystander at all. The check says
			// which hosts it covered, and a lab this small is the operator's
			// choice.
			continue
		}
		for _, h := range hosts {
			if !asBystander[h.Name] {
				t.Errorf("with %d hosts, %s never listens without joining, so flooding to "+
					"that site would go unnoticed", n, h.Name)
			}
		}
	}
}
