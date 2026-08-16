package grade

import (
	"math/rand/v2"
	"strconv"
)

// probePort returns a port to attempt a connection to, drawn when the check
// runs.
//
// The port has to be one nothing is listening on, so that the answer is a
// reset: that is what proves the packets crossed and came back, and it needs no
// service arranged anywhere. It also has to be unpredictable. A fixed port is a
// published answer -- a rule permitting exactly it and discarding every other
// connection was measured as a network in perfect health, because the one port
// the grader ever tried was the one port that worked.
//
// The range is above the registered ports and below the ephemeral range Linux
// hands out by default, so a draw is very unlikely to find a listener and
// almost as unlikely to collide with a connection in flight. If it does find
// one, the connection succeeds, which is also evidence that the packets
// arrived.
func probePort() string {
	return strconv.Itoa(20000 + rand.IntN(20000))
}
