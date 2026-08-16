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
// The draw covers every port a user may bind, because a *range* is a published
// answer as surely as a single port is: this file is public, and a rule
// permitting twenty thousand to forty thousand and discarding the rest was
// measured as a working network. Over the whole space, permitting "the range
// the grader uses" means permitting everything, which is the behaviour being
// asked for. Landing on something that is listening is not a problem either:
// the connection then succeeds, which is the same evidence that the packets
// crossed.
func probePort() string {
	return strconv.Itoa(1024 + rand.IntN(65535-1024))
}
