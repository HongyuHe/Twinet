package agent

import "testing"

// The agent API creates containers and rewires hosts. A bearer token over plain
// HTTP is replayable by anyone who sees one request, identical on every node so
// one leak takes the cluster, and leaves the agent unauthenticated to the
// caller -- so anything that can occupy the port collects tokens.
//
// It used to warn and carry on, which does not survive contact with a working
// cluster: the warning scrolls past once, everything functions, and the
// insecure configuration becomes permanent because nothing forces the question
// again.
func TestInsecureModeNeedsBothExplicitFlagAndLoopback(t *testing.T) {
	for _, tc := range []struct {
		cfg  Config
		want bool
	}{
		{Config{Listen: "127.0.0.1:7200", Insecure: true}, true},
		{Config{Listen: "127.0.0.1:7200"}, false},
		{Config{Listen: "0.0.0.0:7200", Insecure: true}, false},
	} {
		if got := (&Server{cfg: tc.cfg}).insecureLoopbackMode(); got != tc.want {
			t.Errorf("insecureLoopbackMode(%+v) = %v, want %v", tc.cfg, got, tc.want)
		}
	}
}

func TestOnlyLoopbackMayServeWithoutTLS(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:7200", true},
		{"localhost:7200", true},
		{"[::1]:7200", true},
		{"0.0.0.0:7200", false},
		{"10.0.1.1:7200", false},
		{":7200", false},
		{"node-1:7200", false},
	}
	for _, c := range cases {
		if got := loopbackOnly(c.addr); got != c.want {
			t.Errorf("loopbackOnly(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}
