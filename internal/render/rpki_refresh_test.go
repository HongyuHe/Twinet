package render

import (
	"strings"
	"testing"
)

// FRR applies an inbound route-map when a route arrives. ROAs that turn up
// afterwards update each route's validation state and stop there: the table
// then shows "rpki validation-state: invalid" on a route the policy was meant
// to reject, still selected and still advertised to everyone.
//
// That is the ordering on every deployment, because BGP converges while the
// validator is still connecting. It was observed on this cluster: the reference
// solution itself carried the lab's hijack, with a correct deny clause in place,
// so the question could not be answered correctly by anybody.
func TestValidationIsReappliedOnceTheValidatorAnswers(t *testing.T) {
	if !strings.Contains(RPKIRefreshScript, "clear bgp ipv4 unicast * in") {
		t.Error("nothing re-runs inbound policy after the ROAs arrive, so routes that " +
			"turned up before them keep whatever verdict was reached without them")
	}
	if strings.Contains(RPKIRefreshScript, "soft in") {
		t.Error("the refresh replays FRR's stored copy of what the neighbours sent, and " +
			"each stored entry carries the validation state it was given when it " +
			"arrived -- which is the stale answer being corrected. Five refreshes in " +
			"a row changed nothing on a live cluster.")
	}
	if !strings.Contains(RPKIRefreshScript, "setsid ") ||
		!strings.Contains(RPKIRefreshScript, "</dev/null >/dev/null 2>&1 &") {
		t.Error("the watcher is started with a plain & , which does not survive the exec " +
			"that started it: the session ends, the child is signalled, and it is gone " +
			"before its first sleep is over")
	}
}

// Every timed version of this refreshed at the wrong moment and exited: the
// socket reports connected before any record has arrived, the first record
// arrives before the rest, a session the lab deliberately delays delivers its
// routes after all of them, and a repair that restarts FRR an hour later puts
// the router straight back with no deployment running to notice. Thirty-six
// routers stayed as they were through five such versions.
func TestTheRefreshWatchesRatherThanGuessesWhen(t *testing.T) {
	if !strings.Contains(RPKIRefreshScript, "while :; do") {
		t.Error("the refresh runs a bounded number of times and stops, so a restart " +
			"afterwards leaves the router carrying the hijack with nothing watching")
	}
	if !strings.Contains(RPKIRefreshScript, "show rpki prefix-table") {
		t.Error("the refresh does not check that any ROA has arrived, so it re-runs the " +
			"policy against an empty table and changes nothing")
	}
	if !strings.Contains(RPKIRefreshScript, "twinet_rpki_refresh.pid") {
		t.Error("nothing stops a second copy starting, so a router accumulates one " +
			"watcher per deployment for the life of the lab")
	}
}

// A router cannot refresh away an invalid route it heard over iBGP: the border
// that accepted it is the only one that can. Chasing those made each border
// spend its attempts on the other's problem and give up on its own.
func TestTheRefreshOnlyChasesWhatThisRouterLearnedItself(t *testing.T) {
	if !strings.Contains(RPKIRefreshScript, "grep -qv '>i'") {
		t.Error("the refresh counts iBGP-learned invalid routes as its own problem, so it " +
			"refreshes forever over a route only another router can withdraw")
	}
	if !strings.Contains(RPKIRefreshScript, "grep -E '^[A-Za-z]*[*]'") {
		t.Error("FRR puts the validation code before the status field, so a chosen route " +
			"reads \"I*> 10.128.0.0/9\"; matching a bare \"*\" reports every router clean")
	}
}

// The watcher used to be started only after the validator answered, which it
// does not do within thirty seconds of an FRR restart -- which is exactly when
// this runs. So on a deployment it was never started at all, and what was
// measured five times as "the watcher ran and did nothing" was a watcher that
// had never existed.
func TestTheWatcherIsStartedWhateverTheValidatorIsDoing(t *testing.T) {
	start := strings.Index(RPKIRefreshScript, "setsid sh /etc/twinet/rpki_refresh.sh")
	wait := strings.Index(RPKIRefreshScript, "for i in 1 2 3 4 5 6 7 8")
	if start < 0 || wait < 0 {
		t.Fatal("the watcher is not started, or the validator is never waited for")
	}
	if start > wait {
		t.Error("the watcher is started inside the loop that waits for the validator, so " +
			"on a deployment -- where FRR has just restarted and the validator answers " +
			"minutes later -- it is never started at all")
	}
}
