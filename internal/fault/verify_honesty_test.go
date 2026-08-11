package fault

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A verifier that reads back the configuration it just wrote proves that vtysh
// accepted a line. It does not prove the fault happened.
//
// Three faults did exactly that. `ospf_neighbor_missing` checked that a network
// statement was absent, `bgp_asn_misconfig` that the wrong AS number appeared,
// `dns_record_error` that a zone file contained a bad address. Each would have
// passed on a network showing no symptom at all: the adjacency still up through
// another statement, every session still established, named having refused to
// reload the broken zone and still serving the right answer.
//
// That is not a cosmetic problem for this platform. The whole point of the
// fault engine is to pose an episode to an agent and ask it to find the cause.
// An episode whose symptom never appeared has no cause to find, and whatever
// the agent says is scored against a fault the network never had.
//
// This test reads the source of each verifier and fails if it decides on
// configuration text alone. It is deliberately crude -- it cannot know what a
// verifier means -- but it catches the specific regression of reaching for
// `show running-config` because that is the easiest thing to assert on.
func TestVerifiersDoNotDecideOnConfigurationText(t *testing.T) {
	// Faults whose claim genuinely is about configuration, where reading it
	// back is the right check rather than a shortcut.
	aboutConfig := map[string]string{
		"rpki_disabled":     "the claim is that validation is not configured",
		"acl_misconfig":     "the claim is that a filter exists in the configuration",
		"route_map_missing": "the claim is that a policy is absent from the configuration",
	}

	for _, f := range All() {
		if _, ok := aboutConfig[f.Name]; ok {
			continue
		}
		src, ok := verifierSource(t, f.Name)
		if !ok {
			continue
		}
		readsConfig := strings.Contains(src, "show running-config")
		if !readsConfig {
			continue
		}
		// Reading the configuration is fine if the verifier also observes
		// something operational.
		observes := strings.Contains(src, "e.Settled(") ||
			strings.Contains(src, "show ip ospf neighbor") ||
			strings.Contains(src, "show bgp") ||
			strings.Contains(src, "show ip route") ||
			strings.Contains(src, "e.Try") || strings.Contains(src, "e.Run")
		if !observes {
			t.Errorf("%s verifies by reading `show running-config` and nothing else.\n"+
				"That confirms a line was accepted, not that the fault has any symptom. "+
				"An episode built on it would ask an agent to diagnose a network that "+
				"looks entirely healthy.\n"+
				"Check the effect the fault claims, polling with e.Settled if the "+
				"protocol needs time -- or add %s to aboutConfig with the reason its "+
				"claim really is about configuration.", f.Name, f.Name)
		}
	}
}

// The direction of a symptom check depends on who is asking: after an injection
// it must appear, after a resolve it must clear. Polling for "present" in both
// cases made every symptom-checking fault impossible to resolve -- the undo
// worked, the check ran before the protocol reconverged, and resolve declared
// the lab contaminated while it was recovering normally.
func TestSettledWaitsForTheTransitionBeingAskedAbout(t *testing.T) {
	symptomPresent := func(o string) bool { return o == "broken" }

	t.Run("injection waits for the symptom to appear", func(t *testing.T) {
		seq := []string{"healthy", "healthy", "broken"}
		e := &Env{wantSymptom: true}
		got, err := e.Settled(context.Background(), 30*time.Second,
			stepThrough(&seq), symptomPresent)
		if err != nil {
			t.Fatal(err)
		}
		if got != "broken" {
			t.Errorf("injection stopped at %q; it must keep looking until the "+
				"symptom shows, or a fault that works is reported as failing", got)
		}
	})

	t.Run("resolve waits for the symptom to clear", func(t *testing.T) {
		seq := []string{"broken", "broken", "healthy"}
		e := &Env{wantSymptom: false}
		got, err := e.Settled(context.Background(), 30*time.Second,
			stepThrough(&seq), symptomPresent)
		if err != nil {
			t.Fatal(err)
		}
		if got != "healthy" {
			t.Errorf("resolve stopped at %q; it must wait for recovery, or a lab "+
				"that is reconverging normally is declared contaminated", got)
		}
	})

	t.Run("giving up returns the last thing seen", func(t *testing.T) {
		seq := []string{"healthy"}
		e := &Env{wantSymptom: true}
		got, _ := e.Settled(context.Background(), 1*time.Millisecond,
			stepThrough(&seq), symptomPresent)
		if got != "healthy" {
			t.Errorf("gave up with %q; a fault that never appeared must still say "+
				"what it saw instead", got)
		}
	})
}

// stepThrough returns an observer that walks a script and then repeats its last
// entry, so a test can describe how the network settles over time.
func stepThrough(seq *[]string) func(context.Context) (string, error) {
	i := 0
	return func(context.Context) (string, error) {
		s := *seq
		v := s[min(i, len(s)-1)]
		i++
		return v, nil
	}
}

// verifierSource returns the text of a fault's Verify function, located by
// scanning the registration blocks in this package's source.
func verifierSource(t *testing.T, name string) (string, bool) {
	t.Helper()
	files, err := filepath.Glob("faults*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		src := string(b)
		marker := `Name: "` + name + `"`
		i := strings.Index(src, marker)
		if i < 0 {
			continue
		}
		// The registration runs to the next one, or to the end.
		rest := src[i:]
		if j := strings.Index(rest[len(marker):], "Register(&Fault{"); j >= 0 {
			rest = rest[:len(marker)+j]
		}
		k := strings.Index(rest, "Verify:")
		if k < 0 {
			return "", false
		}
		return rest[k:], true
	}
	return "", false
}

// The exported Verify answers "is this fault still present". Nothing outside
// this package can say so: wantSymptom is unexported, so every external caller
// gets whatever the zero value means.
//
// The zero value means "wait for the network to have recovered". So a caller
// asking whether the fault was still there was being told whether it had gone
// away, and a symptom-aware verifier would report a perfectly working fault as
// absent. This is the worst failure available to a benchmark: the episode still
// looks valid, and its ground truth is inverted.
func TestVerifyAsksWhetherTheFaultIsStillThere(t *testing.T) {
	seen := make(chan bool, 1)
	Register(&Fault{
		Name:     "test.records_what_it_was_asked",
		Category: CatMisconfig,
		Describe: "records the direction it was asked to verify",
		Inject:   func(context.Context, *Env, Target) (State, error) { return nil, nil },
		Resolve:  func(context.Context, *Env, Target, State) error { return nil },
		Verify: func(_ context.Context, e *Env, _ Target, _ State) (Evidence, error) {
			seen <- e.wantSymptom
			return Evidence{Verified: true}, nil
		},
	})

	env := &Env{} // exactly what an external caller can build
	if _, err := Verify(context.Background(), env, &Injection{
		Fault: "test.records_what_it_was_asked",
	}); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; !got {
		t.Fatal("the public Verify asked whether the network had recovered.\n" +
			"It is called to confirm a fault is still doing its job, so a " +
			"symptom-aware verifier would report a working fault as absent and " +
			"an absent one as present -- and the episode would still look valid.")
	}
}
