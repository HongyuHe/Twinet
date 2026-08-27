package cli

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// recorder is a stub container runtime that remembers what was written where.
type recorder struct {
	// conf maps a device to the last /etc/frr/frr.conf written to it.
	conf map[string]string
	// ran maps a device to every command line it was asked to run.
	ran map[string][]string
}

func newRecorder() *recorder {
	return &recorder{conf: map[string]string{}, ran: map[string][]string{}}
}

func (r *recorder) exec(_ context.Context, id string, cmd []string) (rt.ExecResult, error) {
	body := strings.Join(cmd, " ")
	r.ran[id] = append(r.ran[id], body)
	// The configuration is written base64-encoded through a pipe; recovering it
	// here means the test reads what the container would actually receive
	// rather than trusting the caller's argument.
	if cfg, ok := decodeWrittenConfig(body); ok {
		r.conf[id] = cfg
	}
	// A device that is asked whether it still carries the last submission's
	// work answers. The probe is deliberately a sequence of absence checks
	// ending in a sentinel, so a fixture that returns nothing at all reads as
	// "the device could not be read" -- which is correct, and not what these
	// tests are about.
	if strings.Contains(body, "--done") {
		return rt.ExecResult{Stdout: "--tunnels\n--routes\n--routes6\n--addrs\n--vlans\n--done\n"}, nil
	}
	// The trust anchor answers too. What a system has published is part of what
	// the reset clears, and a fixture that returned nothing would read as "the
	// anchor could not be asked" -- which is correct behaviour, and not what
	// these tests are about.
	if strings.Contains(body, "/roas") {
		return rt.ExecResult{Stdout: "[]"}, nil
	}
	return rt.ExecResult{}, nil
}

func decodeWrittenConfig(body string) (string, bool) {
	const marker = "printf '%s' "
	i := strings.Index(body, marker)
	if i < 0 || !strings.Contains(body, "/etc/frr/frr.conf") {
		return "", false
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, " |")
	if j < 0 {
		return "", false
	}
	enc := strings.Trim(strings.TrimSpace(rest[:j]), "'")
	out, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", false
	}
	return string(out), true
}

// A submission is a set of files a student wrote. It is not a description of
// every router they own: a router they never touched has no file in the
// archive, and a file can simply be missing.
//
// Loading such a submission onto a lab deployed at the reference left those
// routers holding the model answer, and the student was marked correct for work
// they had not done. Nothing in the report could reveal it -- a correct router
// looks identical however it came to be correct -- so the mark was wrong and
// undetectably so, which is the worst state a grading system can be in.
func TestARouterTheSubmissionOmitsDoesNotKeepTheModelAnswer(t *testing.T) {
	top := labFor(t, "../../examples/cos461")

	var asn int
	for _, n := range top.SortedASNs() {
		if top.ASes[n].Role == model.RoleStudent && len(top.ASes[n].Devices) > 2 {
			asn = n
			break
		}
	}
	if asn == 0 {
		t.Fatal("no student AS with more than two devices in the example lab")
	}

	// A submission that mentions exactly one of the system's routers.
	var first *model.Device
	for _, d := range top.ASes[asn].Devices {
		if d.Kind == model.KindRouter && (first == nil || d.ID < first.ID) {
			first = d
		}
	}
	sub := submission{
		Group: "group-under-test",
		AS:    asn,
		Files: map[string]string{first.Name: "hostname " + first.Name + "\n"},
	}

	rec := newRecorder()
	if err := resetToStudentStart(context.Background(), rec.exec, top, asn); err != nil {
		t.Fatalf("resetting AS %d: %v", asn, err)
	}
	if err := applySubmission(context.Background(), rec.exec, top, sub); err != nil {
		t.Fatalf("applying the submission: %v", err)
	}

	for _, d := range top.ASes[asn].Devices {
		if d.Kind != model.KindRouter || d.ID == first.ID {
			continue
		}
		cfg, err := render.Router(top, d)
		if err != nil {
			t.Fatalf("rendering %s: %v", d.ID, err)
		}
		if cfg.Expected == "" {
			continue
		}
		got, ok := rec.conf[d.ID]
		if !ok {
			t.Errorf("%s is in the submission's own autonomous system but the grader "+
				"never touched it, so it kept whatever the lab was deployed with. In a "+
				"lab deployed at the reference that is the model answer, and the student "+
				"is about to be marked correct for a router they never configured.", d.ID)
			continue
		}
		if strings.TrimSpace(got) != strings.TrimSpace(cfg.Platform) {
			t.Errorf("%s was not returned to the state a student starts from before the "+
				"submission was loaded", d.ID)
		}
		if got == cfg.Platform+cfg.Expected {
			t.Errorf("%s still holds the reference solution", d.ID)
		}
	}
}

// The state a submission installs with ip(8) -- tunnels, hand-written routes,
// addresses on interfaces the student owns -- survives a configuration reload,
// because it lives in the kernel and not in a file. Left behind, it is the
// previous student's answer, and the next student is marked on it.
func TestThePreviousSubmissionsTunnelsAndRoutesAreRemoved(t *testing.T) {
	top := labFor(t, "../../examples/cos461")
	var asn int
	for _, n := range top.SortedASNs() {
		if top.ASes[n].Role == model.RoleStudent {
			asn = n
			break
		}
	}

	rec := newRecorder()
	if err := resetToStudentStart(context.Background(), rec.exec, top, asn); err != nil {
		t.Fatalf("resetting AS %d: %v", asn, err)
	}

	for _, d := range top.ASes[asn].Devices {
		all := strings.Join(rec.ran[d.ID], "\n")
		for _, want := range []string{"ip tunnel del", "route del", "link set dev", "addr flush"} {
			if !strings.Contains(all, want) {
				t.Errorf("%s: the reset never runs %q, so a previous submission's state "+
					"is still installed when the next one is loaded", d.ID, want)
			}
		}
		if d.Kind == model.KindSwitch && !strings.Contains(all, "del-fail-mode") {
			t.Errorf("%s: the reset leaves a previous submission's OVS fail mode in place", d.ID)
		}
	}
}
