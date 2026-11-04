package access

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/collection"
)

func applicationFrames(invocation string, sequence int, kind string, command int, extra map[string]any) []string {
	event := map[string]any{"type": kind, "invocation": invocation, "application": "vtysh", "application_version": "10.0", "process_id": 42, "command_id": fmt.Sprintf("%s:%d", invocation, command)}
	for key, value := range extra {
		event[key] = value
	}
	data, _ := json.Marshal(event)
	count := (len(data) + 1023) / 1024
	var frames []string
	for i := 0; i < count; i++ {
		end := min((i+1)*1024, len(data))
		frames = append(frames, fmt.Sprintf("app;1;%s;%d;%d;%d;%s", invocation, sequence, i, count, hex.EncodeToString(data[i*1024:end])))
	}
	return frames
}

func TestVtyshReportsKeepConcurrentProcessesAndBashCommandsSeparate(t *testing.T) {
	store, err := collection.Open(collection.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	r, err := store.Start(collection.Metadata{Lab: "lab", Group: "group3", AS: 3})
	if err != nil {
		t.Fatal(err)
	}
	r.Select("as3/ALL", "device-segment")
	c := &recordedChannel{recording: r, parentCommand: "gateway-parent", applicationEvents: true}
	var visible bytes.Buffer
	prefix := []byte("\x1b]777;twinet=" + strings.Repeat("a", 32) + ";")
	out := &recordedOutput{channel: c, writer: &visible, kind: "output", prefix: prefix}
	write := func(frame string) {
		t.Helper()
		wire := append(append(append([]byte(nil), prefix...), frame...), 7)
		for len(wire) > 0 {
			n := min(len(wire), 17)
			if _, err := out.Write(wire[:n]); err != nil {
				t.Fatal(err)
			}
			wire = wire[n:]
		}
	}
	a, b := strings.Repeat("b", 32), strings.Repeat("c", 32)
	for _, id := range []string{a, b} {
		for _, f := range applicationFrames(id, 1, "application_start", 0, nil) {
			write(f)
		}
	}
	long := "description " + strings.Repeat("long command ", 400)
	x := applicationFrames(a, 2, "command_start", 1, map[string]any{"command": long, "mode_before": "config", "input_kind": "interactive"})
	y := applicationFrames(b, 2, "command_start", 1, map[string]any{"command": "bad command", "mode_before": "enable", "input_kind": "argument"})
	write(x[0])
	for _, f := range y {
		write(f)
	}
	for _, f := range x[1:] {
		write(f)
	}
	for _, f := range applicationFrames(b, 3, "command_end", 1, map[string]any{"result_code": 2, "mode_after": "enable"}) {
		write(f)
	}
	for _, f := range applicationFrames(a, 3, "command_end", 1, map[string]any{"result_code": 0, "mode_after": "interface"}) {
		write(f)
	}
	for _, f := range applicationFrames(a, 4, "command_start", 2, map[string]any{"command": "sleeping command"}) {
		write(f)
	}
	_, _ = out.Write([]byte("normal output\r\n"))
	if err := c.finishApplications(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close("incomplete", "disconnect", -1); err != nil {
		t.Fatal(err)
	}
	if visible.String() != "normal output\r\n" {
		t.Fatalf("control frames leaked: %q", visible.String())
	}
	var exported bytes.Buffer
	if err := collection.Export(store.Directory(), r.ID(), "activity", &exported); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&exported)
	rows := map[string]collection.Activity{}
	for {
		var row collection.Activity
		err := decoder.Decode(&row)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		rows[row.Command] = row
	}
	if len(rows) != 3 || rows[long].ResultCode == nil || *rows[long].ResultCode != 0 || rows[long].ModeAfter != "interface" || rows[long].ParentCommandID != "gateway-parent" {
		t.Fatalf("joined reports: %+v", rows)
	}
	if rows["bad command"].ResultName != "unknown_command" || rows["bad command"].ExitCode != nil {
		t.Fatal("FRR result confused with process exit status")
	}
	if rows["sleeping command"].Status != "incomplete" || rows["sleeping command"].ResultCode != nil {
		t.Fatal("interrupted command given a fabricated result")
	}
}

func TestApplicationFramesRejectMalformedAndBoundBuffering(t *testing.T) {
	c := &recordedChannel{applicationEvents: true}
	for _, frame := range []string{"app;2;bad", "app;1;../bad;1;0;1;00", "app;1;" + strings.Repeat("a", 32) + ";1;0;999;00"} {
		if c.applicationEvent(frame) {
			t.Fatalf("invalid frame accepted: %q", frame)
		}
	}
	for i := 0; i < 128; i++ {
		frame := fmt.Sprintf("app;1;%032x;1;0;2;7b", i)
		if !c.applicationEvent(frame) {
			t.Fatal("valid bounded fragment rejected")
		}
	}
	if c.applicationEvent(fmt.Sprintf("app;1;%032x;1;0;2;7b", 128)) {
		t.Fatal("unbounded pending reports")
	}
}

func TestApplicationCaptureCanBeDisabledIndependently(t *testing.T) {
	c := &recordedChannel{}
	if c.applicationEvent("capability;vtysh;1") {
		t.Fatal("disabled application collection accepted an event")
	}
}

func TestApplicationEnvironmentReachesTheExecutedCommand(t *testing.T) {
	c := &recordedChannel{out: &recordedOutput{}, errOut: &recordedOutput{}}
	cmd := prepareCollectionCommand(c, []string{"/bin/sh", "-c", `printf '%s:%s' "${#TWINET_COLLECTION_NONCE}" "$TWINET_COLLECTION_FD"`}, false, true)
	output, err := exec.Command(cmd[0], cmd[1:]...).Output()
	if err != nil || string(output) != "32:9" {
		t.Fatalf("application environment lost: %q %v", output, err)
	}
}
