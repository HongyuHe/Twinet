package collection

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"testing"
)

func TestActivityJoinsCommandsAndPreservesMultilineText(t *testing.T) {
	s := newStore(t)
	r, err := s.Start(Metadata{Lab: "course", Group: "group3", AS: 3, Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	r.Select("as3/router", "segment")
	command := "printf 'a,b\nc'"
	for _, event := range []struct {
		kind   string
		fields map[string]any
	}{
		{"command_start", map[string]any{"command_id": "first", "source": "bash_reported", "command": command, "cwd": "/work"}},
		{"command_end", map[string]any{"command_id": "first", "exit_code": 7}},
		{"command_start", map[string]any{"command_id": "unfinished", "source": "gateway", "argv": []string{"sh", "-c", "sleep 10"}}},
	} {
		if err := r.Add(event.kind, nil, event.fields); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close("incomplete", "disconnect", -1); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Export(s.Directory(), r.ID(), "activity", &output); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(&output)
	var first, last Activity
	if err := dec.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(&last); err != nil {
		t.Fatal(err)
	}
	if first.Command != command || first.ExitCode == nil || *first.ExitCode != 7 || first.DurationNS == nil || first.Actor != "alice" || first.Device != "as3/router" {
		t.Fatalf("incorrect joined command: %+v", first)
	}
	if last.Status != "incomplete" || last.ExitCode != nil || last.DurationNS != nil || len(last.Argv) != 3 {
		t.Fatalf("unfinished command was given a false result: %+v", last)
	}
	output.Reset()
	if err := Export(s.Directory(), r.ID(), "csv", &output); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&output).ReadAll()
	if err != nil || len(rows) != 3 || rows[1][10] != command || rows[1][17] != "7" || rows[2][17] != "" {
		t.Fatalf("CSV did not preserve values: %v %v", rows, err)
	}
}
