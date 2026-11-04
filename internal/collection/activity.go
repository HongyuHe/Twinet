package collection

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"time"
)

// Activity joins a command's start and end once, so analysis does not need to
// reconstruct terminal prompts or join event records itself.
type Activity struct {
	Schema          int       `json:"schema"`
	Session         string    `json:"session"`
	Lab             string    `json:"lab"`
	Group           string    `json:"group"`
	AS              int       `json:"as"`
	Actor           string    `json:"actor"`
	Device          string    `json:"device"`
	Segment         string    `json:"segment"`
	CommandID       string    `json:"command_id"`
	Source          string    `json:"source"`
	Command         string    `json:"command,omitempty"`
	Argv            []string  `json:"argv,omitempty"`
	CWD             string    `json:"cwd,omitempty"`
	Started         time.Time `json:"started"`
	StartNS         int64     `json:"start_ns"`
	EndNS           *int64    `json:"end_ns,omitempty"`
	DurationNS      *int64    `json:"duration_ns,omitempty"`
	ExitCode        *int      `json:"exit_code,omitempty"`
	Status          string    `json:"status"`
	Application     string    `json:"application,omitempty"`
	Invocation      string    `json:"invocation,omitempty"`
	ParentCommandID string    `json:"parent_command_id,omitempty"`
	InputKind       string    `json:"input_kind,omitempty"`
	ModeBefore      string    `json:"mode_before,omitempty"`
	ModeAfter       string    `json:"mode_after,omitempty"`
	ResultCode      *int      `json:"result_code,omitempty"`
	ResultName      string    `json:"result_name,omitempty"`
}

func activities(root string, m Metadata, visit func(Activity) error) error {
	pending := map[string]Activity{}
	err := ReadEvents(root, m.ID, func(e Event) error {
		id, _ := e.Fields["command_id"].(string)
		if id == "" {
			return nil
		}
		switch e.Type {
		case "command_start":
			a := Activity{Schema: Schema, Session: m.ID, Lab: m.Lab, Group: m.Group, AS: m.AS, Actor: m.Actor, Device: e.Device, Segment: e.Segment, CommandID: id, StartNS: e.TimeNS, Started: m.Started.Add(time.Duration(e.TimeNS)), Status: "recording"}
			a.Source, _ = e.Fields["source"].(string)
			a.Command, _ = e.Fields["command"].(string)
			a.CWD, _ = e.Fields["cwd"].(string)
			a.Application, _ = e.Fields["application"].(string)
			a.Invocation, _ = e.Fields["invocation"].(string)
			a.ParentCommandID, _ = e.Fields["parent_command_id"].(string)
			a.InputKind, _ = e.Fields["input_kind"].(string)
			a.ModeBefore, _ = e.Fields["mode_before"].(string)
			if argv, ok := e.Fields["argv"].([]any); ok {
				for _, arg := range argv {
					value, _ := arg.(string)
					a.Argv = append(a.Argv, value)
				}
			}
			pending[id] = a
		case "command_end", "command_incomplete":
			a, ok := pending[id]
			if !ok {
				return nil
			}
			delete(pending, id)
			a.Status = "incomplete"
			if e.Type == "command_end" {
				a.Status = "complete"
				duration := e.TimeNS - a.StartNS
				a.EndNS, a.DurationNS = &e.TimeNS, &duration
				if code, ok := e.Fields["exit_code"].(float64); ok {
					value := int(code)
					a.ExitCode = &value
				}
				if code, ok := e.Fields["result_code"].(float64); ok {
					value := int(code)
					a.ResultCode = &value
				}
				a.ResultName, _ = e.Fields["result_name"].(string)
				a.ModeAfter, _ = e.Fields["mode_after"].(string)
			}
			return visit(a)
		}
		return nil
	})
	if err != nil {
		return err
	}
	remaining := make([]Activity, 0, len(pending))
	for _, a := range pending {
		if m.Status != "recording" {
			a.Status = "incomplete"
		}
		remaining = append(remaining, a)
	}
	sort.Slice(remaining, func(i, j int) bool { return remaining[i].StartNS < remaining[j].StartNS })
	for _, a := range remaining {
		if err := visit(a); err != nil {
			return err
		}
	}
	return nil
}

func exportActivities(root string, m Metadata, format string, out io.Writer) error {
	if format == "activity" {
		enc := json.NewEncoder(out)
		return activities(root, m, func(a Activity) error { return enc.Encode(a) })
	}
	w := csv.NewWriter(out)
	if err := w.Write([]string{"schema", "session", "lab", "group", "as", "actor", "device", "segment", "command_id", "source", "command", "argv_json", "cwd", "started", "start_ns", "end_ns", "duration_ns", "exit_code", "status", "application", "invocation", "parent_command_id", "input_kind", "mode_before", "mode_after", "result_code", "result_name"}); err != nil {
		return err
	}
	err := activities(root, m, func(a Activity) error {
		argv, _ := json.Marshal(a.Argv)
		end, duration, code := "", "", ""
		if a.EndNS != nil {
			end = strconv.FormatInt(*a.EndNS, 10)
			duration = strconv.FormatInt(*a.DurationNS, 10)
		}
		if a.ExitCode != nil {
			code = strconv.Itoa(*a.ExitCode)
		}
		result := ""
		if a.ResultCode != nil {
			result = strconv.Itoa(*a.ResultCode)
		}
		return w.Write([]string{strconv.Itoa(a.Schema), a.Session, a.Lab, a.Group, strconv.Itoa(a.AS), a.Actor, a.Device, a.Segment, a.CommandID, a.Source, a.Command, string(argv), a.CWD, a.Started.Format(time.RFC3339Nano), strconv.FormatInt(a.StartNS, 10), end, duration, code, a.Status, a.Application, a.Invocation, a.ParentCommandID, a.InputKind, a.ModeBefore, a.ModeAfter, result, a.ResultName})
	})
	w.Flush()
	if err != nil {
		return err
	}
	return w.Error()
}
