package access

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type applicationState struct {
	command     string
	parent      string
	lastMessage uint64
}

type applicationFragment struct {
	count, next int
	data        []byte
}

var applicationID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var applicationCommandID = regexp.MustCompile(`^[a-f0-9]{32}:[1-9][0-9]{0,19}$`)

// Application control frames are bounded fragments, each written in one small
// write by vtysh. Reassembly keeps concurrent application processes separate.
func (c *recordedChannel) applicationEvent(message string) bool {
	if !c.applicationEvents {
		return false
	}
	c.appMu.Lock()
	defer c.appMu.Unlock()
	f := strings.Split(message, ";")
	if len(f) == 3 && f[0] == "capability" && f[1] == "vtysh" {
		if f[2] != "1" && f[2] != "absent" && f[2] != "unsupported" {
			return false
		}
		_ = c.fail(c.recording.Add("application_capability", nil, map[string]any{"application": "vtysh", "protocol": f[2], "supported": f[2] == "1"}))
		return true
	}
	if len(f) != 7 || f[0] != "app" || f[1] != "1" || !applicationID.MatchString(f[2]) || len(f[6]) > 2048 {
		return false
	}
	number, err := strconv.ParseUint(f[3], 10, 64)
	if err != nil || number == 0 {
		return false
	}
	index, err := strconv.Atoi(f[4])
	if err != nil {
		return false
	}
	count, err := strconv.Atoi(f[5])
	if err != nil || count < 1 || count > 32 || index < 0 || index >= count {
		return false
	}
	chunk, err := hex.DecodeString(f[6])
	if err != nil {
		return false
	}
	if c.fragments == nil {
		c.fragments = map[string]*applicationFragment{}
	}
	key := f[2] + ":" + f[3]
	part := c.fragments[key]
	if part == nil {
		if index != 0 || len(c.fragments) >= 128 {
			return false
		}
		part = &applicationFragment{count: count}
		c.fragments[key] = part
	}
	if index != part.next || count != part.count {
		delete(c.fragments, key)
		return false
	}
	part.data = append(part.data, chunk...)
	part.next++
	if part.next < part.count {
		return true
	}
	delete(c.fragments, key)
	var event struct {
		Type        string `json:"type"`
		Invocation  string `json:"invocation"`
		CommandID   string `json:"command_id"`
		Command     string `json:"command"`
		Application string `json:"application"`
		Version     string `json:"application_version"`
		PID         int    `json:"process_id"`
		ModeBefore  string `json:"mode_before"`
		ModeAfter   string `json:"mode_after"`
		InputKind   string `json:"input_kind"`
		Result      *int   `json:"result_code"`
		Coverage    string `json:"coverage"`
		Reason      string `json:"reason"`
	}
	if json.Unmarshal(part.data, &event) != nil || event.Application != "vtysh" || event.Invocation != f[2] || event.PID <= 0 {
		return false
	}
	if c.applications == nil {
		c.applications = map[string]*applicationState{}
	}
	state := c.applications[event.Invocation]
	fields := map[string]any{"source": "vtysh_reported", "application": "vtysh", "invocation": event.Invocation, "process_id": event.PID, "application_version": event.Version}
	if event.Type == "application_start" {
		if state != nil || len(c.applications) >= 128 {
			return false
		}
		state = &applicationState{parent: c.parentCommand}
		c.applications[event.Invocation] = state
		fields["coverage"] = event.Coverage
	}
	if state == nil || number <= state.lastMessage {
		return false
	}
	state.lastMessage = number
	if state.parent != "" {
		fields["parent_command_id"] = state.parent
	}
	switch event.Type {
	case "application_start":
	case "command_start":
		if !applicationCommandID.MatchString(event.CommandID) || !strings.HasPrefix(event.CommandID, event.Invocation+":") || state.command != "" {
			return false
		}
		state.command = "vtysh:" + event.CommandID
		fields["command"], fields["mode_before"], fields["input_kind"] = event.Command, event.ModeBefore, event.InputKind
		fields["command_id"] = state.command
	case "command_end", "command_incomplete":
		if state.command == "" || state.command != "vtysh:"+event.CommandID {
			return false
		}
		fields["command_id"] = state.command
		if event.Type == "command_end" {
			if event.Result == nil {
				return false
			}
			fields["result_code"], fields["result_name"], fields["mode_after"] = *event.Result, frrResult(*event.Result), event.ModeAfter
		} else {
			fields["reason"] = event.Reason
		}
		state.command = ""
	case "application_end":
		if state.command != "" {
			return false
		}
		delete(c.applications, event.Invocation)
	default:
		return false
	}
	_ = c.fail(c.recording.Add(event.Type, nil, fields))
	return true
}

func frrResult(code int) string {
	names := map[int]string{0: "success", 1: "warning", 2: "unknown_command", 3: "ambiguous_command", 4: "incomplete_command", 5: "too_many_arguments", 6: "nothing_to_do", 10: "success_daemon", 11: "no_file", 13: "configuration_failed", 16: "daemon_unavailable"}
	if name, ok := names[code]; ok {
		return name
	}
	return fmt.Sprintf("frr_result_%d", code)
}

func (c *recordedChannel) finishApplications() error {
	c.appMu.Lock()
	defer c.appMu.Unlock()
	for invocation, state := range c.applications {
		if state.command != "" {
			if err := c.recording.Add("command_incomplete", nil, map[string]any{"source": "vtysh_reported", "application": "vtysh", "invocation": invocation, "command_id": state.command, "reason": "device execution ended before vtysh reported a result"}); err != nil {
				return c.fail(err)
			}
		}
	}
	if len(c.fragments) > 0 {
		if err := c.recording.Add("application_warning", nil, map[string]any{"reason": "incomplete application report", "fragments": len(c.fragments)}); err != nil {
			return c.fail(err)
		}
	}
	c.applications, c.fragments, c.parentCommand = nil, nil, ""
	return nil
}
