package msc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// Only public startup fields are requested. Environment, mounts, credentials,
// and arbitrary Docker inspection output must not enter the evidence bundle.
type startupContainer struct {
	Name        string   `json:"name"`
	Entrypoint  []string `json:"entrypoint"`
	Command     []string `json:"command"`
	Script      string   `json:"script"`
	Resolver    string   `json:"resolver"`
	NameService string   `json:"name_service"`
}

type namespaceProcess struct {
	PID        int    `json:"pid"`
	Executable string `json:"executable"`
	Name       string `json:"name"`
}

type applianceObservation struct {
	Containers      []startupContainer `json:"containers"`
	Processes       []namespaceProcess `json:"processes"`
	WorkerBefore    int64              `json:"worker_before"`
	WorkerAfter     int64              `json:"worker_after"`
	DeviceClock     int64              `json:"device_clock"`
	NTPSynchronized bool               `json:"ntp_synchronized"`
}

// namespaceProcesses includes FRR sidecars and host-launched processes that
// share the appliance network namespace. A container-local ps is insufficient.
// Vanished processes belong to the usual sequential-sampling boundary; other
// read failures are errors rather than evidence of absence.
func namespaceProcesses(procRoot, target string) ([]namespaceProcess, error) {
	want, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	result := []namespaceProcess{}
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || !entry.IsDir() {
			continue
		}
		base := filepath.Join(procRoot, entry.Name())
		actual, statErr := os.Stat(filepath.Join(base, "ns/net"))
		if os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil {
			return nil, statErr
		}
		if !os.SameFile(want, actual) {
			continue
		}
		name, readErr := os.ReadFile(filepath.Join(base, "comm"))
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
		executable, readErr := os.Readlink(filepath.Join(base, "exe"))
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
		result = append(result, namespaceProcess{pid, executable, strings.TrimSpace(string(name))})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PID < result[j].PID })
	return result, nil
}

func (e *Engine) observeAppliance(ctx context.Context, d *Device) (applianceObservation, error) {
	out := applianceObservation{WorkerBefore: time.Now().Unix()}
	// Docker inspection supplies configured startup, including an entrypoint
	// that may already have exec'd sleep. PID 1's current command is not enough.
	if _, dockerBackend := e.Runtime.(*rt.Docker); !dockerBackend {
		return out, fmt.Errorf("configured startup observation currently requires Docker")
	}
	ns, err := e.Runtime.NSPath(ctx, e.Spec.Container(d.ID))
	if err != nil {
		return out, err
	}
	want, err := os.Stat(ns)
	if err != nil {
		return out, err
	}
	containers, err := e.Runtime.List(ctx, rt.Filter{})
	if err != nil {
		return out, err
	}
	for _, c := range containers {
		if !c.State.Joinable() {
			continue
		}
		path, nsErr := e.Runtime.NSPath(ctx, c.Name)
		if nsErr != nil {
			return out, nsErr
		}
		actual, statErr := os.Stat(path)
		if statErr != nil {
			return out, statErr
		}
		if !os.SameFile(want, actual) {
			continue
		}
		format := `{"entrypoint":{{json .Config.Entrypoint}},"command":{{json .Config.Cmd}}}`
		body, inspectErr := exec.CommandContext(ctx, "docker", "inspect", "--format", format, c.Name).Output()
		if inspectErr != nil {
			return out, inspectErr
		}
		var startup startupContainer
		if err = json.Unmarshal(body, &startup); err != nil {
			return out, err
		}
		startup.Name = c.Name
		for path, field := range map[string]*string{"/etc/resolv.conf": &startup.Resolver, "/etc/nsswitch.conf": &startup.NameService} {
			result, readErr := e.Runtime.Exec(ctx, c.Name, rt.ExecCmd{Cmd: []string{"cat", path}})
			if readErr != nil {
				return out, readErr
			}
			if err = result.Err(); err != nil {
				return out, err
			}
			*field = result.Stdout
		}
		if len(startup.Entrypoint) > 0 && startup.Entrypoint[0] == "/usr/local/bin/twinet-entrypoint" {
			result, execErr := e.Runtime.Exec(ctx, c.Name, rt.ExecCmd{Cmd: []string{"cat", "/usr/local/bin/twinet-entrypoint"}})
			if execErr != nil {
				return out, execErr
			}
			if err = result.Err(); err != nil {
				return out, err
			}
			startup.Script = result.Stdout
		}
		out.Containers = append(out.Containers, startup)
	}
	sort.Slice(out.Containers, func(i, j int) bool { return out.Containers[i].Name < out.Containers[j].Name })
	out.Processes, err = namespaceProcesses("/proc", ns)
	if err != nil {
		return out, err
	}
	clock, err := exec.CommandContext(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value").Output()
	if err != nil {
		return out, err
	}
	answer := strings.TrimSpace(string(clock))
	if answer != "yes" && answer != "no" {
		return out, fmt.Errorf("unrecognized NTP synchronization observation")
	}
	out.NTPSynchronized = answer == "yes"
	deviceClock, err := e.exec(ctx, d.ID, "date", "-u", "+%s")
	if err != nil {
		return out, err
	}
	out.DeviceClock, err = strconv.ParseInt(strings.TrimSpace(deviceClock), 10, 64)
	if err != nil {
		return out, err
	}
	out.WorkerAfter = time.Now().Unix()
	return out, nil
}
