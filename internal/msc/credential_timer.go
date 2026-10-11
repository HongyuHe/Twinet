package msc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func systemdArg(s string) string {
	return strconv.Quote(strings.ReplaceAll(strings.ReplaceAll(s, "%", "%%"), "$", "$$"))
}

func (e *Engine) InstallCredentialTimer(ctx context.Context, binary, specPath, targetsPath string) error {
	if _, err := os.Stat(filepath.Join(e.Dir, "credential-worker.json")); err == nil {
		return fmt.Errorf("install renewal on the authority only")
	} else if !os.IsNotExist(err) {
		return err
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		return err
	}
	specPath, err = filepath.Abs(specPath)
	if err != nil {
		return err
	}
	args := []string{binary, "msc", "--spec", specPath, "--state-dir", e.Dir, "credentials", "renew"}
	if targetsPath != "" {
		raw, readErr := os.ReadFile(targetsPath)
		if readErr != nil {
			return readErr
		}
		var plan CredentialTargets
		if err = json.Unmarshal(raw, &plan); err != nil {
			return err
		}
		if err = e.ValidateCredentialTargets(plan); err != nil {
			return err
		}
		retained := filepath.Join(e.Dir, "credential-targets.json")
		if err = writePrivate(retained, raw); err != nil {
			return err
		}
		args = append(args, "--targets", retained)
	}
	for i := range args {
		args[i] = systemdArg(args[i])
	}
	name := "twinet-msc-credentials-" + e.Spec.Name
	marker := "# Twinet credential authority: " + e.Dir + "\n"
	service := marker + "[Unit]\nDescription=Renew Twinet MSC credentials and verify worker delivery\nWants=network-online.target\nAfter=network-online.target docker.service\n\n[Service]\nType=oneshot\nUser=root\nUMask=0077\nTimeoutStartSec=15min\nExecStart=" + strings.Join(args, " ") + "\n"
	timer := marker + "[Unit]\nDescription=Refresh Twinet MSC credentials before expiration\n\n[Timer]\nOnBootSec=2min\nOnCalendar=hourly\nRandomizedDelaySec=5min\nPersistent=true\nUnit=" + name + ".service\n\n[Install]\nWantedBy=timers.target\n"
	for suffix, body := range map[string]string{".service": service, ".timer": timer} {
		path := filepath.Join("/etc/systemd/system", name+suffix)
		if old, readErr := os.ReadFile(path); readErr == nil && !strings.HasPrefix(string(old), marker) {
			return fmt.Errorf("refuse foreign systemd unit %s", path)
		} else if readErr != nil && !os.IsNotExist(readErr) {
			return readErr
		}
		if err = writePrivate(path, []byte(body)); err != nil {
			return err
		}
		if err = os.Chmod(path, 0644); err != nil {
			return err
		}
	}
	for _, a := range [][]string{{"daemon-reload"}, {"enable", "--now", name + ".timer"}} {
		if out, runErr := exec.CommandContext(ctx, "systemctl", a...).CombinedOutput(); runErr != nil {
			return fmt.Errorf("systemctl: %w: %s", runErr, out)
		}
	}
	return nil
}
