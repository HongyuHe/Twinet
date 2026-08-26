package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func acquireHostAgentLock(path, node, listen, runtimeNamespace string) (*os.File, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("host agent lock path must not be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create host agent lock directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open host agent lock %s: %w", path, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		detail, _ := os.ReadFile(path)
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			owner := strings.TrimSpace(string(detail))
			if owner == "" {
				owner = "another running process"
			}
			return nil, fmt.Errorf("another Twinet agent already owns this host network namespace (%s); "+
				"stop the other agent before starting this one. Multiple runtime namespaces do not "+
				"isolate root-namespace veths, bridges, or VXLANs", owner)
		}
		return nil, fmt.Errorf("lock host network namespace with %s: %w", path, err)
	}
	identity := fmt.Sprintf("pid=%d node=%s listen=%s runtime_namespace=%s",
		os.Getpid(), node, listen, runtimeNamespace)
	if err := file.Truncate(0); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("truncate host agent lock: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("seek host agent lock: %w", err)
	}
	if _, err := file.WriteString(identity + "\n"); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("record host agent lock owner: %w", err)
	}
	return file, nil
}
