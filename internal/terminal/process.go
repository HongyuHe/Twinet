package terminal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
)

type executionKey struct{}

const ExecutionEnv = "TWINET_STREAM_ID"

var executionID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func WithExecutionID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, executionKey{}, id)
}
func ExecutionID(ctx context.Context) (string, error) {
	if id, ok := ctx.Value(executionKey{}).(string); ok && executionID.MatchString(id) {
		return id, nil
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// CleanupCommand runs inside the same device and kills only processes carrying
// the random execution tag. It also works with a remote Docker/Podman daemon.
func CleanupCommand(id string) ([]string, error) {
	if !executionID.MatchString(id) {
		return nil, fmt.Errorf("invalid execution ID")
	}
	script := `for f in /proc/[0-9]*/environ; do
  test -r "$f" || continue
  if tr '\000' '\n' < "$f" 2>/dev/null | grep -qxF '` + ExecutionEnv + `=` + id + `'; then
    p=${f#/proc/}; p=${p%/environ}
    kill -KILL "$p" 2>/dev/null || true
  fi
done`
	return []string{"/bin/sh", "-c", script}, nil
}
