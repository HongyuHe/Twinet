package runtime

import (
	"bytes"
	"context"
	"fmt"
	"strings"
)

type execFileWriter interface {
	Exec(context.Context, string, ExecCmd) (ExecResult, error)
}

// writeReadonlyRootfsFile writes through the container process namespace when
// Docker's archive endpoint rejects a read-only rootfs. Docker 29 rejects
// CopyToContainer before considering a mounted tmpfs, while an ordinary shell
// write correctly reaches that explicitly writable mount. The content travels
// over stdin, never through a shell argument.
func writeReadonlyRootfsFile(ctx context.Context, runner execFileWriter, name, dst string,
	mode int64, content []byte,
) error {
	if mode == 0 {
		mode = 0o644
	}
	res, err := runner.Exec(ctx, name, ExecCmd{
		Cmd: []string{
			"sh", "-c",
			`umask 077; mkdir -p "$(dirname "$1")"; cat > "$1"; chmod "$2" "$1"`,
			"twinet-copy", dst, fmt.Sprintf("%#o", mode),
		},
		Stdin: bytes.NewReader(content),
	})
	if err != nil {
		return err
	}
	return res.Err()
}

func readonlyRootfsCopyError(message string) bool {
	message = strings.ToLower(message)
	return strings.Contains(message, "rootfs is marked read-only") ||
		strings.Contains(message, "read-only file system")
}
