// Package initproto defines the local root-only protocol between the native
// containerd backend and the PID-1 helper mounted into each container.
package initproto

type Request struct {
	Command []string          `json:"command"`
	Env     map[string]string `json:"env,omitempty"`
	User    string            `json:"user,omitempty"`
	WorkDir string            `json:"work_dir,omitempty"`
	TTY     bool              `json:"tty,omitempty"`
	Detach  bool              `json:"detach,omitempty"`
	Stdin   []byte            `json:"stdin,omitempty"`
}

type Response struct {
	ExitCode int    `json:"exit_code,omitempty"`
	Stdout   []byte `json:"stdout,omitempty"`
	Stderr   []byte `json:"stderr,omitempty"`
	PID      int    `json:"pid,omitempty"`
	Error    string `json:"error,omitempty"`
}
