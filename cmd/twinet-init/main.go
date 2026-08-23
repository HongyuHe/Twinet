// twinet-init is the PID 1 and local exec broker used by native containerd
// containers.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/HongyuHe/twinet/internal/initproto"
)

type processResult struct {
	status syscall.WaitStatus
	err    error
}

type processReaper struct {
	mu      sync.Mutex
	waiters map[int]chan processResult
	exited  map[int]processResult
}

func newProcessReaper() *processReaper {
	r := &processReaper{
		waiters: map[int]chan processResult{},
		exited:  map[int]processResult{},
	}
	go r.run()
	return r
}

func (r *processReaper) run() {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.ECHILD {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		result := processResult{status: status, err: err}
		r.mu.Lock()
		if waiter := r.waiters[pid]; waiter != nil {
			delete(r.waiters, pid)
			waiter <- result
			close(waiter)
		} else {
			r.exited[pid] = result
		}
		r.mu.Unlock()
	}
}

func (r *processReaper) start(command *exec.Cmd) (int, <-chan processResult, error) {
	if err := command.Start(); err != nil {
		return 0, nil, err
	}
	pid := command.Process.Pid
	waiter := make(chan processResult, 1)
	r.mu.Lock()
	if result, ok := r.exited[pid]; ok {
		delete(r.exited, pid)
		waiter <- result
		close(waiter)
	} else {
		r.waiters[pid] = waiter
	}
	r.mu.Unlock()
	return pid, waiter, nil
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "twinet-init: no child command")
		os.Exit(127)
	}
	reaper := newProcessReaper()
	if socket := strings.TrimSpace(os.Getenv("TWINET_INIT_SOCKET")); socket != "" {
		if err := startExecServer(socket, reaper); err != nil {
			fmt.Fprintf(os.Stderr, "twinet-init: exec server: %v\n", err)
			os.Exit(1)
		}
	}
	child := exec.Command(args[0], args[1:]...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.Env = os.Environ()
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	pid, finished, err := reaper.start(child)
	if err != nil {
		fmt.Fprintf(os.Stderr, "twinet-init: start: %v\n", err)
		os.Exit(127)
	}
	signals := make(chan os.Signal, 32)
	signal.Notify(signals)
	defer signal.Stop(signals)
	go func() {
		for incoming := range signals {
			if value, ok := incoming.(syscall.Signal); ok && value != syscall.SIGCHLD {
				_ = syscall.Kill(-pid, value)
			}
		}
	}()
	result := <-finished
	exit(result)
}

func startExecServer(path string, reaper *processReaper) error {
	if err := os.MkdirAll(filepathDir(path), 0o700); err != nil {
		return err
	}
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return err
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go handleExec(connection, reaper)
		}
	}()
	return nil
}

func handleExec(connection net.Conn, reaper *processReaper) {
	defer func() { _ = connection.Close() }()
	var request initproto.Request
	if err := json.NewDecoder(connection).Decode(&request); err != nil {
		writeResponse(connection, initproto.Response{Error: err.Error()})
		return
	}
	if len(request.Command) == 0 {
		writeResponse(connection, initproto.Response{Error: "empty command"})
		return
	}
	if request.TTY {
		writeResponse(connection, initproto.Response{Error: "TTY exec is unsupported"})
		return
	}
	command := exec.Command(request.Command[0], request.Command[1:]...)
	command.Env = mergeEnv(os.Environ(), request.Env)
	command.Dir = request.WorkDir
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if request.User != "" {
		credential, err := credentialFor(request.User)
		if err != nil {
			writeResponse(connection, initproto.Response{Error: err.Error()})
			return
		}
		command.SysProcAttr.Credential = credential
	}
	if request.Detach {
		command.Stdin, command.Stdout, command.Stderr = nil, nil, nil
		pid, finished, err := reaper.start(command)
		if err != nil {
			writeResponse(connection, initproto.Response{Error: err.Error()})
			return
		}
		go func() { <-finished }()
		writeResponse(connection, initproto.Response{PID: pid})
		return
	}
	var stdout, stderr bytes.Buffer
	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		writeResponse(connection, initproto.Response{Error: err.Error()})
		return
	}
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		writeResponse(connection, initproto.Response{Error: err.Error()})
		return
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		writeResponse(connection, initproto.Response{Error: err.Error()})
		return
	}
	command.Stdin, command.Stdout, command.Stderr = stdinReader, stdoutWriter, stderrWriter
	pid, finished, err := reaper.start(command)
	if err != nil {
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		_ = stderrReader.Close()
		_ = stderrWriter.Close()
		writeResponse(connection, initproto.Response{Error: err.Error()})
		return
	}
	_ = stdinReader.Close()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	stdinDone := make(chan struct{})
	go func() {
		_, _ = stdinWriter.Write(request.Stdin)
		_ = stdinWriter.Close()
		close(stdinDone)
	}()
	stdoutDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&stdout, stdoutReader)
		_ = stdoutReader.Close()
		close(stdoutDone)
	}()
	stderrDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&stderr, stderrReader)
		_ = stderrReader.Close()
		close(stderrDone)
	}()
	cancelled := make(chan struct{})
	done := make(chan struct{})
	go func() {
		var one [1]byte
		_, _ = connection.Read(one[:])
		select {
		case <-done:
		default:
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
		close(cancelled)
	}()
	result := <-finished
	<-stdinDone
	// A daemonized descendant may intentionally retain the exec process's
	// stdout/stderr descriptors after the direct child has exited. Drain output
	// already in the pipes, then close our read ends so one background daemon
	// cannot keep this broker request—and its agent DAG worker—alive forever.
	drainTimer := time.AfterFunc(100*time.Millisecond, func() {
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
	})
	<-stdoutDone
	<-stderrDone
	drainTimer.Stop()
	close(done)
	response := initproto.Response{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if result.err != nil {
		response.Error = result.err.Error()
	} else if result.status.Exited() {
		response.ExitCode = result.status.ExitStatus()
	} else if result.status.Signaled() {
		response.ExitCode = 128 + int(result.status.Signal())
	}
	writeResponse(connection, response)
	<-cancelled
}

func writeResponse(connection net.Conn, response initproto.Response) {
	_ = json.NewEncoder(connection).Encode(response)
}

func credentialFor(value string) (*syscall.Credential, error) {
	name, group, hasGroup := strings.Cut(value, ":")
	var uid, gid uint64
	if parsed, err := strconv.ParseUint(name, 10, 32); err == nil {
		uid = parsed
		gid = parsed
	} else {
		account, lookupErr := user.Lookup(name)
		if lookupErr != nil {
			return nil, lookupErr
		}
		uid, _ = strconv.ParseUint(account.Uid, 10, 32)
		gid, _ = strconv.ParseUint(account.Gid, 10, 32)
	}
	if hasGroup {
		if parsed, err := strconv.ParseUint(group, 10, 32); err == nil {
			gid = parsed
		} else {
			entry, lookupErr := user.LookupGroup(group)
			if lookupErr != nil {
				return nil, lookupErr
			}
			gid, _ = strconv.ParseUint(entry.Gid, 10, 32)
		}
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, nil
}

func mergeEnv(base []string, overrides map[string]string) []string {
	values := map[string]string{}
	for _, entry := range base {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	for key, value := range overrides {
		values[key] = value
	}
	out := make([]string, 0, len(values))
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	return out
}

func filepathDir(path string) string {
	if index := strings.LastIndexByte(path, '/'); index > 0 {
		return path[:index]
	}
	return "."
}

func exit(result processResult) {
	switch {
	case result.err != nil:
		fmt.Fprintf(os.Stderr, "twinet-init: wait: %v\n", result.err)
		os.Exit(1)
	case result.status.Exited():
		os.Exit(result.status.ExitStatus())
	case result.status.Signaled():
		os.Exit(128 + int(result.status.Signal()))
	default:
		os.Exit(1)
	}
}
