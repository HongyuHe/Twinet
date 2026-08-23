package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/initproto"
)

func TestExecBrokerDoesNotWaitForDaemonizedDescendantPipes(t *testing.T) {
	server, client := net.Pipe()
	go handleExec(server, newProcessReaper())
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(750 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	request := initproto.Request{
		Command: []string{"sh", "-c", "sleep 1 & printf done"},
	}
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatal(err)
	}
	var response initproto.Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatalf("broker waited for the background process's inherited pipe: %v", err)
	}
	if response.Error != "" || response.ExitCode != 0 || string(response.Stdout) != "done" {
		t.Fatalf("broker response = %+v", response)
	}
}
