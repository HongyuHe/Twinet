package main

import (
	"net"
	"testing"
	"time"
)

func TestControllerInstallsOperationalNormalFlow(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		server, err := listener.Accept()
		if err == nil {
			serve(server)
		}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))

	typ, _, _, err := readMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	if typ != ofHello {
		t.Fatalf("first controller message type=%d, want hello", typ)
	}
	if err := writeMessage(client, ofHello, 7, nil); err != nil {
		t.Fatal(err)
	}
	if err := writeMessage(client, ofFeaturesRequest, 8, nil); err != nil {
		t.Fatal(err)
	}
	typ, xid, _, err := readMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	if typ != ofFeaturesReply || xid != 8 {
		t.Fatalf("features response type/xid=%d/%d, want %d/8", typ, xid, ofFeaturesReply)
	}
	typ, _, body, err := readMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	if typ != ofFlowMod {
		t.Fatalf("follow-up message type=%d, want flow-mod", typ)
	}
	foundNormal := false
	for i := 0; i+4 <= len(body); i++ {
		if uint32(body[i])<<24|uint32(body[i+1])<<16|uint32(body[i+2])<<8|uint32(body[i+3]) == ofppNormal {
			foundNormal = true
			break
		}
	}
	if !foundNormal {
		t.Fatalf("flow-mod does not output to OFPP_NORMAL: %x", body)
	}
}
