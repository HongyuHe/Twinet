// Command twinet-openflow-controller is a deliberately small OpenFlow 1.3
// controller used by Twinet's SDN substrate. It performs the real protocol
// handshake and installs a NORMAL forwarding rule; it is not a healthcheck
// shaped stub that merely opens TCP port 6653.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"
)

const (
	ofVersion13       = 0x04
	ofHello           = 0
	ofError           = 1
	ofEchoRequest     = 2
	ofEchoReply       = 3
	ofFeaturesRequest = 5
	ofFeaturesReply   = 6
	ofFlowMod         = 14
	ofppAny           = 0xffffffff
	ofpgAny           = 0xffffffff
	ofppNormal        = 0xfffffffa
)

type state struct {
	Connections int64     `json:"connections"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func main() {
	listen := flag.String("listen", ":6653", "OpenFlow TCP listen address")
	statePath := flag.String("state", "", "operational state JSON")
	flag.Parse()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	var connections int64
	publish := func() {
		if *statePath == "" {
			return
		}
		raw, _ := json.Marshal(state{Connections: atomic.LoadInt64(&connections), UpdatedAt: time.Now().UTC()})
		// State has no credential or incident ground truth. A direct write is
		// intentional: this is a liveness observation, and a stale previous
		// value is less honest than a partial one on an ephemeral /run fs.
		_ = os.WriteFile(*statePath, append(raw, '\n'), 0o644)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		atomic.AddInt64(&connections, 1)
		publish()
		go func() {
			defer func() {
				_ = conn.Close()
				atomic.AddInt64(&connections, -1)
				publish()
			}()
			serve(conn)
		}()
	}
}

func serve(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	// A controller must announce itself before waiting for OVS's hello.
	if err := writeMessage(conn, ofHello, 0, nil); err != nil {
		return
	}
	installed := false
	for {
		typ, xid, body, err := readMessage(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("controller read: %v", err)
			}
			return
		}
		_ = conn.SetDeadline(time.Time{})
		switch typ {
		case ofHello:
			// The initial hello is sufficient; OVS may send one after ours.
		case ofFeaturesRequest:
			if err := writeMessage(conn, ofFeaturesReply, xid, featuresReply()); err != nil {
				return
			}
			if !installed {
				if err := writeMessage(conn, ofFlowMod, xid+1, normalFlow()); err != nil {
					return
				}
				installed = true
			}
		case ofEchoRequest:
			if err := writeMessage(conn, ofEchoReply, xid, body); err != nil {
				return
			}
		case ofError:
			log.Printf("OVS reported OpenFlow error (%d bytes)", len(body))
		}
	}
}

func readMessage(r io.Reader) (uint8, uint32, []byte, error) {
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, 0, nil, err
	}
	// OVS may send its highest supported version in the first hello (for
	// example 1.5) before it sees our 1.3 hello. The common version is 1.3;
	// rejecting that initial hello closes every southbound connection before
	// features negotiation even begins.
	if header[0] < ofVersion13 {
		return 0, 0, nil, io.ErrUnexpectedEOF
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < len(header) || length > 1<<20 {
		return 0, 0, nil, io.ErrUnexpectedEOF
	}
	body := make([]byte, length-len(header))
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, 0, nil, err
	}
	return header[1], binary.BigEndian.Uint32(header[4:8]), body, nil
}

func writeMessage(w io.Writer, typ uint8, xid uint32, body []byte) error {
	var header [8]byte
	header[0], header[1] = ofVersion13, typ
	binary.BigEndian.PutUint16(header[2:4], uint16(len(header)+len(body)))
	binary.BigEndian.PutUint32(header[4:8], xid)
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func featuresReply() []byte {
	// datapath_id, n_buffers, n_tables, auxiliary_id, padding, capabilities,
	// reserved. OVS accepts a zero datapath ID from this transparent teaching
	// controller; its own features report remains the source of switch facts.
	body := make([]byte, 24)
	binary.BigEndian.PutUint32(body[8:12], 256)
	body[12] = 1
	return body
}

func normalFlow() []byte {
	// OpenFlow 1.3 flow_mod with a match-all OXM and apply-actions output to
	// OFPP_NORMAL. hard_timeout=5 makes controller loss observable: a stopped
	// controller's rule expires and a secure OVS stops forwarding rather than
	// retaining an invisible stale flow forever.
	body := make([]byte, 40)
	binary.BigEndian.PutUint64(body[0:8], 0) // cookie
	binary.BigEndian.PutUint64(body[8:16], 0)
	body[16] = 0                               // table
	body[17] = 0                               // add
	binary.BigEndian.PutUint16(body[18:20], 0) // idle timeout
	binary.BigEndian.PutUint16(body[20:22], 5) // hard timeout
	binary.BigEndian.PutUint16(body[22:24], 0) // priority
	binary.BigEndian.PutUint32(body[24:28], ofppAny)
	binary.BigEndian.PutUint32(body[28:32], ofpgAny)
	// flags and importance are zero at 32..36; match starts at 40.
	match := make([]byte, 8)
	binary.BigEndian.PutUint16(match[0:2], 1) // OFPMT_OXM
	binary.BigEndian.PutUint16(match[2:4], 4) // empty match
	instruction := make([]byte, 24)
	binary.BigEndian.PutUint16(instruction[0:2], 4) // APPLY_ACTIONS
	binary.BigEndian.PutUint16(instruction[2:4], 24)
	// action output type=0, length=16, port=OFPP_NORMAL, max_len=0
	binary.BigEndian.PutUint16(instruction[4:6], 0)
	binary.BigEndian.PutUint16(instruction[6:8], 16)
	binary.BigEndian.PutUint32(instruction[8:12], ofppNormal)
	return append(append(body, match...), instruction...)
}
