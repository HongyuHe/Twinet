// Command twinet-rtr serves the lab's RPKI payload over RTR.
//
// It runs inside the lab's own validator container rather than on the control
// plane, because a router opens a long-lived TCP session to its cache and
// reconnects to it on its own schedule. It reads a payload file the deployment
// generates, so the trust anchor is derived from the topology and an exercise
// can state exactly which announcement is meant to be invalid.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HongyuHe/twinet/internal/svc"
)

func main() {
	var (
		listen  = flag.String("listen", ":3323", "RTR listen address")
		payload = flag.String("payload", "/etc/twinet/rpki.json", "path to the VRP payload")
		reload  = flag.Duration("reload", 30*time.Second, "how often to re-read the payload")
	)
	flag.Parse()

	load := func() (*svc.Payload, error) {
		raw, err := os.ReadFile(*payload)
		if err != nil {
			return nil, err
		}
		var p svc.Payload
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", *payload, err)
		}
		return &p, nil
	}

	p, err := load()
	if err != nil {
		log.Fatalf("twinet-rtr: %v", err)
	}
	srv := svc.NewRTRServer(p)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("twinet-rtr: listen %s: %v", *listen, err)
	}
	log.Printf("twinet-rtr: serving %d VRP(s) on %s", len(p.Roas), *listen)

	// Re-reading lets a fault injector change what is authorised without
	// restarting the validator, which would drop every router's session and
	// make a policy change look like an outage.
	go func() {
		last := len(p.Roas)
		for range time.Tick(*reload) {
			np, err := load()
			if err != nil {
				continue
			}
			if len(np.Roas) != last {
				srv.Update(np)
				last = len(np.Roas)
			}
		}
	}()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		_ = ln.Close()
	}()

	if err := srv.Serve(ln); err != nil {
		log.Printf("twinet-rtr: %v", err)
	}
}
