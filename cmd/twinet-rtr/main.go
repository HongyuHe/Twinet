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
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/HongyuHe/twinet/internal/svc"
)

// fingerprint summarises a payload so a change of content is noticed even when
// the number of records is the same.
func fingerprint(roas []svc.VRP) string {
	out := make([]string, 0, len(roas))
	for _, v := range roas {
		out = append(out, fmt.Sprintf("%s-%d-%d", v.Prefix, v.MaxLength, v.ASN))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func main() {
	var (
		listen  = flag.String("listen", ":3323", "RTR listen address")
		payload = flag.String("payload", "/etc/twinet/rpki.json", "path to the VRP payload")
		reload  = flag.Duration("reload", 30*time.Second, "how often to re-read the payload")
		// The publication interface, and what the systems are entitled to
		// publish. A student's own ROA is a student's own action, so the
		// payload above holds only what the platform authorises -- staff
		// transit, the exchanges and the discrepancies an exercise declares --
		// and everything else arrives here.
		publish   = flag.String("publish", svc.PublishListen, "HTTP listen address for ROA publication, empty to disable")
		published = flag.String("published", "/etc/twinet/rpki_published.json", "where published ROAs are kept")
		authority = flag.String("authority", "/etc/twinet/rpki_authority.json", "who may publish what")
	)
	flag.Parse()

	// Published ROAs are read back from their own file rather than held only
	// in memory, so that restarting the validator -- or the container it runs
	// in -- does not quietly withdraw every authorisation a class has issued.
	var pub *svc.Publisher
	load := func() (*svc.Payload, error) {
		raw, err := os.ReadFile(*payload)
		if err != nil {
			return nil, err
		}
		var p svc.Payload
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", *payload, err)
		}
		if pub != nil {
			p.Roas = append(p.Roas, pub.Published()...)
		} else if raw, err := os.ReadFile(*published); err == nil {
			var extra []svc.VRP
			if err := json.Unmarshal(raw, &extra); err == nil {
				p.Roas = append(p.Roas, extra...)
			}
		}
		return &p, nil
	}

	if *publish != "" {
		var auth []svc.Authority
		if raw, err := os.ReadFile(*authority); err == nil {
			if err := json.Unmarshal(raw, &auth); err != nil {
				log.Printf("twinet-rtr: %s: %v", *authority, err)
			}
		}
		p, err := svc.NewPublisher(*published, auth)
		if err != nil {
			log.Fatalf("twinet-rtr: %v", err)
		}
		pub = p
		go func() {
			log.Printf("twinet-rtr: publication interface on %s for %d system(s)",
				*publish, len(auth))
			if err := http.ListenAndServe(*publish, pub.Handler()); err != nil {
				log.Printf("twinet-rtr: publication interface: %v", err)
			}
		}()
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
		last := fingerprint(p.Roas)
		for range time.Tick(*reload) {
			np, err := load()
			if err != nil {
				continue
			}
			// Compared by content, not by count.
			//
			// A student who withdraws one authorisation and publishes another
			// in the same minute leaves the count unchanged, and the routers
			// would then never be told -- so the exercise would appear not to
			// work for reasons the student could not see.
			if f := fingerprint(np.Roas); f != last {
				srv.Update(np)
				last = f
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
