// Command twinet-dhcpd serves the lab's own DHCP.
//
// It runs inside a service container of the lab rather than on the control
// plane, because DHCP is a broadcast protocol: the server has to be on the
// clients' own segment to hear them. It reads a configuration file the
// deployment generates and re-reads it on a timer, so a fault injector can
// change one option -- a gateway, a resolver, a whole subnet -- without
// restarting the daemon, which would look like an outage rather than like the
// misconfiguration it is meant to be.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HongyuHe/twinet/internal/svc"
)

func main() {
	var (
		listen = flag.String("listen", svc.DHCPListen, "UDP listen address")
		config = flag.String("config", svc.DHCPConfigPath, "path to the subnet configuration")
		reload = flag.Duration("reload", svc.DHCPReload, "how often to re-read the configuration")
	)
	flag.Parse()

	cfg, err := svc.LoadDHCPConfig(*config)
	if err != nil {
		log.Fatalf("twinet-dhcpd: %v", err)
	}
	srv := svc.NewDHCPServer(cfg)

	log.Printf("twinet-dhcpd: serving %d subnet(s) on %s", len(cfg.Subnets), *listen)

	// Re-read rather than restart. A fault that changes what the server hands
	// out must leave the server running: a client that gets no answer at all is
	// a different fault with a different symptom, and confusing the two would
	// make an episode unfalsifiable.
	go func() {
		last := svc.SummariseDHCP(cfg)
		for range time.Tick(*reload) {
			nc, err := svc.LoadDHCPConfig(*config)
			if err != nil {
				continue
			}
			if s := svc.SummariseDHCP(nc); s != last {
				srv.Update(nc)
				last = s
				log.Printf("twinet-dhcpd: configuration changed, %d subnet(s)", len(nc.Subnets))
			}
		}
	}()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		os.Exit(0)
	}()

	// One socket per segment. A client's first packet is a broadcast carrying
	// no address, so nothing in it says which segment it came from; a single
	// wildcard socket loses the only fact that would have told us, and a server
	// with more than one segment then answers nobody.
	if err := srv.ServeSegments(*listen); err != nil {
		log.Fatalf("twinet-dhcpd: %v", err)
	}
}
