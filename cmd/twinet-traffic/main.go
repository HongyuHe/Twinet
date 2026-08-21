// Command twinet-traffic provides Twinet's deterministic HTTP load-balancer
// and traffic-generator substrate. It deliberately has no external runtime
// dependency: the same static binary runs in the pinned service image and in
// integration fixtures.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type profile struct {
	Name        string `json:"name,omitempty"`
	Target      string `json:"target"`
	Protocol    string `json:"protocol,omitempty"`
	Requests    int    `json:"requests"`
	Concurrency int    `json:"concurrency"`
	Rate        int    `json:"rate,omitempty"`
	Timeout     string `json:"timeout,omitempty"`
	Seed        int64  `json:"seed,omitempty"`
}

type metrics struct {
	Started   int64 `json:"started"`
	Completed int64 `json:"completed"`
	Succeeded int64 `json:"succeeded"`
	Failed    int64 `json:"failed"`
	Rejected  int64 `json:"rejected"`
	Active    int64 `json:"active"`
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: twinet-traffic <load-balancer|run>")
	}
	switch os.Args[1] {
	case "load-balancer":
		loadBalancer(os.Args[2:])
	case "run":
		runTraffic(os.Args[2:])
	default:
		log.Fatalf("unknown mode %q", os.Args[1])
	}
}

func loadBalancer(args []string) {
	fs := flag.NewFlagSet("load-balancer", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "HTTP listen address")
	backendList := fs.String("backends", "", "comma-separated backend URLs")
	maxInflight := fs.Int("max-inflight", 1, "maximum concurrent requests")
	work := fs.Duration("work-delay", 30*time.Millisecond, "minimum per-request service time")
	_ = fs.Parse(args)
	if *maxInflight < 1 {
		log.Fatal("--max-inflight must be positive")
	}
	var backends []*url.URL
	for _, raw := range strings.Split(*backendList, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			log.Fatalf("invalid backend %q", raw)
		}
		backends = append(backends, u)
	}
	var state metrics
	sem := make(chan struct{}, *maxInflight)
	var next uint64
	client := &http.Client{Timeout: 5 * time.Second}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metrics{
			Started: atomic.LoadInt64(&state.Started), Completed: atomic.LoadInt64(&state.Completed),
			Succeeded: atomic.LoadInt64(&state.Succeeded), Failed: atomic.LoadInt64(&state.Failed),
			Rejected: atomic.LoadInt64(&state.Rejected), Active: atomic.LoadInt64(&state.Active),
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&state.Started, 1)
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			atomic.AddInt64(&state.Rejected, 1)
			atomic.AddInt64(&state.Completed, 1)
			http.Error(w, "load balancer overloaded", http.StatusServiceUnavailable)
			return
		}
		atomic.AddInt64(&state.Active, 1)
		defer atomic.AddInt64(&state.Active, -1)
		start := time.Now()
		ok := false
		if len(backends) == 0 {
			// A no-backend service still consumes bounded work and records a
			// real 502. This makes an authoring error observable rather than
			// pretending it was a successful forwarded request.
			http.Error(w, "no backend available", http.StatusBadGateway)
		} else {
			u := *backends[int(atomic.AddUint64(&next, 1)-1)%len(backends)]
			u.Path = r.URL.Path
			u.RawQuery = r.URL.RawQuery
			req, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), r.Body)
			if err == nil {
				resp, err := client.Do(req)
				if err == nil {
					defer resp.Body.Close()
					for k, values := range resp.Header {
						for _, v := range values {
							w.Header().Add(k, v)
						}
					}
					w.WriteHeader(resp.StatusCode)
					_, _ = io.Copy(w, resp.Body)
					ok = resp.StatusCode < 500
				} else {
					http.Error(w, "backend unavailable", http.StatusBadGateway)
				}
			} else {
				http.Error(w, "invalid backend request", http.StatusBadGateway)
			}
		}
		if left := *work - time.Since(start); left > 0 {
			time.Sleep(left)
		}
		atomic.AddInt64(&state.Completed, 1)
		if ok {
			atomic.AddInt64(&state.Succeeded, 1)
		} else {
			atomic.AddInt64(&state.Failed, 1)
		}
	})
	log.Fatal(http.ListenAndServe(*listen, mux))
}

func runTraffic(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	profilePath := fs.String("profile", "", "profile JSON")
	metricsPath := fs.String("metrics", "", "metrics JSON output")
	loop := fs.Bool("loop", false, "repeat until killed")
	_ = fs.Parse(args)
	if *profilePath == "" || *metricsPath == "" {
		log.Fatal("--profile and --metrics are required")
	}
	raw, err := os.ReadFile(*profilePath)
	if err != nil {
		log.Fatal(err)
	}
	var p profile
	if err := json.Unmarshal(raw, &p); err != nil {
		log.Fatal(err)
	}
	if p.Target == "" || p.Requests < 1 || p.Concurrency < 1 {
		log.Fatal("profile requires target, requests, and concurrency")
	}
	timeout := 2 * time.Second
	if p.Timeout != "" {
		if timeout, err = time.ParseDuration(p.Timeout); err != nil || timeout <= 0 {
			log.Fatal("invalid profile timeout")
		}
	}
	client := &http.Client{Timeout: timeout}
	var m metrics
	write := func() {
		raw, _ := json.Marshal(metrics{
			Started: atomic.LoadInt64(&m.Started), Completed: atomic.LoadInt64(&m.Completed),
			Succeeded: atomic.LoadInt64(&m.Succeeded), Failed: atomic.LoadInt64(&m.Failed),
			Rejected: atomic.LoadInt64(&m.Rejected), Active: atomic.LoadInt64(&m.Active),
		})
		if err := os.WriteFile(*metricsPath, append(raw, '\n'), 0o644); err != nil {
			log.Printf("write metrics: %v", err)
		}
	}
	for {
		runBatch(client, p, &m, write)
		write()
		if !*loop {
			return
		}
	}
}

func runBatch(client *http.Client, p profile, m *metrics, write func()) {
	jobs := make(chan struct{})
	var wg sync.WaitGroup
	for n := 0; n < p.Concurrency; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				atomic.AddInt64(&m.Started, 1)
				atomic.AddInt64(&m.Active, 1)
				ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Target, nil)
				if err == nil {
					resp, requestErr := client.Do(req)
					if requestErr == nil {
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
						if resp.StatusCode == http.StatusServiceUnavailable {
							atomic.AddInt64(&m.Rejected, 1)
						}
						if resp.StatusCode >= 200 && resp.StatusCode < 400 {
							atomic.AddInt64(&m.Succeeded, 1)
						} else {
							atomic.AddInt64(&m.Failed, 1)
						}
					} else {
						atomic.AddInt64(&m.Failed, 1)
					}
				} else {
					atomic.AddInt64(&m.Failed, 1)
				}
				cancel()
				atomic.AddInt64(&m.Active, -1)
				atomic.AddInt64(&m.Completed, 1)
				write()
				if p.Rate > 0 {
					time.Sleep(time.Second / time.Duration(p.Rate))
				}
			}
		}()
	}
	for n := 0; n < p.Requests; n++ {
		jobs <- struct{}{}
	}
	close(jobs)
	wg.Wait()
}
