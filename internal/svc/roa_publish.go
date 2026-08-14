// Publication: the interface a student issues their own ROA through.
//
// The assignment asks each group to authorise their own prefix, and for that to
// be an exercise the platform must not have done it for them. So the lab's
// trust anchor starts with ROAs only for the systems nobody is being marked on
// -- staff transit, the exchanges, and the deliberate discrepancies an exercise
// declares -- and every student system publishes its own.
//
// This is the small, self-contained equivalent of the certificate authority a
// real deployment would run. It is not a general RPKI CA: it accepts one kind
// of statement, authorises it by where it came from, and writes it where the
// validator will pick it up.
package svc

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/HongyuHe/twinet/internal/model"
)

// Authority is what a publication request must satisfy.
//
// An autonomous system may authorise prefixes inside its own allocation and
// name only itself as the origin. Without that, the exercise's deliberate
// hijack could be published away by its victim, and a group could authorise a
// neighbour's space and quietly break their marks.
type Authority struct {
	// ASN is the autonomous system this entry describes.
	ASN int `json:"asn"`
	// Blocks are the prefixes it may authorise, in CIDR form.
	Blocks []string `json:"blocks"`
	// From are the addresses it may publish from: its own devices.
	From []string `json:"from"`
}

// PublishRequest is a ROA a system asks the lab's trust anchor to hold.
type PublishRequest struct {
	Prefix    string `json:"prefix"`
	MaxLength int    `json:"max_length,omitempty"`
	ASN       int    `json:"asn"`
	// Withdraw removes the authorisation instead of adding it, so a group can
	// correct a mistake without an operator.
	Withdraw bool `json:"withdraw,omitempty"`
}

// Publisher accepts ROAs from the systems entitled to publish them and keeps
// them in a file the validator reloads.
type Publisher struct {
	mu sync.Mutex
	// path is where published ROAs are kept, separate from the platform's own
	// payload so that redeploying the lab cannot silently erase a group's work
	// and re-rendering the payload cannot silently restore it.
	path      string
	authority []Authority
	published []VRP
}

// NewPublisher loads whatever has already been published.
func NewPublisher(path string, authority []Authority) (*Publisher, error) {
	p := &Publisher{path: path, authority: authority}
	raw, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(raw, &p.published); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return p, nil
}

// Published returns the ROAs the systems have issued.
func (p *Publisher) Published() []VRP {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]VRP, len(p.published))
	copy(out, p.published)
	return out
}

// allowedFor reports which authority, if any, covers a request from an address.
func (p *Publisher) allowedFor(from netip.Addr, req PublishRequest) (Authority, error) {
	var zero Authority
	pfx, err := netip.ParsePrefix(req.Prefix)
	if err != nil {
		return zero, fmt.Errorf("%q is not a prefix", req.Prefix)
	}
	pfx = pfx.Masked()
	for _, a := range p.authority {
		// Where it came from decides who is asking. A lab has no login, and
		// asking the caller to state its own identity would authorise nothing
		// at all.
		owns := false
		for _, f := range a.From {
			if addr, err := netip.ParseAddr(f); err == nil && addr == from {
				owns = true
				break
			}
			if net, err := netip.ParsePrefix(f); err == nil && net.Contains(from) {
				owns = true
				break
			}
		}
		if !owns {
			continue
		}
		if req.ASN != a.ASN {
			return zero, fmt.Errorf("AS %d may authorise only itself as an origin, not AS %d",
				a.ASN, req.ASN)
		}
		for _, b := range a.Blocks {
			block, err := netip.ParsePrefix(b)
			if err != nil {
				continue
			}
			if block.Contains(pfx.Addr()) && pfx.Bits() >= block.Bits() {
				return a, nil
			}
		}
		return zero, fmt.Errorf("%s is not inside AS %d's allocation (%s)",
			req.Prefix, a.ASN, strings.Join(a.Blocks, ", "))
	}
	return zero, fmt.Errorf("%s is not an address of any system that may publish here", from)
}

// Publish records or withdraws an authorisation.
func (p *Publisher) Publish(from netip.Addr, req PublishRequest) error {
	if _, err := p.allowedFor(from, req); err != nil {
		return err
	}
	pfx, err := netip.ParsePrefix(req.Prefix)
	if err != nil {
		return err
	}
	pfx = pfx.Masked()
	maxLen := req.MaxLength
	if maxLen == 0 {
		maxLen = pfx.Bits()
	}
	if maxLen < pfx.Bits() || maxLen > pfx.Addr().BitLen() {
		return fmt.Errorf("a maximum length of %d makes no sense for %s", maxLen, pfx)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	kept := p.published[:0:0]
	for _, v := range p.published {
		if v.Prefix == pfx.String() && v.ASN == req.ASN {
			continue // replaced, or withdrawn
		}
		kept = append(kept, v)
	}
	if !req.Withdraw {
		kept = append(kept, VRP{Prefix: pfx.String(), MaxLength: maxLen, ASN: req.ASN})
	}
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].ASN != kept[j].ASN {
			return kept[i].ASN < kept[j].ASN
		}
		return kept[i].Prefix < kept[j].Prefix
	})
	p.published = kept
	return p.writeLocked()
}

// writeLocked persists the published set.
//
// Written to a temporary file and renamed, because the validator re-reads this
// file on its own schedule: a partially written one would be read as a shorter
// list, and every route it covered would go from valid to unknown for as long
// as it took to finish writing.
func (p *Publisher) writeLocked() error {
	raw, err := json.MarshalIndent(p.published, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(p.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p.path)
}

// Handler serves the publication interface.
//
// GET returns what this lab holds, which is what a student needs to see whether
// their own publication took effect. POST publishes or withdraws.
func (p *Publisher) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/roas", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(p.Published())
		case http.MethodPost:
			var req PublishRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			from, err := callerAddr(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := p.Publish(from, req); err != nil {
				// Refused, with the reason: a student who authorises the wrong
				// prefix should be told which part was wrong, not given a
				// number.
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"published": p.Published(),
				"note": "the validator reloads on its own schedule; routers see this " +
					"within a minute",
			})
		default:
			http.Error(w, "GET to read, POST to publish", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, publishHelp)
	})
	return mux
}

func callerAddr(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("could not tell where this request came from")
	}
	return addr.Unmap(), nil
}

const publishHelp = `This is the lab's route origin authorisation service.

Your autonomous system's prefix is not authorised until you authorise it. Until
then anyone validating sees your announcements as "not found", which is what an
unregistered prefix looks like on the real internet.

To publish, from any router of your own system:

  curl -s -X POST http://<this address>/roas \
       -d '{"prefix":"<your block>","asn":<your AS number>}'

To see what the lab holds:

  curl -s http://<this address>/roas

A system may authorise only prefixes inside its own allocation, and only itself
as the origin.
`

// PublishListen is the port the publication interface listens on.
//
// Separate from the RTR port because they are different protocols to different
// audiences: routers speak RTR, people speak HTTP.
const PublishListen = ":8323"

// AuthorityFor derives who may publish what from the topology.
func AuthorityFor(top *model.Topology) []Authority {
	var out []Authority
	for _, asn := range top.SortedASNs() {
		as := top.ASes[asn]
		if as == nil || as.Role != model.RoleStudent || as.Block == "" {
			continue
		}
		a := Authority{ASN: asn, Blocks: []string{as.Block}}
		if as.BlockV6 != "" {
			a.Blocks = append(a.Blocks, as.BlockV6)
		}
		// Every address of every device of the system, so a group can publish
		// from whichever router they happen to be logged into.
		for _, d := range as.Devices {
			for _, i := range d.Ifaces {
				for _, addr := range []string{i.Addr4, i.Addr6} {
					if addr == "" {
						continue
					}
					if pfx, err := netip.ParsePrefix(addr); err == nil {
						a.From = append(a.From, pfx.Addr().String())
					}
				}
			}
		}
		sort.Strings(a.From)
		out = append(out, a)
	}
	return out
}
