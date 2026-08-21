// The web interface: the lab as a class sees it.
//
// The manifest has declared a `builtin.web` service since the first version of
// this project, and until now nothing served it. A service that is declared,
// validated, and then quietly skipped is worse than one that is absent: the
// manifest says the lab has a looking glass and a connectivity matrix, the
// schema agrees, and a class discovers otherwise.
//
// What a class actually needs from a web interface is small and specific:
//   - whether their system can reach everybody else's, which is the connectivity
//     matrix the original mini-Internet put on a screen in the lecture hall;
//   - what a router of any system currently believes, which is a looking glass;
//   - what the platform itself is doing, so a group can tell "my configuration
//     is wrong" from "the machine holding my router is down".
//
// It is served by the control plane rather than by a container in the lab. A
// container inside the lab can only see the lab, and the third of those three
// questions is precisely about the outside. It is read-only: nothing here can
// change a device, so it can be shown to a class without becoming another way
// to break the lab.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/svc"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Exec runs a command inside a device of the lab.
type Exec func(ctx context.Context, deviceID string, cmd []string) (string, int, error)

// Server serves the read-only view of a lab.
type Server struct {
	Top  *model.Topology
	Exec Exec
	// Refresh bounds how often the connectivity matrix is recomputed. The
	// matrix is hundreds of pings across a cluster, so it is taken on a timer
	// and served from memory: a page that recomputed it per request would let
	// one person holding down reload saturate the lab.
	Refresh time.Duration
	// Nodes reports what the cluster is doing. Optional: a lab on one machine
	// has nothing to report.
	Nodes func(ctx context.Context) []NodeStatus
	// Collector exposes bounded local matrix/measurement work to the web
	// surface. Source-side batches still run through the agent that owns each
	// AS; this records their aggregate without a hidden service-container loop.
	Collector *svc.ServiceCollector

	tpl *template.Template

	mu       sync.Mutex
	matrix   *svc.Matrix
	matrixAt time.Time
	taking   bool
}

// NodeStatus is what the overview says about one machine of the cluster.
type NodeStatus struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	Version    string `json:"version"`
	Containers int    `json:"containers"`
	Err        string `json:"error,omitempty"`
}

// New builds a server.
func New(top *model.Topology, exec Exec) (*Server, error) {
	tpl, err := template.New("").Funcs(template.FuncMap{
		"pct": func(f float64) string { return fmt.Sprintf("%.0f%%", f) },
	}).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{
		Top: top, Exec: exec, Refresh: 2 * time.Minute, tpl: tpl,
		Collector: svc.NewServiceCollector(256),
	}, nil
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.overview)
	mux.HandleFunc("/matrix", s.matrixPage)
	mux.HandleFunc("/matrix.json", s.matrixJSON)
	mux.HandleFunc("/collections.json", s.collectionsJSON)
	mux.HandleFunc("/lg", s.lookingGlass)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	return mux
}

func (s *Server) collectionsJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.Collector == nil {
		_ = json.NewEncoder(w).Encode([]svc.Collection{})
		return
	}
	_ = json.NewEncoder(w).Encode(s.Collector.Events())
}

type asRow struct {
	ASN     int
	Role    string
	Block   string
	Routers int
	Hosts   int
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	var rows []asRow
	for _, asn := range s.Top.SortedASNs() {
		as := s.Top.ASes[asn]
		hosts := 0
		for _, d := range as.Devices {
			if d.Kind == model.KindHost {
				hosts++
			}
		}
		rows = append(rows, asRow{asn, string(as.Role), as.Block, len(as.Routers), hosts})
	}
	var nodes []NodeStatus
	if s.Nodes != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		nodes = s.Nodes(ctx)
	}
	s.render(w, "overview.html", map[string]any{
		"Lab":     s.Top.Name,
		"ASes":    rows,
		"Devices": len(s.Top.Devices),
		"Links":   len(s.Top.Links),
		"Nodes":   nodes,
		"Matrix":  s.cachedMatrix(),
	})
}

func (s *Server) matrixPage(w http.ResponseWriter, r *http.Request) {
	m := s.matrixFor(r.Context())
	if m == nil {
		s.render(w, "matrix.html", map[string]any{"Lab": s.Top.Name, "Pending": true})
		return
	}
	// Cells arrive as a list; a page wants a grid.
	grid := map[int]map[int]*svc.Cell{}
	for i := range m.Cells {
		c := &m.Cells[i]
		if grid[c.From] == nil {
			grid[c.From] = map[int]*svc.Cell{}
		}
		grid[c.From][c.To] = c
	}
	s.render(w, "matrix.html", map[string]any{
		"Lab": s.Top.Name, "M": m, "Grid": grid,
	})
}

func (s *Server) matrixJSON(w http.ResponseWriter, r *http.Request) {
	m := s.matrixFor(r.Context())
	w.Header().Set("Content-Type", "application/json")
	if m == nil {
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "the first matrix is still being taken",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(m)
}

// lookingGlassCommands are the only commands the looking glass will run.
//
// A fixed list rather than free text. This is shown to a whole class, it runs
// as root inside somebody else's router, and "the sandbox will hold" is not a
// reason to accept arbitrary input when the useful set is nine commands long.
var lookingGlassCommands = []string{
	"show ip bgp summary",
	"show ip bgp",
	"show ip route",
	"show ipv6 route",
	"show ip ospf neighbor",
	"show ip ospf database",
	"show bgp ipv4 unicast rpki invalid",
	"show rpki prefix-table",
	"show interface brief",
}

func (s *Server) lookingGlass(w http.ResponseWriter, r *http.Request) {
	var routers []string
	for _, d := range s.Top.Devices {
		if d.Kind == model.KindRouter {
			routers = append(routers, d.ID)
		}
	}
	sort.Strings(routers)

	device := r.URL.Query().Get("device")
	cmd := r.URL.Query().Get("cmd")
	out, errMsg := "", ""
	if device != "" && cmd != "" {
		allowed := false
		for _, c := range lookingGlassCommands {
			if c == cmd {
				allowed = true
			}
		}
		known := false
		for _, d := range routers {
			if d == device {
				known = true
			}
		}
		switch {
		case !allowed:
			errMsg = "that command is not one the looking glass runs"
		case !known:
			errMsg = "no such router in this lab"
		default:
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			body, code, err := s.Exec(ctx, device, []string{"vtysh", "-c", cmd})
			switch {
			case err != nil:
				errMsg = err.Error()
			case code != 0:
				errMsg = fmt.Sprintf("the router answered with status %d", code)
				out = body
			default:
				out = body
			}
		}
	}
	s.render(w, "lg.html", map[string]any{
		"Lab": s.Top.Name, "Routers": routers, "Commands": lookingGlassCommands,
		"Device": device, "Cmd": cmd, "Out": out, "Err": errMsg,
	})
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) cachedMatrix() *svc.Matrix {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.matrix
}

// matrixFor returns the last matrix, taking a new one in the background when it
// is older than the refresh interval.
//
// Never more than one at a time: the matrix is hundreds of pings across the
// cluster, and two overlapping runs would double that for no extra information.
func (s *Server) matrixFor(_ context.Context) *svc.Matrix {
	s.mu.Lock()
	defer s.mu.Unlock()
	stale := time.Since(s.matrixAt) > s.Refresh
	if (s.matrix == nil || stale) && !s.taking {
		s.taking = true
		go s.takeMatrix()
	}
	return s.matrix
}

func (s *Server) takeMatrix() {
	defer func() {
		s.mu.Lock()
		s.taking = false
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	m := svc.BuildMatrixWithSourceBatches(ctx, s.Top, s.batchProber(), s.batchPathProbe(), 32)
	s.mu.Lock()
	s.matrix, s.matrixAt = m, time.Now()
	s.mu.Unlock()
	if s.Collector != nil {
		s.Collector.Publish(svc.Collection{
			Service: "builtin.matrix", Node: "collector", Result: "success",
		})
	}
}

// InvalidateMatrix makes the next request refresh the cache. Runtime and
// routing events can call this without forcing a refresh immediately; bursts
// of events therefore coalesce into one bounded source-side batch.
func (s *Server) InvalidateMatrix() {
	s.mu.Lock()
	s.matrixAt = time.Time{}
	s.mu.Unlock()
}

// batchProber performs every ping from one AS in one container exec. It keeps
// the exact ping arguments of the legacy per-cell path, so result semantics
// (including RTT) stay equivalent while the execution budget falls from N² to
// one per source.
func (s *Server) batchProber() svc.SourceBatchProber {
	return func(ctx context.Context, deviceID string, targets map[int]string) (map[int]svc.BatchProbeResult, error) {
		var script strings.Builder
		for _, asn := range sortedTargets(targets) {
			target := targets[asn]
			fmt.Fprintf(&script, "out=$(ping -c 2 -W 3 -i 0.3 %s 2>&1); rc=$?; ", shellQuote(target))
			script.WriteString("avg=$(printf '%s\\n' \"$out\" | awk -F'=' '/min\\/avg\\/max/ {split($2,a,\"/\"); gsub(/ /,\"\",a[2]); print a[2]; exit}'); ")
			fmt.Fprintf(&script, "printf '__TWINET_PING__%d\\t%%s\\t%%s\\n' \"$rc\" \"$avg\"; ", asn)
		}
		out, code, err := s.Exec(ctx, deviceID, []string{"sh", "-c", script.String()})
		if err != nil {
			return nil, err
		}
		if code != 0 {
			return nil, fmt.Errorf("source ping batch exited %d", code)
		}
		result := map[int]svc.BatchProbeResult{}
		for _, line := range strings.Split(out, "\n") {
			if !strings.HasPrefix(line, "__TWINET_PING__") {
				continue
			}
			parts := strings.Split(strings.TrimPrefix(line, "__TWINET_PING__"), "\t")
			if len(parts) != 3 {
				continue
			}
			asn, asnErr := strconv.Atoi(parts[0])
			rc, rcErr := strconv.Atoi(parts[1])
			if asnErr != nil || rcErr != nil {
				continue
			}
			observation := svc.BatchProbeResult{}
			switch rc {
			case 0:
				observation.Reachable = true
				observation.RTTms, _ = strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
			case 1:
				// iputils ping uses one for a timeout/no reply.
			default:
				observation.Err = fmt.Errorf("ping exited %d", rc)
			}
			result[asn] = observation
		}
		return result, nil
	}
}

// batchPathProbe fetches each selected route from one source in one container
// exec. The payload is marker-framed rather than JSON-encoded so it works in
// the small router images without a Python or jq dependency.
func (s *Server) batchPathProbe() svc.SourceBatchPathProbe {
	return func(ctx context.Context, deviceID string, targets map[int]string) (map[int]svc.BatchPathResult, error) {
		var script strings.Builder
		for _, asn := range sortedTargets(targets) {
			fmt.Fprintf(&script, "out=$(vtysh -c %s 2>&1); rc=$?; ", shellQuote("show ip bgp "+targets[asn]))
			fmt.Fprintf(&script, "printf '__TWINET_PATH_BEGIN__%d\\n'; printf '%%s\\n' \"$out\"; ", asn)
			fmt.Fprintf(&script, "printf '__TWINET_PATH_END__%d\\t%%s\\n' \"$rc\"; ", asn)
		}
		out, code, err := s.Exec(ctx, deviceID, []string{"sh", "-c", script.String()})
		if err != nil {
			return nil, err
		}
		if code != 0 {
			return nil, fmt.Errorf("source path batch exited %d", code)
		}
		result := map[int]svc.BatchPathResult{}
		current := -1
		var body strings.Builder
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "__TWINET_PATH_BEGIN__") {
				current, _ = strconv.Atoi(strings.TrimPrefix(line, "__TWINET_PATH_BEGIN__"))
				body.Reset()
				continue
			}
			if strings.HasPrefix(line, "__TWINET_PATH_END__") {
				parts := strings.Split(strings.TrimPrefix(line, "__TWINET_PATH_END__"), "\t")
				if len(parts) != 2 {
					current = -1
					continue
				}
				asn, asnErr := strconv.Atoi(parts[0])
				rc, rcErr := strconv.Atoi(parts[1])
				if current != asn || asnErr != nil || rcErr != nil {
					current = -1
					continue
				}
				observation := svc.BatchPathResult{}
				if rc != 0 {
					observation.Err = fmt.Errorf("route query exited %d", rc)
				} else {
					observation.Path = firstASPath(body.String())
				}
				result[asn] = observation
				current = -1
				continue
			}
			if current >= 0 {
				body.WriteString(line)
				body.WriteByte('\n')
			}
		}
		return result, nil
	}
}

func sortedTargets(targets map[int]string) []int {
	asns := make([]int, 0, len(targets))
	for asn := range targets {
		asns = append(asns, asn)
	}
	sort.Ints(asns)
	return asns
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

// prober adapts the lab's exec to what the matrix builder wants.
func (s *Server) prober() svc.Prober {
	return func(ctx context.Context, deviceID, target string) (bool, float64, error) {
		out, code, err := s.Exec(ctx, deviceID,
			[]string{"ping", "-c", "2", "-W", "3", "-i", "0.3", target})
		if err != nil {
			return false, 0, err
		}
		if code != 0 {
			return false, 0, nil
		}
		return true, parseRTT(out), nil
	}
}

// parseRTT reads the average round trip out of ping's summary.
func parseRTT(out string) float64 {
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "min/avg/max") {
			continue
		}
		parts := strings.Split(line, "=")
		if len(parts) < 2 {
			continue
		}
		f := strings.Split(strings.TrimSpace(parts[1]), "/")
		if len(f) < 2 {
			continue
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(f[1]), 64); err == nil {
			return v
		}
	}
	return 0
}

// pathProbe asks a router which AS path it uses to reach another system, so a
// cell can say "reachable, but not by a path anybody should be carrying".
func (s *Server) pathProbe() svc.PathProbe {
	targets := svc.MatrixTargets(s.Top)
	return func(ctx context.Context, deviceID string, to int) ([]int, error) {
		addr, ok := targets[to]
		if !ok {
			return nil, nil
		}
		out, code, err := s.Exec(ctx, deviceID,
			[]string{"vtysh", "-c", "show ip bgp " + addr})
		if err != nil || code != 0 {
			return nil, err
		}
		return firstASPath(out), nil
	}
}

// firstASPath reads the path of the selected route out of `show ip bgp <addr>`.
//
// FRR prints each path as a line of AS numbers, then the next hop indented
// below it, and marks the selected one "best". Only the selected path decides
// where the packets went, so a check that read the first path would report on a
// route the router is not using.
func firstASPath(out string) []int {
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "BGP routing table") ||
			strings.HasPrefix(t, "Paths:") || strings.HasPrefix(t, "Advertised") ||
			strings.HasPrefix(t, "Not advertised") {
			continue
		}
		var path []int
		fields := strings.Fields(t)
		numeric := len(fields) > 0
		for _, f := range fields {
			n, err := strconv.Atoi(f)
			if err != nil {
				numeric = false
				break
			}
			path = append(path, n)
		}
		if !numeric && t != "Local" {
			continue
		}
		// Take it only if this path is the selected one.
		for j := i + 1; j < len(lines) && j < i+6; j++ {
			l := lines[j]
			if strings.Contains(l, "best") {
				return path
			}
			if strings.TrimSpace(l) == "" {
				break
			}
		}
	}
	return nil
}
