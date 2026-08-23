package agent

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/limiter"
	"github.com/HongyuHe/twinet/internal/netx"
	"github.com/HongyuHe/twinet/internal/plan"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// agentMetrics is intentionally small and dependency-free. Agents must expose
// useful Prometheus text on a fresh node as well as on an isolated teaching
// cluster where running a metrics service is unnecessary.
//
// Every label is selected from a fixed vocabulary below. In particular, lab,
// device, container, command, error text, and correlation IDs are never metric
// labels: each can grow with a class and would turn a scrape endpoint into an
// unbounded memory sink.
type agentMetrics struct {
	mu sync.Mutex

	operations   map[operationMetricKey]operationMetric
	phases       map[metricKey]counterMetric
	runtime      map[metricKey]counterMetric
	events       map[string]uint64
	repairs      map[string]uint64
	grading      map[string]uint64
	underlay     map[string]uint64
	underlayLast string
}

type operationMetricKey struct {
	Operation string
	Result    string
}

type operationMetric struct {
	Count uint64
	Sum   float64
}

type metricKey struct {
	Name   string
	Result string
}

type counterMetric struct {
	Count uint64
	Sum   float64
}

func newAgentMetrics() *agentMetrics {
	return &agentMetrics{
		operations: map[operationMetricKey]operationMetric{},
		phases:     map[metricKey]counterMetric{},
		runtime:    map[metricKey]counterMetric{},
		events:     map[string]uint64{},
		repairs:    map[string]uint64{},
		grading:    map[string]uint64{},
		underlay:   map[string]uint64{},
	}
}

func (s *Server) metricRegistry() *agentMetrics {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.metrics == nil {
		s.metrics = newAgentMetrics()
	}
	return s.metrics
}

func metricResult(err error) string {
	switch {
	case err == nil:
		return "success"
	case err == context.Canceled || err == context.DeadlineExceeded:
		return "canceled"
	default:
		return "error"
	}
}

func boundedOperation(value string) string {
	switch value {
	case "apply", "destroy", "exec", "lifecycle", "metrics", "reconcile", "sweep",
		"status", "underlay", "events", "matrix", "hold", "exempt", "reshape",
		"state", "gc":
		return value
	default:
		return "other"
	}
}

func boundedRuntimeMethod(value string) string {
	switch value {
	case "ping", "pull", "create", "start", "stop", "pause", "unpause", "remove",
		"inspect", "list", "nspath", "exec", "copy_to", "copy_from", "subscribe":
		return value
	default:
		return "other"
	}
}

func boundedEventAction(value string) string {
	switch value {
	case "create", "start", "restart", "die", "stop", "destroy", "oom", "health":
		return value
	default:
		return "other"
	}
}

func boundedRepairResult(value string) string {
	switch value {
	case "scheduled", "success", "failed", "backoff", "unknown", "held", "exempt":
		return value
	default:
		return "other"
	}
}

func (m *agentMetrics) observeOperation(operation string, elapsed time.Duration, err error) {
	if m == nil {
		return
	}
	key := operationMetricKey{Operation: boundedOperation(operation), Result: metricResult(err)}
	m.mu.Lock()
	value := m.operations[key]
	value.Count++
	value.Sum += elapsed.Seconds()
	m.operations[key] = value
	m.mu.Unlock()
}

func (m *agentMetrics) observeRuntime(method string, elapsed time.Duration, err error) {
	if m == nil {
		return
	}
	key := metricKey{Name: boundedRuntimeMethod(method), Result: metricResult(err)}
	m.mu.Lock()
	value := m.runtime[key]
	value.Count++
	value.Sum += elapsed.Seconds()
	m.runtime[key] = value
	m.mu.Unlock()
}

func (m *agentMetrics) observePhase(phase string, elapsed time.Duration, result string) {
	if m == nil {
		return
	}
	switch phase {
	case "image", "create", "wire", "configure", "ready":
	default:
		phase = "other"
	}
	switch result {
	case "success", "error", "skipped", "canceled":
	default:
		result = "other"
	}
	key := metricKey{Name: phase, Result: result}
	m.mu.Lock()
	value := m.phases[key]
	value.Count++
	value.Sum += elapsed.Seconds()
	m.phases[key] = value
	m.mu.Unlock()
}

func (m *agentMetrics) observeRuntimeEvent(action string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.events[boundedEventAction(action)]++
	m.mu.Unlock()
}

func (m *agentMetrics) observeRepair(result string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.repairs[boundedRepairResult(result)]++
	m.mu.Unlock()
}

func (m *agentMetrics) observeGrading(result string) {
	if m == nil {
		return
	}
	switch result {
	case "success", "error", "canceled":
	default:
		result = "other"
	}
	m.mu.Lock()
	m.grading[result]++
	m.mu.Unlock()
}

func (m *agentMetrics) observeUnderlay(result string) {
	if m == nil {
		return
	}
	switch result {
	case "success", "error", "canceled":
	default:
		result = "other"
	}
	m.mu.Lock()
	m.underlay[result]++
	m.underlayLast = result
	m.mu.Unlock()
}

// observedHandler records an HTTP operation without putting request paths,
// labs, or error strings into labels.
func (s *Server) observedHandler(operation string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recording := &metricResponseWriter{ResponseWriter: w}
		next(recording, withEventCorrelation(s, r))
		var err error
		if recording.status >= http.StatusBadRequest {
			err = fmt.Errorf("HTTP %d", recording.status)
		}
		s.metricRegistry().observeOperation(operation, time.Since(start), err)
	}
}

type metricResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *metricResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *metricResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

func (w *metricResponseWriter) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func metricLabel(name, value string) string {
	return name + `="` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`
}

func writeMetricLine(b *strings.Builder, name string, labels []string, value string) {
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		b.WriteString(strings.Join(labels, ","))
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(value)
	b.WriteByte('\n')
}

// prometheusText returns the bounded in-process counters. Host and limiter
// gauges are appended by handleMetrics because they are observations rather
// than ever-growing counters.
func (m *agentMetrics) prometheusText() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	operations := make(map[operationMetricKey]operationMetric, len(m.operations))
	for key, value := range m.operations {
		operations[key] = value
	}
	phases := make(map[metricKey]counterMetric, len(m.phases))
	for key, value := range m.phases {
		phases[key] = value
	}
	runtimeCalls := make(map[metricKey]counterMetric, len(m.runtime))
	for key, value := range m.runtime {
		runtimeCalls[key] = value
	}
	events := cloneUint64Map(m.events)
	repairs := cloneUint64Map(m.repairs)
	grading := cloneUint64Map(m.grading)
	underlay := cloneUint64Map(m.underlay)
	underlayLast := m.underlayLast
	m.mu.Unlock()

	var b strings.Builder
	b.WriteString("# HELP twinet_operation_duration_seconds Duration of bounded agent operations.\n")
	b.WriteString("# TYPE twinet_operation_duration_seconds summary\n")
	b.WriteString("# HELP twinet_operation_results_total Completed agent operations by result.\n")
	b.WriteString("# TYPE twinet_operation_results_total counter\n")
	keys := make([]operationMetricKey, 0, len(operations))
	for key := range operations {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Operation != keys[j].Operation {
			return keys[i].Operation < keys[j].Operation
		}
		return keys[i].Result < keys[j].Result
	})
	for _, key := range keys {
		value := operations[key]
		labels := []string{metricLabel("operation", key.Operation), metricLabel("result", key.Result)}
		writeMetricLine(&b, "twinet_operation_duration_seconds_count", labels, strconv.FormatUint(value.Count, 10))
		writeMetricLine(&b, "twinet_operation_duration_seconds_sum", labels,
			strconv.FormatFloat(value.Sum, 'f', -1, 64))
		writeMetricLine(&b, "twinet_operation_results_total", labels, strconv.FormatUint(value.Count, 10))
	}

	b.WriteString("# HELP twinet_deployment_phase_duration_seconds Deployment phase durations.\n")
	b.WriteString("# TYPE twinet_deployment_phase_duration_seconds summary\n")
	b.WriteString("# HELP twinet_deployment_phase_results_total Deployment phase results.\n")
	b.WriteString("# TYPE twinet_deployment_phase_results_total counter\n")
	phaseKeys := make([]metricKey, 0, len(phases))
	for key := range phases {
		phaseKeys = append(phaseKeys, key)
	}
	sort.Slice(phaseKeys, func(i, j int) bool {
		if phaseKeys[i].Name != phaseKeys[j].Name {
			return phaseKeys[i].Name < phaseKeys[j].Name
		}
		return phaseKeys[i].Result < phaseKeys[j].Result
	})
	for _, key := range phaseKeys {
		value := phases[key]
		labels := []string{metricLabel("phase", key.Name), metricLabel("result", key.Result)}
		writeMetricLine(&b, "twinet_deployment_phase_duration_seconds_count", labels,
			strconv.FormatUint(value.Count, 10))
		writeMetricLine(&b, "twinet_deployment_phase_duration_seconds_sum", labels,
			strconv.FormatFloat(value.Sum, 'f', -1, 64))
		writeMetricLine(&b, "twinet_deployment_phase_results_total", labels,
			strconv.FormatUint(value.Count, 10))
	}

	b.WriteString("# HELP twinet_runtime_calls_total Container-runtime calls by method and result.\n")
	b.WriteString("# TYPE twinet_runtime_calls_total counter\n")
	b.WriteString("# HELP twinet_runtime_call_duration_seconds Duration of container-runtime calls.\n")
	b.WriteString("# TYPE twinet_runtime_call_duration_seconds summary\n")
	runtimeKeys := make([]metricKey, 0, len(runtimeCalls))
	for key := range runtimeCalls {
		runtimeKeys = append(runtimeKeys, key)
	}
	sort.Slice(runtimeKeys, func(i, j int) bool {
		if runtimeKeys[i].Name != runtimeKeys[j].Name {
			return runtimeKeys[i].Name < runtimeKeys[j].Name
		}
		return runtimeKeys[i].Result < runtimeKeys[j].Result
	})
	for _, key := range runtimeKeys {
		value := runtimeCalls[key]
		labels := []string{metricLabel("method", key.Name), metricLabel("result", key.Result)}
		writeMetricLine(&b, "twinet_runtime_calls_total", labels, strconv.FormatUint(value.Count, 10))
		writeMetricLine(&b, "twinet_runtime_call_duration_seconds_count", labels,
			strconv.FormatUint(value.Count, 10))
		writeMetricLine(&b, "twinet_runtime_call_duration_seconds_sum", labels,
			strconv.FormatFloat(value.Sum, 'f', -1, 64))
	}

	writeNamedCounterFamily(&b, "twinet_runtime_events_total",
		"Container lifecycle events received by the agent.", "action", events)
	writeNamedCounterFamily(&b, "twinet_repairs_total",
		"Automatic repair outcomes.", "result", repairs)
	writeNamedCounterFamily(&b, "twinet_grading_infrastructure_outcomes_total",
		"Grading infrastructure outcomes at the agent boundary.", "result", grading)
	writeNamedCounterFamily(&b, "twinet_underlay_probes_total",
		"Underlay probe outcomes.", "result", underlay)
	writeMetricHeader(&b, "twinet_underlay_health",
		"Most recent underlay probe health (NaN before any probe).", "gauge")
	health := "NaN"
	switch underlayLast {
	case "success":
		health = "1"
	case "error", "canceled":
		health = "0"
	}
	writeMetricLine(&b, "twinet_underlay_health", nil, health)
	return b.String()
}

func (s *Server) recordPlanMetrics(report *plan.Report) {
	if report == nil {
		return
	}
	for _, result := range report.Results {
		if result.Step == nil {
			continue
		}
		outcome := metricResult(result.Err)
		if result.Skipped {
			outcome = "skipped"
		}
		s.metricRegistry().observePhase(string(result.Step.Stage), result.Duration, outcome)
	}
}

func writeNamedCounterFamily(b *strings.Builder, name, help, label string, values map[string]uint64) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteString(" counter\n")
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writeMetricLine(b, name, []string{metricLabel(label, key)}, strconv.FormatUint(values[key], 10))
	}
}

func cloneUint64Map(in map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func metricPointerValue[T ~int | ~int64 | ~float64](value *T) string {
	if value == nil {
		return "NaN"
	}
	return fmt.Sprint(*value)
}

// handleMetrics emits a self-contained Prometheus text exposition. It has no
// lab, device, container, command, or error-text labels; those belong in the
// scoped event stream, not in an unbounded metric registry.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	containers, listErr := s.rt.List(r.Context(), rt.Filter{
		All: true, Labels: map[string]string{deploy.LabelManaged: "true"},
	})
	inventory := s.observeHostInventory(containers, listErr)

	var b strings.Builder
	b.WriteString(s.metricRegistry().prometheusText())
	appendInventoryMetrics(&b, inventory)
	appendLimiterMetrics(&b, s.workLimiter().Snapshot())
	appendContainerMetrics(&b, containers, listErr)

	overlayCount := -1
	if owners, err := netx.OverlayOwners(); err == nil {
		overlayCount = len(owners)
	}
	physicalTrunks := -1
	if overlays, err := netx.InspectOverlayInventory(""); err == nil {
		overlayCount = len(overlays.Bindings)
		physicalTrunks = len(overlays.Trunks)
	}
	writeMetricHeader(&b, "twinet_overlays", "Active Twinet overlay bindings observed on this node.", "gauge")
	if overlayCount >= 0 {
		writeMetricLine(&b, "twinet_overlays", nil, strconv.Itoa(overlayCount))
	} else {
		writeMetricLine(&b, "twinet_overlays", nil, "NaN")
	}
	writeMetricHeader(&b, "twinet_overlay_logical_bindings",
		"Logical VNI/VLAN bindings observed on this node.", "gauge")
	if overlayCount >= 0 {
		writeMetricLine(&b, "twinet_overlay_logical_bindings", nil, strconv.Itoa(overlayCount))
	} else {
		writeMetricLine(&b, "twinet_overlay_logical_bindings", nil, "NaN")
	}
	writeMetricHeader(&b, "twinet_overlay_physical_trunks",
		"Physical bridge/VXLAN overlay trunks observed on this node.", "gauge")
	if physicalTrunks >= 0 {
		writeMetricLine(&b, "twinet_overlay_physical_trunks", nil, strconv.Itoa(physicalTrunks))
	} else {
		writeMetricLine(&b, "twinet_overlay_physical_trunks", nil, "NaN")
	}

	s.mu.Lock()
	activeLabs, busy, reservations := len(s.current), len(s.ops), 0
	for _, claim := range s.overlayClaims {
		if !claim.Live {
			reservations++
		}
	}
	convergence := map[string]int{}
	for _, observation := range s.health {
		convergence[string(observation.Health)]++
	}
	s.mu.Unlock()
	writeMetricHeader(&b, "twinet_labs", "Current agent lab state.", "gauge")
	writeMetricLine(&b, "twinet_labs", []string{metricLabel("state", "active")}, strconv.Itoa(activeLabs))
	writeMetricLine(&b, "twinet_labs", []string{metricLabel("state", "busy")}, strconv.Itoa(busy))
	writeMetricHeader(&b, "twinet_overlay_reservations", "Outstanding non-live overlay reservations.", "gauge")
	writeMetricLine(&b, "twinet_overlay_reservations", nil, strconv.Itoa(reservations))
	writeMetricHeader(&b, "twinet_convergence_devices",
		"Latest desired-versus-observed device health classifications.", "gauge")
	for _, state := range []string{string(healthHealthy), string(healthBroken), string(healthUnknown), string(healthPartial)} {
		writeMetricLine(&b, "twinet_convergence_devices", []string{metricLabel("state", state)},
			strconv.Itoa(convergence[state]))
	}

	writeMetricHeader(&b, "twinet_metrics_scrape_duration_seconds",
		"Time spent collecting the bounded agent metrics snapshot.", "gauge")
	writeMetricLine(&b, "twinet_metrics_scrape_duration_seconds", nil,
		strconv.FormatFloat(time.Since(start).Seconds(), 'f', -1, 64))
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func writeMetricHeader(b *strings.Builder, name, help, typ string) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(typ)
	b.WriteByte('\n')
}

func appendInventoryMetrics(b *strings.Builder, inventory HostInventory) {
	writeMetricHeader(b, "twinet_inventory_resources",
		"Physical, allocatable, used, and Twinet-reserved node resources.", "gauge")
	for _, entry := range []struct {
		state string
		value ResourceInventory
	}{
		{"physical", inventory.Physical},
		{"allocatable", inventory.Allocatable},
		{"used", inventory.Used},
		{"reserved", inventory.Reserved},
	} {
		for _, resource := range []struct {
			name  string
			value string
		}{
			{"cpus", metricPointerValue(entry.value.CPUs)},
			{"memory_bytes", metricPointerValue(entry.value.MemoryBytes)},
			{"disk_bytes", metricPointerValue(entry.value.DiskBytes)},
			{"pids", metricPointerValue(entry.value.Pids)},
			{"file_descriptors", metricPointerValue(entry.value.FileDescriptors)},
			{"netdevs", metricPointerValue(entry.value.NetDevices)},
			{"containers", metricPointerValue(entry.value.Containers)},
		} {
			writeMetricLine(b, "twinet_inventory_resources", []string{
				metricLabel("state", entry.state), metricLabel("resource", resource.name),
			}, resource.value)
		}
	}
	writeMetricHeader(b, "twinet_inventory_unknown",
		"Inventory dimensions that are unavailable rather than assumed to be zero.", "gauge")
	for _, unknown := range inventory.Unknown {
		writeMetricLine(b, "twinet_inventory_unknown",
			[]string{metricLabel("dimension", boundedInventoryDimension(unknown))}, "1")
	}
	writeMetricHeader(b, "twinet_image_cache",
		"Local image-cache metadata when the runtime exposes it.", "gauge")
	writeMetricLine(b, "twinet_image_cache", []string{metricLabel("state", "referenced")},
		strconv.Itoa(inventory.ImageCache.Referenced))
	writeMetricLine(b, "twinet_image_cache", []string{metricLabel("state", "count")},
		metricPointerValue(inventory.ImageCache.Count))
}

func boundedInventoryDimension(value string) string {
	switch value {
	case "physical.cpus", "allocatable.cpus", "used.cpus",
		"physical.memory", "allocatable.memory", "used.memory",
		"physical.disk", "allocatable.disk", "used.disk",
		"physical.pids", "allocatable.pids", "used.pids",
		"physical.file_descriptors", "allocatable.file_descriptors", "used.file_descriptors",
		"physical.netdevs", "allocatable.netdevs", "used.netdevs",
		"physical.containers", "allocatable.containers", "used.containers",
		"network_devices.count", "network_devices.limit", "image_cache.count", "image_cache.bytes",
		"reserved":
		return value
	default:
		return "other"
	}
}

func appendLimiterMetrics(b *strings.Builder, stats map[string]limiter.Stats) {
	writeMetricHeader(b, "twinet_limiter_pressure",
		"Node-wide runtime and netlink limiter pressure.", "gauge")
	writeMetricHeader(b, "twinet_limiter_wait_seconds",
		"Aggregate wait time for node-wide operation budgets.", "counter")
	keys := make([]string, 0, len(stats))
	for key := range stats {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := stats[key]
		labels := []string{metricLabel("kind", boundedLimiterKind(key))}
		writeMetricLine(b, "twinet_limiter_pressure", append(labels, metricLabel("state", "limit")),
			strconv.Itoa(value.Limit))
		writeMetricLine(b, "twinet_limiter_pressure", append(labels, metricLabel("state", "in_flight")),
			strconv.Itoa(value.InFlight))
		writeMetricLine(b, "twinet_limiter_pressure", append(labels, metricLabel("state", "queue")),
			strconv.Itoa(value.QueueDepth))
		writeMetricLine(b, "twinet_limiter_wait_seconds", labels,
			strconv.FormatFloat(value.TotalWait.Seconds(), 'f', -1, 64))
	}
}

func boundedLimiterKind(value string) string {
	switch value {
	case "apply", "lifecycle", "container_create", "container_start",
		"exec_probe", "netlink", "image_pull", "capture", "convergence":
		return value
	default:
		return "other"
	}
}

func appendContainerMetrics(b *strings.Builder, containers []rt.Container, listErr error) {
	writeMetricHeader(b, "twinet_containers",
		"Managed container counts by normalized lifecycle state.", "gauge")
	if listErr != nil {
		writeMetricLine(b, "twinet_containers", []string{metricLabel("state", "unknown")}, "NaN")
		return
	}
	counts := map[string]int{}
	for _, container := range containers {
		state := string(container.State)
		switch state {
		case string(rt.StateCreated), string(rt.StateRunning), string(rt.StatePaused),
			string(rt.StateRestarting), string(rt.StateExited), string(rt.StateDead),
			string(rt.StateAbsent):
		default:
			state = "unknown"
		}
		counts[state]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writeMetricLine(b, "twinet_containers", []string{metricLabel("state", key)},
			strconv.Itoa(counts[key]))
	}
}
