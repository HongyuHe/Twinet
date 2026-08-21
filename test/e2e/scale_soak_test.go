//go:build e2e && soak

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const releaseSoakDuration = 24 * time.Hour

type soakConfig struct {
	duration     time.Duration
	interval     time.Duration
	device       string
	asn          int
	reportPath   string
	artifactRoot string
}

type soakIteration struct {
	Number       int                  `json:"number"`
	StartedAt    time.Time            `json:"started_at"`
	EndedAt      time.Time            `json:"ended_at"`
	NodesBefore  []e2eNodeObservation `json:"nodes_before,omitempty"`
	NodesAfter   []e2eNodeObservation `json:"nodes_after,omitempty"`
	Fingerprint  string               `json:"configuration_fingerprint,omitempty"`
	Matrix       *soakMatrix          `json:"matrix,omitempty"`
	Save         *soakSave            `json:"save,omitempty"`
	Fault        *soakFault           `json:"fault,omitempty"`
	Grade        *soakGrade           `json:"grade,omitempty"`
	OverlaySweep string               `json:"overlay_sweep,omitempty"`
	Failure      string               `json:"failure,omitempty"`
}

type soakMatrix struct {
	Cells     int      `json:"cells"`
	Reachable int      `json:"reachable"`
	Duration  string   `json:"duration"`
	Failures  []string `json:"failures,omitempty"`
}

type soakSave struct {
	Archive string `json:"archive"`
	SHA256  string `json:"sha256"`
}

type soakFault struct {
	Name     string `json:"name"`
	Injected string `json:"injected"`
	Verified string `json:"verified"`
	Resolved string `json:"resolved"`
}

type soakGrade struct {
	Report   string  `json:"report"`
	Total    float64 `json:"total"`
	MaxTotal float64 `json:"max_total"`
}

type soakReport struct {
	SchemaVersion   int             `json:"schema_version"`
	ReleaseDuration string          `json:"release_duration"`
	Requested       string          `json:"requested_duration"`
	Interval        string          `json:"interval"`
	StartedAt       time.Time       `json:"started_at"`
	EndedAt         time.Time       `json:"ended_at"`
	Device          string          `json:"fingerprint_device"`
	AS              int             `json:"student_as"`
	Baseline        string          `json:"baseline_fingerprint,omitempty"`
	Iterations      []soakIteration `json:"iterations"`
	Passed          bool            `json:"passed"`
	Failure         string          `json:"failure,omitempty"`
}

func requireDestructiveSoak(t *testing.T) {
	t.Helper()
	if os.Getenv("TWINET_SOAK_ALLOW_DESTRUCTIVE") == "1" {
		return
	}
	if os.Getenv("TWINET_SOAK_REQUIRED") == "1" {
		t.Fatal("TWINET_SOAK_REQUIRED is set but TWINET_SOAK_ALLOW_DESTRUCTIVE=1 is not; " +
			"the dedicated soak target must never turn destructive coverage into a skip")
	}
	t.Fatal("TWINET_SOAK_ALLOW_DESTRUCTIVE=1 is required; a soak injects reversible faults and writes snapshots")
}

func soakConfigFromEnv(t *testing.T) soakConfig {
	t.Helper()
	duration := releaseSoakDuration
	if raw := os.Getenv("TWINET_SOAK_DURATION"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			t.Fatalf("TWINET_SOAK_DURATION must be a positive Go duration, got %q", raw)
		}
		duration = parsed
	}
	interval := 30 * time.Minute
	if raw := os.Getenv("TWINET_SOAK_INTERVAL"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			t.Fatalf("TWINET_SOAK_INTERVAL must be a positive Go duration, got %q", raw)
		}
		interval = parsed
	}
	asn := 3
	if raw := os.Getenv("TWINET_SOAK_AS"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			t.Fatalf("TWINET_SOAK_AS must be a positive integer, got %q", raw)
		}
		asn = parsed
	}
	device := os.Getenv("TWINET_SOAK_DEVICE")
	if device == "" {
		device = "as3/CHI"
	}
	artifactRoot := os.Getenv("TWINET_E2E_ARTIFACT_DIR")
	if artifactRoot == "" {
		artifactRoot = filepath.Join("..", "..", "reports", "scale_soak")
	}
	if err := os.MkdirAll(artifactRoot, 0o700); err != nil {
		t.Fatalf("create soak evidence directory: %v", err)
	}
	reportPath := os.Getenv("TWINET_SOAK_REPORT")
	if reportPath == "" {
		reportPath = filepath.Join(artifactRoot, "soak_evidence.json")
	}
	return soakConfig{
		duration: duration, interval: interval, device: device, asn: asn,
		reportPath: reportPath, artifactRoot: artifactRoot,
	}
}

func (r *soakReport) fail(t *testing.T, format string, args ...any) {
	t.Helper()
	r.Failure = fmt.Sprintf(format, args...)
	t.Fatal(r.Failure)
}

func (r *soakReport) write(t *testing.T, path string) {
	t.Helper()
	r.EndedAt = time.Now().UTC()
	r.Passed = !t.Failed() && r.Failure == ""
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Errorf("marshal soak report: %v", err)
		return
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Errorf("write soak report %s: %v", path, err)
	}
}

func configFingerprintResult(t *testing.T, dir, device string) (string, error) {
	t.Helper()
	out, err := twinet(t, "exec", "-m", dir, device, "--", "sh", "-c",
		"sha256sum /etc/frr/frr.conf; ip -o -4 addr show | sort")
	if err != nil {
		return "", fmt.Errorf("fingerprint %s: %w: %s", device, err, out)
	}
	value := strings.TrimSpace(stripCLINoise(out))
	if value == "" {
		return "", fmt.Errorf("fingerprint %s returned no evidence", device)
	}
	return value, nil
}

func checkSoakNodes(nodes, baseline []e2eNodeObservation) error {
	if len(nodes) < 2 {
		return fmt.Errorf("only %d node(s) reported; soak requires a multi-node cluster", len(nodes))
	}
	want := map[string]int{}
	for _, node := range baseline {
		want[node.Node] = node.Status.Containers
	}
	for _, node := range nodes {
		if node.Error != "" || node.Status.Runtime == "" || node.Status.RuntimeVer == "" ||
			node.Status.CPUs < 1 || node.Status.Containers < 0 {
			return fmt.Errorf("node %s has incomplete status/resources", node.Node)
		}
		if expected, ok := want[node.Node]; !ok {
			return fmt.Errorf("unexpected node %s appeared during soak", node.Node)
		} else if node.Status.Containers != expected {
			return fmt.Errorf("unexplained process death or creation on %s: managed containers %d, baseline %d",
				node.Node, node.Status.Containers, expected)
		}
		if len(node.Status.Busy) != 0 {
			return fmt.Errorf("node %s still reports a mutating operation: %s",
				node.Node, strings.Join(node.Status.Busy, ", "))
		}
	}
	return nil
}

func collectSoakMatrix(t *testing.T, dir string) (*soakMatrix, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("reserve loopback matrix port: %w", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return nil, fmt.Errorf("release loopback matrix port: %w", err)
	}

	binary := os.Getenv("TWINET_BIN")
	if binary == "" {
		binary = controller(t)
	}
	cmd := exec.Command(binary, "web", "-m", dir, "--listen", address, "--refresh", "1h")
	cmd.Env = os.Environ()
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start matrix-equivalent web probe: %w", err)
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}()

	type matrixCell struct {
		From   int    `json:"from"`
		To     int    `json:"to"`
		State  string `json:"state"`
		Detail string `json:"detail"`
	}
	type matrixResponse struct {
		Duration  string       `json:"duration"`
		Reachable int          `json:"reachable"`
		Total     int          `json:"total"`
		Cells     []matrixCell `json:"cells"`
	}

	deadline := time.Now().Add(6 * time.Minute)
	httpClient := &http.Client{Timeout: 10 * time.Second}
	var last string
	for time.Now().Before(deadline) {
		response, getErr := httpClient.Get("http://" + address + "/matrix.json")
		if getErr != nil {
			last = getErr.Error()
			time.Sleep(2 * time.Second)
			continue
		}
		raw, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			last = readErr.Error()
			time.Sleep(2 * time.Second)
			continue
		}
		if response.StatusCode != http.StatusOK {
			last = fmt.Sprintf("matrix endpoint returned %s: %s", response.Status, raw)
			time.Sleep(2 * time.Second)
			continue
		}
		var matrix matrixResponse
		if err := json.Unmarshal(raw, &matrix); err != nil || matrix.Total == 0 || len(matrix.Cells) == 0 {
			last = fmt.Sprintf("matrix is not ready: %s", raw)
			time.Sleep(2 * time.Second)
			continue
		}
		if len(matrix.Cells) != matrix.Total {
			return nil, fmt.Errorf("matrix reported %d cells but returned %d", matrix.Total, len(matrix.Cells))
		}
		result := &soakMatrix{Cells: matrix.Total, Reachable: matrix.Reachable, Duration: matrix.Duration}
		for _, cell := range matrix.Cells {
			if cell.State != "ok" {
				result.Failures = append(result.Failures,
					fmt.Sprintf("%d->%d is %s: %s", cell.From, cell.To, cell.State, cell.Detail))
			}
		}
		if len(result.Failures) > 0 {
			return result, fmt.Errorf("matrix-equivalent probe found %d non-healthy paths", len(result.Failures))
		}
		if matrix.Reachable != matrix.Total {
			return result, fmt.Errorf("matrix reports %d of %d reachable paths", matrix.Reachable, matrix.Total)
		}
		return result, nil
	}
	return nil, fmt.Errorf("matrix-equivalent probe did not produce a snapshot within six minutes: %s", last)
}

func saveSoakSnapshot(t *testing.T, dir, output string, asn int) (*soakSave, error) {
	t.Helper()
	if err := os.MkdirAll(output, 0o700); err != nil {
		return nil, err
	}
	out, err := twinet(t, "save", "-m", dir, "-o", output, "--as", strconv.Itoa(asn))
	if err != nil {
		return nil, fmt.Errorf("save AS %d: %w: %s", asn, err, out)
	}
	entries, err := os.ReadDir(output)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
		path := filepath.Join(output, entry.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		return &soakSave{Archive: path, SHA256: hex.EncodeToString(sum[:])}, nil
	}
	return nil, fmt.Errorf("save wrote no submission archive")
}

func runSoakFault(t *testing.T, dir string, asn int) (*soakFault, error) {
	t.Helper()
	const name = "link_bandwidth_throttling"
	out, err := twinet(t, "fault", "inject", "-m", dir, name,
		"--as", strconv.Itoa(asn), "--device", "CHI", "--iface", "port_MSP")
	if err != nil {
		return nil, fmt.Errorf("inject %s: %w: %s", name, err, out)
	}
	result := &soakFault{Name: name, Injected: strings.TrimSpace(out)}
	t.Cleanup(func() {
		if cleanup, cleanupErr := twinet(t, "fault", "resolve", "-m", dir, "--all"); cleanupErr != nil {
			t.Errorf("resolve soak fault during cleanup: %v\n%s", cleanupErr, cleanup)
		}
	})
	verified, err := twinet(t, "fault", "verify", "-m", dir, name)
	if err != nil {
		return result, fmt.Errorf("verify %s: %w: %s", name, err, verified)
	}
	result.Verified = strings.TrimSpace(verified)
	resolved, err := twinet(t, "fault", "resolve", "-m", dir, "--all")
	if err != nil {
		return result, fmt.Errorf("resolve %s: %w: %s", name, err, resolved)
	}
	result.Resolved = strings.TrimSpace(resolved)
	return result, nil
}

func runSoakGrade(t *testing.T, dir, output string, asn int) (*soakGrade, error) {
	t.Helper()
	if err := os.MkdirAll(output, 0o700); err != nil {
		return nil, err
	}
	out, err := twinet(t, "grade", "run", "-m", dir, "--as", strconv.Itoa(asn),
		"-o", output, "--converge-timeout", "6m")
	if err != nil {
		return nil, fmt.Errorf("grade AS %d: %w: %s", asn, err, out)
	}
	path := filepath.Join(output, "group"+strconv.Itoa(asn)+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read grade report: %w", err)
	}
	var report struct {
		Total       float64 `json:"total"`
		MaxTotal    float64 `json:"max_total"`
		Err         string  `json:"error"`
		NeedsReview bool    `json:"needs_review"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse grade report: %w", err)
	}
	if report.Err != "" || report.NeedsReview {
		return nil, fmt.Errorf("false infrastructure-shaped grading deduction: needs_review=%v error=%q",
			report.NeedsReview, report.Err)
	}
	if report.MaxTotal <= 0 || report.Total < report.MaxTotal {
		return nil, fmt.Errorf("reference lost marks during soak: %.2f of %.2f", report.Total, report.MaxTotal)
	}
	return &soakGrade{Report: path, Total: report.Total, MaxTotal: report.MaxTotal}, nil
}

func sweepResult(t *testing.T, dir string) (string, error) {
	t.Helper()
	out, err := twinet(t, "node", "sweep", "-m", dir)
	if err != nil {
		return out, fmt.Errorf("inspect stale overlays: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] != "NODE" && fields[1] != "0" {
			return out, fmt.Errorf("node %s retains %s stale overlay object(s)", fields[0], fields[1])
		}
	}
	return out, nil
}

func TestScaleSoak(t *testing.T) {
	requireDestructiveSoak(t)
	config := soakConfigFromEnv(t)
	report := &soakReport{
		SchemaVersion:   1,
		ReleaseDuration: "24h",
		Requested:       config.duration.String(),
		Interval:        config.interval.String(),
		StartedAt:       time.Now().UTC(),
		Device:          config.device,
		AS:              config.asn,
	}
	defer report.write(t, config.reportPath)

	dir := labDir(t)
	baselineNodes := requireHealthyMultiNodeCluster(t, dir)
	baseline, err := configFingerprintResult(t, dir, config.device)
	if err != nil {
		report.fail(t, "%v", err)
	}
	report.Baseline = baseline

	deadline := time.Now().Add(config.duration)
	for iterationNumber := 1; ; iterationNumber++ {
		iteration := soakIteration{Number: iterationNumber, StartedAt: time.Now().UTC()}
		nodes, statusErr := statusObservations(t, dir)
		if statusErr != nil {
			iteration.Failure = statusErr.Error()
			report.Iterations = append(report.Iterations, iteration)
			report.fail(t, "status before soak iteration %d: %v", iterationNumber, statusErr)
		}
		iteration.NodesBefore = nodes
		if err := checkSoakNodes(nodes, baselineNodes); err != nil {
			iteration.Failure = err.Error()
			report.Iterations = append(report.Iterations, iteration)
			report.fail(t, "soak iteration %d: %v", iterationNumber, err)
		}

		fingerprint, err := configFingerprintResult(t, dir, config.device)
		if err != nil {
			iteration.Failure = err.Error()
			report.Iterations = append(report.Iterations, iteration)
			report.fail(t, "%v", err)
		}
		iteration.Fingerprint = fingerprint
		if fingerprint != baseline {
			iteration.Failure = "configuration fingerprint drifted"
			report.Iterations = append(report.Iterations, iteration)
			report.fail(t, "configuration drift on %s\nbaseline:\n%s\nobserved:\n%s",
				config.device, baseline, fingerprint)
		}

		matrix, err := collectSoakMatrix(t, dir)
		iteration.Matrix = matrix
		if err != nil {
			iteration.Failure = err.Error()
			report.Iterations = append(report.Iterations, iteration)
			report.fail(t, "soak iteration %d: %v", iterationNumber, err)
		}

		saveDir := filepath.Join(config.artifactRoot, fmt.Sprintf("save_%03d", iterationNumber))
		saved, err := saveSoakSnapshot(t, dir, saveDir, config.asn)
		iteration.Save = saved
		if err != nil {
			iteration.Failure = err.Error()
			report.Iterations = append(report.Iterations, iteration)
			report.fail(t, "soak iteration %d: %v", iterationNumber, err)
		}

		fault, err := runSoakFault(t, dir, config.asn)
		iteration.Fault = fault
		if err != nil {
			iteration.Failure = err.Error()
			report.Iterations = append(report.Iterations, iteration)
			report.fail(t, "soak iteration %d: %v", iterationNumber, err)
		}
		if current, fingerprintErr := configFingerprintResult(t, dir, config.device); fingerprintErr != nil {
			iteration.Failure = fingerprintErr.Error()
			report.Iterations = append(report.Iterations, iteration)
			report.fail(t, "%v", fingerprintErr)
		} else if current != baseline {
			iteration.Failure = "configuration fingerprint drifted after reversible fault"
			report.Iterations = append(report.Iterations, iteration)
			report.fail(t, "reversible fault did not restore configuration on %s", config.device)
		}

		// Grade at least once in every run, then once per six hours of a
		// release soak. A clean reference that receives a provisional or short
		// mark is an infrastructure failure, never a student deduction.
		if iterationNumber == 1 || time.Until(deadline) < 6*time.Hour ||
			iterationNumber%12 == 0 {
			gradeDir := filepath.Join(config.artifactRoot, fmt.Sprintf("grade_%03d", iterationNumber))
			graded, err := runSoakGrade(t, dir, gradeDir, config.asn)
			iteration.Grade = graded
			if err != nil {
				iteration.Failure = err.Error()
				report.Iterations = append(report.Iterations, iteration)
				report.fail(t, "soak iteration %d: %v", iterationNumber, err)
			}
		}

		sweep, err := sweepResult(t, dir)
		iteration.OverlaySweep = sweep
		if err != nil {
			iteration.Failure = err.Error()
			report.Iterations = append(report.Iterations, iteration)
			report.fail(t, "soak iteration %d: %v", iterationNumber, err)
		}
		nodes, statusErr = statusObservations(t, dir)
		iteration.NodesAfter = nodes
		iteration.EndedAt = time.Now().UTC()
		report.Iterations = append(report.Iterations, iteration)
		if statusErr != nil {
			report.fail(t, "status after soak iteration %d: %v", iterationNumber, statusErr)
		}
		if err := checkSoakNodes(nodes, baselineNodes); err != nil {
			report.fail(t, "soak iteration %d: %v", iterationNumber, err)
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		if remaining > config.interval {
			remaining = config.interval
		}
		time.Sleep(remaining)
	}
}
