package msc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// CredentialWorker assigns each credential-bearing appliance to exactly one
// worker. SSH uses the operator's existing authenticated, host-key-checked
// transport. An empty SSH field denotes the authority's local worker.
type CredentialWorker struct {
	Name           string   `json:"name"`
	SSH            string   `json:"ssh,omitempty"`
	IdentityFile   string   `json:"identity_file,omitempty"`
	KnownHostsFile string   `json:"known_hosts_file,omitempty"`
	Binary         string   `json:"binary"`
	StateDir       string   `json:"state_dir"`
	Devices        []string `json:"devices"`
}
type CredentialTargets struct {
	Workers []CredentialWorker `json:"workers"`
}
type CredentialEntry struct {
	Device string            `json:"device"`
	Kind   string            `json:"kind"`
	Files  map[string][]byte `json:"files"`
}

// CredentialBundle is secret transport data. Never include it in logs, reports,
// command-line arguments, or public snapshot exports. It contains only the
// assigned devices' keys, never a CA signing key or another worker's leaves.
type CredentialBundle struct {
	Version       int               `json:"version"`
	Spec          *Spec             `json:"spec"`
	Worker        string            `json:"worker"`
	Devices       []string          `json:"devices"`
	Entries       []CredentialEntry `json:"entries"`
	ProvisionOnly bool              `json:"provision_only"`
}
type CredentialWorkerResult struct {
	Worker    string `json:"worker"`
	Devices   int    `json:"devices"`
	Applied   bool   `json:"applied"`
	Connected bool   `json:"connected"`
	Error     string `json:"error,omitempty"`
}
type CredentialReport struct {
	At      time.Time                `json:"at"`
	Passed  bool                     `json:"passed"`
	Workers []CredentialWorkerResult `json:"workers"`
	Error   string                   `json:"error,omitempty"`
}

var credentialFiles = []string{"private/key.pem", "x509/cert.pem", "x509ca/ca.pem", "x509crl/ca.crl.pem"}
var sshDestination = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.@:-]*$`)

func (e *Engine) LocalCredentialTargets() CredentialTargets {
	ids := map[string]bool{}
	for _, b := range e.credentialBindings() {
		ids[b.Device.ID] = true
	}
	w := CredentialWorker{Name: "local", StateDir: e.Dir}
	for id := range ids {
		w.Devices = append(w.Devices, id)
	}
	sort.Strings(w.Devices)
	return CredentialTargets{Workers: []CredentialWorker{w}}
}

func (e *Engine) ValidateCredentialTargets(plan CredentialTargets) error {
	expected := map[string]bool{}
	for _, b := range e.credentialBindings() {
		expected[b.Device.ID] = true
	}
	names := map[string]bool{}
	for _, w := range plan.Workers {
		if !identifier.MatchString(w.Name) || names[w.Name] || !filepath.IsAbs(w.StateDir) || filepath.Clean(w.StateDir) == "/" || len(w.Devices) == 0 {
			return fmt.Errorf("invalid or duplicate credential worker %q", w.Name)
		}
		names[w.Name] = true
		if w.SSH != "" && (!sshDestination.MatchString(w.SSH) || !filepath.IsAbs(w.Binary) || strings.ContainsAny(w.Binary+w.StateDir, "\n\r\x00")) {
			return fmt.Errorf("invalid SSH target for %s", w.Name)
		}
		for _, path := range []string{w.IdentityFile, w.KnownHostsFile} {
			if path != "" && (!filepath.IsAbs(path) || strings.ContainsAny(path, "\n\r\x00")) {
				return fmt.Errorf("SSH credential paths must be absolute")
			}
		}
		if w.SSH == "" && filepath.Clean(w.StateDir) != filepath.Clean(e.Dir) {
			return fmt.Errorf("local worker must use the authority state directory")
		}
		for _, id := range w.Devices {
			if !expected[id] {
				return fmt.Errorf("unknown, duplicate, or credential-free device %q", id)
			}
			delete(expected, id)
		}
	}
	if len(expected) != 0 {
		return fmt.Errorf("credential placement does not cover all devices")
	}
	return nil
}

func (e *Engine) BuildCredentialBundle(w CredentialWorker, provisionOnly bool) (CredentialBundle, error) {
	out := CredentialBundle{Version: 1, Spec: e.Spec, Worker: w.Name, Devices: w.Devices, ProvisionOnly: provisionOnly}
	wanted := map[string]bool{}
	for _, id := range w.Devices {
		wanted[id] = true
	}
	for _, b := range e.credentialBindings() {
		if !wanted[b.Device.ID] {
			continue
		}
		dir := e.bindingDir(b)
		if err := e.leaf(b.Device, b.Trust, dir, b.IP, false); err != nil {
			return out, err
		}
		entry := CredentialEntry{Device: b.Device.ID, Kind: b.Kind, Files: map[string][]byte{}}
		for _, name := range credentialFiles {
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return out, err
			}
			entry.Files[name] = raw
		}
		out.Entries = append(out.Entries, entry)
	}
	return out, nil
}

// ValidateCredentialBundle runs before any destination write. The authenticated
// operator transport authorizes initial enrollment. Later updates must retain
// existing CA anchors and all known revocations, and cannot replay old CRLs.
func (e *Engine) ValidateCredentialBundle(bundle CredentialBundle) error {
	if bundle.Version != 1 || bundle.Spec == nil || bundle.Spec.Hash() != e.Spec.Hash() || !identifier.MatchString(bundle.Worker) {
		return fmt.Errorf("invalid credential bundle identity")
	}
	if err := e.Spec.Validate(); err != nil {
		return err
	}
	if raw, readErr := os.ReadFile(filepath.Join(e.Dir, "credential-worker.json")); readErr == nil {
		var previous struct {
			Worker  string   `json:"worker"`
			Devices []string `json:"devices"`
		}
		if err := json.Unmarshal(raw, &previous); err != nil {
			return err
		}
		oldIDs := append([]string{}, previous.Devices...)
		newIDs := append([]string{}, bundle.Devices...)
		sort.Strings(oldIDs)
		sort.Strings(newIDs)
		if previous.Worker != bundle.Worker || strings.Join(oldIDs, ",") != strings.Join(newIDs, ",") {
			return fmt.Errorf("worker assignment changed; explicit reprovisioning is required")
		}
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	if saved, err := Load(filepath.Join(e.Dir, "spec.json")); err == nil {
		if saved.Hash() != e.Spec.Hash() {
			return fmt.Errorf("credential bundle does not match deployed specification")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	expected := map[string]credentialBinding{}
	wanted := map[string]bool{}
	for _, id := range bundle.Devices {
		if wanted[id] || e.Spec.Device(id) == nil {
			return fmt.Errorf("invalid device assignment")
		}
		wanted[id] = true
	}
	for _, b := range e.credentialBindings() {
		if wanted[b.Device.ID] {
			expected[b.Device.ID+"/"+b.Kind] = b
		}
	}
	if len(expected) == 0 || len(expected) != len(bundle.Entries) {
		return fmt.Errorf("incomplete credential bundle")
	}
	for _, entry := range bundle.Entries {
		index := entry.Device + "/" + entry.Kind
		b, ok := expected[index]
		if !ok {
			return fmt.Errorf("unexpected credential entry")
		}
		delete(expected, index)
		if len(entry.Files) != len(credentialFiles) {
			return fmt.Errorf("unexpected credential files")
		}
		for _, name := range credentialFiles {
			if len(entry.Files[name]) == 0 {
				return fmt.Errorf("missing credential %s", name)
			}
		}
		parseCert := func(name string) (*x509.Certificate, error) {
			block, rest := pem.Decode(entry.Files[name])
			if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
				return nil, fmt.Errorf("invalid certificate")
			}
			return x509.ParseCertificate(block.Bytes)
		}
		ca, err := parseCert("x509ca/ca.pem")
		if err != nil {
			return err
		}
		if ca.Subject.CommonName != "Twinet MSC "+b.Trust {
			return fmt.Errorf("wrong trust domain for %s", entry.Device)
		}
		cert, err := parseCert("x509/cert.pem")
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: e.now(), DNSName: b.Device.ID + ".msc.test", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return fmt.Errorf("device certificate validation: %w", err)
		}
		if cert.IsCA || cert.Subject.CommonName != b.Device.ID+".msc.test" || len(cert.DNSNames) != 1 {
			return fmt.Errorf("incorrect device identity")
		}
		if b.IP != "" {
			if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != b.IP {
				return fmt.Errorf("incorrect management IP identity")
			}
		} else if len(cert.IPAddresses) != 0 {
			return fmt.Errorf("unexpected IP identity")
		}
		block, rest := pem.Decode(entry.Files["private/key.pem"])
		if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return fmt.Errorf("invalid private key")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return fmt.Errorf("invalid signing key")
		}
		public, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil {
			return err
		}
		if !bytes.Equal(public, cert.RawSubjectPublicKeyInfo) {
			return fmt.Errorf("device key mismatch")
		}
		block, rest = pem.Decode(entry.Files["x509crl/ca.crl.pem"])
		if block == nil || block.Type != "X509 CRL" || len(bytes.TrimSpace(rest)) != 0 {
			return fmt.Errorf("invalid CRL")
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return err
		}
		if err = crl.CheckSignatureFrom(ca); err != nil {
			return err
		}
		if crl.Number == nil || crl.ThisUpdate.After(e.now()) || !crl.NextUpdate.After(e.now()) || revokedBy(crl, cert) {
			return fmt.Errorf("stale CRL or revoked certificate for %s", entry.Device)
		}
		dir := e.bindingDir(b)
		if old, readErr := readCert(filepath.Join(dir, "x509ca/ca.pem")); readErr == nil {
			if !bytes.Equal(old.Raw, ca.Raw) {
				return fmt.Errorf("refuse CA replacement for %s", entry.Device)
			}
		} else if !os.IsNotExist(readErr) {
			return readErr
		}
		if old, readErr := readCRL(filepath.Join(dir, "x509crl/ca.crl.pem"), ca); readErr == nil {
			if crl.Number.Cmp(old.Number) < 0 || crl.Number.Cmp(old.Number) == 0 && !bytes.Equal(crl.Raw, old.Raw) {
				return fmt.Errorf("refuse CRL rollback for %s", entry.Device)
			}
			for _, r := range old.RevokedCertificateEntries {
				if !revokedBy(crl, &x509.Certificate{SerialNumber: r.SerialNumber}) {
					return fmt.Errorf("refuse removal of recorded revocation")
				}
			}
		} else if !os.IsNotExist(readErr) {
			return readErr
		}
	}
	return nil
}

func (e *Engine) ApplyCredentialBundle(ctx context.Context, bundle CredentialBundle, remoteWorker bool) error {
	if _, err := os.Stat(filepath.Join(e.Dir, "fault.json")); err == nil {
		return fmt.Errorf("credential maintenance refuses an active fault")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := e.ValidateCredentialBundle(bundle); err != nil {
		return err
	}
	for _, id := range bundle.Devices {
		c, err := e.owned(ctx, e.Spec.Device(id))
		if err != nil {
			return err
		}
		if !bundle.ProvisionOnly && c.State != rt.StateRunning {
			return fmt.Errorf("%s is not running", id)
		}
	}
	changed := map[string]bool{}
	for _, entry := range bundle.Entries {
		dir := filepath.Join(e.Dir, "devices", entry.Device, entry.Kind)
		for _, name := range credentialFiles {
			path := filepath.Join(dir, name)
			old, _ := os.ReadFile(path)
			if !bytes.Equal(old, entry.Files[name]) {
				changed[entry.Device+"/"+entry.Kind] = true
				if err := writePrivate(path, entry.Files[name]); err != nil {
					return err
				}
			}
		}
		if entry.Kind == "swanctl" {
			config := filepath.Join(dir, "swanctl.conf")
			if _, err := os.Stat(config); os.IsNotExist(err) {
				if err = writePrivate(config, []byte(swanConfig(e.Spec.Device(entry.Device)))); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
		}
	}
	if remoteWorker {
		marker, _ := json.Marshal(struct {
			Worker  string   `json:"worker"`
			Devices []string `json:"devices"`
		}{bundle.Worker, bundle.Devices})
		if err := writePrivate(filepath.Join(e.Dir, "credential-worker.json"), marker); err != nil {
			return err
		}
		body, _ := json.Marshal(e.Spec)
		if err := writePrivate(filepath.Join(e.Dir, "spec.json"), body); err != nil {
			return err
		}
	}
	if bundle.ProvisionOnly {
		return nil
	}
	var failures []error
	for _, id := range bundle.Devices {
		d := e.Spec.Device(id)
		if d.Tunnel != nil {
			if err := e.startIPsec(ctx, d); err != nil {
				failures = append(failures, err)
				continue
			}
			loaded, err := e.exec(ctx, id, "swanctl", "--list-certs", "--pem")
			if err == nil {
				certs, crls, parseErr := decodePublicPEM([]byte(loaded))
				err = parseErr
				leaf, leafErr := readCert(filepath.Join(e.tunnelDir(d), "x509/cert.pem"))
				if leafErr != nil {
					err = leafErr
				}
				ca, caErr := readCert(filepath.Join(e.tunnelDir(d), "x509ca/ca.pem"))
				if caErr != nil {
					err = caErr
				}
				if err == nil {
					crl, crlErr := readCRL(filepath.Join(e.tunnelDir(d), "x509crl/ca.crl.pem"), ca)
					err = crlErr
					if err == nil {
						foundLeaf, foundCRL := false, false
						for _, c := range certs {
							foundLeaf = foundLeaf || bytes.Equal(c.Raw, leaf.Raw)
						}
						for _, c := range crls {
							foundCRL = foundCRL || bytes.Equal(c.Raw, crl.Raw)
						}
						if !foundLeaf || !foundCRL {
							err = fmt.Errorf("%s did not load renewed credentials", id)
						}
					}
				}
			}
			if err != nil {
				failures = append(failures, err)
			}
		}
		if d.Admin != "" && (changed[id+"/tls"] || !remoteWorker) {
			if err := e.copyFile(ctx, e.Spec.Container(id), "/tmp/msc-admin.py", 0600, []byte(adminServer)); err != nil {
				failures = append(failures, err)
				continue
			}
			if err := e.background(ctx, id, "pkill -f '^python3 /tmp/msc-admin.py$' || true; exec python3 /tmp/msc-admin.py >/tmp/msc-admin.log 2>&1"); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func (e *Engine) ConnectCredentialDevices(ctx context.Context, ids []string, layer string) error {
	if layer != "inner" && layer != "outer" {
		return fmt.Errorf("invalid encryption layer")
	}
	var failures []error
	for _, id := range ids {
		d := e.Spec.Device(id)
		if d == nil {
			return fmt.Errorf("unknown device %s", id)
		}
		if d.Tunnel == nil || d.Role != layer || d.ID > d.Tunnel.Peer {
			continue
		}
		if _, err := e.owned(ctx, d); err != nil {
			failures = append(failures, err)
			continue
		}
		sas, err := e.exec(ctx, id, "swanctl", "--list-sas")
		if err == nil && strings.Contains(sas, "ESTABLISHED") && strings.Contains(sas, "INSTALLED") {
			continue
		}
		if _, err = e.exec(ctx, id, "swanctl", "--initiate", "--child", "protected"); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func credentialSSH(ctx context.Context, w CredentialWorker, args []string, input []byte) error {
	command := []string{"sudo", "-n", w.Binary, "msc", "--state-dir", w.StateDir, "--spec", filepath.Join(w.StateDir, "spec.json"), "credentials"}
	command = append(command, args...)
	for i := range command {
		command[i] = shellQuote(command[i])
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	sshArgs := []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10"}
	if w.IdentityFile != "" {
		sshArgs = append(sshArgs, "-i", w.IdentityFile, "-o", "IdentitiesOnly=yes")
	}
	if w.KnownHostsFile != "" {
		sshArgs = append(sshArgs, "-o", "UserKnownHostsFile="+w.KnownHostsFile)
	}
	sshArgs = append(sshArgs, "--", w.SSH, strings.Join(command, " "))
	cmd := exec.CommandContext(cctx, "ssh", sshArgs...)
	cmd.Stdin = bytes.NewReader(input)
	// Remote output is never forwarded: input contains keys and a broken helper
	// must not accidentally turn them into a controller log or public report.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("worker %s credential command failed: %w; inspect its credential-receipt.json", w.Name, err)
	}
	return nil
}

func (e *Engine) RenewCredentials(ctx context.Context, plan CredentialTargets, force, provisionOnly bool) (report CredentialReport, err error) {
	report = CredentialReport{At: e.now(), Passed: false, Workers: []CredentialWorkerResult{}}
	defer func() {
		report.Passed = err == nil
		if err != nil {
			report.Error = err.Error()
		}
		body, _ := json.MarshalIndent(report, "", "  ")
		if saveErr := writePrivate(filepath.Join(e.Dir, "credential-renewal.json"), body); saveErr != nil {
			err = errors.Join(err, saveErr)
			report.Passed = false
			report.Error = err.Error()
		}
	}()
	if _, statErr := os.Stat(filepath.Join(e.Dir, "credential-worker.json")); statErr == nil {
		return report, fmt.Errorf("run renewal on the authority, not a credential worker")
	} else if !os.IsNotExist(statErr) {
		return report, statErr
	}
	if _, statErr := os.Stat(filepath.Join(e.Dir, "fault.json")); statErr == nil {
		return report, fmt.Errorf("credential maintenance refuses an active fault")
	} else if !os.IsNotExist(statErr) {
		return report, statErr
	}
	if err = e.ValidateCredentialTargets(plan); err != nil {
		return report, err
	}
	if force {
		seen := map[string]bool{}
		for _, b := range e.credentialBindings() {
			if seen[b.Trust] {
				continue
			}
			seen[b.Trust] = true
			if _, err = e.canonicalCRL(b.Trust, nil, true); err != nil {
				return report, err
			}
		}
	}
	bundles := make([]CredentialBundle, len(plan.Workers))
	for i, w := range plan.Workers {
		bundles[i], err = e.BuildCredentialBundle(w, provisionOnly)
		if err != nil {
			return report, err
		}
	}
	var failures []error
	for i, w := range plan.Workers {
		result := CredentialWorkerResult{Worker: w.Name, Devices: len(w.Devices)}
		if w.SSH == "" {
			err = e.ApplyCredentialBundle(ctx, bundles[i], false)
		} else {
			var body []byte
			body, err = json.Marshal(bundles[i])
			if err == nil {
				err = credentialSSH(ctx, w, []string{"apply"}, body)
			}
		}
		result.Applied = err == nil
		if err != nil {
			result.Error = err.Error()
			failures = append(failures, err)
		}
		report.Workers = append(report.Workers, result)
	}
	if len(failures) == 0 && !provisionOnly {
		for _, layer := range []string{"outer", "inner"} {
			for i, w := range plan.Workers {
				if w.SSH == "" {
					err = e.ConnectCredentialDevices(ctx, w.Devices, layer)
				} else {
					err = credentialSSH(ctx, w, []string{"connect", "--devices", strings.Join(w.Devices, ","), "--layer", layer}, nil)
				}
				if err != nil {
					report.Workers[i].Error = err.Error()
					failures = append(failures, err)
				}
			}
		}
		for i := range report.Workers {
			report.Workers[i].Connected = report.Workers[i].Error == ""
		}
	}
	err = errors.Join(failures...)
	return report, err
}
