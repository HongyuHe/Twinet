package deploy

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/runtime"
)

// hardenedRuntimeSpec maps the typed model policy to one OCI runtime request.
// It is intentionally the sole mapping point: creating one device without it
// is a security regression rather than a merely different Docker invocation.
func (e *Engine) hardenedRuntimeSpec(d *model.Device, binds []runtime.Bind) (*runtime.Spec, error) {
	if d == nil {
		return nil, fmt.Errorf("cannot harden a nil device")
	}
	h := model.EffectiveRuntimeHardening(d.Kind, d.Hardening)
	if d.EffectiveNOS() == "bird" {
		h.WritablePaths = append(h.WritablePaths, "/etc/bird")
	}
	if err := validateRuntimeHardening(d, h); err != nil {
		return nil, err
	}
	if e.Runtime != nil && e.Runtime.Name() == "podman" &&
		(len(h.MaskedPaths) > 0 || len(h.ReadonlyPaths) > 0) {
		return nil, fmt.Errorf(
			"runtime podman cannot enforce required masked/readonly system paths for %s; refusing a weaker deployment",
			d.ID)
	}
	tmpfs := map[string]string{}
	for _, target := range h.WritablePaths {
		if bindCovers(target, binds) {
			continue
		}
		tmpfs[target] = hardeningTmpfsOptions(target)
	}
	security := []string{
		"no-new-privileges",
		"seccomp=" + h.SeccompProfile,
		"apparmor=" + h.AppArmorProfile,
	}
	return &runtime.Spec{
		CapDrop:        []string{"ALL"},
		Capabilities:   effectiveCapabilities(d),
		SecurityOpt:    security,
		ReadOnlyRootfs: *h.ReadOnlyRootfs,
		RuntimeClass:   h.RuntimeClass,
		UsernsMode:     h.UsernsMode,
		PidMode:        h.PIDMode,
		MaskedPaths:    append([]string(nil), h.MaskedPaths...),
		ReadonlyPaths:  append([]string(nil), h.ReadonlyPaths...),
		Tmpfs:          tmpfs,
		NetworkMode:    "none",
	}, nil
}

func hardeningTmpfsOptions(target string) string {
	if target == "/tmp" || target == "/var/tmp" {
		return "rw,nosuid,nodev,noexec,mode=1777,size=64m"
	}
	return "rw,nosuid,nodev,size=64m"
}

func bindCovers(target string, binds []runtime.Bind) bool {
	for _, bind := range binds {
		if bind.Target == target || strings.HasPrefix(target, strings.TrimRight(bind.Target, "/")+"/") {
			return true
		}
	}
	return false
}

func effectiveCapabilities(d *model.Device) []string {
	set := map[string]bool{}
	for _, capability := range d.Capabilities {
		if capability != "" {
			set[normalizeCapability(capability)] = true
		}
	}
	// Dropping ALL removes Docker's default NET_BIND_SERVICE capability. FRR
	// and DNS legitimately bind well-known ports, so add only that missing
	// capability where the shipped programs actually need it.
	switch d.Kind {
	case model.KindRouter:
		set["NET_BIND_SERVICE"] = true
		// Student shells edit their own FRR configuration through a narrow
		// bind owned by the frr user; root in the user namespace needs this
		// capability to retain the historical shell workflow.
		set["DAC_OVERRIDE"] = true
	case model.KindService:
		set["NET_BIND_SERVICE"] = true
		// BIND starts as root, binds port 53, then drops to named.
		set["SETUID"], set["SETGID"], set["CHOWN"] = true, true, true
	}
	out := make([]string, 0, len(set))
	for capability := range set {
		out = append(out, capability)
	}
	sort.Strings(out)
	return out
}

// effectiveRuntimeLimits ensures every expanded device gets enforceable
// cgroup limits even when an older manifest only declared schedulable
// requests. Requests are conservative per-kind defaults, so using them as the
// compatibility limit is safer than leaving a container unlimited.
func effectiveRuntimeLimits(d *model.Device) (cpus float64, memory string, pids int64) {
	if d == nil {
		return 0, "", 0
	}
	request := d.Requests
	if request.Empty() {
		request = model.DefaultResourceRequest(d.Kind)
	}
	cpus, memory, pids = d.CPUs, d.Memory, d.Pids
	if cpus <= 0 {
		cpus = request.CPUs
	}
	if memory == "" {
		memory = request.Memory
	}
	if pids <= 0 {
		pids = request.Pids
	}
	return cpus, memory, pids
}

func normalizeCapability(capability string) string {
	capability = strings.ToUpper(strings.TrimSpace(capability))
	return strings.TrimPrefix(capability, "CAP_")
}

func frrControlCapabilities(d *model.Device) []string {
	set := map[string]bool{}
	for _, capability := range effectiveCapabilities(d) {
		set[capability] = true
	}
	// FRR's init script manages daemons owned by the frr/frrvty accounts and
	// their shared vty/config paths. KILL is needed because root must stop
	// daemons running as frr during the reversible FRR lifecycle fault. These
	// additions are intentionally confined to the internal sidecar, never a
	// topology router shell.
	for _, capability := range []string{"SYS_ADMIN", "SETUID", "SETGID", "CHOWN", "DAC_OVERRIDE", "FOWNER", "KILL"} {
		set[capability] = true
	}
	out := make([]string, 0, len(set))
	for capability := range set {
		out = append(out, capability)
	}
	sort.Strings(out)
	return out
}

func validateRuntimeHardening(d *model.Device, h model.RuntimeHardening) error {
	if d.Privileged {
		if !h.DevelopmentOverrideActive() {
			return fmt.Errorf("%s requests privileged mode without an audited development override", d.ID)
		}
		return fmt.Errorf("%s requests privileged mode; Twinet devices may never be privileged", d.ID)
	}
	if h.NoNewPrivileges == nil || !*h.NoNewPrivileges {
		if !h.DevelopmentOverrideActive() {
			return fmt.Errorf("%s disables no-new-privileges without an audited development override", d.ID)
		}
	}
	if h.ReadOnlyRootfs == nil || !*h.ReadOnlyRootfs {
		if !h.DevelopmentOverrideActive() {
			return fmt.Errorf("%s disables the read-only root filesystem without an audited development override", d.ID)
		}
	}
	if h.SeccompProfile == "" || strings.EqualFold(h.SeccompProfile, "unconfined") {
		if !h.DevelopmentOverrideActive() {
			return fmt.Errorf("%s disables seccomp without an audited development override", d.ID)
		}
	}
	if h.AppArmorProfile == "" || strings.EqualFold(h.AppArmorProfile, "unconfined") {
		if !h.DevelopmentOverrideActive() {
			return fmt.Errorf("%s disables AppArmor without an audited development override", d.ID)
		}
	}
	if strings.EqualFold(h.UsernsMode, "host") && !h.DevelopmentOverrideActive() {
		return fmt.Errorf("%s selects host user namespaces without an audited development override", d.ID)
	}
	pidMode, err := runtime.NormalizePIDMode(h.PIDMode)
	if err != nil {
		return fmt.Errorf("%s has invalid PID namespace mode: %w", d.ID, err)
	}
	if pidMode != "" && !h.DevelopmentOverrideActive() {
		return fmt.Errorf("%s selects shared PID mode %q without an audited development override", d.ID, pidMode)
	}
	for _, capability := range effectiveCapabilities(d) {
		if !allowedDeviceCapability(capability) || !capabilityAllowedForKind(d.Kind, capability) {
			return fmt.Errorf("%s requests disallowed capability %s", d.ID, capability)
		}
		if capability == "SYS_ADMIN" {
			return fmt.Errorf("%s requests SYS_ADMIN; only the internal FRR control sidecar may use it", d.ID)
		}
	}
	for _, bind := range d.Binds {
		if sensitiveHostBind(bind) {
			return fmt.Errorf("%s mounts sensitive host path %q", d.ID, bind)
		}
	}
	for key := range d.Env {
		upper := strings.ToUpper(key)
		if strings.Contains(upper, "TWINET_TOKEN") || strings.Contains(upper, "TWINET_TLS") ||
			upper == "DOCKER_HOST" || upper == "CONTAINER_HOST" {
			return fmt.Errorf("%s carries an agent or container-engine credential in environment %q", d.ID, key)
		}
	}
	for _, target := range h.WritablePaths {
		if !validWritableHardeningPath(target) {
			return fmt.Errorf("%s has an invalid writable hardening path %q", d.ID, target)
		}
	}
	for _, target := range h.MaskedPaths {
		if !validHardeningPath(target) {
			return fmt.Errorf("%s has an invalid hardening path %q", d.ID, target)
		}
	}
	for _, target := range h.ReadonlyPaths {
		if !validHardeningPath(target) {
			return fmt.Errorf("%s has an invalid readonly hardening path %q", d.ID, target)
		}
	}
	return nil
}

func allowedDeviceCapability(capability string) bool {
	switch capability {
	case "NET_ADMIN", "NET_RAW", "NET_BIND_SERVICE", "SYS_NICE",
		"DAC_OVERRIDE", "SETUID", "SETGID", "CHOWN":
		return true
	}
	return false
}

func capabilityAllowedForKind(kind model.DeviceKind, capability string) bool {
	switch capability {
	case "DAC_OVERRIDE":
		return kind == model.KindRouter
	case "SETUID", "SETGID", "CHOWN":
		return kind == model.KindService
	}
	return true
}

func sensitiveHostBind(bind string) bool {
	source := strings.SplitN(bind, ":", 2)[0]
	source = path.Clean(source)
	lower := strings.ToLower(source)
	if strings.Contains(lower, "docker.sock") || strings.Contains(lower, "containerd.sock") ||
		strings.Contains(lower, "podman.sock") {
		return true
	}
	for _, prefix := range []string{"/proc", "/sys", "/dev", "/run/docker", "/var/lib/docker", "/etc/twinet"} {
		if source == prefix || strings.HasPrefix(source, prefix+"/") {
			return true
		}
	}
	return false
}

func validHardeningPath(target string) bool {
	clean := path.Clean(target)
	if clean == "." || !strings.HasPrefix(clean, "/") {
		return false
	}
	for _, prefix := range []string{"/proc", "/sys", "/dev"} {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			// System paths are valid only when they are being masked/read-only,
			// not writable. The caller distinguishes that policy elsewhere.
			return true
		}
	}
	return !strings.Contains(clean, "..")
}

func validWritableHardeningPath(target string) bool {
	if !validHardeningPath(target) {
		return false
	}
	clean := path.Clean(target)
	for _, prefix := range []string{"/proc", "/sys", "/dev"} {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			return false
		}
	}
	return true
}
