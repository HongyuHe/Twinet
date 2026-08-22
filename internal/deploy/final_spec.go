package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"sort"
	"strconv"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/runtime"
)

// runtimeSpecContractVersion changes whenever Twinet derives a new runtime
// security/mount contract. It intentionally forces one safe migration of
// legacy containers whose model-only LabelSpec could not describe their actual
// create request.
const RuntimeSpecContractVersion = "runtime-spec-v1"

const runtimeSpecContractVersion = RuntimeSpecContractVersion

type finalDeviceSpec struct {
	device        *model.Device
	spec          *runtime.Spec
	controlSpec   *runtime.Spec
	controlBinds  []runtime.Bind
	platformBinds []runtime.Bind
}

// finalRuntimeSpecs is the sole constructor for device and FRR-sidecar create
// requests. It hashes the final runtime.Spec before stamping LabelSpec, so
// observation, migration, and create can never disagree about derived
// hardening, writable bind targets, tmpfs, or OCI restrictions.
func (e *Engine) finalRuntimeSpecs(top *model.Topology, d *model.Device) (finalDeviceSpec, error) {
	if top == nil || d == nil {
		return finalDeviceSpec{}, fmt.Errorf("final runtime spec needs a topology and device")
	}
	device := e.effectiveRuntimeDevice(d)
	controlBinds, err := e.frrControlBinds(top, device)
	if err != nil {
		return finalDeviceSpec{}, err
	}
	binds, err := authoredRuntimeBinds(device)
	if err != nil {
		return finalDeviceSpec{}, err
	}
	binds = append(binds, controlBinds...)
	platformBinds, err := e.writableBinds(top, device, binds)
	if err != nil {
		return finalDeviceSpec{}, err
	}
	binds = append(binds, platformBinds...)
	hardening, err := e.hardenedRuntimeSpec(device, binds)
	if err != nil {
		return finalDeviceSpec{}, err
	}
	cpus, memory, pids := effectiveRuntimeLimits(device)
	spec := &runtime.Spec{
		Name:           device.Container,
		Image:          device.Image,
		Hostname:       shortHostname(device),
		Command:        append([]string(nil), device.Command...),
		Env:            cloneStringMap(device.Env),
		Labels:         e.labels(top, device, ""),
		Sysctls:        cloneStringMap(device.Sysctls),
		Capabilities:   append([]string(nil), hardening.Capabilities...),
		CapDrop:        append([]string(nil), hardening.CapDrop...),
		SecurityOpt:    append([]string(nil), hardening.SecurityOpt...),
		ReadOnlyRootfs: hardening.ReadOnlyRootfs,
		RuntimeClass:   hardening.RuntimeClass,
		UsernsMode:     hardening.UsernsMode,
		PidMode:        hardening.PidMode,
		MaskedPaths:    append([]string(nil), hardening.MaskedPaths...),
		ReadonlyPaths:  append([]string(nil), hardening.ReadonlyPaths...),
		Privileged:     device.Privileged,
		CPUs:           cpus,
		Memory:         memory,
		PidsLimit:      pids,
		Restart:        device.Restart,
		NetworkMode:    hardening.NetworkMode,
		Init:           true,
		Binds:          append([]runtime.Bind(nil), binds...),
		Tmpfs:          cloneStringMap(hardening.Tmpfs),
	}
	if spec.NetworkMode == "" {
		spec.NetworkMode = "none"
	}
	spec.Labels[LabelRuntimeContract] = runtimeSpecContractVersion
	spec.Labels[LabelSpec] = runtimeSpecHash(spec)
	out := finalDeviceSpec{
		device: device, spec: spec, controlBinds: controlBinds, platformBinds: platformBinds,
	}
	if !e.usesFRRControl(device) {
		return out, nil
	}
	control, err := e.finalFRRControlSpec(top, device, controlBinds)
	if err != nil {
		return finalDeviceSpec{}, err
	}
	out.controlSpec = control
	return out, nil
}

func authoredRuntimeBinds(d *model.Device) ([]runtime.Bind, error) {
	var out []runtime.Bind
	for _, raw := range d.Binds {
		parts := strings.Split(raw, ":")
		if len(parts) == 0 || parts[0] == "" {
			return nil, fmt.Errorf("%s has an invalid bind %q", d.ID, raw)
		}
		bind := runtime.Bind{Source: parts[0]}
		if len(parts) > 1 {
			bind.Target = parts[1]
		}
		if bind.Target == "" {
			return nil, fmt.Errorf("%s bind %q has no container target", d.ID, raw)
		}
		if len(parts) > 2 && parts[2] == "ro" {
			bind.ReadOnly = true
		}
		out = append(out, bind)
	}
	return out, nil
}

func (e *Engine) finalFRRControlSpec(top *model.Topology, d *model.Device,
	binds []runtime.Bind,
) (*runtime.Spec, error) {
	logBind, err := e.frrControlLogBind(top, d)
	if err != nil {
		return nil, err
	}
	sidecarBinds := append([]runtime.Bind(nil), binds...)
	sidecarBinds = append(sidecarBinds, logBind)
	hardening, err := e.hardenedRuntimeSpec(d, sidecarBinds)
	if err != nil {
		return nil, err
	}
	labels := e.labels(top, d, "")
	labels[LabelFRRControl] = "true"
	labels[LabelInternal] = "true"
	labels[LabelKind] = "frr-control"
	setRequestLabels(labels, model.FRRControlResourceRequest())
	request := model.FRRControlResourceRequest()
	spec := &runtime.Spec{
		Name:           FRRControlContainer(d),
		Image:          d.Image,
		Command:        []string{"sleep", "infinity"},
		Labels:         labels,
		Binds:          sidecarBinds,
		Capabilities:   frrControlCapabilities(d),
		CapDrop:        append([]string(nil), hardening.CapDrop...),
		SecurityOpt:    append([]string(nil), hardening.SecurityOpt...),
		ReadOnlyRootfs: hardening.ReadOnlyRootfs,
		RuntimeClass:   hardening.RuntimeClass,
		UsernsMode:     hardening.UsernsMode,
		PidMode:        hardening.PidMode,
		MaskedPaths:    append([]string(nil), hardening.MaskedPaths...),
		ReadonlyPaths:  append([]string(nil), hardening.ReadonlyPaths...),
		Tmpfs:          cloneStringMap(hardening.Tmpfs),
		CPUs:           request.CPUs,
		Memory:         request.Memory,
		PidsLimit:      request.Pids,
		Restart:        d.Restart,
		NetworkMode:    "container:" + d.Container,
		Init:           true,
	}
	spec.Labels[LabelRuntimeContract] = runtimeSpecContractVersion
	spec.Labels[LabelSpec] = runtimeSpecHash(spec)
	return spec, nil
}

// FinalSpecHash exposes the exact label value expected for a primary device.
// It is used by observed-diff and agent reconciliation; callers that cannot
// build a final spec must fail closed rather than compare a legacy model hash.
func (e *Engine) FinalSpecHash(top *model.Topology, d *model.Device) (string, error) {
	final, err := e.finalRuntimeSpecs(top, d)
	if err != nil {
		return "", err
	}
	return final.spec.Labels[LabelSpec], nil
}

func (e *Engine) FinalControlSpecHash(top *model.Topology, d *model.Device) (string, error) {
	final, err := e.finalRuntimeSpecs(top, d)
	if err != nil {
		return "", err
	}
	if final.controlSpec == nil {
		return "", nil
	}
	return final.controlSpec.Labels[LabelSpec], nil
}

// RuntimeSpec returns the exact final primary-container create request used by
// ensureContainer. Recovery persists this contract before replacement, so it
// never reinterprets an old topology through newer hardening policy.
func (e *Engine) RuntimeSpec(_ context.Context, top *model.Topology, d *model.Device) (*runtime.Spec, error) {
	final, err := e.finalRuntimeSpecs(top, d)
	if err != nil {
		return nil, err
	}
	return final.spec, nil
}

// PrepareRuntimeSpec materializes bind sources for an already-derived spec.
// Recovery calls it only immediately before Runtime.Create.
func (e *Engine) PrepareRuntimeSpec(top *model.Topology, d *model.Device) error {
	final, err := e.finalRuntimeSpecs(top, d)
	if err != nil {
		return err
	}
	return e.prepareFinalRuntimeSpecs(top, final)
}

// RuntimeControlSpec returns the exact sidecar request paired with RuntimeSpec,
// when this device uses the split FRR control runtime.
func (e *Engine) RuntimeControlSpec(top *model.Topology, d *model.Device) (*runtime.Spec, error) {
	final, err := e.finalRuntimeSpecs(top, d)
	if err != nil {
		return nil, err
	}
	return final.controlSpec, nil
}

// RewireTopology restores host/network objects without changing container
// specs or rendered files.
func (e *Engine) RewireTopology(ctx context.Context, top *model.Topology) error {
	var problems []string
	for _, link := range top.Links {
		if link == nil || (link.A.Device.Node != e.Node && link.B.Device.Node != e.Node) {
			continue
		}
		if err := e.wire(ctx, top, link); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", link.ID, err))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("%s", strings.Join(problems, "; "))
}

// EnsureRuntimeSupport recreates internal sidecars after a persisted primary
// container has been started.
func (e *Engine) EnsureRuntimeSupport(ctx context.Context, top *model.Topology, d *model.Device) error {
	final, err := e.finalRuntimeSpecs(top, d)
	if err != nil {
		return err
	}
	return e.ensureFRRControl(ctx, top, final)
}

func runtimeSpecHash(spec *runtime.Spec) string {
	h := sha256.New()
	write := func(key, value string) { fmt.Fprintf(h, "%s=%d:%s\n", key, len(value), value) }
	write("contract", runtimeSpecContractVersion)
	write("name", spec.Name)
	write("image", spec.Image)
	write("hostname", spec.Hostname)
	writeStrings(h, "command", spec.Command, false)
	writeStrings(h, "entrypoint", spec.Entrypoint, false)
	writeStringMap(h, "env", spec.Env)
	writeStringMap(h, "sysctl", spec.Sysctls)
	writeStrings(h, "caps", spec.Capabilities, true)
	writeStrings(h, "cap-drop", spec.CapDrop, true)
	writeStrings(h, "security", spec.SecurityOpt, true)
	write("readonly-rootfs", strconv.FormatBool(spec.ReadOnlyRootfs))
	write("runtime-class", spec.RuntimeClass)
	write("userns", spec.UsernsMode)
	write("pid", spec.PidMode)
	writeStrings(h, "masked", spec.MaskedPaths, true)
	writeStrings(h, "readonly", spec.ReadonlyPaths, true)
	write("privileged", strconv.FormatBool(spec.Privileged))
	write("cpus", strconv.FormatFloat(spec.CPUs, 'g', -1, 64))
	write("memory", spec.Memory)
	write("pids", strconv.FormatInt(spec.PidsLimit, 10))
	write("restart", spec.Restart)
	writeStrings(h, "dns", spec.DNS, false)
	writeStrings(h, "dns-search", spec.DNSSearch, false)
	writeStrings(h, "extra-hosts", spec.ExtraHosts, false)
	writePorts(h, spec.Ports)
	writeBinds(h, spec.Binds)
	writeStringMap(h, "tmpfs", spec.Tmpfs)
	write("network", spec.NetworkMode)
	write("stop-signal", spec.StopSignal)
	if spec.StopTimeout != nil {
		write("stop-timeout", strconv.Itoa(*spec.StopTimeout))
	}
	write("init", strconv.FormatBool(spec.Init))
	writeHealth(h, spec.Health)
	return hex.EncodeToString(h.Sum(nil))[:24]
}

func writeStrings(h hash.Hash, key string, values []string, unordered bool) {
	values = append([]string(nil), values...)
	if unordered {
		sort.Strings(values)
	}
	for index, value := range values {
		fmt.Fprintf(h, "%s[%d]=%d:%s\n", key, index, len(value), value)
	}
}

func writeStringMap(h hash.Hash, key string, values map[string]string) {
	keys := make([]string, 0, len(values))
	for name := range values {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		fmt.Fprintf(h, "%s[%d:%s]=%d:%s\n", key, len(name), name, len(values[name]), values[name])
	}
}

func writePorts(h hash.Hash, ports []runtime.PortMap) {
	ports = append([]runtime.PortMap(nil), ports...)
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].HostIP != ports[j].HostIP {
			return ports[i].HostIP < ports[j].HostIP
		}
		if ports[i].HostPort != ports[j].HostPort {
			return ports[i].HostPort < ports[j].HostPort
		}
		if ports[i].Container != ports[j].Container {
			return ports[i].Container < ports[j].Container
		}
		return ports[i].Protocol < ports[j].Protocol
	})
	for index, port := range ports {
		fmt.Fprintf(h, "port[%d]=%s:%d:%d:%s\n", index, port.HostIP, port.HostPort, port.Container, port.Protocol)
	}
}

func writeBinds(h hash.Hash, binds []runtime.Bind) {
	binds = append([]runtime.Bind(nil), binds...)
	sort.Slice(binds, func(i, j int) bool {
		if binds[i].Target != binds[j].Target {
			return binds[i].Target < binds[j].Target
		}
		if binds[i].Source != binds[j].Source {
			return binds[i].Source < binds[j].Source
		}
		return !binds[i].ReadOnly && binds[j].ReadOnly
	})
	for index, bind := range binds {
		fmt.Fprintf(h, "bind[%d]=%s:%s:%t\n", index, bind.Source, bind.Target, bind.ReadOnly)
	}
}

func writeHealth(h hash.Hash, health *runtime.Health) {
	if health == nil {
		return
	}
	writeStrings(h, "health-test", health.Test, false)
	fmt.Fprintf(h, "health=%s:%s:%d:%s\n",
		health.Interval, health.Timeout, health.Retries, health.StartPeriod)
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
