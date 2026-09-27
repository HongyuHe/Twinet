package msc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

// Export produces a deliberately allowlisted bundle: no state-directory walk,
// private key, credential store, or unredacted XFRM state can enter the output.
// A manifest written last marks a complete, independently hashable snapshot.
func (e *Engine) Export(ctx context.Context, dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("export destination already exists: %s", dir)
	} else if !os.IsNotExist(err) {
		return err
	}
	status, err := e.Status(ctx)
	if err != nil {
		return err
	}
	files := map[string][]byte{}
	putJSON := func(name string, value any) error {
		b, er := json.MarshalIndent(value, "", "  ")
		if er != nil {
			return er
		}
		files[name] = append(b, '\n')
		return nil
	}
	if err = putJSON("spec.json", e.Spec); err != nil {
		return err
	}
	if err = putJSON("status.json", status); err != nil {
		return err
	}
	type facts struct {
		Device           string            `json:"device"`
		Role             string            `json:"role"`
		ObservedAt       time.Time         `json:"observed_at"`
		DeployedSpecHash string            `json:"deployed_spec_sha256,omitempty"`
		State            string            `json:"state"`
		Image            string            `json:"image_id"`
		Values           map[string]any    `json:"values"`
		Errors           map[string]string `json:"errors,omitempty"`
	}
	normalized := []facts{}
	for _, o := range status.Devices {
		values := map[string]any{}
		for key, raw := range o.Facts {
			var value any
			if json.Unmarshal([]byte(raw), &value) == nil {
				values[key] = value
			} else {
				values[key] = raw
			}
		}
		normalized = append(normalized, facts{o.Device, o.Role, o.ObservedAt, o.DeployedSpecHash, string(o.State), o.Image, values, o.Errors})
		d := e.Spec.Device(o.Device)
		base := "devices/" + d.ID + "/"
		if err = putJSON(base+"declared.json", d); err != nil {
			return err
		}
		files[base+"intended.iptables"] = []byte(filterRules(e.Spec, d))
		if filter, ok := o.Facts["filter"]; ok {
			files[base+"observed.iptables"] = []byte(filter)
		}
		if e.Spec.IsFRR(d) {
			files[base+"intended.frr.conf"] = []byte(frrConfig(e.Spec, d))
			if config, ok := o.Facts["frr-config"]; ok {
				files[base+"observed.frr.conf"] = []byte(config)
			}
		}
		if e.Spec.IsOVS(d) {
			ports := []string{}
			for _, p := range d.Interfaces {
				ports = append(ports, p.Name)
			}
			if err = putJSON(base+"intended.ovs.json", map[string]any{"bridge": "br0", "ports": ports, "fail_mode": "secure", "flows": []string{"priority=0,actions=NORMAL"}, "controllers": []string{}}); err != nil {
				return err
			}
		}
		if d.Tunnel != nil {
			files[base+"intended.swanctl.conf"] = []byte(swanConfig(d))
		}
	}
	if err = putJSON("facts.json", map[string]any{"schema_version": 1, "spec_sha256": e.Spec.Hash(), "started": status.Started, "finished": status.Finished, "devices": normalized}); err != nil {
		return err
	}
	build := map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		build["go_version"] = info.GoVersion
		for _, setting := range info.Settings {
			if strings.HasPrefix(setting.Key, "vcs.") {
				build[setting.Key] = setting.Value
			}
		}
	}
	hashes := map[string]string{}
	for name, body := range files {
		sum := sha256.Sum256(body)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	manifest := map[string]any{"schema_version": 1, "kind": "twinet-msc-observation", "lab": e.Spec.Name, "spec_sha256": e.Spec.Hash(), "started": status.Started, "finished": status.Finished, "build": build, "sha256": hashes,
		"semantics": []string{"Intended configuration is generated from spec.json; observed configuration is read from running devices.", "Observations are sampled sequentially and are not an atomic network snapshot.", "Missing observations and command errors are unknown facts, not negative evidence.", "Export does not run reachability or compliance checks. Run msc check separately for active probes.", "Device containers emulate separate appliances while sharing the worker kernel."}}
	if err = os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
		return err
	}
	if err = os.Mkdir(dir, 0755); err != nil {
		return err
	}
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		if err = os.WriteFile(path, body, 0644); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), append(b, '\n'), 0644)
}
