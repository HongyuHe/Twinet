package render

import (
	"sort"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
)

// MutablePath is a path Renderer.Files or a renderer command changes. External
// paths are Docker-managed mounts rather than Twinet-owned writable mounts.
type MutablePath struct {
	Path     string
	External bool
}

// MutablePaths is the rendering write contract used by hardening tests. Keep
// command targets explicit: a shell string that starts writing somewhere new
// must make the mount decision visible in review rather than hoping a
// read-only-rootfs failure finds it during a course deployment.
func (r *Renderer) MutablePaths(d *model.Device) ([]MutablePath, error) {
	files, err := r.Files(d)
	if err != nil {
		return nil, err
	}
	seen := map[string]MutablePath{}
	for path := range files {
		seen[path] = MutablePath{Path: path}
	}
	for _, path := range rendererCommandWritePaths(d) {
		if path.Path != "" {
			seen[path.Path] = path
		}
	}
	out := make([]MutablePath, 0, len(seen))
	for _, path := range seen {
		out = append(out, path)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func rendererCommandWritePaths(d *model.Device) []MutablePath {
	if d == nil {
		return nil
	}
	out := []MutablePath{{Path: "/etc/twinet"}, {Path: "/run"}, {Path: "/var/log"}}
	switch d.Kind {
	case model.KindRouter:
		if d.EffectiveNOS() == "bird" {
			out = append(out,
				MutablePath{Path: "/etc/bird"},
				MutablePath{Path: "/tmp"},
				MutablePath{Path: "/run/bird.ctl"},
			)
		} else {
			out = append(out,
				MutablePath{Path: "/etc/frr"},
				MutablePath{Path: "/run/frr"},
				MutablePath{Path: "/var/log/frr"},
			)
		}
		out = append(out, MutablePath{Path: "/etc/resolv.conf", External: true})
	case model.KindSwitch:
		out = append(out, MutablePath{Path: "/etc/openvswitch"})
	case model.KindP4:
		out = append(out, MutablePath{Path: "/etc/twinet/p4"}, MutablePath{Path: "/var/log/twinet"})
	case model.KindController:
		out = append(out, MutablePath{Path: "/run/twinet"})
	case model.KindHost:
		out = append(out, MutablePath{Path: "/etc/resolv.conf", External: true})
	case model.KindService:
		if isDNS(d) {
			out = append(out,
				MutablePath{Path: "/etc/bind"},
				MutablePath{Path: "/var/named"},
				MutablePath{Path: "/var/run/named"},
			)
		}
	}
	return out
}

// HardenedWritableContract reports whether a non-external renderer target is
// covered by the deployment's declared writable paths.
func HardenedWritableContract(d *model.Device, target MutablePath) bool {
	if target.External {
		return target.Path == "/etc/resolv.conf"
	}
	return deploy.WritablePathCovers(deploy.PlatformWritablePaths(d), target.Path)
}
