package nos

import (
	"sort"

	"github.com/HongyuHe/twinet/internal/model"
)

// RequiredFeatures derives the functionality a router must provide from the
// authored topology. It deliberately describes the requested network rather
// than a provider's configuration file, so validation occurs before deploy.
func RequiredFeatures(lab *model.Lab, tpl *model.ASTemplate, router string) []Feature {
	required := map[Feature]bool{FeatureIPv4: true}
	if lab != nil {
		a := lab.Addressing
		if a.ASBlockV6 != "" || a.RouterLoopbackV6 != "" || a.L2DomainV6 != "" || a.L2VLANV6 != "" {
			required[FeatureIPv6] = true
		}
	}
	if tpl == nil {
		return sortedFeatures(required)
	}
	if len(tpl.InternalLinks) > 0 || tpl.Interior != nil || len(tpl.Routers) > 1 {
		required[FeatureOSPF] = true
	}
	if len(tpl.ExternalPorts) > 0 || len(tpl.Routers) > 1 {
		required[FeatureBGP] = true
	}
	if len(tpl.ExternalPorts) > 0 {
		required[FeaturePolicy] = true
		required[FeatureCommunity] = true
	}
	if tpl.MPLS.Enabled {
		required[FeatureMPLS] = true
		required[FeatureLDP] = true
	}
	if len(tpl.VRFs) > 0 {
		required[FeatureVRF] = true
	}
	if tpl.Multicast.Enabled {
		required[FeatureMulticast] = true
	}
	if len(tpl.L2Domains) > 0 {
		required[FeatureVLAN] = true
		required[FeatureDHCP] = true
	}
	// A course's RPKI attachment is a request only for the selected router.
	// Other routers in that AS can still route an RPKI-filtered table without
	// running an RTR client themselves.
	if lab != nil {
		for _, service := range lab.Services {
			if service == nil || service.Kind != "builtin.rpki" || service.Attach == nil {
				continue
			}
			if service.Attach.Template == "" || service.Attach.Template == tpl.Metadata.Name {
				if service.Attach.Router == router {
					required[FeatureRPKI] = true
				}
			}
		}
	}
	return sortedFeatures(required)
}

func sortedFeatures(values map[Feature]bool) []Feature {
	out := make([]Feature, 0, len(values))
	for feature := range values {
		out = append(out, feature)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
