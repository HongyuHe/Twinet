package grade

import (
	"context"
	"strings"
)

// legacyECMPHops is the pre-snapshot FRR observation retained solely for
// shadow validation. A mismatch is surfaced as infrastructure uncertainty by
// checkECMP rather than silently changing a routing mark.
func legacyECMPHops(ctx context.Context, env *Env, router, target string) ([]installedHop, map[string]bool, error) {
	var routes ospfRouteJSON
	if err := env.VtyshJSON(ctx, router, "show ip route json", &routes); err != nil {
		return nil, nil, err
	}
	other := map[string]bool{}
	var hops []installedHop
	for _, entry := range routes[target] {
		if !entry.Selected && !entry.Installed {
			continue
		}
		if entry.Protocol != "" && entry.Protocol != "ospf" {
			other[entry.Protocol] = true
			continue
		}
		for _, nextHop := range entry.Nexthops {
			if nextHop.InterfaceName != "" || nextHop.IP != "" {
				hops = append(hops, installedHop{iface: nextHop.InterfaceName, ip: nextHop.IP})
			}
		}
	}
	return hops, other, nil
}

func sameInstalledHopSet(a, b []installedHop) bool {
	return sameStrings(sortedKeysOfBool(hopNames(a)), sortedKeysOfBool(hopNames(b)))
}

func sameStringBoolSet(a, b map[string]bool) bool {
	left, right := sortedKeysOfBool(a), sortedKeysOfBool(b)
	return sameStrings(left, right)
}

func describeInstalledHops(hops []installedHop) string {
	labels := sortedKeysOfBool(hopNames(hops))
	if len(labels) == 0 {
		return "none"
	}
	return strings.Join(labels, ", ")
}
