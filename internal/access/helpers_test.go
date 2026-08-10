package access

import "github.com/HongyuHe/twinet/internal/model"

// twoASTopology builds the smallest lab that can show an authorisation
// boundary: two autonomous systems, each with a router the other must not
// reach.
func twoASTopology() *model.Topology {
	top := &model.Topology{
		Name:    "t",
		Devices: map[string]*model.Device{},
		ASes:    map[int]*model.AS{},
	}
	add := func(asn int, name string, kind model.DeviceKind) {
		d := &model.Device{ID: model.DeviceID(asn, name), Name: name, ASN: asn, Kind: kind}
		top.Devices[d.ID] = d
		as, ok := top.ASes[asn]
		if !ok {
			as = &model.AS{ASN: asn, Role: model.RoleStudent}
			top.ASes[asn] = as
		}
		as.Devices = append(as.Devices, d)
		if kind == model.KindRouter {
			as.Routers = append(as.Routers, d)
		}
	}
	add(3, "MSP", model.KindRouter)
	add(3, "MSP_host", model.KindHost)
	add(4, "NYC", model.KindRouter)
	return top
}
