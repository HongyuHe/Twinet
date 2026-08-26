package netx

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/vishvananda/netlink"
)

// EndpointSpec describes one side of a link as it should appear inside a
// container's network namespace.
type EndpointSpec struct {
	// NSPath is the target namespace, normally /proc/<pid>/ns/net.
	NSPath string
	// Name is the final in-container interface name.
	Name string
	// MAC, when set, is applied before the interface is brought up.
	MAC string
	// MTU, when non-zero, overrides the default.
	MTU int
	// Addrs are addresses to configure, in CIDR form. Empty for interfaces the
	// student is expected to address themselves.
	Addrs []string
	// OwnAddrs says the platform owns this interface's addressing, so anything
	// else present is stale and must go.
	//
	// It is false for interfaces a student addresses: removing what they chose
	// would be the platform undoing their work every time anyone redeployed.
	OwnAddrs bool
	// MPLS enables label switching on this interface.
	//
	// It has to be done per interface and from outside the container: the
	// kernel drops labelled packets unless net.mpls.conf.<iface>.input is 1,
	// and a container's /proc/sys is read-only, so the router cannot set it
	// for itself. The interface also does not exist when the container is
	// created, so a sysctl in the manifest cannot name it either.
	//
	// Without this a router configured with `mpls ldp` reports operational
	// sessions, a populated label table and label-switched routes, and drops
	// every labelled packet that arrives.
	MPLS bool
	// Altname is the ownership tag stamped on the interface so orphans left by
	// a crash can be found and removed without consulting any external state.
	Altname string
	// VRF, when set, is the virtual routing table this interface is enslaved
	// to, and VRFTable its kernel table number.
	//
	// This is a kernel device, not merely an FRR setting. FRR's `interface X
	// vrf Y` binds its own view; without the master device the addresses stay
	// in the main table, so two customers using the same private prefix
	// overwrite each other's routes and the isolation the exercise is about
	// does not exist -- with nothing anywhere reporting a problem.
	VRF      string
	VRFTable int
	// Shaping is applied inside the namespace, on the container side, so that
	// it is identical whether the peer is local or across the cluster.
	Shaping *Shaping
	// Up brings the interface up. Almost always true; switch ports created
	// before the bridge exists are the exception.
	Up bool
}

// VethSpec describes a point-to-point link between two namespaces.
type VethSpec struct {
	// TempA and TempB are the transient names used in the host namespace
	// between creation and the move. They must be unique and fit IFNAMSIZ-1.
	TempA, TempB string
	MTU          int
	A, B         EndpointSpec
}

// CreateVeth creates a veth pair and installs each half in its namespace.
//
// The operation is idempotent at the level that matters: if both endpoints
// already exist with the right altname, it does nothing. That is what makes
// `twinet deploy` safe to re-run over a partially built lab, which the legacy
// platform could not do (its remedy for a failed run was a full teardown).
func CreateVeth(spec VethSpec) error {
	aOK, err := endpointPresent(spec.A)
	if err != nil {
		return err
	}
	bOK, err := endpointPresent(spec.B)
	if err != nil {
		return err
	}
	if aOK && bOK {
		// Already wired. Re-apply shaping and addresses, which are cheap and
		// may have changed, then return.
		if err := configureEndpoint(spec.A); err != nil {
			return err
		}
		return configureEndpoint(spec.B)
	}
	if aOK != bOK {
		// A half-built link: one side survived, the other did not. Remove the
		// survivor so the pair can be recreated cleanly.
		if aOK {
			_ = deleteEndpoint(spec.A)
		}
		if bOK {
			_ = deleteEndpoint(spec.B)
		}
	}

	host, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("open host netlink handle: %w", err)
	}
	defer host.Close()

	// Clean up any stale host-side halves from a previous interrupted run.
	deleteHostLinkWith(host, spec.TempA)
	deleteHostLinkWith(host, spec.TempB)

	mtu := spec.MTU
	if mtu == 0 {
		mtu = 1500
	}
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: spec.TempA, MTU: mtu},
		PeerName:  spec.TempB,
	}
	if err := host.LinkAdd(veth); err != nil {
		return fmt.Errorf("create veth %s<->%s: %w", spec.TempA, spec.TempB, err)
	}

	if err := installHalf(host, spec.TempA, spec.A, mtu); err != nil {
		deleteHostLinkWith(host, spec.TempA)
		deleteHostLinkWith(host, spec.TempB)
		return err
	}
	if err := installHalf(host, spec.TempB, spec.B, mtu); err != nil {
		deleteHostLinkWith(host, spec.TempB)
		_ = deleteEndpoint(spec.A)
		return err
	}
	return nil
}

// installHalf moves one veth end into its namespace and configures it there.
func installHalf(host *netlink.Handle, tempName string, ep EndpointSpec, mtu int) error {
	link, err := host.LinkByName(tempName)
	if err != nil {
		return fmt.Errorf("find %s in host namespace: %w", tempName, err)
	}

	// A nil namespace path means "leave it in the host namespace", used for the
	// host side of a cross-node VXLAN bridge port.
	if ep.NSPath == "" {
		if err := renameAndConfigure(host, link, ep, mtu); err != nil {
			return err
		}
		return nil
	}

	ns, err := OpenNS(ep.NSPath)
	if err != nil {
		return err
	}
	if err := host.LinkSetNsFd(link, ns.Fd()); err != nil {
		_ = ns.Close()
		return fmt.Errorf("move %s into %s: %w", tempName, ep.NSPath, err)
	}
	h, err := ns.Handle()
	_ = ns.Close()
	if err != nil {
		return err
	}
	defer h.Close()
	l, err := h.LinkByName(tempName)
	if err != nil {
		return fmt.Errorf("find %s after move: %w", tempName, err)
	}
	return renameAndConfigure(h, l, ep, mtu)
}

// renameAndConfigure applies the final name, MAC, MTU, altname, addresses,
// shaping and admin state. It must be called in the namespace that owns link.
func renameAndConfigure(h *netlink.Handle, link netlink.Link, ep EndpointSpec, mtu int) error {
	// The link must be down to be renamed.
	if err := h.LinkSetDown(link); err != nil {
		return fmt.Errorf("set %s down: %w", link.Attrs().Name, err)
	}
	if link.Attrs().Name != ep.Name {
		if err := h.LinkSetName(link, ep.Name); err != nil {
			return fmt.Errorf("rename %s to %s: %w", link.Attrs().Name, ep.Name, err)
		}
	}
	link, err := h.LinkByName(ep.Name)
	if err != nil {
		return fmt.Errorf("re-resolve %s: %w", ep.Name, err)
	}

	if ep.MAC != "" {
		hw, err := net.ParseMAC(ep.MAC)
		if err != nil {
			return fmt.Errorf("interface %s: bad MAC %q: %w", ep.Name, ep.MAC, err)
		}
		if !bytes.Equal(link.Attrs().HardwareAddr, hw) {
			if err := h.LinkSetHardwareAddr(link, hw); err != nil {
				return fmt.Errorf("set MAC on %s: %w", ep.Name, err)
			}
		}
	}
	want := ep.MTU
	if want == 0 {
		want = mtu
	}
	if want > 0 && link.Attrs().MTU != want {
		if err := h.LinkSetMTU(link, want); err != nil {
			return fmt.Errorf("set MTU %d on %s: %w", want, ep.Name, err)
		}
	}
	if ep.Altname != "" {
		// Best effort: altname support needs a recent kernel, and its absence
		// only costs us orphan detection, not correctness.
		hasAltname := false
		for _, altname := range link.Attrs().AltNames {
			if altname == ep.Altname {
				hasAltname = true
				break
			}
		}
		if !hasAltname {
			_ = h.LinkAddAltName(link, ep.Altname)
		}
	}

	if ep.MPLS {
		if err := enableMPLSInNS(ep.NSPath, ep.Name); err != nil {
			return err
		}
	}

	// Enslaved before the addresses are applied. Moving an interface into a
	// VRF afterwards makes the kernel flush them, so doing it the other way
	// round leaves the interface in the right table with no addresses at all.
	if ep.VRF != "" {
		if err := joinVRF(h, link, ep.VRF, ep.VRFTable); err != nil {
			return err
		}
		if link, err = h.LinkByName(ep.Name); err != nil {
			return fmt.Errorf("re-resolve %s after enslaving it: %w", ep.Name, err)
		}
	}
	if ep.Up && link.Attrs().Flags&net.FlagUp == 0 {
		if err := h.LinkSetUp(link); err != nil {
			return fmt.Errorf("set %s up: %w", ep.Name, err)
		}
	}
	if err := applyAddrs(h, link, ep.Addrs, ep.OwnAddrs); err != nil {
		return err
	}
	if ep.Shaping != nil {
		if err := applyShaping(h, link, *ep.Shaping); err != nil {
			return err
		}
	}
	// Checksum offload on veth defers checksum computation, which confuses
	// software dataplanes and packet captures inside the lab.
	disableTXOffloadInNS(ep.NSPath, ep.Name)
	return nil
}

// applyAddrs makes an interface hold exactly the addresses the model gives it,
// when the platform owns them.
//
// Converging by adding alone is not converging. An address left over from an
// earlier revision of the manifest stays on the interface, the router answers
// on both, and the session that matters comes up on neither: the two ends each
// use the address their own copy of the model says, and those no longer agree.
// It presents as a peering that is permanently Active, on a lab whose manifest
// and configuration are both correct, and it cost a grading run here to find.
func applyAddrs(h *netlink.Handle, link netlink.Link, addrs []string, authoritative bool) error {
	if len(addrs) == 0 && !authoritative {
		return nil
	}
	existing, err := h.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list addresses on %s: %w", link.Attrs().Name, err)
	}
	have := map[string]bool{}
	for _, a := range existing {
		have[a.IPNet.String()] = true
	}

	if authoritative {
		want := map[string]bool{}
		for _, s := range addrs {
			if a, err := netlink.ParseAddr(s); err == nil {
				want[a.IPNet.String()] = true
			}
		}
		for _, a := range existing {
			// Link-local addresses are the kernel's, not ours.
			if a.IP.IsLinkLocalUnicast() || a.IP.IsLoopback() {
				continue
			}
			if want[a.IPNet.String()] {
				continue
			}
			if err := h.AddrDel(link, &a); err != nil {
				return fmt.Errorf("remove stale %s from %s: %w",
					a.IPNet.String(), link.Attrs().Name, err)
			}
			delete(have, a.IPNet.String())
		}
	}

	for _, s := range addrs {
		if s == "" {
			continue
		}
		addr, err := netlink.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("interface %s: bad address %q: %w", link.Attrs().Name, s, err)
		}
		if have[addr.IPNet.String()] {
			continue
		}
		if err := h.AddrAdd(link, addr); err != nil && !errors.Is(err, errExists) {
			// EEXIST races with a concurrent deploy; anything else is real.
			if !isExist(err) {
				return fmt.Errorf("add %s to %s: %w", s, link.Attrs().Name, err)
			}
		}
	}
	return nil
}

// endpointPresent reports whether the interface already exists in its target
// namespace carrying the expected ownership altname.
func endpointPresent(ep EndpointSpec) (bool, error) {
	h, err := endpointHandle(ep.NSPath)
	if err != nil {
		return false, err
	}
	defer h.Close()
	l, err := h.LinkByName(ep.Name)
	if err != nil {
		if IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	if ep.Altname == "" {
		return true, nil
	}
	for _, an := range l.Attrs().AltNames {
		if an == ep.Altname {
			return true, nil
		}
	}
	// Same name, different owner: not ours, and a genuine conflict.
	return false, fmt.Errorf("interface %s already exists in %s but is not owned by this link",
		ep.Name, ep.NSPath)
}

// configureEndpoint re-applies mutable settings to an existing interface.
func configureEndpoint(ep EndpointSpec) error {
	h, err := endpointHandle(ep.NSPath)
	if err != nil {
		return err
	}
	defer h.Close()
	l, err := h.LinkByName(ep.Name)
	if err != nil {
		return err
	}
	// Membership of a virtual routing table is re-asserted here, not only
	// when the interface is first created.
	//
	// Deploy converges: an interface that already exists takes this path
	// and not the creation one, so a lab that gained a VRF -- because the
	// manifest changed, or because the platform learned how to do them --
	// would keep every interface in the main table for ever, with the
	// routing daemon configured for tables the kernel does not have. The
	// routes then land in one shared table and two customers using the
	// same private prefix silently overwrite each other, which is the
	// exact failure the tables exist to prevent.
	// The MTU is re-asserted on convergence, not only at creation.
	//
	// Every mutable property of an interface has to be applied on both
	// paths, because deploy converges: an interface that already exists
	// never takes the creation path again. An MTU applied only at creation
	// is correct on a fresh lab and silently stale on every redeployed
	// one -- which is the harder case to notice, since the lab that has
	// been running longest is the one that is wrong.
	if ep.MTU > 0 && l.Attrs().MTU != ep.MTU {
		if err := h.LinkSetMTU(l, ep.MTU); err != nil {
			return fmt.Errorf("set MTU %d on %s: %w", ep.MTU, ep.Name, err)
		}
	}
	if ep.MPLS {
		if err := enableMPLSInNS(ep.NSPath, ep.Name); err != nil {
			return err
		}
	}
	if ep.VRF != "" {
		if err := joinVRF(h, l, ep.VRF, ep.VRFTable); err != nil {
			return err
		}
		// Enslaving flushes the addresses, so they are re-applied after.
		if l, err = h.LinkByName(ep.Name); err != nil {
			return err
		}
	}
	if ep.Up && l.Attrs().Flags&net.FlagUp == 0 {
		if err := h.LinkSetUp(l); err != nil {
			return fmt.Errorf("set %s up: %w", ep.Name, err)
		}
	}
	if err := applyAddrs(h, l, ep.Addrs, ep.OwnAddrs); err != nil {
		return err
	}
	if ep.Shaping != nil {
		if err := applyShaping(h, l, *ep.Shaping); err != nil {
			return err
		}
	}
	return nil
}

func deleteEndpoint(ep EndpointSpec) error {
	h, err := endpointHandle(ep.NSPath)
	if err != nil {
		return err
	}
	defer h.Close()
	l, err := h.LinkByName(ep.Name)
	if err != nil {
		if IsNotFound(err) {
			return nil
		}
		return err
	}
	return h.LinkDel(l)
}

func deleteHostLinkWith(h *netlink.Handle, name string) {
	if l, err := h.LinkByName(name); err == nil {
		_ = h.LinkDel(l)
	}
}

// DeleteVeth removes a link by deleting either half; the kernel removes both.
func DeleteVeth(spec VethSpec) error {
	if err := deleteEndpoint(spec.A); err != nil {
		return err
	}
	return deleteEndpoint(spec.B)
}

// DeleteHostLink removes an interface from the root namespace, ignoring absence.
func DeleteHostLink(name string) error {
	h, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("open host netlink handle: %w", err)
	}

	defer h.Close()
	l, err := h.LinkByName(name)
	if err != nil {
		if IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("look up %s: %w", name, err)
	}
	if err := h.LinkDel(l); err != nil {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	return nil
}

// HostLinkPresent reports whether a host-namespace link exists without
// modifying it.
func HostLinkPresent(name string) (bool, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return false, fmt.Errorf("open host netlink handle: %w", err)
	}
	defer h.Close()
	_, err = h.LinkByName(name)
	if err == nil {
		return true, nil
	}
	if IsNotFound(err) {
		return false, nil
	}
	return false, fmt.Errorf("look up %s: %w", name, err)
}

// HostLinksPresent surveys a set of root-namespace links with one netlink
// dump. Scale reconciliation checks thousands of endpoint veths, so opening a
// socket and issuing a lookup for each one would put the correctness check on
// the deployment critical path.
func HostLinksPresent(names []string) (map[string]bool, error) {
	want := make(map[string]struct{}, len(names))
	out := make(map[string]bool, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		want[name] = struct{}{}
		out[name] = false
	}
	if len(want) == 0 {
		return out, nil
	}
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("open host netlink handle: %w", err)
	}
	defer h.Close()
	links, err := listHandleLinks(h)
	if err != nil {
		return nil, fmt.Errorf("list host interfaces: %w", err)
	}
	for _, link := range links {
		name := link.Attrs().Name
		if _, ok := want[name]; ok {
			out[name] = true
		}
	}
	return out, nil
}

// endpointHandle opens an independent netlink socket in an endpoint's target
// namespace. Once opened, the socket remains namespace-scoped without changing
// whichever OS thread subsequently uses it.
func endpointHandle(nsPath string) (*netlink.Handle, error) {
	if nsPath == "" {
		h, err := netlink.NewHandle()
		if err != nil {
			return nil, fmt.Errorf("open host netlink handle: %w", err)
		}
		return h, nil
	}
	ns, err := OpenNS(nsPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ns.Close() }()
	return ns.Handle()
}

func inNS(nsPath string, fn func() error) error {
	if nsPath == "" {
		return fn()
	}
	ns, err := OpenNS(nsPath)
	if err != nil {
		return err
	}
	defer func() { _ = ns.Close() }()
	return ns.Do(fn)
}

func enableMPLSInNS(nsPath, name string) error {
	return inNS(nsPath, func() error { return enableMPLS(name) })
}

func disableTXOffloadInNS(nsPath, name string) {
	_ = inNS(nsPath, func() error {
		disableTXOffload(name)
		return nil
	})
}

// joinVRF makes an interface a member of a virtual routing table, creating the
// table's device if it is not there yet.
//
// Idempotent in both parts: an existing VRF with the right table is reused, and
// an interface already enslaved to it is left alone. Deploy runs repeatedly
// against a live lab, so anything here that was not idempotent would tear a
// customer's routing down on every convergence pass.
func joinVRF(h *netlink.Handle, link netlink.Link, name string, table int) error {
	if table <= 0 {
		return fmt.Errorf("VRF %q has no routing table number", name)
	}
	master, err := h.LinkByName(name)
	if err != nil {
		vrf := &netlink.Vrf{
			LinkAttrs: netlink.LinkAttrs{Name: name},
			Table:     uint32(table),
		}
		if err := h.LinkAdd(vrf); err != nil {
			return fmt.Errorf("create VRF %s (table %d): %w", name, table, err)
		}
		if err := h.LinkSetUp(vrf); err != nil {
			return fmt.Errorf("bring VRF %s up: %w", name, err)
		}
		master, err = h.LinkByName(name)
		if err != nil {
			return fmt.Errorf("re-resolve VRF %s: %w", name, err)
		}
	}
	if v, ok := master.(*netlink.Vrf); ok && int(v.Table) != table {
		// Two tables under one name would silently merge two customers'
		// routes, which is the one failure this whole mechanism exists to
		// prevent, so it is refused rather than papered over.
		return fmt.Errorf("VRF %s already exists with table %d, not %d", name, v.Table, table)
	}
	if link.Attrs().MasterIndex == master.Attrs().Index {
		return nil
	}
	if err := h.LinkSetMaster(link, master); err != nil {
		return fmt.Errorf("enslave %s to VRF %s: %w", link.Attrs().Name, name, err)
	}
	return nil
}

// enableMPLS lets an interface accept labelled packets.
//
// Written through /proc rather than with a netlink call because the kernel
// exposes no netlink attribute for it. The caller is already inside the
// target network namespace, and /proc/sys/net is per-namespace, so this
// reaches the right interface.
//
// A missing directory is not an error: it means the mpls_router module is not
// loaded, which is the normal state on a node running no label-switching lab,
// and there is nothing to enable.
func enableMPLS(name string) error {
	path := fmt.Sprintf("/proc/sys/net/mpls/conf/%s/input", name)
	if _, statErr := os.Stat("/proc/sys/net/mpls"); os.IsNotExist(statErr) {
		return nil
	} else if statErr != nil {
		// Present but unreadable is a different thing from absent, and
		// treating it as absent would turn a broken node into a lab that
		// deploys cleanly and drops every labelled packet.
		return fmt.Errorf("checking for label-switching support: %w", statErr)
	}
	if current, err := os.ReadFile(path); err == nil && string(current) == "1\n" {
		return nil
	}
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
		return fmt.Errorf("enabling label switching on %s: %w", name, err)
	}
	return nil
}
