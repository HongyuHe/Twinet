package netx

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	maxVLANID = 4094
	maxVNI    = 1<<24 - 1

	pairAliasPrefix = aliasPrefix + "pair:"

	// Flow-based VXLAN devices are keyed by their receive socket. Linux
	// permits only one unfiltered external VNI-0 device for a local
	// address/UDP port tuple, so node-pair trunks must not all bind 4789.
	multiplexPortFirst = 20_000
	multiplexPortLast  = 60_999
)

// MultiplexOverlaySpec describes a VLAN-to-VNI binding on the one external
// VXLAN device shared by a lab and a pair of nodes.
//
// VNI remains the link's existing isolation identifier on the wire. VLAN is a
// local, bridge-only tag used to multiplex that VNI over the shared device.
type MultiplexOverlaySpec struct {
	Lab                   string
	LocalNode, RemoteNode string
	LocalIP, RemoteIP     string
	UnderlayDev           string
	MTU                   int
	// Port is the pair-specific VXLAN UDP destination port. Zero derives a
	// deterministic port from the lab/node-pair identity.
	Port int
	VNI  uint32
	VLAN uint16
	// PreserveActive keeps an already forwarding trunk untouched during
	// transactional rollback. It may retain a legacy port/MTU long enough to
	// restore service; ordinary apply still converges to the requested values.
	PreserveActive bool
	// ForcePort replaces an active trunk whose receive port differs from the
	// deterministic pair assignment. Repair uses this only after observing a
	// broken cross-node link; retaining mismatched active ports on opposite
	// endpoints black-holes the VNI forever.
	ForcePort bool
}

// MultiplexOverlay is one shared bridge/VXLAN pair and its active VNIs.
type MultiplexOverlay struct {
	Lab           string
	NodeA, NodeB  string
	Bridge, Vxlan string
	VNIs          []uint32
}

type pairKey struct {
	lab, a, b string
}

type multiplexLock struct {
	mu   sync.Mutex
	refs int
}

var multiplexLocks = struct {
	sync.Mutex
	byKey map[string]*multiplexLock
}{byKey: map[string]*multiplexLock{}}

var multiplexLockOverrides = struct {
	sync.RWMutex
	override func([]string) func()
}{}

func lockMultiplexKeys(keys []string) func() {
	multiplexLockOverrides.RLock()
	override := multiplexLockOverrides.override
	multiplexLockOverrides.RUnlock()
	if override != nil {
		return override(keys)
	}
	keys = append([]string(nil), keys...)
	sort.Strings(keys)
	keys = dedupStrings(keys)
	locks := make([]*multiplexLock, 0, len(keys))
	multiplexLocks.Lock()
	for _, key := range keys {
		lock := multiplexLocks.byKey[key]
		if lock == nil {
			lock = &multiplexLock{}
			multiplexLocks.byKey[key] = lock
		}
		lock.refs++
		locks = append(locks, lock)
	}
	multiplexLocks.Unlock()
	for _, lock := range locks {
		lock.mu.Lock()
	}
	return func() {
		for i := len(locks) - 1; i >= 0; i-- {
			locks[i].mu.Unlock()
		}
		multiplexLocks.Lock()
		for i, key := range keys {
			lock := locks[i]
			lock.refs--
			if lock.refs == 0 {
				delete(multiplexLocks.byKey, key)
			}
		}
		multiplexLocks.Unlock()
	}
}

func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:1]
	for _, value := range in[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func newPairKey(lab, first, second string) (pairKey, error) {
	if lab == "" {
		return pairKey{}, errors.New("multiplex overlay: lab is empty")
	}
	if first == "" || second == "" {
		return pairKey{}, errors.New("multiplex overlay: node name is empty")
	}
	if first == second {
		return pairKey{}, fmt.Errorf("multiplex overlay: node pair %q is not distinct", first)
	}
	if first > second {
		first, second = second, first
	}
	return pairKey{lab: lab, a: first, b: second}, nil
}

func (k pairKey) identity() string { return k.lab + "\x00" + k.a + "\x00" + k.b }

func (k pairKey) alias() (string, error) {
	alias := pairAliasPrefix + base64.RawURLEncoding.EncodeToString([]byte(k.identity()))
	// IFALIASZ is 256 including the trailing NUL. Refuse a name that cannot
	// carry its full owner identity rather than falling back to a lossy tag
	// and risking two labs sharing an overlay after a hash collision.
	if len(alias) >= 256 {
		return "", fmt.Errorf("multiplex overlay: owner identity is too long")
	}
	return alias, nil
}

func pairKeyFromAlias(alias string) (pairKey, bool) {
	if !strings.HasPrefix(alias, pairAliasPrefix) {
		return pairKey{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(alias, pairAliasPrefix))
	if err != nil {
		return pairKey{}, false
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 {
		return pairKey{}, false
	}
	k, err := newPairKey(parts[0], parts[1], parts[2])
	if err != nil {
		return pairKey{}, false
	}
	return k, true
}

func pairDeviceName(prefix string, k pairKey, salt int) string {
	sum := sha256.Sum256([]byte(k.identity() + "\x00" + strconv.Itoa(salt)))
	// prefix is four bytes, leaving eleven hexadecimal characters under
	// IFNAMSIZ. A colliding name is detected through the complete alias and
	// retried with the next salt.
	return prefix + hex.EncodeToString(sum[:])[:11]
}

func pairPortCandidate(k pairKey, probe int) int {
	sum := sha256.Sum256([]byte("port\x00" + k.identity() + "\x00" + strconv.Itoa(probe)))
	span := multiplexPortLast - multiplexPortFirst + 1
	return multiplexPortFirst + int(binaryBigEndianUint32(sum[:4])%uint32(span))
}

func binaryBigEndianUint32(in []byte) uint32 {
	return uint32(in[0])<<24 | uint32(in[1])<<16 | uint32(in[2])<<8 | uint32(in[3])
}

// MultiplexPairID is the canonical, lab-independent key for a node pair.
// It is suitable for indexing a result from AssignMultiplexPorts.
func MultiplexPairID(first, second string) (string, error) {
	if first == "" || second == "" || first == second {
		return "", fmt.Errorf("multiplex overlay: invalid node pair %q/%q", first, second)
	}
	if first > second {
		first, second = second, first
	}
	return first + "\x00" + second, nil
}

// AssignMultiplexPorts deterministically assigns a distinct UDP destination
// port to every active node pair in one lab. This avoids Linux's one
// flow-based-VNI-0-device-per-local-port socket constraint while preserving
// identical assignments on both endpoint nodes.
func AssignMultiplexPorts(lab string, pairs [][2]string) (map[string]int, error) {
	keys := map[string]pairKey{}
	for _, pair := range pairs {
		k, err := newPairKey(lab, pair[0], pair[1])
		if err != nil {
			return nil, err
		}
		id, _ := MultiplexPairID(k.a, k.b)
		keys[id] = k
	}
	ordered := make([]string, 0, len(keys))
	for id := range keys {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	used := map[int]bool{}
	out := make(map[string]int, len(ordered))
	for _, id := range ordered {
		k := keys[id]
		port := 0
		for probe := 0; probe <= multiplexPortLast-multiplexPortFirst; probe++ {
			candidate := pairPortCandidate(k, probe)
			if !used[candidate] {
				port = candidate
				used[port] = true
				break
			}
		}
		if port == 0 {
			return nil, fmt.Errorf("multiplex overlay: no UDP port available for node pair %q/%q", k.a, k.b)
		}
		out[id] = port
	}
	return out, nil
}

// MultiplexOverlayPort returns the default deterministic port for callers
// that have only one pair. Deploy uses AssignMultiplexPorts to deconflict all
// pairs in a topology before calling EnsureMultiplexOverlay.
func MultiplexOverlayPort(lab, first, second string) (int, error) {
	k, err := newPairKey(lab, first, second)
	if err != nil {
		return 0, err
	}
	return pairPortCandidate(k, 0), nil
}

// MultiplexOverlayNames returns deterministic names for the first candidate
// of a lab/node pair. EnsureMultiplexOverlay probes salted candidates if this
// name is already occupied by another complete owner identity.
func MultiplexOverlayNames(lab, first, second string) (bridge, vxlan string, err error) {
	k, err := newPairKey(lab, first, second)
	if err != nil {
		return "", "", err
	}
	return pairDeviceName("twbp", k, 0), pairDeviceName("twvp", k, 0), nil
}

// AssignOverlayVLANs deterministically maps the supplied VNIs to access VLANs
// for one node pair. It preserves each VNI on the VXLAN wire; only the bridge
// tag is remapped. A pair can carry at most 4094 isolated links.
func AssignOverlayVLANs(vnis []uint32) (map[uint32]uint16, error) {
	unique := map[uint32]bool{}
	for _, vni := range vnis {
		if vni == 0 || vni > maxVNI {
			return nil, fmt.Errorf("multiplex overlay: invalid VNI %d", vni)
		}
		unique[vni] = true
	}
	if len(unique) > maxVLANID {
		return nil, fmt.Errorf("multiplex overlay: %d links exceed %d VLANs for one node pair",
			len(unique), maxVLANID)
	}
	ordered := make([]uint32, 0, len(unique))
	for vni := range unique {
		ordered = append(ordered, vni)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })

	used := make([]bool, maxVLANID+1)
	out := make(map[uint32]uint16, len(ordered))
	for _, vni := range ordered {
		candidate := int((vni-1)%maxVLANID) + 1
		for probe := 0; probe < maxVLANID; probe++ {
			vid := (candidate+probe-1)%maxVLANID + 1
			if used[vid] {
				continue
			}
			used[vid] = true
			out[vni] = uint16(vid)
			break
		}
		if out[vni] == 0 {
			return nil, fmt.Errorf("multiplex overlay: no VLAN available for VNI %d", vni)
		}
	}
	return out, nil
}

// EnsureMultiplexOverlay ensures a shared external VXLAN and bridge exist for
// the lab/node pair, then installs this link's VLAN-to-VNI and FDB bindings.
func EnsureMultiplexOverlay(spec MultiplexOverlaySpec) (string, error) {
	k, err := newPairKey(spec.Lab, spec.LocalNode, spec.RemoteNode)
	if err != nil {
		return "", err
	}
	unlock := lockMultiplexKeys([]string{k.identity()})
	defer unlock()
	if spec.VNI == 0 || spec.VNI > maxVNI {
		return "", fmt.Errorf("multiplex overlay: invalid VNI %d", spec.VNI)
	}
	if spec.VLAN == 0 || spec.VLAN > maxVLANID {
		return "", fmt.Errorf("multiplex overlay VNI %d: invalid VLAN %d", spec.VNI, spec.VLAN)
	}
	local := net.ParseIP(spec.LocalIP)
	if local == nil {
		return "", fmt.Errorf("multiplex overlay VNI %d: local IP %q is not an address", spec.VNI, spec.LocalIP)
	}
	remote := net.ParseIP(spec.RemoteIP)
	if remote == nil {
		return "", fmt.Errorf("multiplex overlay VNI %d: remote IP %q is not an address", spec.VNI, spec.RemoteIP)
	}
	if spec.MTU == 0 {
		spec.MTU = 1500
	}
	if spec.Port == 0 {
		spec.Port = pairPortCandidate(k, 0)
	}

	h, err := netlink.NewHandle()
	if err != nil {
		return "", fmt.Errorf("open host netlink handle: %w", err)
	}
	defer h.Close()

	br, vx, err := ensureMultiplexPair(h, k, spec, local)
	if err != nil {
		return "", err
	}
	if err := ensureMultiplexBinding(h, vx, spec.VLAN, spec.VNI, remote); err != nil {
		return "", err
	}
	return br.Attrs().Name, nil
}

func ensureMultiplexPair(h *netlink.Handle, k pairKey, spec MultiplexOverlaySpec,
	local net.IP) (*netlink.Bridge, *netlink.Vxlan, error) {

	alias, err := k.alias()
	if err != nil {
		return nil, nil, err
	}
	vtepIndex := 0
	if spec.UnderlayDev != "" {
		underlay, err := h.LinkByName(spec.UnderlayDev)
		if err != nil {
			return nil, nil, fmt.Errorf("multiplex overlay VNI %d: underlay device %s: %w",
				spec.VNI, spec.UnderlayDev, err)
		}
		vtepIndex = underlay.Attrs().Index
	}
	// The keyed in-process lock covers plan fan-out. EEXIST handling below is
	// still mandatory: controller retries and a local CLI can be separate
	// processes sharing the same kernel namespace.
	last := ""
	for retry := 0; retry < 16; retry++ {
		bridgeName, vxlanName, _, _, err := multiplexPairCandidate(h, k, alias)
		if err != nil {
			return nil, nil, err
		}
		br, raced, err := ensurePairBridge(h, bridgeName, alias, spec.MTU+50)
		if err != nil {
			return nil, nil, err
		}
		if raced {
			last = "bridge creation raced"
			continue
		}
		if err := reconcileMultiplexBridge(h, br, spec.MTU+50, alias, spec.PreserveActive); err != nil {
			return nil, nil, err
		}

		vx, raced, err := ensurePairVXLAN(h, vxlanName, alias, spec.MTU, local, vtepIndex, spec.Port)
		if err != nil {
			return nil, nil, err
		}
		if raced {
			last = "VXLAN creation raced"
			continue
		}
		if reason := multiplexVXLANReason(vx, local, vtepIndex, spec.Port, spec.MTU); reason != "" {
			if spec.PreserveActive && canKeepRecoveryTrunk(vx, local, vtepIndex) {
				// Recovery must never tear down a known pair merely because
				// the old generation used a legacy MTU/port. The subsequent
				// binding reconciliation is idempotent and proves the trunk
				// can carry the restored VNI before recovery succeeds.
				reason = ""
			}
			if reason == "" {
				// Keep the existing recovery trunk.
			} else {
				active, err := multiplexPairActive(h, br, vx)
				if err != nil {
					return nil, nil, err
				}
				if active {
					if (spec.PreserveActive && canKeepRecoveryTrunk(vx, local, vtepIndex)) ||
						(!spec.ForcePort && canKeepActivePort(vx, local, vtepIndex, spec.MTU)) {
						// Keep a previously allocated (including the first
						// rollout's standard) port while it carries links.
						// Pair sets can change between generations, so replacing
						// an active trunk merely to reshuffle a collision probe
						// would cut student traffic and make rollback impossible.
						reason = ""
					} else {
						if !spec.ForcePort {
							return nil, nil, fmt.Errorf(
								"multiplex VXLAN %s conflicts with the requested pair configuration (%s) while active; refusing to replace it",
								vxlanName, reason)
						}
						// A targeted repair observed a broken pair on both
						// endpoint agents. Replacing the active receive socket
						// is the only way to converge an old 4789 trunk with a
						// peer that has moved to the deterministic port.
					}
				}
				if reason == "" {
					// The legacy standard-port trunk is otherwise identical and
					// may continue through the ordinary binding reconciliation.
				} else {
					if err := h.LinkDel(vx); err != nil && !IsNotFound(err) {
						return nil, nil, fmt.Errorf("replace inactive multiplex VXLAN %s: %w", vxlanName, err)
					}
					last = "replacing inactive VXLAN: " + reason
					continue
				}
			}
		}
		if vx.Attrs().MasterIndex != 0 && vx.Attrs().MasterIndex != br.Attrs().Index {
			return nil, nil, fmt.Errorf("multiplex VXLAN %s is attached to an unexpected bridge", vxlanName)
		}
		if err := attachToBridgeHandle(h, vx, br); err != nil {
			return nil, nil, err
		}
		if err := multiplexCreatedStep("vxlan-attached"); err != nil {
			return nil, nil, err
		}
		if vx.Attrs().Flags&net.FlagUp == 0 {
			if err := h.LinkSetUp(vx); err != nil {
				return nil, nil, fmt.Errorf("set multiplex VXLAN %s up: %w", vxlanName, err)
			}
		}
		prot, err := h.LinkGetProtinfo(vx)
		if err != nil {
			return nil, nil, fmt.Errorf("multiplex VXLAN %s needs bridge VLAN tunnel support: %w", vxlanName, err)
		}
		if !prot.VlanTunnel {
			if err := h.LinkSetVlanTunnel(vx, true); err != nil {
				return nil, nil, fmt.Errorf(
					"multiplex VXLAN %s requires Linux bridge VLAN tunnel mapping (kernel >= 4.11): %w",
					vxlanName, err)
			}
		}
		if err := multiplexCreatedStep("trunk-ready"); err != nil {
			return nil, nil, err
		}
		return br, vx, nil
	}
	return nil, nil, fmt.Errorf("multiplex overlay %q/%q did not converge after concurrent object creation (%s)",
		k.a, k.b, last)
}

// ensurePairBridge creates or adopts an inactive matching bridge. raced means
// a different process won LinkAdd, so the caller must re-select and validate
// the candidate instead of assuming the object it just observed is unchanged.
func ensurePairBridge(h *netlink.Handle, name, alias string, mtu int) (*netlink.Bridge, bool, error) {
	link, err := h.LinkByName(name)
	created := false
	if err != nil {
		if !IsNotFound(err) {
			return nil, false, fmt.Errorf("look up multiplex bridge %s: %w", name, err)
		}
		filtering := true
		defaultPVID := uint16(0)
		bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{
			Name: name, MTU: mtu, Alias: alias,
		}, VlanFiltering: &filtering, VlanDefaultPVID: &defaultPVID}
		if err := h.LinkAdd(bridge); err != nil {
			if isExist(err) {
				return nil, true, nil
			}
			return nil, false, fmt.Errorf("create multiplex bridge %s: %w", name, err)
		}
		created = true
		link, err = h.LinkByName(name)
		if err != nil {
			return nil, false, fmt.Errorf("re-resolve multiplex bridge %s: %w", name, err)
		}
	}
	bridge, ok := link.(*netlink.Bridge)
	if !ok {
		return nil, false, fmt.Errorf("multiplex bridge %s exists as %s", name, link.Type())
	}
	if err := adoptInactivePairLink(h, bridge, alias, "bridge"); err != nil {
		return nil, false, err
	}
	link, err = h.LinkByName(name)
	if err != nil {
		return nil, false, fmt.Errorf("re-resolve multiplex bridge %s: %w", name, err)
	}
	bridge, ok = link.(*netlink.Bridge)
	if !ok {
		return nil, false, fmt.Errorf("multiplex bridge %s became %s", name, link.Type())
	}
	if created {
		if err := multiplexCreatedStep("bridge-created"); err != nil {
			return bridge, false, err
		}
	}
	return bridge, false, nil
}

func ensurePairVXLAN(h *netlink.Handle, name, alias string, mtu int, local net.IP,
	vtepIndex, port int) (*netlink.Vxlan, bool, error) {

	link, err := h.LinkByName(name)
	created := false
	if err != nil {
		if !IsNotFound(err) {
			return nil, false, fmt.Errorf("look up multiplex VXLAN %s: %w", name, err)
		}
		vxlan := &netlink.Vxlan{
			LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu, Alias: alias},
			// FlowBased is iproute2's `external` VXLAN. The bridge's VLAN
			// tunnel map supplies the VNI for each frame, rather than one
			// netdev carrying exactly one VNI.
			FlowBased:    true,
			VtepDevIndex: vtepIndex,
			SrcAddr:      local,
			Port:         port,
			Learning:     false,
			L2miss:       false,
			L3miss:       false,
		}
		if err := h.LinkAdd(vxlan); err != nil {
			if isExist(err) {
				if existing, lookupErr := h.LinkByName(name); lookupErr == nil && existing != nil {
					return nil, true, nil
				}
				return nil, false, fmt.Errorf(
					"create multiplex VXLAN %s: UDP port %d is already bound by another external VXLAN; "+
						"assign a distinct pair port: %w", name, port, err)
			}
			return nil, false, fmt.Errorf("create multiplex VXLAN %s: %w", name, err)
		}
		created = true
		link, err = h.LinkByName(name)
		if err != nil {
			return nil, false, fmt.Errorf("re-resolve multiplex VXLAN %s: %w", name, err)
		}
	}
	vxlan, ok := link.(*netlink.Vxlan)
	if !ok {
		return nil, false, fmt.Errorf("multiplex VXLAN %s exists as %s", name, link.Type())
	}
	if err := adoptInactivePairLink(h, vxlan, alias, "VXLAN"); err != nil {
		return nil, false, err
	}
	link, err = h.LinkByName(name)
	if err != nil {
		return nil, false, fmt.Errorf("re-resolve multiplex VXLAN %s: %w", name, err)
	}
	vxlan, ok = link.(*netlink.Vxlan)
	if !ok {
		return nil, false, fmt.Errorf("multiplex VXLAN %s became %s", name, link.Type())
	}
	if created {
		if err := multiplexCreatedStep("vxlan-created"); err != nil {
			return vxlan, false, err
		}
	}
	return vxlan, false, nil
}

var multiplexStepHooks = struct {
	sync.RWMutex
	hook func(string) error
}{}

// multiplexCreatedStep is deliberately unexported. Focused netx tests use it
// to leave a bridge, a VXLAN, or an attached trunk behind at each interruption
// boundary and prove a later Ensure converges it safely.
func multiplexCreatedStep(step string) error {
	multiplexStepHooks.RLock()
	hook := multiplexStepHooks.hook
	multiplexStepHooks.RUnlock()
	if hook == nil {
		return nil
	}
	return hook(step)
}

func adoptInactivePairLink(h *netlink.Handle, link netlink.Link, alias, kind string) error {
	switch link.Attrs().Alias {
	case alias:
		return nil
	case "":
		active, err := multiplexLinkActive(h, link)
		if err != nil {
			return err
		}
		if active && !recognizablePartialPair(h, link, alias) {
			return fmt.Errorf("refusing to adopt active unowned multiplex %s %s",
				kind, link.Attrs().Name)
		}
		if err := h.LinkSetAlias(link, alias); err != nil {
			return fmt.Errorf("stamp multiplex %s %s owner: %w", kind, link.Attrs().Name, err)
		}
		return nil
	default:
		return fmt.Errorf("multiplex %s %s is owned by another pair", kind, link.Attrs().Name)
	}
}

// recognizablePartialPair permits recovery from the narrow, unavoidable
// window between LinkAdd and LinkSetAlias in another process. It never adopts
// a bridge carrying a host-side port: that could be a live foreign lab. The
// only active partial shape accepted is the deterministic bridge/VXLAN pair
// itself, with no access ports attached yet.
func recognizablePartialPair(h *netlink.Handle, link netlink.Link, alias string) bool {
	key, ok := pairKeyFromAlias(alias)
	if !ok {
		return false
	}
	matches := func(prefix, name string) bool {
		for salt := 0; salt < 16; salt++ {
			if pairDeviceName(prefix, key, salt) == name {
				return true
			}
		}
		return false
	}
	switch typed := link.(type) {
	case *netlink.Bridge:
		if !matches("twbp", typed.Attrs().Name) {
			return false
		}
		links, err := h.LinkList()
		if err != nil {
			return false
		}
		foundVXLAN := false
		for _, child := range links {
			if child.Attrs().MasterIndex != typed.Attrs().Index {
				continue
			}
			vx, ok := child.(*netlink.Vxlan)
			if !ok || !matches("twvp", vx.Attrs().Name) {
				return false
			}
			if vx.Attrs().Alias != "" && vx.Attrs().Alias != alias {
				return false
			}
			foundVXLAN = true
		}
		return foundVXLAN
	case *netlink.Vxlan:
		if !matches("twvp", typed.Attrs().Name) || typed.Attrs().MasterIndex == 0 {
			return false
		}
		master, err := h.LinkByIndex(typed.Attrs().MasterIndex)
		if err != nil {
			return false
		}
		bridge, ok := master.(*netlink.Bridge)
		if !ok || !matches("twbp", bridge.Attrs().Name) {
			return false
		}
		if bridge.Attrs().Alias != "" && bridge.Attrs().Alias != alias {
			return false
		}
		links, err := h.LinkList()
		if err != nil {
			return false
		}
		for _, child := range links {
			if child.Attrs().MasterIndex == bridge.Attrs().Index &&
				child.Attrs().Index != typed.Attrs().Index {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func multiplexLinkActive(h *netlink.Handle, link netlink.Link) (bool, error) {
	switch typed := link.(type) {
	case *netlink.Vxlan:
		active, err := vxlanHasActiveBindings(typed)
		if err != nil || active || typed.Attrs().MasterIndex == 0 {
			return active, err
		}
		links, err := h.LinkList()
		if err != nil {
			return false, fmt.Errorf("list host interfaces: %w", err)
		}
		for _, child := range links {
			if child.Attrs().MasterIndex == typed.Attrs().MasterIndex &&
				child.Attrs().Index != typed.Attrs().Index {
				return true, nil
			}
		}
		return false, nil
	case *netlink.Bridge:
		links, err := h.LinkList()
		if err != nil {
			return false, fmt.Errorf("list host interfaces: %w", err)
		}
		for _, child := range links {
			if child.Attrs().MasterIndex != typed.Attrs().Index {
				continue
			}
			if vx, ok := child.(*netlink.Vxlan); ok {
				active, err := vxlanHasActiveBindings(vx)
				if err != nil {
					return false, err
				}
				if active {
					return true, nil
				}
				continue
			}
			return true, nil
		}
		return false, nil
	default:
		return false, fmt.Errorf("multiplex object %s has unsupported type %s",
			link.Attrs().Name, link.Type())
	}
}

func vxlanHasActiveBindings(vx *netlink.Vxlan) (bool, error) {
	entries, err := listExternalFDB(vx)
	if err != nil {
		return false, err
	}
	zero := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	for _, entry := range entries {
		if !bytesEqual(entry.HardwareAddr, zero) || entry.IP == nil {
			continue
		}
		if entry.SourceVNI != 0 || entry.VNI != 0 {
			return true, nil
		}
	}
	return false, nil
}

func multiplexPairActive(h *netlink.Handle, bridge *netlink.Bridge, vxlan *netlink.Vxlan) (bool, error) {
	if active, err := vxlanHasActiveBindings(vxlan); err != nil || active {
		return active, err
	}
	links, err := h.LinkList()
	if err != nil {
		return false, fmt.Errorf("list host interfaces: %w", err)
	}
	for _, child := range links {
		if child.Attrs().MasterIndex == bridge.Attrs().Index &&
			child.Attrs().Index != vxlan.Attrs().Index {
			return true, nil
		}
	}
	return false, nil
}

func multiplexPairCandidate(h *netlink.Handle, k pairKey, alias string) (
	bridgeName, vxlanName string, br *netlink.Bridge, vx *netlink.Vxlan, err error,
) {
	for salt := 0; salt < 4096; salt++ {
		bridgeName, vxlanName = pairDeviceName("twbp", k, salt), pairDeviceName("twvp", k, salt)
		brLink, brState, err := ownedPairLink(h, bridgeName, alias, "bridge")
		if err != nil {
			return "", "", nil, nil, err
		}
		vxLink, vxState, err := ownedPairLink(h, vxlanName, alias, "vxlan")
		if err != nil {
			return "", "", nil, nil, err
		}
		if brState == pairLinkConflict || vxState == pairLinkConflict {
			if brState == pairLinkOwned || brState == pairLinkPartial ||
				vxState == pairLinkOwned || vxState == pairLinkPartial {
				return "", "", nil, nil, fmt.Errorf(
					"multiplex overlay name collision for %q/%q: one of %s or %s belongs to another object",
					k.a, k.b, bridgeName, vxlanName)
			}
			continue
		}
		if brLink != nil {
			var ok bool
			br, ok = brLink.(*netlink.Bridge)
			if !ok {
				return "", "", nil, nil, fmt.Errorf("%s is not a bridge", bridgeName)
			}
		}
		if vxLink != nil {
			var ok bool
			vx, ok = vxLink.(*netlink.Vxlan)
			if !ok {
				return "", "", nil, nil, fmt.Errorf("%s is not a VXLAN", vxlanName)
			}
		}
		return bridgeName, vxlanName, br, vx, nil
	}
	return "", "", nil, nil, fmt.Errorf("multiplex overlay: exhausted deterministic name collision probes")
}

type pairLinkState uint8

const (
	pairLinkMissing pairLinkState = iota
	pairLinkOwned
	pairLinkPartial
	pairLinkConflict
)

func ownedPairLink(h *netlink.Handle, name, alias, kind string) (netlink.Link, pairLinkState, error) {
	link, err := h.LinkByName(name)
	if err != nil {
		if IsNotFound(err) {
			return nil, pairLinkMissing, nil
		}
		return nil, pairLinkConflict, fmt.Errorf("look up multiplex %s %s: %w", kind, name, err)
	}
	switch kind {
	case "bridge":
		if _, ok := link.(*netlink.Bridge); !ok {
			return link, pairLinkConflict, nil
		}
	case "vxlan":
		if _, ok := link.(*netlink.Vxlan); !ok {
			return link, pairLinkConflict, nil
		}
	}
	switch link.Attrs().Alias {
	case alias:
		return link, pairLinkOwned, nil
	case "":
		return link, pairLinkPartial, nil
	default:
		return link, pairLinkConflict, nil
	}
}

func reconcileMultiplexBridge(h *netlink.Handle, br *netlink.Bridge, mtu int, alias string,
	preserveActive bool,
) error {
	if br.Attrs().Alias != alias {
		return fmt.Errorf("multiplex bridge %s has an unexpected owner", br.Attrs().Name)
	}
	if br.Attrs().MTU != mtu && !preserveActive {
		if err := h.LinkSetMTU(br, mtu); err != nil {
			return fmt.Errorf("set multiplex bridge %s MTU: %w", br.Attrs().Name, err)
		}
	}
	if br.VlanFiltering == nil || !*br.VlanFiltering {
		if err := h.BridgeSetVlanFiltering(br, true); err != nil {
			return fmt.Errorf("enable VLAN filtering on multiplex bridge %s: %w", br.Attrs().Name, err)
		}
	}
	if br.VlanDefaultPVID == nil || *br.VlanDefaultPVID != 0 {
		if err := h.BridgeSetVlanDefaultPVID(br, 0); err != nil {
			return fmt.Errorf("disable default VLAN on multiplex bridge %s: %w", br.Attrs().Name, err)
		}
	}
	if br.Attrs().Flags&net.FlagUp == 0 {
		if err := h.LinkSetUp(br); err != nil {
			return fmt.Errorf("set multiplex bridge %s up: %w", br.Attrs().Name, err)
		}
	}
	return nil
}

func multiplexVXLANReason(vx *netlink.Vxlan, local net.IP, vtepIndex, port, mtu int) string {
	switch {
	case !vx.FlowBased:
		return "it is not an external (flow-based) VXLAN"
	case vx.VxlanId != 0:
		return fmt.Sprintf("it has fixed VNI %d", vx.VxlanId)
	case !vx.SrcAddr.Equal(local):
		return fmt.Sprintf("it is sourced from %s, not %s", vx.SrcAddr, local)
	case vtepIndex != 0 && vx.VtepDevIndex != vtepIndex:
		return fmt.Sprintf("it is sourced from interface index %d, not %d", vx.VtepDevIndex, vtepIndex)
	case vx.Port != port:
		return fmt.Sprintf("it uses VTEP port %d, not %d", vx.Port, port)
	case vx.Attrs().MTU != mtu:
		return fmt.Sprintf("it has MTU %d, not %d", vx.Attrs().MTU, mtu)
	case vx.Learning:
		return "it has MAC learning enabled"
	}

	return ""
}

func canKeepActivePort(vx *netlink.Vxlan, local net.IP, vtepIndex, mtu int) bool {
	if vx.Port <= 0 || !vx.FlowBased || vx.VxlanId != 0 || vx.Learning ||
		!vx.SrcAddr.Equal(local) || vx.Attrs().MTU != mtu {
		return false
	}
	return vtepIndex == 0 || vx.VtepDevIndex == vtepIndex
}

func canKeepRecoveryTrunk(vx *netlink.Vxlan, local net.IP, vtepIndex int) bool {
	if !vx.FlowBased || vx.VxlanId != 0 || vx.Learning || !vx.SrcAddr.Equal(local) {
		return false
	}
	return vtepIndex == 0 || vx.VtepDevIndex == vtepIndex
}

func ensureMultiplexBinding(h *netlink.Handle, vx *netlink.Vxlan, vlan uint16, vni uint32, remote net.IP) error {
	if err := ensureVLANMembership(h, vx, vlan, false, false, false); err != nil {
		return err
	}
	if err := multiplexCreatedStep("binding-vlan"); err != nil {
		return err
	}
	if err := reconcileTunnelMapping(h, vx, vlan, vni); err != nil {
		return err
	}
	if err := h.BridgeVlanAddTunnelInfo(vx, vlan, 0, vni, 0, false, false); err != nil && !isExist(err) {
		return fmt.Errorf("map VLAN %d to VNI %d on %s: %w", vlan, vni, vx.Attrs().Name, err)
	}
	tunnels, err := h.BridgeVlanTunnelShow()
	if err != nil {
		return fmt.Errorf("multiplex VXLAN %s: verify VLAN tunnel mapping: %w", vx.Attrs().Name, err)
	}
	for _, tunnel := range tunnels {
		if tunnel.Vid == vlan && tunnel.TunId == vni {
			if err := multiplexCreatedStep("binding-mapped"); err != nil {
				return err
			}
			if err := ensureVNIForwarding(vx, vni, remote); err != nil {
				return err
			}
			if err := multiplexCreatedStep("binding-fdb"); err != nil {
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("multiplex VXLAN %s did not retain VLAN %d to VNI %d mapping",
		vx.Attrs().Name, vlan, vni)
}

func reconcileTunnelMapping(h *netlink.Handle, vx *netlink.Vxlan, vlan uint16, vni uint32) error {
	vnis, err := multiplexVNIs(h, vx)
	if err != nil {
		return err
	}
	own := make(map[uint32]bool, len(vnis))
	for _, current := range vnis {
		own[current] = true
	}
	tunnels, err := h.BridgeVlanTunnelShow()
	if err != nil {
		return fmt.Errorf("multiplex VXLAN %s: list VLAN tunnel mappings: %w", vx.Attrs().Name, err)
	}
	for _, tunnel := range tunnels {
		// VNI allocation is node-global, so a mapping for one of this
		// VXLAN's FDB VNIs belongs to this port even though v1.3.1 of the
		// netlink library omits the port index from TunnelInfo.
		if !own[tunnel.TunId] {
			continue
		}
		if (tunnel.TunId == vni && tunnel.Vid != vlan) ||
			(tunnel.Vid == vlan && tunnel.TunId != vni) {
			if err := h.BridgeVlanDelTunnelInfo(vx, tunnel.Vid, 0, tunnel.TunId, 0, false, false); err != nil &&
				!errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("multiplex VXLAN %s: replace VLAN %d/VNI %d mapping: %w",
					vx.Attrs().Name, tunnel.Vid, tunnel.TunId, err)
			}
		}
	}
	return nil
}

// AttachToMultiplexOverlay adds a host-side veth as one isolated access VLAN
// on a shared bridge. The veth is never left in VLAN 1, which would otherwise
// join all links on the pair and leak broadcasts and MAC learning.
func AttachToMultiplexOverlay(iface, bridge string, vlan uint16) error {
	if vlan == 0 || vlan > maxVLANID {
		return fmt.Errorf("multiplex overlay: invalid VLAN %d", vlan)
	}
	h, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("open host netlink handle: %w", err)
	}
	defer h.Close()
	port, err := h.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("find host port %s: %w", iface, err)
	}
	link, err := h.LinkByName(bridge)
	if err != nil {
		return fmt.Errorf("find multiplex bridge %s: %w", bridge, err)
	}
	br, ok := link.(*netlink.Bridge)
	if !ok {
		return fmt.Errorf("%s is not a bridge", bridge)
	}
	if br.VlanFiltering == nil || !*br.VlanFiltering {
		return fmt.Errorf("multiplex bridge %s does not have VLAN filtering enabled", bridge)
	}
	if _, ok := pairKeyFromAlias(br.Attrs().Alias); !ok {
		return fmt.Errorf("multiplex bridge %s is not owned by Twinet", bridge)
	}
	if err := attachToBridgeHandle(h, port, br); err != nil {
		return err
	}
	if err := ensureVLANMembership(h, port, vlan, true, true, true); err != nil {
		return err
	}
	if port.Attrs().Flags&net.FlagUp == 0 {
		if err := h.LinkSetUp(port); err != nil {
			return fmt.Errorf("set host port %s up: %w", iface, err)
		}
	}
	return nil
}

func attachToBridgeHandle(h *netlink.Handle, link netlink.Link, bridge *netlink.Bridge) error {
	if link.Attrs().MasterIndex == bridge.Attrs().Index {
		return nil
	}
	if err := h.LinkSetMaster(link, bridge); err != nil {
		return fmt.Errorf("attach %s to bridge %s: %w", link.Attrs().Name, bridge.Attrs().Name, err)
	}
	return nil
}

func ensureVLANMembership(h *netlink.Handle, link netlink.Link, vlan uint16,
	pvid, untagged, exclusive bool) error {

	memberships, err := h.BridgeVlanList()
	if err != nil {
		return fmt.Errorf("list VLANs on %s: %w", link.Attrs().Name, err)
	}
	infos := memberships[int32(link.Attrs().Index)]
	haveDesired := false
	for _, info := range infos {
		if info.Vid == vlan {
			if info.PortVID() == pvid && info.EngressUntag() == untagged {
				haveDesired = true
				continue
			}
			if err := deleteVLANMembership(h, link, info); err != nil {
				return err
			}
			continue
		}
		// A tunnel trunk may carry other link VLANs, but it must never retain
		// a PVID or untagged default membership: either one would put unknown
		// untagged frames into a shared broadcast domain.
		if exclusive || info.PortVID() || info.EngressUntag() {
			if err := deleteVLANMembership(h, link, info); err != nil {
				return err
			}
		}
	}
	if haveDesired {
		return nil
	}
	if err := h.BridgeVlanAdd(link, vlan, pvid, untagged, false, false); err != nil && !isExist(err) {
		return fmt.Errorf("add VLAN %d to %s: %w", vlan, link.Attrs().Name, err)
	}
	return nil
}

func deleteVLANMembership(h *netlink.Handle, link netlink.Link, info *nl.BridgeVlanInfo) error {
	if err := h.BridgeVlanDel(link, info.Vid, info.PortVID(), info.EngressUntag(), false, false); err != nil &&
		!errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("remove VLAN %d from %s: %w", info.Vid, link.Attrs().Name, err)
	}
	return nil
}

func ensureVNIForwarding(vx *netlink.Vxlan, vni uint32, remote net.IP) error {
	entries, err := listExternalFDB(vx)
	if err != nil {
		return fmt.Errorf("multiplex VXLAN %s: list forwarding entries: %w", vx.Attrs().Name, err)
	}
	zero := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	correct := 0
	for i := range entries {
		entry := entries[i]
		if entry.VNI != int(vni) || !bytesEqual(entry.HardwareAddr, zero) {
			continue
		}
		if entry.SourceVNI == vni && entry.IP != nil && entry.IP.Equal(remote) {
			correct++
			if correct == 1 {
				continue
			}
		}
		if err := deleteExternalFDB(vx, entry.SourceVNI, uint32(entry.VNI), entry.IP, entry.HardwareAddr); err != nil &&
			!errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("multiplex VXLAN %s: remove stale VNI %d FDB entry: %w",
				vx.Attrs().Name, vni, err)
		}
	}
	if correct > 0 {
		return nil
	}
	if err := addExternalFDB(vx, vni, vni, remote, zero); err != nil && !isExist(err) {
		return fmt.Errorf("multiplex VXLAN %s: add VNI %d FDB entry: %w", vx.Attrs().Name, vni, err)
	}
	return nil
}

// externalFDBEntry keeps the source VNI that the public netlink.Neigh type
// omits. On a flow-based VXLAN, NDA_VNI names the remote encapsulation VNI,
// while NDA_SRC_VNI keys the local FDB lookup performed for bridge tunnel
// metadata. Both must be set to the link VNI.
type externalFDBEntry struct {
	netlink.Neigh
	SourceVNI uint32
}

func listExternalFDB(vx *netlink.Vxlan) ([]externalFDBEntry, error) {
	msg := netlink.Ndmsg{Family: syscall.AF_BRIDGE, Index: uint32(vx.Attrs().Index)}
	req := nl.NewNetlinkRequest(unix.RTM_GETNEIGH, unix.NLM_F_DUMP)
	req.AddData(&msg)
	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWNEIGH)
	if err != nil {
		return nil, err
	}
	var out []externalFDBEntry
	for _, raw := range msgs {
		neigh, err := netlink.NeighDeserialize(raw)
		if err != nil || neigh.LinkIndex != vx.Attrs().Index || neigh.Family != syscall.AF_BRIDGE {
			continue
		}
		attrs, err := nl.ParseRouteAttr(raw[msg.Len():])
		if err != nil {
			return nil, err
		}
		entry := externalFDBEntry{Neigh: *neigh}
		for _, attr := range attrs {
			if attr.Attr.Type == unix.NDA_SRC_VNI && len(attr.Value) >= 4 {
				entry.SourceVNI = nl.NativeEndian().Uint32(attr.Value[:4])
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

func addExternalFDB(vx *netlink.Vxlan, sourceVNI, remoteVNI uint32, remote net.IP,
	hardware net.HardwareAddr) error {

	return externalFDBRequest(unix.RTM_NEWNEIGH, unix.NLM_F_CREATE|unix.NLM_F_APPEND,
		vx, sourceVNI, remoteVNI, remote, hardware)
}

func deleteExternalFDB(vx *netlink.Vxlan, sourceVNI, remoteVNI uint32, remote net.IP,
	hardware net.HardwareAddr) error {

	return externalFDBRequest(unix.RTM_DELNEIGH, 0, vx, sourceVNI, remoteVNI, remote, hardware)
}

func externalFDBRequest(operation, flags int, vx *netlink.Vxlan, sourceVNI, remoteVNI uint32,
	remote net.IP, hardware net.HardwareAddr) error {

	req := nl.NewNetlinkRequest(operation, flags|unix.NLM_F_ACK)
	msg := netlink.Ndmsg{
		Family: uint8(syscall.AF_BRIDGE),
		Index:  uint32(vx.Attrs().Index),
		State:  uint16(netlink.NUD_PERMANENT),
		Flags:  uint8(netlink.NTF_SELF),
	}
	req.AddData(&msg)
	ip := remote.To4()
	if ip == nil {
		ip = remote.To16()
	}
	if ip == nil {
		return fmt.Errorf("invalid FDB remote %q", remote)
	}
	req.AddData(nl.NewRtAttr(unix.NDA_DST, []byte(ip)))
	req.AddData(nl.NewRtAttr(unix.NDA_LLADDR, []byte(hardware)))
	if remoteVNI != 0 {
		req.AddData(nl.NewRtAttr(unix.NDA_VNI, nl.Uint32Attr(remoteVNI)))
	}
	if sourceVNI != 0 {
		req.AddData(nl.NewRtAttr(unix.NDA_SRC_VNI, nl.Uint32Attr(sourceVNI)))
	}
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

type multiplexDevice struct {
	key pairKey
	vx  *netlink.Vxlan
	br  *netlink.Bridge
}

func multiplexDevices(h *netlink.Handle, lab string) ([]multiplexDevice, error) {
	links, err := h.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list host interfaces: %w", err)
	}
	byIndex := make(map[int]netlink.Link, len(links))
	for _, link := range links {
		byIndex[link.Attrs().Index] = link
	}
	var out []multiplexDevice
	for _, link := range links {
		vx, ok := link.(*netlink.Vxlan)
		if !ok {
			continue
		}
		key, ok := pairKeyFromAlias(vx.Attrs().Alias)
		if !ok {
			continue
		}
		if lab != "" && key.lab != lab {
			continue
		}
		if !vx.FlowBased {
			return nil, fmt.Errorf("multiplex VXLAN %s is not flow-based", vx.Attrs().Name)
		}
		var br *netlink.Bridge
		if master, ok := byIndex[vx.Attrs().MasterIndex]; ok {
			br, _ = master.(*netlink.Bridge)
		}
		if br != nil && br.Attrs().Alias != vx.Attrs().Alias {
			return nil, fmt.Errorf("multiplex VXLAN %s is attached to bridge %s owned by another pair",
				vx.Attrs().Name, br.Attrs().Name)
		}
		out = append(out, multiplexDevice{key: key, vx: vx, br: br})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].vx.Attrs().Name < out[j].vx.Attrs().Name })
	return out, nil
}

func multiplexVNIs(_ *netlink.Handle, vx *netlink.Vxlan) ([]uint32, error) {
	entries, err := listExternalFDB(vx)
	if err != nil {
		return nil, fmt.Errorf("multiplex VXLAN %s: list forwarding entries: %w", vx.Attrs().Name, err)
	}
	zero := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	seen := map[uint32]bool{}
	for _, entry := range entries {
		if entry.SourceVNI == 0 || !bytesEqual(entry.HardwareAddr, zero) {
			continue
		}
		seen[entry.SourceVNI] = true
	}
	out := make([]uint32, 0, len(seen))
	for vni := range seen {
		out = append(out, vni)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func listMultiplexOverlays(lab string) ([]MultiplexOverlay, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("open host netlink handle: %w", err)
	}
	defer h.Close()
	devices, err := multiplexDevices(h, lab)
	if err != nil {
		return nil, err
	}
	out := make([]MultiplexOverlay, 0, len(devices))
	for _, device := range devices {
		vnis, err := multiplexVNIs(h, device.vx)
		if err != nil {
			return nil, err
		}
		bridge := ""
		if device.br != nil {
			bridge = device.br.Attrs().Name
		}
		out = append(out, MultiplexOverlay{
			Lab: device.key.lab, NodeA: device.key.a, NodeB: device.key.b,
			Bridge: bridge, Vxlan: device.vx.Attrs().Name, VNIs: vnis,
		})
	}
	return out, nil
}

// ListMultiplexOverlaysOfLab lists shared overlay objects and their active
// VNI bindings for one lab.
func ListMultiplexOverlaysOfLab(lab string) ([]MultiplexOverlay, error) {
	return listMultiplexOverlays(lab)
}

func listMultiplexVNIs(lab string) ([]uint32, error) {
	overlays, err := listMultiplexOverlays(lab)
	if err != nil {
		return nil, err
	}
	seen := map[uint32]bool{}
	for _, overlay := range overlays {
		for _, vni := range overlay.VNIs {
			seen[vni] = true
		}
	}
	out := make([]uint32, 0, len(seen))
	for vni := range seen {
		out = append(out, vni)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func multiplexOwners() (map[uint32]string, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("open host netlink handle: %w", err)
	}
	defer h.Close()
	devices, err := multiplexDevices(h, "")
	if err != nil {
		return nil, err
	}
	out := map[uint32]string{}
	for _, device := range devices {
		vnis, err := multiplexVNIs(h, device.vx)
		if err != nil {
			return nil, err
		}
		for _, vni := range vnis {
			out[vni] = device.key.lab
		}
	}
	return out, nil
}

func removeMultiplexVNI(vni uint32) error {
	h, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("open host netlink handle: %w", err)
	}
	defer h.Close()
	devices, err := multiplexDevices(h, "")
	if err != nil {
		return err
	}
	targets, err := multiplexDevicesForVNI(h, devices, vni)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(targets))
	for _, device := range targets {
		keys = append(keys, device.key.identity())
	}
	unlock := lockMultiplexKeys(keys)
	defer unlock()
	// Re-list after obtaining pair locks so concurrent VNI removals cannot
	// delete the shared VXLAN between observation and mutation.
	devices, err = multiplexDevices(h, "")
	if err != nil {
		return err
	}
	targets, err = multiplexDevicesForVNI(h, devices, vni)
	if err != nil {
		return err
	}
	var problems []string
	for _, device := range targets {
		if err := removeVNIFromDevice(h, device, vni); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func multiplexDevicesForVNI(h *netlink.Handle, devices []multiplexDevice, vni uint32) ([]multiplexDevice, error) {
	var out []multiplexDevice
	for _, device := range devices {
		vnis, err := multiplexVNIs(h, device.vx)
		if err != nil {
			return nil, err
		}
		for _, candidate := range vnis {
			if candidate == vni {
				out = append(out, device)
				break
			}
		}
	}
	return out, nil
}

func removeVNIFromDevice(h *netlink.Handle, device multiplexDevice, vni uint32) error {
	entries, err := listExternalFDB(device.vx)
	if err != nil {
		return fmt.Errorf("multiplex VXLAN %s: list forwarding entries: %w", device.vx.Attrs().Name, err)
	}
	found := false
	for i := range entries {
		entry := entries[i]
		if entry.SourceVNI != vni && uint32(entry.VNI) != vni {
			continue
		}
		found = true
		if err := deleteExternalFDB(device.vx, entry.SourceVNI, uint32(entry.VNI),
			entry.IP, entry.HardwareAddr); err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("multiplex VXLAN %s: remove VNI %d FDB entry: %w",
				device.vx.Attrs().Name, vni, err)
		}
	}
	if !found {
		return nil
	}
	tunnels, err := h.BridgeVlanTunnelShow()
	if err != nil {
		return fmt.Errorf("multiplex VXLAN %s: list VLAN tunnel mappings: %w", device.vx.Attrs().Name, err)
	}
	for _, tunnel := range tunnels {
		if tunnel.TunId != vni {
			continue
		}
		if err := h.BridgeVlanDelTunnelInfo(device.vx, tunnel.Vid, 0, vni, 0, false, false); err != nil &&
			!errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("multiplex VXLAN %s: remove VLAN %d/VNI %d mapping: %w",
				device.vx.Attrs().Name, tunnel.Vid, vni, err)
		}
		if err := h.BridgeVlanDel(device.vx, tunnel.Vid, false, false, false, false); err != nil &&
			!errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("multiplex VXLAN %s: remove VLAN %d: %w",
				device.vx.Attrs().Name, tunnel.Vid, err)
		}
	}
	return cleanupEmptyMultiplexDevice(h, device)
}

func cleanupEmptyMultiplexDevice(h *netlink.Handle, device multiplexDevice) error {
	vnis, err := multiplexVNIs(h, device.vx)
	if err != nil {
		return err
	}
	if len(vnis) > 0 {
		return nil
	}
	if device.br == nil {
		if err := h.LinkDel(device.vx); err != nil && !IsNotFound(err) {
			return fmt.Errorf("delete unattached empty multiplex VXLAN %s: %w", device.vx.Attrs().Name, err)
		}
		return nil
	}
	links, err := h.LinkList()
	if err != nil {
		return fmt.Errorf("list host interfaces: %w", err)
	}
	for _, link := range links {
		if link.Attrs().MasterIndex == device.br.Attrs().Index &&
			link.Attrs().Index != device.vx.Attrs().Index {
			// A host-side veth is still attached. Keeping the pair is safer
			// than deleting a port whose binding could be repaired later.
			return nil
		}
	}
	if err := h.LinkDel(device.vx); err != nil && !IsNotFound(err) {
		return fmt.Errorf("delete empty multiplex VXLAN %s: %w", device.vx.Attrs().Name, err)
	}
	if err := h.LinkDel(device.br); err != nil && !IsNotFound(err) {
		return fmt.Errorf("delete empty multiplex bridge %s: %w", device.br.Attrs().Name, err)
	}
	return nil
}

// RemoveEmptyMultiplexOverlays removes pair objects belonging to lab that have
// neither an active VNI FDB binding nor a host-side port. It is the final
// cleanup path for interrupted migrations where no legacy VNI object remains.
func RemoveEmptyMultiplexOverlays(lab string) ([]string, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("open host netlink handle: %w", err)
	}
	defer h.Close()
	devices, err := multiplexDevices(h, lab)
	if err != nil {
		return nil, err
	}
	var removed, problems []string
	for _, device := range devices {
		unlock := lockMultiplexKeys([]string{device.key.identity()})
		beforeVX := device.vx.Attrs().Name
		beforeBR := ""
		if device.br != nil {
			beforeBR = device.br.Attrs().Name
		}
		if err := cleanupEmptyMultiplexDevice(h, device); err != nil {
			problems = append(problems, err.Error())
			unlock()
			continue
		}
		unlock()
		if _, err := h.LinkByName(beforeVX); IsNotFound(err) {
			removed = append(removed, beforeVX)
			if beforeBR != "" {
				if _, err := h.LinkByName(beforeBR); IsNotFound(err) {
					removed = append(removed, beforeBR)
				}
			}
		}
	}
	bridges, err := removeOrphanMultiplexBridges(h, lab)
	if err != nil {
		problems = append(problems, err.Error())
	} else {
		removed = append(removed, bridges...)
	}
	sort.Strings(removed)
	if len(problems) > 0 {
		sort.Strings(problems)
		return removed, errors.New(strings.Join(problems, "; "))
	}
	return removed, nil
}

func removeOrphanMultiplexBridges(h *netlink.Handle, lab string) ([]string, error) {
	links, err := h.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list host interfaces: %w", err)
	}
	var removed []string
	for _, link := range links {
		br, ok := link.(*netlink.Bridge)
		if !ok {
			continue
		}
		key, owned := pairKeyFromAlias(br.Attrs().Alias)
		if !owned || (lab != "" && key.lab != lab) {
			continue
		}
		unlock := lockMultiplexKeys([]string{key.identity()})
		current, err := h.LinkByName(br.Attrs().Name)
		if err != nil {
			unlock()
			if IsNotFound(err) {
				continue
			}
			return removed, fmt.Errorf("re-resolve orphan multiplex bridge %s: %w", br.Attrs().Name, err)
		}
		br, ok = current.(*netlink.Bridge)
		if !ok {
			unlock()
			continue
		}
		currentLinks, err := h.LinkList()
		if err != nil {
			unlock()
			return removed, fmt.Errorf("list host interfaces: %w", err)
		}
		inUse := false
		for _, child := range currentLinks {
			if child.Attrs().MasterIndex == br.Attrs().Index {
				inUse = true
				break
			}
		}
		if inUse {
			unlock()
			continue
		}
		if err := h.LinkDel(br); err != nil && !IsNotFound(err) {
			unlock()
			return removed, fmt.Errorf("delete orphan multiplex bridge %s: %w", br.Attrs().Name, err)
		}
		removed = append(removed, br.Attrs().Name)
		unlock()
	}
	return removed, nil
}

// RemoveLegacyOverlay removes only the original per-link bridge/VXLAN objects.
// It is used after a host veth has successfully moved to a multiplexed bridge,
// so upgrading a live lab never leaves two data paths for the same VNI.
func RemoveLegacyOverlay(vni uint32) error {
	return removeLegacyOverlay(vni, "")
}

// RemoveLegacyOverlayForLab removes a legacy overlay only when its ownership
// label is either absent (pre-ownership upgrade) or belongs to lab.
func RemoveLegacyOverlayForLab(vni uint32, lab string) error {
	return removeLegacyOverlay(vni, lab)
}

func removeLegacyOverlay(vni uint32, lab string) error {
	for _, name := range []string{VxlanName(vni), BridgeName(vni)} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			if IsNotFound(err) {
				continue
			}
			return fmt.Errorf("look up legacy overlay %s: %w", name, err)
		}
		if owner := ownerFromAlias(link.Attrs().Alias); lab != "" && owner != "" && owner != lab {
			return fmt.Errorf("refusing to delete legacy overlay %s owned by lab %q", name, owner)
		}
		if err := netlink.LinkDel(link); err != nil {
			return fmt.Errorf("delete legacy overlay %s: %w", name, err)
		}
	}
	return nil
}
