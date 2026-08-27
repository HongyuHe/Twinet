package deploy

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// A device has one slot in the state store and can have more than one
// container claiming it.
//
// That happens whenever a container's name and the device's identifier stop
// agreeing: a manifest that renames a device's container leaves the old one
// running under the same identifier, an interrupted rename leaves two, a
// device moved to another node keeps its name here while the manifest points
// somewhere else, and a duplicate started by a half-finished deployment
// carries the same labels as the one beside it. Each of those is a *claimant*
// -- a container asserting it is where this device's saved state should come
// from -- and only one of them can write the slot.
//
// Letting them all write it in turn is how a prune files a dead container's
// reading as a live device's work, and then deletes the rest. Letting none of
// them write it and deleting them all is the same loss more quietly: a
// claimant that is not the authority may still hold the newest thing anyone
// did, and the store cannot merge two of them.
//
// So the authority writes, and every other claimant must *prove it has nothing
// to lose* before it is removed: what was read out of it has to be the state
// already held for the device, kind for kind, present for present. Anything
// else -- a difference in any kind, a durable side that is missing while the
// claimant holds content, a durable side that cannot be read -- refuses the
// removal by name and leaves the container where it is. An operator can then
// look at both and decide; nothing else can.
type claimant struct {
	// canonical says this container is the one whose reading may be written to
	// the device's slot in the store.
	canonical bool
	// authority names the container that is the canonical source instead, for
	// the refusal to quote. It is empty when nothing established one.
	authority string
}

// resolveClaimants decides, for one prune's candidates, which container speaks
// for each device.
//
// Authority comes from the topology and from container identity, never from
// preference: a device the manifest still places somewhere has exactly one
// container name, and a container carrying that name is the authority for it.
// Everything else is a claimant that has to prove equivalence. Where nothing
// establishes an authority -- two containers for a device the manifest has
// forgotten, say -- there is no canonical source and every claimant is held to
// the same proof, which is the fail-closed answer rather than a guess.
func (e *Engine) resolveClaimants(top *model.Topology, candidates []runtime.Container,
	targets []*model.Device,
) []claimant {
	out := make([]claimant, len(candidates))
	groups := map[string][]int{}
	for i := range candidates {
		if targets[i] == nil {
			continue
		}
		groups[targets[i].ID] = append(groups[targets[i].ID], i)
	}
	for id, members := range groups {
		modelled, known := top.Device(id)
		switch {
		case known && modelled.Node == e.Node:
			// The manifest gives this device a container on this node, and a
			// container the manifest names is never a prune candidate. So the
			// authority is not in this list at all: every candidate here is a
			// leftover, and none of them writes the slot.
			for _, i := range members {
				out[i] = claimant{authority: modelled.Container}
			}
		case known:
			// Moved to another node. The container it moved with keeps its
			// name, so a candidate carrying that name is the device -- and is
			// the ordinary moved orphan, captured and removed as before.
			authority := ""
			for _, i := range members {
				if candidates[i].Name == modelled.Container {
					authority = candidates[i].Name
					break
				}
			}
			for _, i := range members {
				out[i] = claimant{
					canonical: authority != "" && candidates[i].Name == authority,
					authority: authority,
				}
			}
		case len(members) == 1:
			// Gone from the manifest, and one container holds it. There is
			// nothing to collide with, and the ordinary orphan is captured and
			// removed exactly as before.
			out[members[0]] = claimant{canonical: true}
		default:
			// Gone from the manifest and claimed twice. Nothing left says
			// which of them is the device, and picking the first or the
			// newest would be inventing an answer that decides whose work
			// survives. Neither writes; both must prove equivalence.
			for _, i := range members {
				out[i] = claimant{}
			}
		}
	}
	return out
}

// equivalentToDurable reports whether what was read out of a non-canonical
// claimant is already in the store, and so whether removing that container
// loses anything.
//
// Its own successful capture is the evidence of what it currently holds -- not
// a namespace baseline, which belongs to whichever container the deployment
// last configured and would otherwise let the *new* container's identity vouch
// for the old one's contents. The comparison is over the union of both sides,
// so a kind the claimant holds and the store does not is a difference, and so
// is a kind the store holds and the claimant did not read.
//
// Every kind is compared, not only the namespace-backed ones: a leftover's
// routing configuration is a term's work as surely as its addressing, and it
// is the one thing that survives the container's task restarting.
func (e *Engine) equivalentToDurable(top *model.Topology, d *model.Device,
	captured []state.Snapshot,
) (bool, string) {
	held := map[state.Kind]string{}
	for _, snap := range captured {
		body := canonicalState(snap.Kind, string(snap.Content))
		if body == "" {
			continue
		}
		// Two snapshots of one kind from one capture is not something Capture
		// produces, and quietly keeping the last would compare the wrong one.
		if _, twice := held[snap.Kind]; twice {
			return false, fmt.Sprintf("it was read twice for its %s and the two readings "+
				"cannot both be compared", snap.Kind)
		}
		held[snap.Kind] = body
	}
	var reasons []string
	for _, kind := range state.AllKinds {
		durable, present, err := durableBody(e.State, top.Name, d.ID, kind)
		if err != nil {
			// The side that decides whether removal is safe is the side that
			// cannot be read. Nothing saved and unreadable used to be the same
			// answer here, and it is the answer that deletes a container while
			// the only other copy is in question.
			return false, fmt.Sprintf("the %s already saved for %s could not be read, so "+
				"there is nothing trustworthy to compare it against: %v", kind, d.ID, err)
		}
		mine, holds := held[kind]
		switch {
		case holds && !present:
			reasons = append(reasons, fmt.Sprintf(
				"it holds %s that nothing is saved for", kind))
		case !holds && present:
			reasons = append(reasons, fmt.Sprintf(
				"%s is saved for %s and it holds none", kind, d.ID))
		case holds && present && mine != durable:
			reasons = append(reasons, fmt.Sprintf(
				"its %s is not the %s saved for %s", kind, kind, d.ID))
		}
	}
	if len(reasons) == 0 {
		return true, ""
	}
	sort.Strings(reasons)
	return false, strings.Join(reasons, ", ")
}

// durableBody reads one saved artefact in the form a capture would have
// written it, and says whether there is one.
//
// A snapshot that has genuinely never been taken is a legitimate none. A body
// whose digest does not match what was recorded beside it, a half-written
// pair, or a disk refusing reads is an error and stays one.
func durableBody(store *state.Store, lab, device string, kind state.Kind) (string, bool, error) {
	if store == nil {
		return "", false, errors.New("there is no state store to compare against")
	}
	snapshot, err := store.Current(lab, device, kind)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !store.Has(lab, device, kind) {
			return "", false, nil
		}
		return "", false, err
	}
	body := canonicalState(kind, string(snapshot.Content))
	return body, body != "", nil
}

// canonicalState is a capture's own representation of one artefact, with a
// snapshot that records nothing reduced to nothing at all.
//
// A device with no tunnels is captured and stored as a typed snapshot with a
// version header and no facts under it, which is not the same shape as never
// having been captured -- and both mean the device holds no tunnels. Comparing
// the raw bodies would call that a difference and refuse to remove every
// claimant that happens to have no tunnels while the store has no tunnels
// snapshot for it, which is most of them.
func canonicalState(kind state.Kind, raw string) string {
	body := strings.TrimSpace(CanonicalDynamicSnapshot(kind, raw))
	if body == dynamicStateVersion+" "+string(kind) {
		return ""
	}
	return body
}
