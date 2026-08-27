package deploy

import (
	"context"
	"fmt"
	"sort"

	"github.com/HongyuHe/twinet/internal/limiter"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// Preserving what a prune would delete, separately from deleting it.
//
// A prune reads every candidate before it removes any of them and refuses the
// removal of anything it could not safely save. That is one operation, and it
// is the right one when the prune is the whole of what is happening.
//
// A deployment that installs the reference solution is not that case. It is a
// transition with two destructive halves -- the answer is written over the
// devices the manifest still wants, and the containers it no longer wants are
// removed -- and only the second half preserved anything. A solve that failed
// part way therefore left the stale containers running and unread, and the
// retry, which correctly refuses to read a lab that may already hold the
// answer, deleted them without ever having looked inside. A term's work was
// gone, and every command in the sequence had behaved as written.
//
// So the two halves are separable. PreserveOrphans does everything a prune
// does except the removal, which lets a caller put every candidate's state
// safely on disk *before* the first reference command runs. What it preserved
// is a record the caller can keep, and a later prune that carries one may
// remove only the candidates that record covers -- in this process, or, after
// a crash, in the next one.

// OrphanPreservation records what was established about one prune candidate
// before anything destructive ran.
//
// It is written down rather than held in memory because the transition it
// belongs to can be interrupted between its two halves: the process that
// preserves a container is not necessarily the process that removes it.
type OrphanPreservation struct {
	// Container is the runtime object this record speaks for.
	Container string `json:"container"`
	// Device is the canonical identifier the container carried. A candidate
	// without one is refused rather than recorded, so this is empty only for
	// objects that own no student state of their own.
	Device string `json:"device,omitempty"`
	// Stored says the container's own reading went into the state store, so
	// what it held outlives it.
	Stored bool `json:"stored"`
	// Detail says why nothing was stored when nothing was, so that whoever
	// reads this record later can tell "there was nothing in it" from "what is
	// in it is already saved" without having to derive either again.
	Detail string `json:"detail,omitempty"`
}

// OrphanPreservationSet is the whole of what one preservation phase
// established. A prune given one may remove only what it covers.
type OrphanPreservationSet struct {
	Preserved []OrphanPreservation `json:"preserved"`
}

func (s *OrphanPreservationSet) find(container string) (OrphanPreservation, bool) {
	if s == nil {
		return OrphanPreservation{}, false
	}
	for _, p := range s.Preserved {
		if p.Container == container {
			return p, true
		}
	}
	return OrphanPreservation{}, false
}

// candidateDeviceID is the canonical identifier a container carries.
//
// The *canonical* identifier, not the short name. Every autonomous system in
// these labs has a router called ATL, so keying on the name files as3/ATL's
// configuration and as4/ATL's under the same "ATL" -- one overwriting the
// other, and neither findable by the identifier a restore looks up.
func candidateDeviceID(c runtime.Container) string {
	if id := c.Labels[LabelDeviceID]; id != "" {
		return id
	}
	return c.Labels[LabelDevice]
}

// pruneCandidates lists the containers of this lab that this node is
// responsible for and that the topology no longer places here.
func (e *Engine) pruneCandidates(ctx context.Context, top *model.Topology) ([]runtime.Container, error) {
	want := map[string]bool{}
	for _, d := range top.DevicesOnNode(e.Node) {
		want[d.Container] = true
		if e.usesFRRControl(d) {
			want[FRRControlContainer(d)] = true
		}
	}
	// A device that has moved to another node must also be removed from here.
	elsewhere := map[string]bool{}
	for _, d := range top.SortedDevices() {
		if d.Node != e.Node {
			elsewhere[d.Container] = true
		}
	}

	cs, err := e.Runtime.List(ctx, runtime.Filter{All: true,
		Labels: map[string]string{LabelLab: top.Name}})
	if err != nil {
		return nil, err
	}
	var candidates []runtime.Container
	for _, c := range cs {
		if want[c.Name] {
			continue
		}
		// Only remove what this node is responsible for, and only what the
		// topology genuinely no longer places here.
		if c.Labels[LabelNode] != "" && c.Labels[LabelNode] != e.Node && !elsewhere[c.Name] {
			continue
		}
		candidates = append(candidates, c)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
	return candidates, nil
}

// preserveOrphans reads every prune candidate and decides, for each of them,
// whether removing it would lose anything.
//
// It returns one record per candidate, in the candidates' own order, and the
// refusals that must stop the removal. Nothing here removes anything: a caller
// that only wants the state safe calls PreserveOrphans, and the prune is the
// caller that goes on to delete what this cleared.
func (e *Engine) preserveOrphans(ctx context.Context, top *model.Topology,
	candidates []runtime.Container,
) ([]OrphanPreservation, []string, error) {
	// Capture every candidate before removing any one of them. A parallel
	// prune must not turn a capture failure into a race where another worker
	// has already destroyed an unrelated student's only copy.
	//
	// Each candidate's identity is resolved once, up front, so that the
	// capture, the safety check that decides what may be stored, and the
	// refusal that may follow are all talking about the same device.
	targets := make([]*model.Device, len(candidates))
	records := make([]OrphanPreservation, len(candidates))
	var preCaptureProblems []string
	for i, c := range candidates {
		var refusal string
		targets[i], refusal = e.orphanDevice(top, c)
		records[i] = OrphanPreservation{Container: c.Name, Device: candidateDeviceID(c)}
		if refusal != "" {
			preCaptureProblems = append(preCaptureProblems, refusal)
		}
		if targets[i] == nil {
			records[i].Detail = "it holds no student-owned state of its own"
			if e.WritesReference {
				records[i].Detail = "this deployment installs the reference solution, " +
					"so nothing was read out of it"
			}
		}
	}
	// Which container speaks for each device, before anything is read, so that
	// the capture, the store write and any refusal all agree about it.
	claims := e.resolveClaimants(top, candidates, targets)
	captures := make([][]state.Snapshot, len(candidates))
	_, captureErrs, ctxErr := e.runBounded(ctx, len(candidates), func(i int) error {
		if targets[i] == nil {
			return nil
		}
		return e.limited(ctx, []limiter.Kind{limiter.Capture}, func() error {
			snaps, err := Capture(ctx, e.Runtime, targets[i], top.Name, top.Hash)
			captures[i] = snaps
			return err
		})
	})
	// Only the candidates that actually read something go to the store, and
	// they go through the same guarded funnel every other capture uses. A
	// prune is the one path nobody gets to undo, and it was reading a
	// container's namespace and filing it directly -- so an orphan whose task
	// had restarted, which is a container with its labels, its filesystem and
	// an empty namespace, wrote that emptiness over the only saved copy of a
	// student's addressing and was then deleted.
	var (
		writable []*model.Device
		written  [][]state.Snapshot
	)
	for i := range candidates {
		if targets[i] == nil {
			continue
		}
		if len(captures[i]) == 0 {
			records[i].Detail = "there was nothing in it to read"
			continue
		}
		// A container that is not the authority for this device does not get
		// to write the device's saved state. There is one slot in the store
		// per device, and a claimant's reading filed there would replace the
		// record of whichever container the deployment actually keeps -- which
		// is not the namespace hazard, it is the whole snapshot.
		//
		// Excluding it is only half the answer. What it holds is now the one
		// copy of itself, so it is not deleted until the check below shows the
		// store already has the same thing.
		if !claims[i].canonical {
			continue
		}
		records[i].Stored = true
		writable = append(writable, targets[i])
		written = append(written, captures[i])
	}
	_, problems := e.storeCaptured(ctx, top, e.State, writable, written, true)
	problems = append(preCaptureProblems, problems...)
	for i := range problems {
		problems[i] = "refusing to remove an orphan: its state could not be safely saved (" +
			problems[i] + "). Destroy the lab explicitly if it is genuinely disposable"
	}
	unproven := e.UnprovenNamespaceDevices()
	for i, c := range candidates {
		// Capture before removing. An orphan is usually a device that moved to
		// another node or left the manifest, and in both cases it may hold a
		// student's work -- the only copy of it. Removing first and asking
		// later is not recoverable, and the loss is silent: the deployment
		// reports success, the container is gone, and nobody discovers what
		// was in it until someone asks for a mark.
		//
		// Refusing is the right failure. A lab with one stale container is a
		// nuisance; a lab that has quietly eaten a group's configuration is
		// not something an apology fixes.
		if err := captureErrs[i]; err != nil {
			records[i].Stored = false
			records[i].Detail = fmt.Sprintf("it could not be captured: %v", err)
			problems = append(problems, fmt.Sprintf(
				"refusing to remove %s: its configuration could not be captured (%v). "+
					"Destroy the lab explicitly if it is genuinely disposable", c.Name, err))
			continue
		}
		if targets[i] == nil {
			continue
		}
		// A namespace that could not be accounted for is not the same as one
		// this proved had been replaced. A replaced namespace is settled: what
		// is in it now demonstrably is not the student's work, the saved copy
		// was left alone, and deleting the container costs nothing -- which is
		// what keeps a device that moved to another node from announcing its
		// prefixes from two places for ever.
		//
		// An unaccounted-for one is not settled. Nothing here can say whether
		// the container holds a term's work or an empty room, this pass
		// deliberately did not save what is in it, and removing it would
		// destroy the one thing that could still answer the question.
		if reason, ok := unproven[targets[i].ID]; ok {
			records[i].Stored = false
			records[i].Detail = "what is in its network namespace could not be established"
			problems = append(problems, fmt.Sprintf(
				"refusing to remove %s: what is in its network namespace could not be "+
					"established (%s), so it was not saved over the state already held for %s. "+
					"Destroy the lab explicitly if it is genuinely disposable",
				c.Name, reason, targets[i].ID))
			continue
		}
		// A claimant that was deliberately kept out of the store has to show
		// it has nothing to lose.
		//
		// Its reading was excluded because the slot belongs to another
		// container, which says nothing about whether what it holds is
		// already saved. A leftover from a rename can carry the last hour of
		// a student's work; two containers under one identifier can each
		// carry a different half of it; and a source the class edits between
		// one capture and this one diverges without anybody doing anything
		// wrong. None of that can be merged into a single slot, and deleting
		// it settles the question by destroying one side of it.
		if claims[i].canonical {
			continue
		}
		same, why := e.equivalentToDurable(top, targets[i], captures[i])
		if same {
			records[i].Detail = fmt.Sprintf(
				"what it holds is already the state saved for %s", targets[i].ID)
			continue
		}
		authority := "no container is established as the authority"
		if claims[i].authority != "" {
			authority = "the established authority is " + claims[i].authority
		}
		records[i].Detail = why
		problems = append(problems, fmt.Sprintf(
			"refusing to remove %s: it is one of several containers claiming %s; %s, and "+
				"what this claimant holds is not what is saved (%s). Its "+
				"reading was deliberately not written over that state, so removing it "+
				"would destroy the only copy. Compare the two and remove it by hand, or "+
				"destroy the lab explicitly if it is genuinely disposable",
			c.Name, targets[i].ID, authority, why))
	}
	return records, problems, ctxErr
}

// PreserveOrphans captures everything a prune of this topology would delete,
// and removes nothing.
//
// It is the first half of a destructive transition whose second half runs
// later: the caller gets the record of what was preserved, keeps it somewhere
// durable, and hands it back to the prune that finishes the job. It refuses on
// exactly what a prune refuses on, and it refuses *before* the transition has
// changed anything, which is the point of running it early.
func (e *Engine) PreserveOrphans(ctx context.Context, top *model.Topology) ([]OrphanPreservation, error) {
	candidates, err := e.pruneCandidates(ctx, top)
	if err != nil {
		return nil, err
	}
	records, problems, ctxErr := e.preserveOrphans(ctx, top, candidates)
	if err := deterministicError(ctxErr, problems); err != nil {
		return nil, err
	}
	return records, nil
}

// unpreservedCandidates names every candidate this prune is not entitled to
// remove, given the preservation this transition can prove.
//
// A prune finishing an interrupted transition cannot read its candidates:
// after a partial solve, what is in a container may be the reference answer,
// and filing that as a student's work is its own kind of loss. So it does not
// guess. Either the pre-reference preservation covers the container in front
// of it, or the container stays and the command says why.
func (e *Engine) unpreservedCandidates(candidates []runtime.Container) []string {
	if e.PreservedOrphans == nil {
		return nil
	}
	var problems []string
	for _, c := range candidates {
		record, known := e.PreservedOrphans.find(c.Name)
		switch {
		case !known:
			problems = append(problems, fmt.Sprintf(
				"refusing to remove %s: this deployment is finishing a transition that was "+
					"interrupted, and nothing was preserved for that container before the "+
					"reference solution was written, so what is in it now can be neither "+
					"read as a student's work nor told apart from the answer. Return the lab "+
					"to teaching mode with `twinet deploy` and run the prune again, or "+
					"destroy the lab explicitly if it is genuinely disposable", c.Name))
		case record.Device != candidateDeviceID(c):
			problems = append(problems, fmt.Sprintf(
				"refusing to remove %s: the state preserved before the reference solution "+
					"was written belongs to %q, and the container now carries %q, so the "+
					"preserved copy is not this container's. Return the lab to teaching mode "+
					"with `twinet deploy` and run the prune again, or destroy the lab "+
					"explicitly if it is genuinely disposable",
				c.Name, record.Device, candidateDeviceID(c)))
		}
	}
	return problems
}
