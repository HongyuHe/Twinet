package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
)

// A clustered solve is a transition, and both of its halves destroy something.
//
// The reference answer is written over the devices the manifest still places
// on this node, and -- when the deployment was asked to prune -- the
// containers it no longer places here are removed. Only the first half was
// preserved beforehand: prepare captures every dirty student-owned device and
// replicates it before the apply phase touches anything. The second half ran
// at the far end of commit, with WritesReference set because the transaction's
// mode is solve, which is precisely the condition under which a prune reads
// nothing at all. So the stale containers this node was told to remove were
// deleted having been read by nobody, in a deployment where nothing had gone
// wrong.
//
// A container the manifest has forgotten is not in the topology to be
// enumerated, so the prepare capture never covered it. It is also the one
// object in the lab whose only copy of a group's work lives inside it. The
// interrupted case is worse only in that it takes two commands: a solve that
// fails part way leaves the lab in a transaction whose desired mode is solve,
// and every retry, rollback, and forward recovery after that is correctly
// forbidden from reading a lab that may already hold the answer -- and would
// have removed the container anyway.
//
// Neither available guess is safe, and they fail in opposite directions.
// Reading the orphan as student work files the answer as theirs the moment a
// manifest edited between two attempts turns a solved device into an orphan.
// Treating it as the reference and deleting it is the loss above. What tells
// them apart existed before the first reference command ran, and was not
// written down anywhere.
//
// So it is written down. Before the apply phase of a solve that was asked to
// prune, this node preserves every prune candidate through the same guarded
// funnel every other capture uses, proves the copies reached the failure
// domains the lab's state policy requires, and records what it preserved in
// the prepared transaction -- lab, node, generation, fence, manifest hash,
// mode, prune intent, and each container with the device identifier it
// carried. The record is journalled before the phase that writes the reference
// solution, so whichever process finishes the job -- this one, a forward
// recovery, or the rollback that undoes it -- may remove precisely what that
// record covers and refuses, before mutating anything, otherwise.

// solveTransition is what one node preserved before it wrote any part of the
// reference solution, and the only thing that entitles a later prune to remove
// anything.
//
// It is persisted in the prepared transaction rather than held in memory
// because the process that preserves a container is not necessarily the
// process that removes it: an agent restart, a controller crash, and a
// forward recovery each put a different process in front of the same lab.
type solveTransition struct {
	Lab  string `json:"lab"`
	Node string `json:"node"`
	// Generation and Fence tie the record to one fenced attempt. A record left
	// behind by an earlier transaction cannot be read as this one's proof.
	Generation string `json:"generation"`
	Fence      uint64 `json:"fence_generation"`
	// Topology is the manifest hash the preservation was taken against. A
	// different one means the candidate set was worked out from a different
	// lab, so the record does not describe what is in front of this run.
	Topology string `json:"topology_hash"`
	Mode     string `json:"mode"`
	Ungraded int    `json:"ungraded_as,omitempty"`
	// Prune says the interrupted deployment was asked to prune, and so that
	// the preservation below covers every candidate rather than none.
	Prune bool `json:"prune"`
	// Replicated says the preserved copies were acknowledged by the peer
	// failure domains the lab's state policy asks for. It is false only where
	// that policy explicitly permits an audited bypass.
	Replicated bool                        `json:"replicated"`
	Preserved  []deploy.OrphanPreservation `json:"preserved"`
	Recorded   time.Time                   `json:"recorded"`
}

// solveTransitionRemedy is the same sentence everywhere, because the operator
// has the same two ways out of every one of these refusals.
const solveTransitionRemedy = "Return the lab to teaching mode by deploying it without " +
	"--solve, which replays the preserved student state, and then run the solve and its " +
	"prune again; or re-run this deployment without --prune to finish the solve and leave " +
	"the stale containers where they are. `twinet destroy` remains the way to say that a " +
	"lab is genuinely disposable."

// transactionForwardTopology rehydrates the topology this transaction was
// applying, which is the only description of what its forward half may have
// written the reference solution into.
func transactionForwardTopology(tx applyTransaction) (*model.Topology, error) {
	if len(tx.Requested) == 0 {
		return nil, nil
	}
	var wire Wire
	if err := json.Unmarshal(tx.Requested, &wire); err != nil {
		return nil, fmt.Errorf("decode the topology this transaction was applying: %w", err)
	}
	top, err := wire.Rehydrate()
	if err != nil {
		return nil, fmt.Errorf("rehydrate the topology this transaction was applying: %w", err)
	}
	return top, nil
}

// solvePreservationRequired says this transaction's forward half will both
// write the reference solution and remove containers, so the containers must
// be preserved before either happens.
//
// A lab that already holds the reference is deliberately excluded, exactly as
// the single-node path excludes it: nothing in it can be read as a student's
// work any more, so there is nothing a preservation pass could honestly save.
func solvePreservationRequired(desired render.Mode, previous string, prune bool) bool {
	return prune && desired == render.ModeSolve &&
		canonicalMode(previous) != string(render.ModeSolve)
}

// transactionWritesReference says the forward half of this transaction put the
// reference solution onto the devices it placed on this node.
func transactionWritesReference(tx applyTransaction) bool {
	return render.Mode(tx.Mode) == render.ModeSolve
}

// preserveSolveTransition puts everything this transaction may destroy safely
// on disk, and proves it, before the apply phase runs.
//
// The order is the whole point. Prepare has already captured and replicated
// every dirty student-owned device the manifest still places here; this covers
// the other half -- every container a requested prune will later remove --
// through the same guarded funnel, while what is in them is still demonstrably
// the students'. Anything that cannot be preserved returns an error, with
// nothing on this node changed and the transaction still refusing to apply.
func (s *Server) preserveSolveTransition(ctx context.Context, top *model.Topology,
	tx applyTransaction, fence Fence,
) (*solveTransition, error) {
	// A capture engine of its own, deliberately not the transaction's. The
	// engine that applies a solve must never capture the answer, which is
	// exactly why it cannot be the one that reads the orphans here.
	//
	// A node with no state store is not special-cased: the preservation pass
	// refuses every candidate it cannot save, by name, and a node with no
	// candidates has nothing to preserve and nothing to refuse.
	capture := &deploy.Engine{
		Runtime: s.rt, Node: s.cfg.Node, Limiter: s.workLimiter(), State: s.store,
		Renderer:        renderer(top, render.ModePlatform, 0),
		ObservationRoot: s.observationRoot,
	}
	preserved, err := capture.PreserveOrphans(ctx, top)
	if err != nil {
		return nil, fmt.Errorf("refusing to install the reference solution because a container "+
			"it was asked to prune could not be preserved first: %w. %s", err, solveTransitionRemedy)
	}
	// The copies have to leave this node before the reference solution lands
	// on it. A preserved orphan whose only copy is on the machine that is
	// about to rewrite the lab is not preserved against the failure the
	// policy was written for.
	replicated := true
	if s.store != nil {
		if err := s.replicateDurableState(ctx, top); err != nil {
			replicated = false
			if boundary := s.durableBoundary(top,
				"preserving the containers a solve was asked to prune", err); boundary != nil {
				return nil, fmt.Errorf("refusing to install the reference solution: %w. %s",
					boundary, solveTransitionRemedy)
			}
		}
	}
	return &solveTransition{
		Lab: top.Name, Node: s.cfg.Node, Generation: tx.Generation, Fence: fence.Generation,
		Topology: top.Hash, Mode: tx.Mode, Ungraded: tx.Ungraded, Prune: tx.Prune,
		Replicated: replicated, Preserved: preserved, Recorded: s.nowTime().UTC(),
	}, nil
}

// solveApplyRefusal stops the apply phase of a transaction that would write
// the reference solution and then remove containers nothing had read.
//
// Preservation and its record both happen in prepare, before this phase is
// reachable, and a crash between the two leaves a transaction that will not
// apply rather than one that applies and then deletes. Refusing here costs the
// deployment; not refusing costs whatever was in the containers.
func (s *Server) solveApplyRefusal(lab string, tx applyTransaction) error {
	if !solvePreservationRequired(render.Mode(tx.Mode), tx.PreviousMode, tx.Prune) {
		return nil
	}
	if tx.SolveTransition != nil {
		return nil
	}
	return fmt.Errorf("refusing to install the reference solution for %s on %s: generation %q "+
		"was asked to prune, and there is no record of the containers it would remove being "+
		"preserved beforehand, so they would be deleted without ever having been read. "+
		"Prepare this generation again, or re-run the deployment without --prune. %s",
		lab, s.cfg.Node, tx.Generation, solveTransitionRemedy)
}

// solveRecaptureRefusal is what stops a second attempt from reading a lab that
// may already hold the answer.
//
// Prepare's first act is to capture the student state it is about to destroy,
// and that is right the first time round. It is a loss the second time: the
// apply phase of the attempt before it may have solved half the devices on
// this node, so what is in them is the reference answer, and capturing it
// files the answer as every one of those students' own work -- to be replayed
// onto their routers by the next deployment that recreates a container.
//
// The refusal therefore comes before the capture rather than at the end of
// prepare, where the transaction compare-and-swap would otherwise catch the
// same request a moment too late.
func (s *Server) solveRecaptureRefusal(lab, generation string, fence Fence) error {
	s.mu.Lock()
	tx, active := s.transactions[lab]
	s.mu.Unlock()
	if !active || !transactionWritesReference(tx) {
		return nil
	}
	// The same fenced attempt, still at the point where nothing has been
	// written, is a duplicate prepare rather than a second attempt.
	if tx.Generation == generation && tx.FenceGeneration == fence.Generation &&
		tx.Phase == transactionPrepared {
		return nil
	}
	return fmt.Errorf("refusing to prepare generation %q of lab %q on %s: generation %q was "+
		"installing the reference solution here and has not finished (%s), so the devices on "+
		"this node may already hold the answer and must not be read as student work. Recover "+
		"or abort that transaction first; %s", generation, lab, s.cfg.Node, tx.Generation,
		transactionPhaseName(tx.Phase), solveTransitionRemedy)
}

func transactionPhaseName(phase transactionPhase) string {
	if phase == "" {
		return "phase unknown"
	}
	return string(phase)
}

// solvePruneEntitlement is what the prune of a solve transaction is allowed to
// remove.
//
// It answers before anything is deleted, and it refuses rather than guesses,
// because both guesses available to it are losses: reading a container may
// file the reference answer as a student's work, and removing it may delete
// the only copy of theirs.
func solvePruneEntitlement(tx applyTransaction, top *model.Topology, node string,
	desired render.Mode,
) (*deploy.OrphanPreservationSet, error) {
	if !solvePreservationRequired(desired, tx.PreviousMode, tx.Prune) {
		// Either this deployment is not writing the reference solution, in
		// which case the prune reads its own candidates as it always has, or
		// the lab already held it, in which case there was never any student
		// work in these containers to preserve.
		return nil, nil
	}
	record := tx.SolveTransition
	switch {
	case record == nil:
		return nil, fmt.Errorf("refusing to prune %s on %s: the reference solution was "+
			"installed without first preserving the containers this prune would remove, so "+
			"what is in them now can be neither read as a student's work nor told apart "+
			"from the answer. %s", tx.labName(top), node, solveTransitionRemedy)
	case !record.Prune:
		return nil, fmt.Errorf("refusing to prune %s on %s: the transaction that installed "+
			"the reference solution was not asked to prune, so nothing was preserved for "+
			"the containers this one would remove. %s", tx.labName(top), node, solveTransitionRemedy)
	case record.Lab != top.Name || record.Node != node:
		return nil, fmt.Errorf("refusing to prune %s on %s: what was preserved before the "+
			"reference solution was written was preserved for lab %q on node %q, so it does "+
			"not describe the containers this prune would remove. %s",
			top.Name, node, record.Lab, record.Node, solveTransitionRemedy)
	case record.Generation != tx.Generation || record.Fence != tx.FenceGeneration:
		return nil, fmt.Errorf("refusing to prune %s on %s: what was preserved belongs to "+
			"generation %q under fence %d, and this is generation %q under fence %d, so the "+
			"record is an earlier attempt's rather than this one's. %s",
			top.Name, node, record.Generation, record.Fence, tx.Generation,
			tx.FenceGeneration, solveTransitionRemedy)
	case record.Mode != tx.Mode || record.Ungraded != tx.Ungraded:
		return nil, fmt.Errorf("refusing to prune %s on %s: what was preserved was preserved "+
			"for mode %s/%d and this transaction commits %s/%d, so the record does not "+
			"describe what this deployment did. %s", top.Name, node, record.Mode,
			record.Ungraded, tx.Mode, tx.Ungraded, solveTransitionRemedy)
	case record.Topology != top.Hash:
		return nil, fmt.Errorf("refusing to prune %s on %s: the manifest has changed since "+
			"the containers this prune would remove were preserved (they were preserved "+
			"against topology %s, this is %s), so which containers are stale was decided "+
			"against a different lab and the preserved copies may not be theirs. %s",
			top.Name, node, shortTopologyHash(record.Topology), shortTopologyHash(top.Hash),
			solveTransitionRemedy)
	}
	return &deploy.OrphanPreservationSet{Preserved: record.Preserved}, nil
}

// rollbackPrunePreservation is what a rollback of a solve transaction may
// remove, and what it must not read on the way.
//
// Undoing a solve is the one prune that meets both kinds of container at once.
// The objects the failed forward half created or adopted hold the reference
// answer, so reading them would file it as the work of whichever student owns
// that identifier -- over the very snapshot prepare took to make this rollback
// possible. The objects it never touched still hold the students' own, are the
// only copy of it, and must be read exactly as an ordinary prune reads them.
// The transition is the only thing that knows which is which, so it says so.
//
// Removal is entitled the same way. A container the forward half created holds
// nothing that predates the transaction. One it adopted holds the answer over
// student state prepare captured and replicated, which is what StateSafe
// records. A container that predates the transaction and was never covered by
// either is left alone and named.
func rollbackPrunePreservation(tx applyTransaction, forward *model.Topology,
	node string, previous render.Mode,
) *deploy.OrphanPreservationSet {
	if !transactionWritesReference(tx) || forward == nil {
		// Nothing wrote a reference answer into these containers, so the
		// ordinary prune -- which reads every candidate before removing it --
		// is already the safe one.
		return nil
	}
	if previous == render.ModeSolve {
		// The lab held the reference before this transaction as well, so this
		// pass reads nothing whatever it is told; there is no student work in
		// any of these containers for a record to speak for.
		return nil
	}
	existed := map[string]bool{}
	for _, container := range tx.Prestate.Containers {
		existed[container.Name] = true
	}
	written := map[string]bool{}
	for _, device := range forward.DevicesOnNode(node) {
		written[device.Container] = true
		if deploy.UsesFRRControl(device) {
			written[deploy.FRRControlContainer(device)] = true
		}
	}
	set := &deploy.OrphanPreservationSet{Preserved: tx.solvePreserved()}
	for name := range written {
		set.Unreadable = append(set.Unreadable, name)
		if !existed[name] || tx.Prestate.StateSafe {
			set.Removable = append(set.Removable, name)
		}
	}
	sort.Strings(set.Unreadable)
	sort.Strings(set.Removable)
	return set
}

// solvePreserved is what this transaction wrote down before its forward half
// ran, or nothing when it never got that far.
func (tx applyTransaction) solvePreserved() []deploy.OrphanPreservation {
	if tx.SolveTransition == nil {
		return nil
	}
	return tx.SolveTransition.Preserved
}

// labName prefers the topology in front of the caller and falls back to the
// record, so a refusal can always name the lab it is refusing.
func (tx applyTransaction) labName(top *model.Topology) string {
	if top != nil && top.Name != "" {
		return top.Name
	}
	if tx.SolveTransition != nil {
		return tx.SolveTransition.Lab
	}
	return "this lab"
}

// preservedContainerNames is the audit line an operator reads: which
// containers this node put safely on disk before it wrote the answer.
func preservedContainerNames(preserved []deploy.OrphanPreservation) []string {
	out := make([]string, 0, len(preserved))
	for _, record := range preserved {
		out = append(out, record.Container)
	}
	sort.Strings(out)
	return out
}

// shortTopologyHash keeps a refusal readable while still naming the two hashes
// it is complaining about.
func shortTopologyHash(hash string) string {
	if hash == "" {
		return "(none)"
	}
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
