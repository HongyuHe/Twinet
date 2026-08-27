package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// A single-node platform-to-solve deployment is a transition, not a command
// that either happens or does not.
//
// Two separate things it does are destructive. It writes the reference answer
// over the devices the manifest still places here, and -- when it was asked to
// prune -- it removes the containers the manifest no longer wants. Only the
// first of those was preserved beforehand, and the second one ran afterwards,
// so an execution that failed part way left the stale containers untouched and
// unread while the lab was already marked as possibly holding the answer.
//
// The retry then did exactly what it was told to. A lab that may hold the
// answer must not have its containers read as student work, so the retry's
// prune read nothing -- and deleted a container whose contents had never been
// saved by anything. Every command reported what it did; the work was gone all
// the same.
//
// Both halves are therefore preserved before either of them runs, and what was
// preserved is written down beside the mode marker. The record is what lets the
// second attempt finish the job: it may remove exactly the containers the first
// attempt proved it could remove, and nothing else. A manifest edited between
// the two attempts, a container that appeared since, a first attempt that was
// never asked to prune, and a missing or unreadable record all end the same
// way -- the deployment refuses, before it changes anything, and says which
// remedy applies. Guessing has two failure modes here and they point in
// opposite directions: guess that a container is still the student's and a
// later capture files the answer as their work; guess that it holds the answer
// and the prune deletes a term of theirs.
const localTransitionFile = "solve-transition.json"

// localSolveTransition is what a solve preserved before it wrote anything, and
// the only thing that entitles the deployment finishing it to remove anything.
type localSolveTransition struct {
	Lab  string `json:"lab"`
	Node string `json:"node"`
	// Topology is the manifest hash the preservation was taken against. A
	// different one means the candidate set was worked out from a different
	// lab, so the record does not describe what is in front of this run.
	Topology string `json:"topology_hash"`
	// Mode is the marker this record was written for, so a record left behind
	// by an earlier transition cannot be read as this one's proof.
	Mode string `json:"mode"`
	// Prune says the interrupted deployment was asked to prune, and so that
	// the preservation below covers every candidate rather than none.
	Prune     bool                        `json:"prune"`
	Preserved []deploy.OrphanPreservation `json:"preserved"`
	Recorded  time.Time                   `json:"recorded"`
}

// recordSolveTransition writes the record atomically, beside the mode marker
// it must be readable with.
func recordSolveTransition(top *model.Topology, tr localSolveTransition) error {
	dir := labPrivateDir(top)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(tr, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(dir, localTransitionFile, append(body, '\n'), 0o644)
}

// readSolveTransition returns the record, or nil when there has never been
// one. A record that exists and cannot be read is an error: it is the proof
// this lab's removals depend on, and treating an unreadable one as absent
// would make a corrupted file indistinguishable from a lab that was never in a
// transition at all.
func readSolveTransition(top *model.Topology) (*localSolveTransition, error) {
	raw, err := os.ReadFile(filepath.Join(labPrivateDir(top), localTransitionFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var tr localSolveTransition
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, fmt.Errorf("read what the interrupted solve preserved: %w", err)
	}
	return &tr, nil
}

// clearSolveTransition forgets the record once the transition it describes has
// finished. It runs after the mode marker has been moved on, so a crash in
// between leaves a record that no longer applies rather than a marker with no
// record -- the first is ignored, the second refuses.
func clearSolveTransition(top *model.Topology) error {
	err := os.Remove(filepath.Join(labPrivateDir(top), localTransitionFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// preserveLocalSolveTransition puts everything this deployment may destroy
// safely on disk, and records that it did, before the first reference command
// runs.
//
// The order is the whole point. Every desired device is captured and proven,
// then every container a requested prune could later remove is captured
// through the same guarded funnel, then what was preserved is written down,
// and only then is the lab marked as one that may hold the answer. Anything
// that cannot be preserved returns an error here, with the marker unwritten
// and the lab still exactly as the students left it.
func preserveLocalSolveTransition(ctx context.Context, rt runtime.Runtime, top *model.Topology,
	store *state.Store, node string, prune bool,
) (*deploy.OrphanPreservationSet, error) {
	// A capture engine of its own: the desired solve engine must never capture
	// the answer on a later solve pass, so it is not the one that reads here.
	capture := &deploy.Engine{Runtime: rt, Node: node, State: store}
	if _, err := capture.CaptureAll(ctx, top, store); err != nil {
		return nil, fmt.Errorf("refusing to install the reference solution because "+
			"the current student state could not be captured: %w", err)
	}
	if unproven := capture.UnprovenNamespaceDevices(); len(unproven) > 0 {
		var devices []string
		for id, reason := range unproven {
			devices = append(devices, id+": "+reason)
		}
		sort.Strings(devices)
		return nil, fmt.Errorf("refusing to install the reference solution because "+
			"the current namespace state could not be proven: %s",
			strings.Join(devices, "; "))
	}
	// A prune this deployment was asked for is part of the transition rather
	// than something that happens after it. CaptureAll covers the devices the
	// manifest still wants and nothing else, so a stale container was the one
	// object in the lab that the transition could destroy without ever having
	// read it. It is read now, while what is in it is still demonstrably the
	// students' work.
	var preserved []deploy.OrphanPreservation
	if prune {
		var err error
		preserved, err = capture.PreserveOrphans(ctx, top)
		if err != nil {
			return nil, fmt.Errorf("refusing to install the reference solution because a "+
				"container it was asked to prune could not be preserved first: %w", err)
		}
	}
	if err := recordSolveTransition(top, localSolveTransition{
		Lab: top.Name, Node: node, Topology: top.Hash, Mode: localModeSolvePending,
		Prune: prune, Preserved: preserved, Recorded: time.Now().UTC(),
	}); err != nil {
		return nil, fmt.Errorf("refusing to install the reference solution because "+
			"what it preserved could not be recorded: %w", err)
	}
	// Persisted before the first reference command. If execution fails halfway,
	// a retry or destroy must not capture the already-solved half as student
	// work; the complete platform snapshot taken above remains the recovery
	// source, and the record written just before this says which containers it
	// covers.
	if err := recordLabMode(top, localModeSolvePending); err != nil {
		return nil, fmt.Errorf("refusing to install the reference solution because "+
			"its captured transition could not be recorded: %w", err)
	}
	if !prune {
		return nil, nil
	}
	return &deploy.OrphanPreservationSet{Preserved: preserved}, nil
}

// resumeLocalSolveTransition is what a deployment finishing an interrupted
// solve is entitled to remove.
//
// It refuses rather than guesses, and it refuses before the deployment has
// changed anything, because both guesses available to it are losses: reading
// the container may file the reference answer as a student's work, and
// removing it may delete the only copy of theirs.
func resumeLocalSolveTransition(top *model.Topology, node string) (*deploy.OrphanPreservationSet, error) {
	const remedy = "Put the lab back into teaching mode with `twinet deploy`, which replays " +
		"the preserved student state, and then run the solve and its prune again; or " +
		"re-run this deployment without --prune to finish the solve and leave the stale " +
		"containers where they are. `twinet destroy` remains the way to say that a lab is " +
		"genuinely disposable."
	tr, err := readSolveTransition(top)
	if err != nil {
		return nil, fmt.Errorf("refusing to prune %s: the last deployment was interrupted "+
			"while it was installing the reference solution, and the record of what it "+
			"preserved beforehand could not be read (%v), so a stale container cannot be "+
			"told apart from one holding the answer. %s", top.Name, err, remedy)
	}
	switch {
	case tr == nil, tr.Mode != localModeSolvePending:
		return nil, fmt.Errorf("refusing to prune %s: the last deployment was interrupted "+
			"while it was installing the reference solution, and there is no record of what "+
			"it preserved beforehand, so a stale container cannot be told apart from one "+
			"holding the answer. %s", top.Name, remedy)
	case !tr.Prune:
		return nil, fmt.Errorf("refusing to prune %s: the interrupted deployment was not "+
			"asked to prune, so nothing was preserved for the containers this one would "+
			"remove, and after a partial solve what is in them can be neither read as "+
			"student work nor told apart from the answer. %s", top.Name, remedy)
	case tr.Lab != top.Name || tr.Node != node:
		return nil, fmt.Errorf("refusing to prune %s on %s: what the interrupted deployment "+
			"preserved was preserved for lab %q on node %q, so it does not describe the "+
			"containers this one would remove. %s", top.Name, node, tr.Lab, tr.Node, remedy)
	case tr.Topology != top.Hash:
		return nil, fmt.Errorf("refusing to prune %s: the manifest has changed since the "+
			"interrupted deployment preserved what it was about to destroy (it preserved "+
			"topology %s, this is %s), so which containers are stale was decided against a "+
			"different lab and the preserved copies may not be theirs. %s",
			top.Name, shortHash(tr.Topology), shortHash(top.Hash), remedy)
	}
	return &deploy.OrphanPreservationSet{Preserved: tr.Preserved}, nil
}

// shortHash keeps a refusal readable while still naming the two hashes it is
// complaining about.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	if h == "" {
		return "(none)"
	}
	return h
}
