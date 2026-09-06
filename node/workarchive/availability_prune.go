package workarchive

import (
	"context"
	"errors"
	"time"

	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

var ErrAvailabilityClock = errors.New("archive availability clock is invalid or moved backwards")

// PruneCanonicalPrefix is the policy-enforcing entry point for destructive
// canonical maintenance. Unlike historical inspection, it uses the live clock,
// not a caller-supplied timestamp. It fully replays each replica, publishes the
// immutable evidence, and rechecks freshness and cancellation after WorkChain
// has acquired its lock and prepared the deletion batch. VerifiedAt records
// that final authorization sample, not the completion time of the disk write.
//
// Inputs and replica directories must remain immutable throughout the call.
// The supplied trust sets remain static operational policy, not a cross-host
// revocation authority. Cancellation is checked between bounded operations and
// before commit, not per replayed block; an issued commit is not rolled back.
func PruneCanonicalPrefix(
	ctx context.Context, chain *workchain.Store, replicas []Replica, availabilityPath string,
	checkpoint Checkpoint, checkpointPolicy Policy, replicaPolicy ReplicaPolicy,
	base workchain.Base, parameters workblock.Parameters, limits Limits,
) (CanonicalPruneResult, error) {
	return pruneCanonicalPrefix(ctx, chain, replicas, availabilityPath, checkpoint,
		checkpointPolicy, replicaPolicy, base, parameters, limits, time.Now)
}

func pruneCanonicalPrefix(
	ctx context.Context, chain *workchain.Store, replicas []Replica, availabilityPath string,
	checkpoint Checkpoint, checkpointPolicy Policy, replicaPolicy ReplicaPolicy,
	base workchain.Base, parameters workblock.Parameters, limits Limits, clock func() time.Time,
) (CanonicalPruneResult, error) {
	if ctx == nil || clock == nil {
		return CanonicalPruneResult{}, ErrAvailability
	}
	var previous time.Time
	sample := func() (uint64, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		// Compare wall time explicitly, including subsecond regressions. Go's
		// monotonic component must not hide a backwards wall-clock adjustment.
		current := clock().Round(0)
		if current.Unix() <= 0 || (!previous.IsZero() && current.Before(previous)) {
			return 0, ErrAvailabilityClock
		}
		previous = current
		return uint64(current.Unix()), nil
	}
	now, err := sample()
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	if chain == nil || availabilityPath == "" || VerifyChain(checkpoint, checkpointPolicy, chain) != nil {
		return CanonicalPruneResult{}, ErrChain
	}
	evidenceResolved, err := resolvedArchivePath(availabilityPath)
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	for _, replica := range replicas {
		replicaResolved, pathErr := resolvedArchivePath(replica.Directory)
		if pathErr != nil || pathContains(replicaResolved, evidenceResolved) {
			return CanonicalPruneResult{}, ErrAvailability
		}
	}
	bundle, err := VerifyReplicaSet(
		replicas, checkpoint, checkpointPolicy, replicaPolicy, base, parameters, limits, now,
	)
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	check := func() (uint64, error) {
		at, err := sample()
		if err != nil {
			return 0, err
		}
		for _, receipt := range bundle.Receipts {
			if err := receipt.verifyAvailabilityTime(replicaPolicy, at); err != nil {
				return 0, err
			}
		}
		return at, ctx.Err()
	}
	// Do not publish an already-expired result after a long replay.
	now, err = check()
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	bundleID, err := bundle.ID()
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	if err := SaveAvailabilityBundleFile(
		availabilityPath, bundle, checkpoint, checkpointPolicy, replicaPolicy, now, bundleID,
	); err != nil {
		return CanonicalPruneResult{}, err
	}
	// Publication/fsync can also be slow. Any published file remains evidence,
	// not a permit to skip the final time gate on this attempt or on retry.
	now, err = check()
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	retainUntil := bundle.Receipts[0].RetainUntil
	for _, receipt := range bundle.Receipts[1:] {
		retainUntil = min(retainUntil, receipt.RetainUntil)
	}
	report, err := chain.PruneCanonicalPrefixAuthorized(workchain.CanonicalFloor{
		Pruned: true, BaseID: checkpoint.Statement.BaseID, Anchor: checkpoint.Statement.Anchor,
		AncestryNodes: checkpoint.Statement.AncestryNodes, AncestryRoot: checkpoint.Statement.AncestryRoot,
		StatementID: bundle.StatementID, ManifestID: bundle.ManifestID,
		AvailabilityID: bundleID, VerifiedAt: now, RetainUntil: retainUntil,
	}, check)
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	return CanonicalPruneResult{Bundle: bundle, Report: report}, nil
}
