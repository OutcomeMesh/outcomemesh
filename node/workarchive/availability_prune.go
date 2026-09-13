package workarchive

import (
	"bytes"
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
	verified, err := prepareCanonicalPrune(ctx, chain, replicas, availabilityPath, checkpoint,
		checkpointPolicy, replicaPolicy, base, parameters, limits, clock, nil)
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	report, err := chain.PruneCanonicalPrefixAuthorized(verified.boundary, verified.Authorize)
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	return CanonicalPruneResult{Bundle: verified.bundle, Report: report}, nil
}

// CanonicalPruneVerification retains immutable replayed evidence and a live
// time check, not an authority grant. The managed caller must keep every required
// assignment guard through the final batch and result publication. Authorize is
// synchronous, must not be called concurrently, and never executes chain work.
type CanonicalPruneVerification struct {
	boundary workchain.CanonicalFloor
	bundle   AvailabilityBundle
	check    func() (uint64, error)
}

func (verified *CanonicalPruneVerification) Authorize() (uint64, error) {
	if verified == nil || verified.check == nil {
		return 0, ErrAvailability
	}
	return verified.check()
}

// VerifyCanonicalPruneRequest fully replays replicas and publishes exact evidence
// for an independently retained request. All floor fields must match; VerifiedAt
// is the original request observation and cannot be in the future. This does not
// create a request, start work or make a historical bundle a reusable permission.
// The returned live clock check must run inside the final prepared storage batch.
func VerifyCanonicalPruneRequest(ctx context.Context, chain *workchain.Store, replicas []Replica, availabilityPath string,
	checkpoint Checkpoint, checkpointPolicy Policy, replicaPolicy ReplicaPolicy,
	base workchain.Base, parameters workblock.Parameters, limits Limits, expected workchain.CanonicalFloor,
) (*CanonicalPruneVerification, error) {
	return prepareCanonicalPrune(ctx, chain, replicas, availabilityPath, checkpoint,
		checkpointPolicy, replicaPolicy, base, parameters, limits, time.Now, &expected)
}

func prepareCanonicalPrune(ctx context.Context, chain *workchain.Store, replicas []Replica, availabilityPath string,
	checkpoint Checkpoint, checkpointPolicy Policy, replicaPolicy ReplicaPolicy,
	base workchain.Base, parameters workblock.Parameters, limits Limits, clock func() time.Time, expected *workchain.CanonicalFloor,
) (*CanonicalPruneVerification, error) {
	if ctx == nil || clock == nil {
		return nil, ErrAvailability
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
		return nil, err
	}
	if chain == nil || availabilityPath == "" || VerifyChain(checkpoint, checkpointPolicy, chain) != nil {
		return nil, ErrChain
	}
	evidenceResolved, err := resolvedArchivePath(availabilityPath)
	if err != nil {
		return nil, err
	}
	for _, replica := range replicas {
		replicaResolved, pathErr := resolvedArchivePath(replica.Directory)
		if pathErr != nil || pathContains(replicaResolved, evidenceResolved) {
			return nil, ErrAvailability
		}
	}
	bundle, err := VerifyReplicaSet(
		replicas, checkpoint, checkpointPolicy, replicaPolicy, base, parameters, limits, now,
	)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	bundleID, err := bundle.ID()
	if err != nil {
		return nil, err
	}
	retainUntil := bundle.Receipts[0].RetainUntil
	for _, receipt := range bundle.Receipts[1:] {
		retainUntil = min(retainUntil, receipt.RetainUntil)
	}
	boundary := workchain.CanonicalFloor{
		Pruned: true, BaseID: checkpoint.Statement.BaseID, Anchor: checkpoint.Statement.Anchor,
		AncestryNodes: checkpoint.Statement.AncestryNodes, AncestryRoot: checkpoint.Statement.AncestryRoot,
		StatementID: bundle.StatementID, ManifestID: bundle.ManifestID,
		AvailabilityID: bundleID, VerifiedAt: now, RetainUntil: retainUntil,
	}
	if expected != nil {
		boundary.VerifiedAt = expected.VerifiedAt
		actual, err := boundary.CanonicalBytes()
		want, wantErr := expected.CanonicalBytes()
		if err != nil || wantErr != nil || expected.VerifiedAt > now || !bytes.Equal(actual, want) {
			return nil, ErrAvailability
		}
	}
	if err := SaveAvailabilityBundleFile(
		availabilityPath, bundle, checkpoint, checkpointPolicy, replicaPolicy, now, bundleID,
	); err != nil {
		return nil, err
	}
	// Publication/fsync can also be slow. Any published file remains evidence,
	// not a permit to skip the final time gate on this attempt or on retry.
	now, err = check()
	if err != nil {
		return nil, err
	}
	if expected == nil {
		boundary.VerifiedAt = now
	}
	return &CanonicalPruneVerification{boundary: boundary, bundle: bundle, check: check}, nil
}
