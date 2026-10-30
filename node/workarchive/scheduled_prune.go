package workarchive

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// VerifyScheduledCanonicalPruneRequest replays every migrated archive and full
// original custody lineage. Its live time gate must run inside the final storage
// batch while the caller holds all original authority and journal guards. The
// caller separately retains the immutable inventory before starting any effect.
func VerifyScheduledCanonicalPruneRequest(ctx context.Context, chain *workchain.Store, directories []string, bundle ScheduledAvailabilityBundle,
	checkpoint Checkpoint, oldPolicy Policy, replicaPolicy ReplicaPolicy, assignments []custodyauthority.Assignment, evidence []ScheduledReplicaEvidence,
	base workchain.Base, parameters workblock.Parameters, limits Limits, expected workchain.CanonicalFloor) (*CanonicalPruneVerification, error) {
	return verifyScheduledCanonicalPruneRequest(ctx, chain, directories, bundle, checkpoint, oldPolicy, replicaPolicy, assignments, evidence, base, parameters, limits, expected, time.Now)
}
func verifyScheduledCanonicalPruneRequest(ctx context.Context, chain *workchain.Store, directories []string, bundle ScheduledAvailabilityBundle,
	checkpoint Checkpoint, oldPolicy Policy, replicaPolicy ReplicaPolicy, assignments []custodyauthority.Assignment, evidence []ScheduledReplicaEvidence,
	base workchain.Base, parameters workblock.Parameters, limits Limits, expected workchain.CanonicalFloor, clock func() time.Time) (*CanonicalPruneVerification, error) {
	if ctx == nil || chain == nil || clock == nil || len(directories) != len(bundle.Receipts) || len(directories) < MinimumReplicas || len(directories) > MaximumReplicas {
		return nil, ErrAvailability
	}
	var previous time.Time
	sample := func() (uint64, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		now := clock().Round(0)
		if now.Unix() <= 0 || (!previous.IsZero() && now.Before(previous)) {
			return 0, ErrAvailabilityClock
		}
		previous = now
		return uint64(now.Unix()), nil
	}
	now, err := sample()
	if err != nil {
		return nil, err
	}
	policy := oldPolicy
	policy.Binding.RadixActivationHeight = bundle.RadixActivationHeight
	if parameters.RadixActivationHeight != bundle.RadixActivationHeight || VerifyChain(checkpoint, policy, chain) != nil {
		return nil, ErrChain
	}
	if err := bundle.Verify(ctx, checkpoint, oldPolicy, replicaPolicy, assignments, evidence, now); err != nil {
		return nil, err
	}
	seen := make(map[string]os.FileInfo, len(directories))
	for _, directory := range directories {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path, err := filepath.Abs(directory)
		if err != nil {
			return nil, err
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrAvailability
		}
		for prior, old := range seen {
			if prior == path || os.SameFile(info, old) {
				return nil, ErrAvailability
			}
		}
		seen[path] = info
		manifest, err := VerifyArchiveDirectory(path, checkpoint, policy, base, parameters, limits)
		if err != nil {
			return nil, err
		}
		id, _ := manifest.ID()
		if id != bundle.ManifestID {
			return nil, ErrAvailability
		}
	}
	receipts := append([]ScheduledReplicaReceipt(nil), bundle.Receipts...)
	check := func() (uint64, error) {
		at, err := sample()
		if err != nil {
			return 0, err
		}
		for _, r := range receipts {
			if err := r.Original.verifyAvailabilityTime(replicaPolicy, at); err != nil {
				return 0, err
			}
		}
		return at, ctx.Err()
	}
	now, err = check()
	if err != nil {
		return nil, err
	}
	bid, _ := bundle.ID()
	retain := receipts[0].Original.RetainUntil
	for _, r := range receipts[1:] {
		retain = min(retain, r.Original.RetainUntil)
	}
	st := checkpoint.Statement
	boundary := workchain.CanonicalFloor{Pruned: true, RadixActivationHeight: bundle.RadixActivationHeight, BaseID: st.BaseID, Anchor: st.Anchor, AncestryNodes: st.AncestryNodes, AncestryRoot: st.AncestryRoot, StatementID: bundle.StatementID, ManifestID: bundle.ManifestID, AvailabilityID: bid, VerifiedAt: expected.VerifiedAt, RetainUntil: retain}
	actual, err := boundary.CanonicalBytes()
	want, werr := expected.CanonicalBytes()
	if err != nil || werr != nil || !bytes.Equal(actual, want) || expected.VerifiedAt > now {
		return nil, errors.Join(ErrAvailability, err, werr)
	}
	return &CanonicalPruneVerification{boundary: boundary, check: check}, nil
}
