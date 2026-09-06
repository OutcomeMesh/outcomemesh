package workarchive

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

type custodyRetirementHooks struct {
	beforeLocks, afterLocks, beforeCommit, afterAuditor, afterReplica func() error
	afterTemporary                                                    func(string) error
}

// RetireLocalCustodyParticipants irreversibly disables TWO exact local journal
// roots, after their managed operations drain. It changes only retirement.omcrt
// in each root; the pinned backups, reconstruction, signed proposal, archive and
// existing journal/artifact bytes are preserved. This is local retirement, NOT
// cross-host fencing or activation. Caller must upgrade/quiesce legacy writers.
//
// Both current inventories must match the reviewed source pins before the first
// marker. The first durable marker commits intent to retire this whole pair.
// A crash can leave just one participant retired: preserve it and retry exactly
// that intent. Retry may finish after proposal expiry, but only if the other
// participant has not advanced or changed. No path clears a retirement marker.
func RetireLocalCustodyParticipants(ctx context.Context, local CustodyLocalParticipants,
	proposal CustodyRebaselineProposal, expectedProposalID types.Hash, evidence CustodyRebaselineEvidence, archive CustodyRebaselineArchive,
	manifest Manifest, initial ReplicaReceipt, oldPolicy CustodyPolicy, next CustodyRebaselineAssignment,
) (CustodyLocalRetirementPair, bool, error) {
	return retireLocalCustodyParticipants(ctx, local, proposal, expectedProposalID, evidence, archive,
		manifest, initial, oldPolicy, next, time.Now, custodyRetirementHooks{})
}

func retireLocalCustodyParticipants(ctx context.Context, local CustodyLocalParticipants,
	proposal CustodyRebaselineProposal, expectedProposalID types.Hash, evidence CustodyRebaselineEvidence, archive CustodyRebaselineArchive,
	manifest Manifest, initial ReplicaReceipt, oldPolicy CustodyPolicy, next CustodyRebaselineAssignment,
	clock func() time.Time, hooks custodyRetirementHooks,
) (CustodyLocalRetirementPair, bool, error) {
	if ctx == nil || clock == nil || validateCustodyLocalParticipantPaths(local, evidence, archive) != nil {
		return CustodyLocalRetirementPair{}, false, ErrCustodyRetirement
	}
	transfer, err := reviewCustodyRetirementProposal(ctx, proposal, expectedProposalID, evidence, archive, manifest, initial, oldPolicy, next)
	if err != nil {
		return CustodyLocalRetirementPair{}, false, err
	}
	if err := runCustodyApplicationHook(hooks.beforeLocks); err != nil {
		return CustodyLocalRetirementPair{}, false, err
	}
	release, err := lockCustodyLocalParticipants(local)
	if err != nil {
		return CustodyLocalRetirementPair{}, false, err
	}
	defer release()
	if err := runCustodyApplicationHook(hooks.afterLocks); err != nil {
		return CustodyLocalRetirementPair{}, false, err
	}
	var pair CustodyLocalRetirementPair
	a, aExists, err := loadCustodyRetirement(local.AuditorJournal)
	if err != nil {
		return pair, false, err
	}
	r, rExists, err := loadCustodyRetirement(local.ReplicaJournal)
	if err != nil {
		return pair, false, err
	}
	// The auditor marker is the first durable intent. Replica-only retirement
	// cannot result from our ordered, synced publication: do not silently repair
	// a lost/rolled-back first decision from a later marker.
	if rExists && !aExists {
		return pair, false, ErrCustodyRetirementIncomplete
	}
	var decidedAt uint64
	for _, candidate := range []struct {
		value  CustodyParticipantRetirement
		exists bool
		before CustodyCheckpoint
	}{
		{a, aExists, transfer.AuditorCheckpoint}, {r, rExists, transfer.ReplicaCheckpoint},
	} {
		if !candidate.exists {
			continue
		}
		if candidate.value.ProposalID != expectedProposalID || candidate.value.Before != candidate.before ||
			proposal.VerifyReviewWindow(candidate.value.DecidedAt) != nil ||
			(decidedAt != 0 && decidedAt != candidate.value.DecidedAt) {
			return pair, false, ErrCustodyRetirement
		}
		decidedAt = candidate.value.DecidedAt
	}
	if decidedAt == 0 {
		at := clock().Unix()
		if at <= 0 || proposal.VerifyReviewWindow(uint64(at)) != nil {
			return pair, false, ErrCustodyRebaselineExpired
		}
		decidedAt = uint64(at)
	}
	pair = CustodyLocalRetirementPair{
		Auditor: CustodyParticipantRetirement{Version: CustodyParticipantRetirementVersion0, ProposalID: expectedProposalID, Before: transfer.AuditorCheckpoint, DecidedAt: decidedAt},
		Replica: CustodyParticipantRetirement{Version: CustodyParticipantRetirementVersion0, ProposalID: expectedProposalID, Before: transfer.ReplicaCheckpoint, DecidedAt: decidedAt},
	}
	partial := func(err error) (CustodyLocalRetirementPair, bool, error) {
		if aExists != rExists {
			err = errors.Join(ErrCustodyRetirementIncomplete, err)
		}
		return CustodyLocalRetirementPair{}, false, err
	}
	if err := verifyCustodyRetirementBefore(local.AuditorJournal, local.AuditorArtifacts, pair.Auditor.Before, manifest, initial, oldPolicy); err != nil {
		return partial(err)
	}
	if err := verifyCustodyRetirementBefore(local.ReplicaJournal, "", pair.Replica.Before, manifest, initial, oldPolicy); err != nil {
		return partial(err)
	}
	for _, item := range []struct {
		root   string
		exists bool
	}{{local.AuditorJournal, aExists}, {local.ReplicaJournal, rExists}} {
		if item.exists {
			continue
		}
		usage, err := inventoryCustodyJournal(item.root)
		if err != nil {
			return partial(err)
		}
		// Administrative retirement can exceed a reduced local growth budget,
		// but must leave the full evidence replayable under its hard ceilings.
		if err := usage.admit(CustodyJournalLimits{MaximumBytes: MaximumCustodyJournalBytes, MaximumPaths: MaximumCustodyJournalPaths},
			MaximumCustodyParticipantRetirementBytes, 1); err != nil {
			return partial(err)
		}
	}
	if err := runCustodyApplicationHook(hooks.beforeCommit); err != nil {
		return partial(err)
	}
	changed := false
	for _, item := range []struct {
		root, role string
		value      CustodyParticipantRetirement
		exists     bool
		hook       func() error
	}{
		{local.AuditorJournal, "auditor", pair.Auditor, aExists, hooks.afterAuditor},
		{local.ReplicaJournal, "replica", pair.Replica, rExists, hooks.afterReplica},
	} {
		if err := ctx.Err(); err != nil {
			return pair, changed, errors.Join(ErrCustodyRetirementIncomplete, err)
		}
		if !item.exists {
			// Until the first durable intent, lock/replay time counts against the
			// review window. Later completion continues the SAME decision time.
			if !aExists && !rExists {
				at := clock().Unix()
				if at <= 0 || uint64(at) < decidedAt || proposal.VerifyReviewWindow(uint64(at)) != nil {
					return CustodyLocalRetirementPair{}, false, ErrCustodyRebaselineExpired
				}
			}
			encoded, _ := item.value.CanonicalBytes()
			published, err := publishCustodyRetirement(ctx, item.root, item.role, encoded, hooks.afterTemporary,
				func() error {
					if aExists || rExists {
						return nil
					}
					at := clock().Unix()
					if at <= 0 || uint64(at) < decidedAt {
						return ErrCustodyRebaselineExpired
					}
					return proposal.VerifyReviewWindow(uint64(at))
				})
			changed = changed || published
			if err != nil {
				return pair, changed, errors.Join(ErrCustodyRetirementIncomplete, err)
			}
			if item.role == "auditor" {
				aExists = true
			} else {
				rExists = true
			}
		} else if err := syncCustodyRetirement(item.root, item.value); err != nil {
			return pair, changed, err
		}
		if err := runCustodyApplicationHook(item.hook); err != nil {
			return pair, changed, errors.Join(ErrCustodyRetirementIncomplete, err)
		}
	}
	if err := verifyLocalCustodyRetirementLocked(local, pair, proposal, expectedProposalID, manifest, initial, oldPolicy); err != nil {
		return pair, changed, err
	}
	return pair, changed, nil
}

// VerifyLocalCustodyRetirement requires independently retained proposal AND
// pair IDs. It replays the retained source/reconstruction/archive evidence and
// verifies both complete local inventories. It asserts no current proposal
// freshness and creates no files or missing locks, including after restart.
func VerifyLocalCustodyRetirement(ctx context.Context, local CustodyLocalParticipants, expectedPairID types.Hash,
	proposal CustodyRebaselineProposal, expectedProposalID types.Hash, evidence CustodyRebaselineEvidence, archive CustodyRebaselineArchive,
	manifest Manifest, initial ReplicaReceipt, oldPolicy CustodyPolicy, next CustodyRebaselineAssignment,
) (CustodyLocalRetirementPair, error) {
	if ctx == nil || expectedPairID.IsZero() || validateCustodyLocalParticipantPaths(local, evidence, archive) != nil {
		return CustodyLocalRetirementPair{}, ErrCustodyRetirement
	}
	transfer, err := reviewCustodyRetirementProposal(ctx, proposal, expectedProposalID, evidence, archive, manifest, initial, oldPolicy, next)
	if err != nil {
		return CustodyLocalRetirementPair{}, err
	}
	release, err := lockCustodyLocalParticipants(local)
	if err != nil {
		return CustodyLocalRetirementPair{}, err
	}
	defer release()
	a, aExists, aErr := loadCustodyRetirement(local.AuditorJournal)
	r, rExists, rErr := loadCustodyRetirement(local.ReplicaJournal)
	if aErr != nil || rErr != nil || !aExists || !rExists {
		return CustodyLocalRetirementPair{}, errors.Join(ErrCustodyRetirementIncomplete, aErr, rErr)
	}
	pair := CustodyLocalRetirementPair{Auditor: a, Replica: r}
	id, err := pair.ID()
	if err != nil || id != expectedPairID || a.Before != transfer.AuditorCheckpoint || r.Before != transfer.ReplicaCheckpoint {
		return CustodyLocalRetirementPair{}, ErrCustodyRetirement
	}
	if err := verifyLocalCustodyRetirementLocked(local, pair, proposal, expectedProposalID, manifest, initial, oldPolicy); err != nil {
		return CustodyLocalRetirementPair{}, err
	}
	return pair, ctx.Err()
}

func reviewCustodyRetirementProposal(ctx context.Context, proposal CustodyRebaselineProposal, expectedID types.Hash,
	evidence CustodyRebaselineEvidence, archive CustodyRebaselineArchive, manifest Manifest, initial ReplicaReceipt, oldPolicy CustodyPolicy, next CustodyRebaselineAssignment,
) (CustodyHistoricalTransfer, error) {
	id, err := proposal.ID()
	if err != nil || expectedID.IsZero() || id != expectedID {
		return CustodyHistoricalTransfer{}, ErrCustodyRetirement
	}
	transfer, err := reviewCustodyRebaselineTransfer(ctx, evidence, archive, manifest, initial, oldPolicy, next)
	if err != nil {
		return CustodyHistoricalTransfer{}, err
	}
	if err := proposal.verifyAssignment(evidence, manifest, transfer.Entry.Record.RenewedReceipt, next); err != nil {
		return CustodyHistoricalTransfer{}, err
	}
	return transfer, nil
}

func verifyLocalCustodyRetirementLocked(local CustodyLocalParticipants, pair CustodyLocalRetirementPair, proposal CustodyRebaselineProposal,
	proposalID types.Hash, manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) error {
	if _, err := pair.ID(); err != nil || pair.Auditor.ProposalID != proposalID || proposal.VerifyReviewWindow(pair.Auditor.DecidedAt) != nil {
		return ErrCustodyRetirement
	}
	for _, item := range []struct {
		root, artifacts string
		want            CustodyParticipantRetirement
	}{
		{local.AuditorJournal, local.AuditorArtifacts, pair.Auditor}, {local.ReplicaJournal, "", pair.Replica},
	} {
		got, exists, err := loadCustodyRetirement(item.root)
		if err != nil || !exists || got != item.want {
			return errors.Join(ErrCustodyRetirement, err)
		}
		if err := verifyCustodyRetirementBefore(item.root, item.artifacts, item.want.Before, manifest, initial, policy); err != nil {
			return err
		}
	}
	return nil
}

func publishCustodyRetirement(ctx context.Context, root, role string, encoded []byte, afterTemporary func(string) error, beforeLink func() error) (bool, error) {
	// Scratch space is a sibling, never inside the pinned journal/artifact tree.
	// Incomplete attempts are retained. Only a successfully committed temporary
	// link is removed; retries never discover or promote arbitrary scratch files.
	temporary, err := writeCustodyTransferTemporary(ctx, filepath.Dir(root), encoded)
	if err != nil {
		return false, err
	}
	if afterTemporary != nil {
		if err := afterTemporary(role); err != nil {
			return false, err
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := beforeLink(); err != nil {
		return false, err
	}
	if err := os.Link(temporary, filepath.Join(root, custodyRetirementFileName)); err != nil {
		return false, err
	}
	if err := syncDirectory(root); err != nil {
		return true, err
	}
	committed, err := readRegularArchiveFile(filepath.Join(root, custodyRetirementFileName), MaximumCustodyParticipantRetirementBytes)
	if err != nil || !bytes.Equal(committed, encoded) {
		return true, errors.Join(ErrCustodyRetirement, err)
	}
	if err := os.Remove(temporary); err != nil {
		return true, err
	}
	return true, syncDirectory(filepath.Dir(root))
}

func syncCustodyRetirement(root string, want CustodyParticipantRetirement) error {
	got, exists, err := loadCustodyRetirement(root)
	if err != nil || !exists || got != want {
		return errors.Join(ErrCustodyRetirement, err)
	}
	file, err := os.OpenFile(filepath.Join(root, custodyRetirementFileName), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(syncErr, closeErr, syncDirectory(root))
}
