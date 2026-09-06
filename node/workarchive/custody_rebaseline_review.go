package workarchive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// CustodyRebaselineEvidence names immutable evidence and independently retained
// IDs. None may be inferred from candidate metadata by the caller.
type CustodyRebaselineEvidence struct {
	Recovery, TransferPackage, AuditorBackup, ReplicaBackup             string
	ApplicationID, TransferID, AuditorCheckpointID, ReplicaCheckpointID types.Hash
}

// CustodyRebaselineArchive supplies the trusted consensus context for a fresh
// full replay. The archive must remain immutable for the duration of the call,
// as required by VerifyArchiveDirectory; it is never repaired or imported.
type CustodyRebaselineArchive struct {
	Directory  string
	Checkpoint Checkpoint
	Policy     Policy
	Base       workchain.Base
	Parameters workblock.Parameters
	Limits     Limits
}

// CustodyRebaselineAssignment is independently selected, never trusted from
// the proposal itself. All proposed evidence keys must be disjoint from both
// old roles. This is key separation, not proof of independent operators or a
// cross-host fence. The location is an operator-selected opaque commitment.
type CustodyRebaselineAssignment struct {
	Policy           CustodyPolicy
	ReplicaPublicKey [ed25519.PublicKeySize]byte
	LocationID       types.Hash
}

// CreateCustodyRebaselineProposal revalidates the entire historical application
// and fully replays the archive before signing in a distinct proposal domain.
// Time is sampled AFTER replay. No ordinary receipt/signature is produced and
// no participant, journal, source, pin, or service is changed. The result needs
// independent review and future enforceable cutover, even while within age.
// Cancellation is checked between bounded replay/lock operations, not per block.
func CreateCustodyRebaselineProposal(ctx context.Context, evidence CustodyRebaselineEvidence, archive CustodyRebaselineArchive,
	manifest Manifest, initial ReplicaReceipt, oldPolicy CustodyPolicy, next CustodyRebaselineAssignment,
	key ed25519.PrivateKey, reviewLifetime, retainUntil uint64,
) (CustodyRebaselineProposal, error) {
	return createCustodyRebaselineProposal(ctx, evidence, archive, manifest, initial, oldPolicy, next, key, reviewLifetime, retainUntil, time.Now)
}

func createCustodyRebaselineProposal(ctx context.Context, evidence CustodyRebaselineEvidence, archive CustodyRebaselineArchive,
	manifest Manifest, initial ReplicaReceipt, oldPolicy CustodyPolicy, next CustodyRebaselineAssignment,
	key ed25519.PrivateKey, reviewLifetime, retainUntil uint64, clock func() time.Time,
) (CustodyRebaselineProposal, error) {
	if ctx == nil || clock == nil || len(key) != ed25519.PrivateKeySize || reviewLifetime == 0 ||
		reviewLifetime > MaximumCustodyRebaselineReviewLifetime || !bytes.Equal(key.Public().(ed25519.PublicKey), next.ReplicaPublicKey[:]) ||
		!bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()), key) {
		return CustodyRebaselineProposal{}, ErrCustodyRebaseline
	}
	previous, err := reviewCustodyRebaselineInputs(ctx, evidence, archive, manifest, initial, oldPolicy, next)
	if err != nil {
		return CustodyRebaselineProposal{}, err
	}
	seconds := clock().Unix()
	if seconds <= 0 {
		return CustodyRebaselineProposal{}, ErrCustodyRebaseline
	}
	at := uint64(seconds)
	if ^uint64(0)-at < reviewLifetime {
		return CustodyRebaselineProposal{}, ErrCustodyRebaseline
	}
	manifestID, _ := manifest.ID()
	previousID, _ := previous.ID()
	policyID, _ := custodyJournalPolicyID(next.Policy)
	proposal := CustodyRebaselineProposal{Version: CustodyRebaselineProposalVersion0,
		ApplicationID: evidence.ApplicationID, PreviousReceiptID: previousID, ManifestID: manifestID,
		StatementID: previous.StatementID, NextPolicyID: policyID, LocationID: next.LocationID,
		ReplicaPublicKey: next.ReplicaPublicKey, ReplayedAt: at, ReviewUntil: at + reviewLifetime, RetainUntil: retainUntil}
	if err := proposal.verifyAssignment(evidence, manifest, previous, next); err != nil {
		return CustodyRebaselineProposal{}, err
	}
	if err := ctx.Err(); err != nil {
		return CustodyRebaselineProposal{}, err
	}
	message, _ := proposal.signatureMessage()
	copy(proposal.Signature[:], ed25519.Sign(key, message))
	return proposal, nil
}

// VerifyCustodyRebaselineProposal requires an independent proposal ID and new
// assignment, the original four evidence IDs, and a fresh full archive replay.
// It checks the signed review window again AFTER expensive verification. A
// successful review is still not authority to serve, challenge, prune, or retire.
func VerifyCustodyRebaselineProposal(ctx context.Context, proposal CustodyRebaselineProposal, expectedID types.Hash,
	evidence CustodyRebaselineEvidence, archive CustodyRebaselineArchive, manifest Manifest, initial ReplicaReceipt,
	oldPolicy CustodyPolicy, next CustodyRebaselineAssignment,
) error {
	return verifyCustodyRebaselineProposal(ctx, proposal, expectedID, evidence, archive, manifest, initial, oldPolicy, next, time.Now)
}

func verifyCustodyRebaselineProposal(ctx context.Context, proposal CustodyRebaselineProposal, expectedID types.Hash,
	evidence CustodyRebaselineEvidence, archive CustodyRebaselineArchive, manifest Manifest, initial ReplicaReceipt,
	oldPolicy CustodyPolicy, next CustodyRebaselineAssignment, clock func() time.Time,
) error {
	if ctx == nil || clock == nil || expectedID.IsZero() {
		return ErrCustodyRebaseline
	}
	id, err := proposal.ID()
	if err != nil || id != expectedID {
		return ErrCustodyRebaseline
	}
	var lastTime int64
	checkTime := func() error {
		at := clock().Unix()
		if err := ctx.Err(); err != nil {
			return err
		}
		if at <= 0 || (lastTime != 0 && at < lastTime) {
			return ErrCustodyRebaselineExpired
		}
		lastTime = at
		return proposal.VerifyReviewWindow(uint64(at))
	}
	if err := checkTime(); err != nil {
		return err
	}
	previous, err := reviewCustodyRebaselineInputs(ctx, evidence, archive, manifest, initial, oldPolicy, next)
	if err != nil {
		return err
	}
	if err := proposal.verifyAssignment(evidence, manifest, previous, next); err != nil {
		return err
	}
	return checkTime()
}

func (proposal CustodyRebaselineProposal) verifyAssignment(evidence CustodyRebaselineEvidence, manifest Manifest,
	previous ReplicaReceipt, next CustodyRebaselineAssignment,
) error {
	manifestID, err := manifest.ID()
	if err != nil {
		return err
	}
	previousID, err := previous.ID()
	if err != nil {
		return err
	}
	policyID, err := custodyJournalPolicyID(next.Policy)
	if err != nil || proposal.validateShape() != nil || proposal.ApplicationID != evidence.ApplicationID ||
		proposal.PreviousReceiptID != previousID || proposal.ManifestID != manifestID || proposal.StatementID != previous.StatementID ||
		proposal.NextPolicyID != policyID || proposal.LocationID != next.LocationID || proposal.ReplicaPublicKey != next.ReplicaPublicKey ||
		proposal.ReplayedAt < previous.StoredAt || proposal.RetainUntil <= previous.RetainUntil ||
		proposal.RetainUntil-proposal.ReplayedAt > next.Policy.MaximumRenewalTerm {
		return ErrCustodyRebaseline
	}
	return nil
}

func reviewCustodyRebaselineInputs(ctx context.Context, evidence CustodyRebaselineEvidence, archive CustodyRebaselineArchive,
	manifest Manifest, initial ReplicaReceipt, oldPolicy CustodyPolicy, next CustodyRebaselineAssignment,
) (ReplicaReceipt, error) {
	fail := func(err error) (ReplicaReceipt, error) {
		return ReplicaReceipt{}, errors.Join(ErrCustodyRebaseline, err)
	}
	if ctx == nil || evidence.ApplicationID.IsZero() || archive.Directory == "" ||
		archive.Limits.Validate() != nil || oldPolicy.validate() != nil || next.Policy.validate() != nil ||
		next.LocationID.IsZero() || types.Hash(next.ReplicaPublicKey).IsZero() || next.ReplicaPublicKey == initial.ReplicaPublicKey {
		return fail(nil)
	}
	for _, key := range next.Policy.TrustedAuditors {
		if key == initial.ReplicaPublicKey || key == next.ReplicaPublicKey {
			return fail(nil)
		}
		for _, old := range oldPolicy.TrustedAuditors {
			if key == old || next.ReplicaPublicKey == old {
				return fail(nil)
			}
		}
	}
	for _, path := range []string{evidence.Recovery, evidence.TransferPackage, evidence.AuditorBackup, evidence.ReplicaBackup} {
		if path == "" || CustodyEvidencePathsOverlap(archive.Directory, path) {
			return fail(nil)
		}
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	transfer, header, release, err := lockCustodyApplicationInputs(evidence.Recovery, evidence.TransferPackage, evidence.TransferID,
		evidence.AuditorBackup, evidence.ReplicaBackup, evidence.AuditorCheckpointID, evidence.ReplicaCheckpointID, manifest, initial, oldPolicy)
	if err != nil {
		return fail(err)
	}
	defer release()
	if _, err := verifyCustodyApplicationLockedInputs(evidence.Recovery, evidence.ApplicationID, transfer, header,
		evidence.AuditorBackup, manifest, initial, oldPolicy); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	verified, err := VerifyArchiveDirectory(archive.Directory, archive.Checkpoint, archive.Policy, archive.Base, archive.Parameters, archive.Limits)
	if err != nil {
		return fail(err)
	}
	wantID, err := manifest.ID()
	if err != nil {
		return fail(err)
	}
	gotID, _ := verified.ID()
	statementID, _ := archive.Checkpoint.Statement.ID()
	if gotID != wantID || statementID != initial.StatementID {
		return fail(nil)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return transfer.Entry.Record.RenewedReceipt, nil
}
