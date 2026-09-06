package workarchive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	CustodyHistoricalTransferVersion0     uint16 = 0
	MaximumCustodyHistoricalTransferBytes        = 8 + 2 + 2*MaximumCustodyCheckpointBytes + binary.MaxVarintLen64 + MaximumCustodyJournalEntryBytes
	custodyHistoricalTransferIDDomain            = "OMESH/workgraph/archive/custody-historical-transfer/id/v0"
)

var (
	ErrCustodyHistoricalTransfer   = errors.New("invalid or ineligible custody historical transfer")
	custodyHistoricalTransferMagic = [8]byte{'O', 'M', 'W', 'A', 'C', 'H', 'T', 'R'}
)

// CustodyHistoricalTransfer is an unsigned, content-addressed handoff envelope,
// not a new response or permission to append, rebaseline, or resume. Entry keeps
// the original signed challenge, response time, proof, and renewed receipt.
// Decoding checks shape only. Source inventories and pending intent must still
// be checked against independently retained IDs with the package verifier.
type CustodyHistoricalTransfer struct {
	Version                              uint16
	AuditorCheckpoint, ReplicaCheckpoint CustodyCheckpoint
	Entry                                CustodyJournalEntry
}

func (transfer CustodyHistoricalTransfer) validate() error {
	a, r, entry := transfer.AuditorCheckpoint, transfer.ReplicaCheckpoint, transfer.Entry
	if transfer.Version != CustodyHistoricalTransferVersion0 || a.validate() != nil || r.validate() != nil ||
		a.Artifacts == (CustodyCheckpointTree{}) || r.Artifacts != (CustodyCheckpointTree{}) ||
		a.HeaderID != r.HeaderID || a.Sequence >= MaximumCustodyJournalPaths || r.Sequence != a.Sequence+1 ||
		entry.Sequence != r.Sequence || entry.PreviousEntryID != a.HeadEntryID {
		return ErrCustodyHistoricalTransfer
	}
	entryID, err := entry.ID()
	previousID, previousErr := entry.PreviousReceipt.ID()
	receiptID, receiptErr := entry.Record.RenewedReceipt.ID()
	if err != nil || previousErr != nil || receiptErr != nil || entryID != r.HeadEntryID ||
		previousID != a.ReceiptID || receiptID != r.ReceiptID {
		return ErrCustodyHistoricalTransfer
	}
	return nil
}

func (transfer CustodyHistoricalTransfer) CanonicalBytes() ([]byte, error) {
	if err := transfer.validate(); err != nil {
		return nil, err
	}
	a, _ := transfer.AuditorCheckpoint.CanonicalBytes()
	r, _ := transfer.ReplicaCheckpoint.CanonicalBytes()
	entry, _ := transfer.Entry.CanonicalBytes()
	encoder := codec.NewEncoder(8 + 2 + len(a) + len(r) + binary.MaxVarintLen64 + len(entry))
	encoder.Fixed(custodyHistoricalTransferMagic[:])
	encoder.U16(transfer.Version)
	encoder.Fixed(a)
	encoder.Fixed(r)
	encoder.BytesField(entry)
	return encoder.Bytes(), nil
}

func DecodeCustodyHistoricalTransfer(input []byte) (CustodyHistoricalTransfer, error) {
	if len(input) < 8+2+2*MaximumCustodyCheckpointBytes+1 || len(input) > MaximumCustodyHistoricalTransferBytes {
		return CustodyHistoricalTransfer{}, ErrCustodyHistoricalTransfer
	}
	decoder := codec.NewDecoder(input)
	magic, _ := decoder.Fixed(len(custodyHistoricalTransferMagic))
	var transfer CustodyHistoricalTransfer
	transfer.Version, _ = decoder.U16()
	a, _ := decoder.Fixed(MaximumCustodyCheckpointBytes)
	r, _ := decoder.Fixed(MaximumCustodyCheckpointBytes)
	var err error
	transfer.AuditorCheckpoint, err = DecodeCustodyCheckpoint(a)
	if err != nil {
		return CustodyHistoricalTransfer{}, errors.Join(ErrCustodyHistoricalTransfer, err)
	}
	transfer.ReplicaCheckpoint, err = DecodeCustodyCheckpoint(r)
	if err != nil {
		return CustodyHistoricalTransfer{}, errors.Join(ErrCustodyHistoricalTransfer, err)
	}
	entry, err := decoder.BytesField(MaximumCustodyJournalEntryBytes)
	if err != nil {
		return CustodyHistoricalTransfer{}, errors.Join(ErrCustodyHistoricalTransfer, err)
	}
	transfer.Entry, err = DecodeCustodyJournalEntry(entry)
	if err != nil || !bytes.Equal(magic, custodyHistoricalTransferMagic[:]) || decoder.Finish() != nil || transfer.validate() != nil {
		return CustodyHistoricalTransfer{}, errors.Join(ErrCustodyHistoricalTransfer, err)
	}
	return transfer, nil
}

func (transfer CustodyHistoricalTransfer) ID() (types.Hash, error) {
	encoded, err := transfer.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(custodyHistoricalTransferIDDomain, encoded), nil
}

// PrepareCustodyHistoricalTransfer selects exactly one replica-committed next
// entry that matches the auditor's retained pending intent and complete prefix.
// No current clock is used: this is historical evidence, never a live proof.
// Even harmless-looking unknown/temp/orphan evidence blocks this first transfer
// format. Larger gaps and missing historical artifacts require separate review.
func PrepareCustodyHistoricalTransfer(auditorPath, replicaPath string, auditorID, replicaID types.Hash,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) (CustodyHistoricalTransfer, error) {
	if auditorID.IsZero() || replicaID.IsZero() || CustodyEvidencePathsOverlap(auditorPath, replicaPath) {
		return CustodyHistoricalTransfer{}, ErrCustodyHistoricalTransfer
	}
	release, err := lockCustodyPinBackups(auditorPath, replicaPath)
	if err != nil {
		return CustodyHistoricalTransfer{}, err
	}
	defer release()
	return prepareCustodyHistoricalTransferLocked(auditorPath, replicaPath, auditorID, replicaID, manifest, initial, policy)
}

func prepareCustodyHistoricalTransferLocked(auditorPath, replicaPath string, auditorID, replicaID types.Hash,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) (CustodyHistoricalTransfer, error) {
	evidence, err := loadCustodyReconciliationEvidenceLocked(auditorPath, replicaPath, auditorID, replicaID, manifest, initial, policy)
	if err != nil {
		return CustodyHistoricalTransfer{}, err
	}
	a, r := evidence.auditor, evidence.replica
	// Backup verification may retain an abandoned final-checkpoint temp link.
	// Preserve it, but do not export until that extra evidence has been reviewed.
	for path, count := range map[string]int{auditorPath: 4, replicaPath: 3} {
		directory, err := os.Open(path)
		if err != nil {
			return CustodyHistoricalTransfer{}, err
		}
		entries, readErr := directory.ReadDir(6)
		_ = directory.Close()
		if len(entries) != count || (readErr != nil && !errors.Is(readErr, io.EOF)) {
			return CustodyHistoricalTransfer{}, ErrCustodyHistoricalTransfer
		}
	}
	if a.Sequence >= MaximumCustodyJournalPaths || r.Sequence != a.Sequence+1 {
		return CustodyHistoricalTransfer{}, ErrCustodyHistoricalTransfer
	}
	entry, err := evidence.r.entry(r.Sequence)
	if err != nil {
		return CustodyHistoricalTransfer{}, err
	}
	// Reuse the same evidence classification at the historical signed response
	// time. Its age fields are deliberately neither exported nor used as a
	// present-time freshness assertion or transfer eligibility condition.
	report, err := evidence.inspect(auditorPath, replicaPath, manifest, initial, policy, entry.Record.Proof.RespondedAt)
	if err != nil {
		return CustodyHistoricalTransfer{}, err
	}
	if report.Relation != "replica-ahead" || report.CommonSequence != a.Sequence ||
		report.Pending.State != "historical-response" ||
		(report.Pending.RecordSource != "replica-slot" && report.Pending.RecordSource != "both") ||
		report.MissingCommittedArtifacts != 0 || report.ConflictingArtifacts != 0 || report.UnclassifiedArtifacts != 0 ||
		report.AuditorOrphanBodies != 0 || report.ReplicaOrphanBodies != 0 || report.AuditorPendingFiles != 0 || report.ReplicaPendingFiles != 0 {
		return CustodyHistoricalTransfer{}, ErrCustodyHistoricalTransfer
	}
	transfer := CustodyHistoricalTransfer{Version: CustodyHistoricalTransferVersion0, AuditorCheckpoint: a, ReplicaCheckpoint: r, Entry: entry}
	return transfer, transfer.validate()
}
