package workarchive

import (
	"errors"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
)

var ErrCustodyReconciliation = errors.New("invalid custody reconciliation evidence")

// CustodyReconciliationReport describes two exact historical snapshots at a
// caller-supplied time. It is not a freshness attestation, recovery permission,
// or new baseline. Neither participant's files or pin authority are changed.
type CustodyReconciliationReport struct {
	AuditorRespondedAt, ReplicaRespondedAt                                 uint64
	AuditorProofWithinAge, ReplicaProofWithinAge                           bool
	AssessedAt                                                             uint64
	AuditorCheckpointID, ReplicaCheckpointID, HeaderID                     types.Hash
	AuditorSequence, ReplicaSequence, CommonSequence, FirstDivergence      uint64
	Relation                                                               string // aligned, auditor-ahead, replica-ahead, or diverged
	AuditorRetainUntil, ReplicaRetainUntil                                 uint64
	AuditorReceiptUnexpired, ReplicaReceiptUnexpired                       bool
	ClockBeforeEvidence                                                    bool
	Pending                                                                CustodyReconciliationPending
	MissingCommittedArtifacts, ConflictingArtifacts, UnclassifiedArtifacts uint64
	AuditorOrphanBodies, ReplicaOrphanBodies                               uint64
	AuditorPendingFiles, ReplicaPendingFiles                               uint64
	NextStep                                                               string // advisory review only; never consumed by a writer
	AutomaticResumeAllowed                                                 bool   // always false
}

type CustodyReconciliationPending struct {
	Sequence                            uint64
	ChallengeID                         types.Hash
	State                               string // none, unanswered-open, unanswered-expired, future-request, historical-response, or conflict
	RecordSource                        string // none, auditor-artifact, replica-slot, or both
	ExpiresAt, RespondedAt, RetainUntil uint64
	ProofWithinAge, ReceiptUnexpired    bool
}

// InspectCustodyReconciliation verifies independently pinned, immutable backup
// bundles, then compares their committed spines and the auditor's intent. The
// auditor must have its artifact tree; the replica must be replica-only. Pins
// select historical copies, not necessarily the latest decisions. Missing trust,
// malformed evidence, and scope changes fail closed. Valid conflicting evidence
// is reported without selecting a winner, even if one chain is longer.
func InspectCustodyReconciliation(auditorPath, replicaPath string, auditorID, replicaID types.Hash,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy, at uint64,
) (CustodyReconciliationReport, error) {
	if at == 0 || auditorID.IsZero() || replicaID.IsZero() || CustodyEvidencePathsOverlap(auditorPath, replicaPath) {
		return CustodyReconciliationReport{}, ErrCustodyReconciliation
	}
	// The same ordered bundle locks used for pin promotion span verification and
	// analysis. Never use retained bundles as live journals or mutate them out of band.
	release, err := lockCustodyPinBackups(auditorPath, replicaPath)
	if err != nil {
		return CustodyReconciliationReport{}, errors.Join(ErrCustodyReconciliation, err)
	}
	defer release()
	auditor, err := verifyCustodyBackupLocked(auditorPath, auditorID, manifest, initial, policy)
	if err != nil {
		return CustodyReconciliationReport{}, errors.Join(ErrCustodyReconciliation, err)
	}
	replica, err := verifyCustodyBackupLocked(replicaPath, replicaID, manifest, initial, policy)
	if err != nil {
		return CustodyReconciliationReport{}, errors.Join(ErrCustodyReconciliation, err)
	}
	if auditor.Artifacts.ID.IsZero() || !replica.Artifacts.ID.IsZero() || auditor.HeaderID != replica.HeaderID {
		return CustodyReconciliationReport{}, ErrCustodyReconciliation
	}
	a, err := indexCustodyReconciliationJournal(filepath.Join(auditorPath, custodyBackupJournalName), auditor)
	if err != nil {
		return CustodyReconciliationReport{}, err
	}
	r, err := indexCustodyReconciliationJournal(filepath.Join(replicaPath, custodyBackupJournalName), replica)
	if err != nil {
		return CustodyReconciliationReport{}, err
	}
	report := CustodyReconciliationReport{
		AssessedAt: at, AuditorCheckpointID: auditorID, ReplicaCheckpointID: replicaID, HeaderID: auditor.HeaderID,
		AuditorSequence: auditor.Sequence, ReplicaSequence: replica.Sequence, Relation: "aligned",
		AuditorOrphanBodies: uint64(len(a.bodies) - len(a.slots)), ReplicaOrphanBodies: uint64(len(r.bodies) - len(r.slots)),
		Pending: CustodyReconciliationPending{Sequence: auditor.Sequence + 1, State: "none", RecordSource: "none"},
	}
	for index := 0; index < min(len(a.slots), len(r.slots)); index++ {
		if a.slots[index].EntryID != r.slots[index].EntryID {
			report.Relation, report.FirstDivergence = "diverged", uint64(index)+1
			break
		}
		report.CommonSequence++
	}
	if report.Relation != "diverged" {
		if auditor.Sequence > replica.Sequence {
			report.Relation = "auditor-ahead"
		}
		if replica.Sequence > auditor.Sequence {
			report.Relation = "replica-ahead"
		}
	}
	aReceipt, aRespondedAt, err := a.tip(initial)
	if err != nil {
		return CustodyReconciliationReport{}, err
	}
	rReceipt, rRespondedAt, err := r.tip(initial)
	if err != nil {
		return CustodyReconciliationReport{}, err
	}
	report.AuditorRetainUntil, report.ReplicaRetainUntil = aReceipt.RetainUntil, rReceipt.RetainUntil
	report.AuditorRespondedAt, report.ReplicaRespondedAt = aRespondedAt, rRespondedAt
	report.AuditorProofWithinAge = aRespondedAt != 0 && at >= aRespondedAt && at-aRespondedAt <= policy.MaximumProofAge
	report.ReplicaProofWithinAge = rRespondedAt != 0 && at >= rRespondedAt && at-rRespondedAt <= policy.MaximumProofAge
	report.AuditorReceiptUnexpired = at >= aReceipt.StoredAt && at < aReceipt.RetainUntil
	report.ReplicaReceiptUnexpired = at >= rReceipt.StoredAt && at < rReceipt.RetainUntil
	report.ClockBeforeEvidence = at < aReceipt.StoredAt || at < rReceipt.StoredAt
	for _, item := range []struct {
		root  string
		count *uint64
	}{
		{filepath.Join(auditorPath, custodyBackupJournalName, custodyJournalPendingName), &report.AuditorPendingFiles},
		{filepath.Join(replicaPath, custodyBackupJournalName, custodyJournalPendingName), &report.ReplicaPendingFiles},
	} {
		if err := visitCustodyReconciliationDirectory(item.root, item.count, func(string, bool) error { return nil }); err != nil {
			return CustodyReconciliationReport{}, err
		}
	}
	pending, err := inspectCustodyReconciliationArtifacts(filepath.Join(auditorPath, custodyBackupArtifactsName), a, &report)
	if err != nil {
		return CustodyReconciliationReport{}, err
	}
	var peerRecord *CustodyRecord
	if report.Relation == "replica-ahead" {
		entry, err := r.entry(auditor.Sequence + 1)
		if err != nil {
			return CustodyReconciliationReport{}, err
		}
		peerRecord = &entry.Record
	}
	if err := inspectCustodyReconciliationPending(pending, peerRecord, manifest, aReceipt, policy, &report); err != nil {
		return CustodyReconciliationReport{}, err
	}
	report.NextStep = custodyReconciliationNextStep(report)
	return report, nil
}

// Payloads stay on disk. The checkpoint verifier has already bounded all paths
// and verified every slot/body. Index once to avoid rescanning every segment
// for every historical cycle, and recheck each loaded body against its ID.
type custodyReconciliationJournal struct {
	slots  []custodyJournalSlot
	bodies map[types.Hash][]string
}

func indexCustodyReconciliationJournal(path string, checkpoint CustodyCheckpoint) (custodyReconciliationJournal, error) {
	journal := &CustodyJournal{path: path}
	bodies, err := journal.scanBodyPaths()
	if err != nil {
		return custodyReconciliationJournal{}, err
	}
	slots, err := journal.scanSlots()
	if err != nil {
		return custodyReconciliationJournal{}, err
	}
	if uint64(len(slots)) != checkpoint.Sequence || len(bodies) < len(slots) ||
		(len(slots) != 0 && slots[len(slots)-1].EntryID != checkpoint.HeadEntryID) {
		return custodyReconciliationJournal{}, ErrCustodyReconciliation
	}
	return custodyReconciliationJournal{slots: slots, bodies: bodies}, nil
}

func (journal custodyReconciliationJournal) entry(sequence uint64) (CustodyJournalEntry, error) {
	if sequence == 0 || sequence > uint64(len(journal.slots)) {
		return CustodyJournalEntry{}, ErrCustodyReconciliation
	}
	slot := journal.slots[sequence-1]
	if slot.Sequence != sequence {
		return CustodyJournalEntry{}, ErrCustodyReconciliation
	}
	encoded, err := loadCustodyJournalBodyPaths(slot.EntryID, journal.bodies[slot.EntryID])
	if err != nil {
		return CustodyJournalEntry{}, err
	}
	entry, err := DecodeCustodyJournalEntry(encoded)
	if err != nil || entry.Sequence != sequence {
		return CustodyJournalEntry{}, errors.Join(ErrCustodyReconciliation, err)
	}
	return entry, nil
}

func (journal custodyReconciliationJournal) tip(initial ReplicaReceipt) (ReplicaReceipt, uint64, error) {
	if len(journal.slots) == 0 {
		return initial, 0, nil
	}
	entry, err := journal.entry(uint64(len(journal.slots)))
	return entry.Record.RenewedReceipt, entry.Record.Proof.RespondedAt, err
}

func custodyReconciliationNextStep(report CustodyReconciliationReport) string {
	switch {
	case report.Relation == "diverged":
		return "review-divergent-history"
	case report.ConflictingArtifacts != 0 || report.Pending.State == "conflict":
		return "review-conflicting-evidence"
	case report.ClockBeforeEvidence:
		return "review-clock"
	case report.UnclassifiedArtifacts != 0 || report.AuditorOrphanBodies != 0 || report.ReplicaOrphanBodies != 0 || report.AuditorPendingFiles != 0 || report.ReplicaPendingFiles != 0:
		return "review-retained-evidence"
	case report.MissingCommittedArtifacts != 0:
		return "review-missing-artifacts"
	case report.Pending.State == "historical-response":
		return "review-historical-response"
	case report.Relation != "aligned":
		return "review-participant-prefix"
	case report.Pending.State == "unanswered-expired" || !report.AuditorReceiptUnexpired:
		return "review-rebaseline"
	case report.Pending.State == "unanswered-open":
		return "review-exact-retry"
	default:
		return "review-next-cycle"
	}
}
