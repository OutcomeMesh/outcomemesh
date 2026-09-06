package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func runWorkArchiveCustodyReconcile(arguments []string) error {
	flags := flag.NewFlagSet("work-archive-custody-reconcile", flag.ContinueOnError)
	auditorPath := flags.String("auditor-backup", "", "immutable auditor backup including the full artifact tree")
	replicaPath := flags.String("replica-backup", "", "immutable replica-only backup")
	auditorIDText := flags.String("auditor-checkpoint-id", "", "auditor checkpoint ID retained independently of the candidate backup")
	replicaIDText := flags.String("replica-checkpoint-id", "", "replica checkpoint ID retained independently of the candidate backup")
	manifestPath := flags.String("manifest", "", "trusted canonical manifest file")
	receiptPath := flags.String("receipt", "", "trusted immutable initial receipt file shared by both journals")
	auditorText := flags.String("auditor-public-key", "", "trusted custody auditor public key")
	at := flags.Uint64("at", unixNow(), "assessment Unix seconds; defaults to the local clock, not a time attestation")
	policyFlags := addArchiveCustodyPolicyFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *auditorPath == "" || *replicaPath == "" || *manifestPath == "" || *receiptPath == "" || *auditorText == "" || *at == 0 {
		return errors.New("auditor/replica backups, independent checkpoint IDs, manifest, initial receipt, auditor public key, and nonzero assessment time are required")
	}
	auditorID, err := parseHash(*auditorIDText)
	if err != nil || auditorID.IsZero() {
		return errors.New("auditor-checkpoint-id must be a nonzero independently retained ID")
	}
	replicaID, err := parseHash(*replicaIDText)
	if err != nil || replicaID.IsZero() {
		return errors.New("replica-checkpoint-id must be a nonzero independently retained ID")
	}
	if err := policyFlags.validate(); err != nil {
		return err
	}
	auditorKey, err := parseArchivePublicKey(*auditorText)
	if err != nil {
		return err
	}
	manifest, err := loadArchiveManifest(*manifestPath)
	if err != nil {
		return err
	}
	receipt, err := loadArchiveReplicaReceipt(*receiptPath)
	if err != nil {
		return err
	}
	report, err := workarchive.InspectCustodyReconciliation(*auditorPath, *replicaPath, auditorID, replicaID, manifest, receipt, policyFlags.policy(auditorKey), *at)
	if err != nil {
		return err
	}
	// Successful inspection is not successful recovery. No writer or service
	// consumes this advisory output; every report explicitly denies auto-resume.
	_, err = fmt.Printf("work_archive_custody_reconciliation assessed_at=%d auditor_checkpoint=%s replica_checkpoint=%s header=%s relation=%s common_sequence=%d first_divergence=%d auditor_sequence=%d replica_sequence=%d automatic_resume=false availability_attested=false\n"+
		"work_archive_custody_reconciliation_freshness auditor_responded_at=%d replica_responded_at=%d auditor_proof_within_age=%t replica_proof_within_age=%t auditor_retain_until=%d replica_retain_until=%d auditor_receipt_unexpired=%t replica_receipt_unexpired=%t clock_before_evidence=%t\n"+
		"work_archive_custody_reconciliation_pending sequence=%d challenge=%s state=%s source=%s expires_at=%d responded_at=%d retain_until=%d proof_within_age=%t receipt_unexpired=%t\n"+
		"work_archive_custody_reconciliation_review next_step=%s missing_committed_artifacts=%d conflicting_artifacts=%d unclassified_artifacts=%d auditor_orphan_bodies=%d replica_orphan_bodies=%d auditor_pending_files=%d replica_pending_files=%d\n",
		report.AssessedAt, report.AuditorCheckpointID, report.ReplicaCheckpointID, report.HeaderID, report.Relation, report.CommonSequence, report.FirstDivergence, report.AuditorSequence, report.ReplicaSequence,
		report.AuditorRespondedAt, report.ReplicaRespondedAt, report.AuditorProofWithinAge, report.ReplicaProofWithinAge, report.AuditorRetainUntil, report.ReplicaRetainUntil, report.AuditorReceiptUnexpired, report.ReplicaReceiptUnexpired, report.ClockBeforeEvidence,
		report.Pending.Sequence, report.Pending.ChallengeID, report.Pending.State, report.Pending.RecordSource, report.Pending.ExpiresAt, report.Pending.RespondedAt, report.Pending.RetainUntil, report.Pending.ProofWithinAge, report.Pending.ReceiptUnexpired,
		report.NextStep, report.MissingCommittedArtifacts, report.ConflictingArtifacts, report.UnclassifiedArtifacts, report.AuditorOrphanBodies, report.ReplicaOrphanBodies, report.AuditorPendingFiles, report.ReplicaPendingFiles)
	return err
}
