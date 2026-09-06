package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func runWorkArchiveCustodyCheckpoint(arguments []string, verify bool) error {
	name := "work-archive-custody-checkpoint"
	if verify {
		name = "work-archive-custody-verify-checkpoint"
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	journalPath := flags.String("journal", "", "existing custody journal; never initialized or repaired")
	artifactsPath := flags.String("artifacts", "", "auditor cycle directory, including unfinished challenges")
	replicaOnly := flags.Bool("replica-only", false, "explicitly checkpoint a replica without auditor artifacts")
	manifestPath := flags.String("manifest", "", "trusted canonical archive manifest file")
	receiptPath := flags.String("receipt", "", "trusted immutable initial receipt file")
	auditorText := flags.String("auditor-public-key", "", "trusted custody auditor Ed25519 public key")
	checkpointPath := flags.String("checkpoint", "", "checkpoint file outside both evidence directories (no-replace output for capture)")
	var expectedText *string
	if verify {
		expectedText = flags.String("expected-id", "", "checkpoint ID retained independently of the backup; required")
	}
	policyFlags := addArchiveCustodyPolicyFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *journalPath == "" || *manifestPath == "" || *receiptPath == "" ||
		*auditorText == "" || *checkpointPath == "" || (*artifactsPath == "") != *replicaOnly {
		return errors.New("journal, manifest, initial receipt, auditor public key, checkpoint, and exactly one of artifacts or replica-only are required")
	}
	if workarchive.CustodyEvidencePathsOverlap(*journalPath, *checkpointPath) ||
		(*artifactsPath != "" && (workarchive.CustodyEvidencePathsOverlap(*artifactsPath, *checkpointPath) ||
			workarchive.CustodyEvidencePathsOverlap(*journalPath, *artifactsPath))) {
		return errors.New("custody checkpoint, journal, and artifacts must have separate paths")
	}
	if err := policyFlags.validate(); err != nil {
		return err
	}
	var expectedID types.Hash
	var checkpoint workarchive.CustodyCheckpoint
	if verify {
		var err error
		expectedID, err = parseHash(*expectedText)
		if err != nil || expectedID.IsZero() {
			return errors.New("a nonzero independently retained expected-id is required")
		}
		encoded, err := readRegularArtifact(*checkpointPath, workarchive.MaximumCustodyCheckpointBytes)
		if err != nil {
			return err
		}
		checkpoint, err = workarchive.DecodeCustodyCheckpoint(encoded)
		if err != nil {
			return err
		}
		id, err := checkpoint.ID()
		if err != nil || id != expectedID {
			return workarchive.ErrCustodyCheckpointMismatch
		}
	}
	auditor, err := parseArchivePublicKey(*auditorText)
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
	policy := policyFlags.policy(auditor)
	if verify {
		if err := workarchive.VerifyCustodyCheckpoint(checkpoint, expectedID, *journalPath, *artifactsPath, manifest, receipt, policy); err != nil {
			return err
		}
	} else {
		checkpoint, err = workarchive.CaptureCustodyCheckpoint(*journalPath, *artifactsPath, manifest, receipt, policy)
		if err != nil {
			return err
		}
		encoded, err := checkpoint.CanonicalBytes()
		if err != nil {
			return err
		}
		if err := publishImmutableArtifact(*checkpointPath, encoded); err != nil {
			return err
		}
	}
	id, _ := checkpoint.ID()
	_, err = fmt.Printf("work_archive_custody_checkpoint id=%s sequence=%d head=%s receipt=%s journal_bytes=%d journal_paths=%d artifact_bytes=%d artifact_paths=%d replica_only=%t verified=%t checkpoint=%s\n",
		id, checkpoint.Sequence, checkpoint.HeadEntryID, checkpoint.ReceiptID,
		checkpoint.Journal.Bytes, checkpoint.Journal.Paths, checkpoint.Artifacts.Bytes, checkpoint.Artifacts.Paths,
		*replicaOnly, verify, *checkpointPath)
	return err
}
