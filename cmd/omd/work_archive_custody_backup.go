package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func runWorkArchiveCustodyBackup(arguments []string, verify bool) error {
	name := "work-archive-custody-backup"
	if verify {
		name = "work-archive-custody-verify-backup"
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	destination := flags.String("backup", "", "backup bundle directory; creation requires a new destination or an identical completed backup")
	manifestPath := flags.String("manifest", "", "trusted canonical archive manifest file")
	receiptPath := flags.String("receipt", "", "trusted immutable initial replica receipt file")
	auditorText := flags.String("auditor-public-key", "", "trusted custody auditor Ed25519 public key")
	var journalPath, artifactsPath, expectedText string
	var replicaOnly bool
	if verify {
		flags.StringVar(&expectedText, "expected-id", "", "nonzero checkpoint ID retained independently of this backup; required")
	} else {
		flags.StringVar(&journalPath, "journal", "", "existing source journal, including its permanent lock")
		flags.StringVar(&artifactsPath, "artifacts", "", "source auditor cycle directory, including custody.lock and pending artifacts")
		flags.BoolVar(&replicaOnly, "replica-only", false, "explicitly back up a replica without an auditor artifact tree")
	}
	policyFlags := addArchiveCustodyPolicyFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *destination == "" || *manifestPath == "" || *receiptPath == "" || *auditorText == "" {
		return errors.New("backup, manifest, initial receipt, and auditor public key are required")
	}
	if !verify && (journalPath == "" || (artifactsPath == "") != replicaOnly) {
		return errors.New("journal and exactly one of artifacts or replica-only are required")
	}
	var expectedID types.Hash
	if verify {
		var err error
		expectedID, err = parseHash(expectedText)
		if err != nil || expectedID.IsZero() {
			return errors.New("a nonzero independently retained expected-id is required")
		}
	}
	if err := policyFlags.validate(); err != nil {
		return err
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
	var checkpoint workarchive.CustodyCheckpoint
	var created bool
	if verify {
		checkpoint, err = workarchive.VerifyCustodyBackup(*destination, expectedID, manifest, receipt, policy)
	} else {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		checkpoint, created, err = workarchive.CreateCustodyBackup(ctx, *destination, journalPath, artifactsPath, manifest, receipt, policy)
	}
	if err != nil {
		return err
	}
	id, _ := checkpoint.ID()
	_, err = fmt.Printf("work_archive_custody_backup id=%s sequence=%d head=%s journal_bytes=%d journal_paths=%d artifact_bytes=%d artifact_paths=%d replica_only=%t created=%t verified=true backup=%s\n",
		id, checkpoint.Sequence, checkpoint.HeadEntryID, checkpoint.Journal.Bytes, checkpoint.Journal.Paths,
		checkpoint.Artifacts.Bytes, checkpoint.Artifacts.Paths, checkpoint.Artifacts == (workarchive.CustodyCheckpointTree{}), created, *destination)
	return err
}
