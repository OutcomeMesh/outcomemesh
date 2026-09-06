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

func runWorkArchiveCustodyTransfer(arguments []string) error {
	flags := flag.NewFlagSet("work-archive-custody-transfer", flag.ContinueOnError)
	mode := flags.String("mode", "plan", "plan (read-only), export (new package), or verify (existing package)")
	destination := flags.String("package", "", "handoff directory outside both backups; required for export and verify")
	expectedText := flags.String("expected-id", "", "independently reviewed transfer ID; required for export and verify")
	auditorPath := flags.String("auditor-backup", "", "immutable auditor backup including its complete artifact tree")
	replicaPath := flags.String("replica-backup", "", "immutable replica-only backup")
	auditorIDText := flags.String("auditor-checkpoint-id", "", "independently retained auditor checkpoint ID")
	replicaIDText := flags.String("replica-checkpoint-id", "", "independently retained replica checkpoint ID")
	manifestPath := flags.String("manifest", "", "trusted canonical manifest file")
	receiptPath := flags.String("receipt", "", "trusted immutable initial receipt shared by both journals")
	auditorText := flags.String("auditor-public-key", "", "trusted custody auditor public key")
	policyFlags := addArchiveCustodyPolicyFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *auditorPath == "" || *replicaPath == "" || *manifestPath == "" || *receiptPath == "" || *auditorText == "" {
		return errors.New("both backups, independent checkpoint IDs, manifest, initial receipt, and auditor public key are required")
	}
	switch *mode {
	case "plan":
		if *destination != "" || *expectedText != "" {
			return errors.New("plan is read-only and does not accept package or expected-id")
		}
	case "export", "verify":
		if *destination == "" || *expectedText == "" {
			return errors.New("export and verify require package and independently reviewed expected-id")
		}
	default:
		return errors.New("mode must be plan, export, or verify; import and resume are not supported")
	}
	aID, err := parseHash(*auditorIDText)
	if err != nil || aID.IsZero() {
		return errors.New("auditor-checkpoint-id must be a nonzero independently retained ID")
	}
	rID, err := parseHash(*replicaIDText)
	if err != nil || rID.IsZero() {
		return errors.New("replica-checkpoint-id must be a nonzero independently retained ID")
	}
	var expectedID types.Hash
	if *mode != "plan" {
		expectedID, err = parseHash(*expectedText)
		if err != nil || expectedID.IsZero() {
			return errors.New("expected-id must be a nonzero independently reviewed transfer ID")
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
	var transfer workarchive.CustodyHistoricalTransfer
	var created bool
	switch *mode {
	case "plan":
		transfer, err = workarchive.PrepareCustodyHistoricalTransfer(*auditorPath, *replicaPath, aID, rID, manifest, receipt, policy)
	case "export":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		transfer, created, err = workarchive.CreateCustodyHistoricalTransferPackage(ctx, *destination, expectedID, *auditorPath, *replicaPath, aID, rID, manifest, receipt, policy)
	case "verify":
		transfer, err = workarchive.VerifyCustodyHistoricalTransferPackage(*destination, expectedID, *auditorPath, *replicaPath, aID, rID, manifest, receipt, policy)
	}
	if err != nil {
		return err
	}
	id, _ := transfer.ID()
	entryID, _ := transfer.Entry.ID()
	challengeID, _ := transfer.Entry.Record.Challenge.ID()
	_, err = fmt.Printf("work_archive_custody_transfer mode=%s id=%s auditor_checkpoint=%s replica_checkpoint=%s sequence=%d entry=%s challenge=%s responded_at=%d created=%t historical_only=true automatic_resume=false availability_attested=false\n",
		*mode, id, aID, rID, transfer.Entry.Sequence, entryID, challengeID, transfer.Entry.Record.Proof.RespondedAt, created)
	return err
}
