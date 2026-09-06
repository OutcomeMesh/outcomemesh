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

func runWorkArchiveCustodyApplyHistory(arguments []string) error {
	flags := flag.NewFlagSet("work-archive-custody-apply-history", flag.ContinueOnError)
	mode := flags.String("mode", "create", "create a new historical-only reconstruction, or verify an existing one")
	recovery := flags.String("recovery", "", "separate recovery directory; never a live journal or source directory")
	packagePath := flags.String("package", "", "verified historical handoff package")
	transferText := flags.String("transfer-id", "", "independently reviewed historical transfer ID")
	expectedText := flags.String("expected-id", "", "independently retained application ID; required only for verify")
	auditorPath := flags.String("auditor-backup", "", "original immutable auditor backup with artifacts")
	replicaPath := flags.String("replica-backup", "", "original immutable replica-only backup")
	auditorIDText := flags.String("auditor-checkpoint-id", "", "independently retained auditor checkpoint ID")
	replicaIDText := flags.String("replica-checkpoint-id", "", "independently retained replica checkpoint ID")
	manifestPath := flags.String("manifest", "", "trusted canonical manifest")
	receiptPath := flags.String("receipt", "", "trusted immutable initial receipt; never a new baseline")
	auditorText := flags.String("auditor-public-key", "", "trusted custody auditor public key")
	policyFlags := addArchiveCustodyPolicyFlags(flags)
	limitFlags := addArchiveCustodyJournalLimitFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *recovery == "" || *packagePath == "" || *auditorPath == "" || *replicaPath == "" || *manifestPath == "" || *receiptPath == "" || *auditorText == "" {
		return errors.New("recovery, package, both backups, independent IDs, manifest, initial receipt, and auditor public key are required")
	}
	switch *mode {
	case "create":
		if *expectedText != "" {
			return errors.New("create returns a new application ID; expected-id is only for verify")
		}
	case "verify":
		if *expectedText == "" {
			return errors.New("verify requires an independently retained expected-id")
		}
		explicitLimit := false
		flags.Visit(func(value *flag.Flag) {
			if value.Name == "journal-max-bytes" || value.Name == "journal-max-paths" {
				explicitLimit = true
			}
		})
		if explicitLimit {
			return errors.New("journal growth limits apply only to create")
		}
	default:
		return errors.New("mode must be create or verify; activate, resume, and rebaseline are unsupported")
	}
	parseRequired := func(value string) (types.Hash, error) {
		id, err := parseHash(value)
		if err != nil || id.IsZero() {
			return types.Hash{}, errors.New("all supplied IDs must be nonzero independently retained values")
		}
		return id, nil
	}
	aID, err := parseRequired(*auditorIDText)
	if err != nil {
		return err
	}
	rID, err := parseRequired(*replicaIDText)
	if err != nil {
		return err
	}
	transferID, err := parseRequired(*transferText)
	if err != nil {
		return err
	}
	var expectedID types.Hash
	if *mode == "verify" {
		expectedID, err = parseRequired(*expectedText)
		if err != nil {
			return err
		}
	}
	if err := policyFlags.validate(); err != nil {
		return err
	}
	if err := limitFlags.validate(flags, *recovery); err != nil {
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
	var application workarchive.CustodyHistoricalApplication
	var created bool
	if *mode == "verify" {
		application, err = workarchive.VerifyCustodyHistoricalApplication(*recovery, expectedID, *packagePath, transferID,
			*auditorPath, *replicaPath, aID, rID, manifest, receipt, policy)
	} else {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		application, created, err = workarchive.CreateCustodyHistoricalApplication(ctx, *recovery, *packagePath, transferID,
			*auditorPath, *replicaPath, aID, rID, manifest, receipt, policy, limitFlags.limits())
	}
	if err != nil {
		return err
	}
	id, _ := application.ID()
	checkpointID, _ := application.Result.ID()
	_, err = fmt.Printf("work_archive_custody_application mode=%s id=%s transfer=%s checkpoint=%s sequence=%d head=%s created=%t historical_only=true automatic_resume=false participant_fenced=false availability_attested=false\n",
		*mode, id, application.TransferID, checkpointID, application.Result.Sequence, application.Result.HeadEntryID, created)
	return err
}
