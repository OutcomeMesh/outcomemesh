package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func runWorkArchiveCustodyPin(arguments []string, action string) error {
	flags := flag.NewFlagSet("work-archive-custody-"+action, flag.ContinueOnError)
	pinsPath := flags.String("pins", "", "independently managed pin journal, outside live evidence and backup roots")
	if action == "pin-head" {
		if err := flags.Parse(arguments); err != nil {
			return err
		}
		if *pinsPath == "" || flags.NArg() != 0 {
			return errors.New("pins is required")
		}
		head, err := workarchive.ReadCustodyBackupPinHead(*pinsPath)
		if err != nil {
			return err
		}
		return printCustodyBackupPin(head, false, false)
	}
	backupPath := flags.String("backup", "", "completed custody backup to pin or verify")
	manifestPath := flags.String("manifest", "", "trusted canonical manifest file")
	receiptPath := flags.String("receipt", "", "trusted immutable initial receipt file")
	auditorText := flags.String("auditor-public-key", "", "trusted custody auditor public key")
	expectedText := flags.String("expected-pin", "", "previous pin ID for updates; optional for verification trusting the current independent store")
	var checkpointText, previousBackup string
	var initial bool
	if action == "pin-backup" {
		flags.StringVar(&checkpointText, "checkpoint-id", "", "checkpoint ID from the authoritative backup operation; required")
		flags.StringVar(&previousBackup, "previous-backup", "", "previous pinned bundle; required for a new pin after initialization")
		flags.BoolVar(&initial, "initial", false, "explicitly authorize the first pin in a new journal")
	} else if action != "verify-pinned-backup" {
		return errors.New("unknown custody pin action")
	}
	policyFlags := addArchiveCustodyPolicyFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *pinsPath == "" || *backupPath == "" || *manifestPath == "" || *receiptPath == "" || *auditorText == "" {
		return errors.New("pins, backup, manifest, initial receipt, and auditor public key are required")
	}
	if action == "pin-backup" && ((initial && (*expectedText != "" || previousBackup != "")) || (!initial && *expectedText == "")) {
		return errors.New("choose initial for the first pin, or supply a nonzero expected-pin for an update")
	}
	var expectedPin, checkpointID types.Hash
	if *expectedText != "" {
		var err error
		expectedPin, err = parseHash(*expectedText)
		if err != nil || expectedPin.IsZero() {
			return errors.New("expected-pin must be a nonzero pin ID")
		}
	}
	if action == "pin-backup" {
		var err error
		checkpointID, err = parseHash(checkpointText)
		if err != nil || checkpointID.IsZero() {
			return errors.New("checkpoint-id must be a nonzero authoritative checkpoint ID")
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
	var pin workarchive.CustodyBackupPin
	var created bool
	if action == "pin-backup" {
		pin, created, err = workarchive.PinCustodyBackup(*pinsPath, *backupPath, previousBackup, expectedPin, checkpointID, manifest, receipt, policyFlags.policy(auditor))
	} else {
		pin, err = workarchive.VerifyPinnedCustodyBackup(*pinsPath, *backupPath, expectedPin, manifest, receipt, policyFlags.policy(auditor))
	}
	if err != nil {
		return err
	}
	return printCustodyBackupPin(pin, created, true)
}

func printCustodyBackupPin(pin workarchive.CustodyBackupPin, created, verified bool) error {
	id, _ := pin.ID()
	checkpointID, _ := pin.Checkpoint.ID()
	_, err := fmt.Printf("work_archive_custody_pin pin_id=%s pin_sequence=%d previous_pin=%s checkpoint_id=%s custody_sequence=%d head=%s replica_only=%t created=%t verified=%t\n",
		id, pin.Sequence, pin.PreviousPinID, checkpointID, pin.Checkpoint.Sequence, pin.Checkpoint.HeadEntryID,
		pin.Checkpoint.Artifacts == (workarchive.CustodyCheckpointTree{}), created, verified)
	return err
}
