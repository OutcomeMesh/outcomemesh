package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func runWorkArchiveCustodyRebaseline(arguments []string) error {
	flags := flag.NewFlagSet("work-archive-custody-rebaseline", flag.ContinueOnError)
	mode := flags.String("mode", "verify", "create/verify a proposal, or retire-local/verify-local-retirement; no activation")
	proposalPath := flags.String("proposal", "", "separate immutable proposal file; create never replaces it")
	expectedText := flags.String("expected-id", "", "independently reviewed proposal ID; required only for verify")
	evidence := workarchive.CustodyRebaselineEvidence{}
	flags.StringVar(&evidence.Recovery, "recovery", "", "complete historical-only reconstruction")
	flags.StringVar(&evidence.TransferPackage, "package", "", "original historical handoff package")
	flags.StringVar(&evidence.AuditorBackup, "auditor-backup", "", "original immutable auditor backup")
	flags.StringVar(&evidence.ReplicaBackup, "replica-backup", "", "original immutable replica backup")
	applicationText := flags.String("application-id", "", "independently retained application ID")
	transferText := flags.String("transfer-id", "", "independently retained handoff ID")
	auditorIDText := flags.String("auditor-checkpoint-id", "", "independently retained auditor checkpoint ID")
	replicaIDText := flags.String("replica-checkpoint-id", "", "independently retained replica checkpoint ID")
	archivePath := flags.String("archive", "", "immutable complete archive to replay; not a sampled object batch")
	archiveFlags := addArchiveVerificationFlags(flags)
	receiptPath := flags.String("receipt", "", "trusted original initial receipt")
	auditorText := flags.String("auditor-public-key", "", "trusted original custody auditor public key")
	policyFlags := addArchiveCustodyPolicyFlags(flags)
	nextAuditorText := flags.String("next-auditor-public-key", "", "independently selected new auditor; same custody timing policy")
	nextReplicaText := flags.String("next-replica-public-key", "", "independently selected new replica public key")
	nextKeyPath := flags.String("next-replica-key", "", "new replica seed file; create only")
	locationText := flags.String("location-id", "", "independently selected next replica location commitment")
	lifetime := flags.Uint64("review-lifetime-seconds", 300, "create only: signed review window, at most 600 seconds")
	retainUntil := flags.Uint64("retain-until", 0, "create only: proposed UTC Unix retention deadline; must extend the old receipt")
	local := workarchive.CustodyLocalParticipants{}
	flags.StringVar(&local.AuditorJournal, "auditor-journal", "", "retirement only: exact local old auditor journal to disable permanently")
	flags.StringVar(&local.AuditorArtifacts, "auditor-artifacts", "", "retirement only: old auditor's complete artifact directory")
	flags.StringVar(&local.ReplicaJournal, "replica-journal", "", "retirement only: exact local old replica journal to disable permanently")
	retirementText := flags.String("retirement-id", "", "independently retained local retirement pair ID; verify-local-retirement only")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *proposalPath == "" || *archivePath == "" || *receiptPath == "" ||
		*auditorText == "" || *nextAuditorText == "" || *nextReplicaText == "" || *locationText == "" ||
		evidence.Recovery == "" || evidence.TransferPackage == "" || evidence.AuditorBackup == "" || evidence.ReplicaBackup == "" {
		return errors.New("proposal, archive, complete recovery evidence, independent IDs, receipt, and old/new public assignments are required")
	}
	localMode := *mode == "retire-local" || *mode == "verify-local-retirement"
	localOptions := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "auditor-journal" || f.Name == "auditor-artifacts" || f.Name == "replica-journal" || f.Name == "retirement-id" {
			localOptions = true
		}
	})
	if !localMode && localOptions {
		return errors.New("local participant paths and retirement-id require an explicit local retirement mode")
	}
	if localMode && (local.AuditorJournal == "" || local.AuditorArtifacts == "" || local.ReplicaJournal == "" ||
		(*mode == "retire-local" && *retirementText != "") || (*mode == "verify-local-retirement" && *retirementText == "")) {
		return errors.New("local retirement requires both journal paths and auditor artifacts; retirement-id is required only for verification")
	}
	switch *mode {
	case "create":
		if *expectedText != "" || *nextKeyPath == "" || *retainUntil == 0 || *lifetime == 0 || *lifetime > workarchive.MaximumCustodyRebaselineReviewLifetime {
			return errors.New("create requires next-replica-key, retain-until, and a 1..600-second review window; expected-id is verify-only")
		}
		if _, err := os.Lstat(*proposalPath); err == nil {
			return errors.New("proposal already exists; retain it and verify its independent ID, or explicitly choose a new path")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	case "verify", "retire-local", "verify-local-retirement":
		createOnly := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "next-replica-key" || f.Name == "retain-until" || f.Name == "review-lifetime-seconds" {
				createOnly = true
			}
		})
		if *expectedText == "" || createOnly {
			return errors.New("review/retirement requires expected-id and accepts no private key or new time/term options")
		}
	default:
		return errors.New("mode must be create, verify, retire-local, or verify-local-retirement; activation and cross-host fencing are unsupported")
	}
	// No proposal or temporary output may land inside an evidence, archive, or
	// node-data tree, or replace one of the explicitly supplied input files.
	for _, source := range []string{evidence.Recovery, evidence.TransferPackage, evidence.AuditorBackup, evidence.ReplicaBackup,
		*archivePath, *archiveFlags.data, *archiveFlags.manifest, *archiveFlags.checkpoint, *receiptPath, *nextKeyPath} {
		if source != "" && workarchive.CustodyEvidencePathsOverlap(*proposalPath, source) {
			return errors.New("proposal must be separate from every input and node-data directory")
		}
	}
	if localMode {
		for _, target := range []string{local.AuditorJournal, local.AuditorArtifacts, local.ReplicaJournal} {
			for _, input := range []string{*proposalPath, *archiveFlags.data, *archiveFlags.manifest, *archiveFlags.checkpoint, *receiptPath} {
				if input != "" && workarchive.CustodyEvidencePathsOverlap(target, input) {
					return errors.New("local retirement targets must be separate from proposal, trust files and node data")
				}
			}
		}
	}
	var expectedID types.Hash
	var retirementID types.Hash
	for _, item := range []struct {
		text string
		out  *types.Hash
	}{
		{*applicationText, &evidence.ApplicationID}, {*transferText, &evidence.TransferID},
		{*auditorIDText, &evidence.AuditorCheckpointID}, {*replicaIDText, &evidence.ReplicaCheckpointID},
	} {
		id, err := parseHash(item.text)
		if err != nil || id.IsZero() {
			return errors.New("all evidence IDs must be independently retained nonzero hashes")
		}
		*item.out = id
	}
	if *mode != "create" {
		var err error
		expectedID, err = parseHash(*expectedText)
		if err != nil || expectedID.IsZero() {
			return errors.New("expected-id must be independently retained and nonzero")
		}
	}
	if *mode == "verify-local-retirement" {
		var err error
		retirementID, err = parseHash(*retirementText)
		if err != nil || retirementID.IsZero() {
			return errors.New("retirement-id must be independently retained and nonzero")
		}
	}
	if err := policyFlags.validate(); err != nil {
		return err
	}
	oldAuditor, err := parseArchivePublicKey(*auditorText)
	if err != nil {
		return err
	}
	nextAuditor, err := parseArchivePublicKey(*nextAuditorText)
	if err != nil {
		return err
	}
	nextReplica, err := parseArchivePublicKey(*nextReplicaText)
	if err != nil {
		return err
	}
	locationID, err := parseHash(*locationText)
	if err != nil || locationID.IsZero() {
		return errors.New("location-id must be nonzero")
	}
	initial, err := loadArchiveReplicaReceipt(*receiptPath)
	if err != nil {
		return err
	}
	verification, err := archiveFlags.load()
	if err != nil {
		return err
	}
	archive := workarchive.CustodyRebaselineArchive{Directory: *archivePath, Checkpoint: verification.checkpoint,
		Policy: verification.policy, Base: verification.base, Parameters: verification.parameters, Limits: verification.limits}
	next := workarchive.CustodyRebaselineAssignment{Policy: policyFlags.policy(nextAuditor), ReplicaPublicKey: nextReplica, LocationID: locationID}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var proposal workarchive.CustodyRebaselineProposal
	if *mode == "create" {
		key, err := loadPrivateKey(*nextKeyPath)
		if err != nil {
			return err
		}
		proposal, err = workarchive.CreateCustodyRebaselineProposal(ctx, evidence, archive, verification.manifest, initial,
			policyFlags.policy(oldAuditor), next, key, *lifetime, *retainUntil)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := proposal.VerifyReviewWindow(uint64(time.Now().Unix())); err != nil {
			return err
		}
		encoded, _ := proposal.CanonicalBytes()
		// The shared bounded writer publishes one complete file with fsync and a
		// no-replace link. A lost reply never leads to silent timestamp renewal.
		if err := writeNewTieCommandFile(*proposalPath, encoded, workarchive.MaximumCustodyRebaselineProposalBytes,
			workarchive.ErrCustodyRebaseline, ".outcomemesh-custody-rebaseline-*"); err != nil {
			return err
		}
	} else {
		encoded, err := readRegularArtifact(*proposalPath, workarchive.MaximumCustodyRebaselineProposalBytes)
		if err != nil {
			return err
		}
		proposal, err = workarchive.DecodeCustodyRebaselineProposal(encoded)
		if err != nil {
			return err
		}
		if localMode {
			var pair workarchive.CustodyLocalRetirementPair
			var changed bool
			if *mode == "retire-local" {
				pair, changed, err = workarchive.RetireLocalCustodyParticipants(ctx, local, proposal, expectedID, evidence, archive,
					verification.manifest, initial, policyFlags.policy(oldAuditor), next)
			} else {
				pair, err = workarchive.VerifyLocalCustodyRetirement(ctx, local, retirementID, proposal, expectedID, evidence, archive,
					verification.manifest, initial, policyFlags.policy(oldAuditor), next)
			}
			if err != nil {
				return err
			}
			id, err := pair.ID()
			if err != nil {
				return err
			}
			_, err = fmt.Printf("work_archive_custody_retirement mode=%s id=%s proposal=%s decided_at=%d changed=%t local_pair_retired=true global_participants_fenced=false active_cutover=false availability_attested=false\n",
				*mode, id, expectedID, pair.Auditor.DecidedAt, changed)
			return err
		}
		if err := workarchive.VerifyCustodyRebaselineProposal(ctx, proposal, expectedID, evidence, archive, verification.manifest,
			initial, policyFlags.policy(oldAuditor), next); err != nil {
			return err
		}
	}
	if err := proposal.VerifyReviewWindow(uint64(time.Now().Unix())); err != nil {
		return err
	}
	id, _ := proposal.ID()
	_, err = fmt.Printf("work_archive_custody_rebaseline mode=%s id=%s application=%s previous_receipt=%s next_policy=%s replayed_at=%d review_until=%d retain_until=%d proposal_only=true archive_replayed=true automatic_resume=false participant_fenced=false availability_attested=false\n",
		*mode, id, proposal.ApplicationID, proposal.PreviousReceiptID, proposal.NextPolicyID, proposal.ReplayedAt, proposal.ReviewUntil, proposal.RetainUntil)
	return err
}
