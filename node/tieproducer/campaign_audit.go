package tieproducer

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

var ErrCampaignAudit = errors.New("invalid controlled-tie campaign audit")

type CampaignAuditDisposition string

const (
	CampaignAuditHealthy     CampaignAuditDisposition = "healthy"
	CampaignAuditRecoverable CampaignAuditDisposition = "recoverable"
	CampaignAuditBlocked     CampaignAuditDisposition = "blocked"
)

type CampaignAuditObserver struct {
	ObserverPublicKey     [ed25519.PublicKeySize]byte
	ReceiptPath           string
	ConfirmationDirectory string
}

type CampaignAuditConfig struct {
	Plan                 calibration.TiePlan
	Binding              calibration.TiePlanBinding
	ExpectedPlanID       types.Hash
	StatePath            string
	ArtifactDirectory    string
	PublicationDirectory string
	Observers            []CampaignAuditObserver
}

type CampaignAuditIssue struct {
	Code              string
	Sequence          uint64
	ObserverPublicKey [ed25519.PublicKeySize]byte
	ReceiptTail       types.Hash
	Recoverable       bool
	Detail            string
}

type CampaignAuditObserverStatus struct {
	ObserverPublicKey [ed25519.PublicKeySize]byte
	ClosedSlots       uint64
	CompletedTrials   uint64
	NoPairSlots       uint64
	ConfirmedSlots    uint64
	LastReceiptID     types.Hash
}

type CampaignAuditReport struct {
	PlanID                  types.Hash
	StateVersion            uint16
	PlannedSlots            uint64
	NextSequence            uint64
	Phase                   CampaignPhase
	SkippedSequences        []uint64
	VerifiedSuccessfulSlots uint64
	VerifiedSkippedSlots    uint64
	PendingObservers        uint64
	RecoverableAcks         uint64
	Disposition             CampaignAuditDisposition
	CampaignComplete        bool
	Observers               []CampaignAuditObserverStatus
	Issues                  []CampaignAuditIssue
}

type campaignAuditArtifact struct {
	pair         Pair
	checkpoint   calibration.TiePairCheckpoint
	checkpointID types.Hash
	present      bool
	published    bool
}

// AuditCampaignFiles cross-checks coordinator and observer durable state
// without opening a mutable Campaign or TieCollector. Malformed signed inputs
// return an error; operational drift is classified in the report as either
// retryable or permanently blocking.
func AuditCampaignFiles(config CampaignAuditConfig) (CampaignAuditReport, error) {
	if config.StatePath == "" || config.ArtifactDirectory == "" ||
		config.PublicationDirectory == "" || config.ExpectedPlanID.IsZero() {
		return CampaignAuditReport{}, ErrCampaignAudit
	}
	if err := config.Plan.Verify(config.Binding); err != nil {
		return CampaignAuditReport{}, err
	}
	planID, err := config.Plan.ID()
	if err != nil {
		return CampaignAuditReport{}, err
	}
	if planID != config.ExpectedPlanID {
		return CampaignAuditReport{}, ErrCampaignAudit
	}
	expectedObservers := campaignObservers(config.Plan)
	if len(config.Observers) != len(expectedObservers) {
		return CampaignAuditReport{}, ErrCampaignAudit
	}
	for index, observer := range config.Observers {
		if observer.ObserverPublicKey != expectedObservers[index] || observer.ReceiptPath == "" ||
			observer.ConfirmationDirectory == "" {
			return CampaignAuditReport{}, ErrCampaignAudit
		}
	}
	status, err := LoadCampaignStatus(CampaignConfig{
		Plan: config.Plan, Binding: config.Binding, ExpectedPlanID: planID,
		StatePath: config.StatePath,
	})
	if err != nil {
		return CampaignAuditReport{}, err
	}
	report := CampaignAuditReport{
		PlanID: planID, StateVersion: status.StateVersion,
		PlannedSlots: status.PlannedSlots, NextSequence: status.NextSequence,
		Phase: status.Phase, SkippedSequences: append([]uint64(nil), status.SkippedSequences...),
		Disposition: CampaignAuditHealthy,
		Observers:   make([]CampaignAuditObserverStatus, len(config.Observers)),
	}
	addIssue := func(issue CampaignAuditIssue) {
		report.Issues = append(report.Issues, issue)
		if issue.Recoverable {
			if report.Disposition == CampaignAuditHealthy {
				report.Disposition = CampaignAuditRecoverable
			}
		} else {
			report.Disposition = CampaignAuditBlocked
		}
	}
	skipped := make(map[uint64]struct{}, len(status.SkippedSequences))
	for _, sequence := range status.SkippedSequences {
		skipped[sequence] = struct{}{}
	}

	artifacts := make([]campaignAuditArtifact, len(config.Plan.Slots)+1)
	store := &FileCampaignArtifacts{
		directory: config.ArtifactDirectory, plan: config.Plan,
		binding: config.Binding, planID: planID,
	}
	for sequence := uint64(1); sequence < status.NextSequence; sequence++ {
		if _, wasSkipped := skipped[sequence]; wasSkipped {
			if _, publicationErr := readCampaignPublicationID(
				config.PublicationDirectory, sequence,
			); publicationErr == nil {
				addIssue(CampaignAuditIssue{
					Code: "published_skipped_slot", Sequence: sequence,
					Detail: "a safely skipped slot later acquired a publication marker",
				})
			} else if !errors.Is(publicationErr, os.ErrNotExist) {
				addIssue(CampaignAuditIssue{
					Code: "invalid_skipped_publication", Sequence: sequence,
					Detail: publicationErr.Error(),
				})
			}
			continue
		}
		artifacts[sequence] = auditCampaignArtifact(
			store, config.PublicationDirectory, sequence, true, addIssue,
		)
	}
	if status.Phase != CampaignComplete {
		sequence := status.NextSequence
		requireArtifact := status.Phase != CampaignAwaitingPair
		requirePublication := status.Phase == CampaignDelivering || status.Phase == CampaignAwaitingAdvance
		if requireArtifact {
			artifacts[sequence] = auditCampaignArtifact(
				store, config.PublicationDirectory, sequence, requirePublication, addIssue,
			)
			artifact := artifacts[sequence]
			if artifact.present && (artifact.checkpoint.PairID != status.PairID ||
				artifact.checkpointID != status.CheckpointID) {
				addIssue(CampaignAuditIssue{
					Code: "current_artifact_state_mismatch", Sequence: sequence,
					Detail: "campaign journal IDs do not match the immutable current artifact",
				})
			}
		}
	}

	receiptSets := make([][]calibration.TieTrialReceipt, len(config.Observers))
	confirmationSets := make([]map[uint64]ObserverCampaignConfirmation, len(config.Observers))
	for observerIndex, observerConfig := range config.Observers {
		binding := config.Binding
		binding.ObserverPublicKey = observerConfig.ObserverPublicKey
		_, receipts, aggregate, loadErr := calibration.LoadTieReceiptFile(observerConfig.ReceiptPath, binding)
		if errors.Is(loadErr, os.ErrNotExist) {
			receipts = nil
		} else if loadErr != nil {
			return CampaignAuditReport{}, fmt.Errorf("observer %d receipt manifest: %w", observerIndex+1, loadErr)
		}
		receiptSets[observerIndex] = receipts
		observerStatus := CampaignAuditObserverStatus{
			ObserverPublicKey: observerConfig.ObserverPublicKey, ClosedSlots: uint64(len(receipts)),
		}
		if len(receipts) != 0 {
			observerStatus.CompletedTrials = aggregate.CompletedTrials
			observerStatus.NoPairSlots = aggregate.NoPairSlots
			observerStatus.LastReceiptID = aggregate.LastReceiptID
		}
		confirmations := make(map[uint64]ObserverCampaignConfirmation)
		confirmationSets[observerIndex] = confirmations
		files := &FileObserverCampaign{
			confirmationDirectory: observerConfig.ConfirmationDirectory,
			plan:                  config.Plan, binding: binding, planID: planID,
		}
		for _, receipt := range receipts {
			confirmation, confirmationErr := files.LoadConfirmation(receipt.Sequence)
			switch receipt.Status {
			case calibration.TieTrialNoPair:
				if confirmationErr == nil {
					addIssue(CampaignAuditIssue{
						Code: "confirmation_for_no_pair", Sequence: receipt.Sequence,
						ObserverPublicKey: observerConfig.ObserverPublicKey,
						Detail:            "NoPair receipt must not have a delivery confirmation",
					})
				} else if !IsMissingObserverCampaignFile(confirmationErr) {
					return CampaignAuditReport{}, confirmationErr
				}
			case calibration.TieTrialCompleted:
				if confirmationErr == nil {
					confirmations[receipt.Sequence] = confirmation
					observerStatus.ConfirmedSlots++
				} else if !IsMissingObserverCampaignFile(confirmationErr) {
					return CampaignAuditReport{}, confirmationErr
				}
			}
		}
		report.Observers[observerIndex] = observerStatus
	}

	for sequence := uint64(1); sequence < status.NextSequence; sequence++ {
		_, wasSkipped := skipped[sequence]
		allVerified := true
		var first *calibration.TieTrialReceipt
		for observerIndex, observerConfig := range config.Observers {
			receipts := receiptSets[observerIndex]
			if sequence > uint64(len(receipts)) {
				allVerified = false
				addIssue(CampaignAuditIssue{
					Code: "observer_lag", Sequence: sequence,
					ObserverPublicKey: observerConfig.ObserverPublicKey, Recoverable: wasSkipped,
					Detail: "observer has not durably closed a coordinator-advanced slot",
				})
				continue
			}
			receipt := receipts[sequence-1]
			if wasSkipped {
				if receipt.Status != calibration.TieTrialNoPair {
					allVerified = false
					addIssue(CampaignAuditIssue{
						Code: "completed_skipped_slot", Sequence: sequence,
						ObserverPublicKey: observerConfig.ObserverPublicKey,
						Detail:            "observer admitted a pair that coordinator classified as zero-delivery",
					})
				}
				continue
			}
			if receipt.Status != calibration.TieTrialCompleted {
				allVerified = false
				addIssue(CampaignAuditIssue{
					Code: "no_pair_for_delivered_slot", Sequence: sequence,
					ObserverPublicKey: observerConfig.ObserverPublicKey,
					Detail:            "coordinator advanced a delivered slot without a completed observer receipt",
				})
				continue
			}
			artifact := artifacts[sequence]
			if !artifact.present || !auditReceiptMatchesPair(receipt, artifact.pair) {
				allVerified = false
				addIssue(CampaignAuditIssue{
					Code: "receipt_pair_mismatch", Sequence: sequence,
					ObserverPublicKey: observerConfig.ObserverPublicKey,
					Detail:            "observer receipt does not describe the published sibling artifact",
				})
			}
			receiptID, idErr := receipt.ID(config.Plan)
			if idErr != nil {
				return CampaignAuditReport{}, idErr
			}
			confirmation, confirmed := confirmationSets[observerIndex][sequence]
			if !confirmed || confirmation.PairID != artifact.checkpoint.PairID ||
				confirmation.ReceiptTail != receiptID {
				allVerified = false
				addIssue(CampaignAuditIssue{
					Code: "missing_completed_confirmation", Sequence: sequence,
					ObserverPublicKey: observerConfig.ObserverPublicKey,
					Detail:            "advanced delivery lacks its exact observer confirmation marker",
				})
			}
			if first == nil {
				copyReceipt := receipt
				first = &copyReceipt
			} else if !auditSameCompletedObservation(*first, receipt) {
				allVerified = false
				addIssue(CampaignAuditIssue{
					Code: "observer_divergence", Sequence: sequence,
					ObserverPublicKey: observerConfig.ObserverPublicKey,
					Detail:            "independent observers recorded different blocks or selected tips",
				})
			}
		}
		if allVerified {
			if wasSkipped {
				report.VerifiedSkippedSlots++
			} else {
				report.VerifiedSuccessfulSlots++
			}
		}
	}

	if status.Phase != CampaignComplete {
		sequence := status.NextSequence
		var firstCurrent *calibration.TieTrialReceipt
		for observerIndex, observerConfig := range config.Observers {
			receipts := receiptSets[observerIndex]
			if uint64(len(receipts)) > sequence {
				addIssue(CampaignAuditIssue{
					Code: "observer_ahead_of_coordinator", Sequence: sequence,
					ObserverPublicKey: observerConfig.ObserverPublicKey,
					Detail:            "observer receipt chain extends beyond coordinator current sequence",
				})
				continue
			}
			if uint64(len(receipts)) < sequence {
				report.PendingObservers++
				if status.Phase == CampaignAwaitingAdvance ||
					(observerIndex < len(status.ObserverReceiptTails) &&
						!status.ObserverReceiptTails[observerIndex].IsZero()) {
					addIssue(CampaignAuditIssue{
						Code: "coordinator_ack_without_receipt", Sequence: sequence,
						ObserverPublicKey: observerConfig.ObserverPublicKey,
						Detail:            "coordinator journal contains an ACK absent from observer evidence",
					})
				}
				continue
			}
			receipt := receipts[sequence-1]
			if status.Phase == CampaignAwaitingPair || status.Phase == CampaignAwaitingPublication {
				if receipt.Status == calibration.TieTrialNoPair {
					addIssue(CampaignAuditIssue{
						Code: "observer_closed_current_slot", Sequence: sequence,
						ObserverPublicKey: observerConfig.ObserverPublicKey, Recoverable: true,
						Detail: "observer closed current slot before coordinator persisted its safe skip",
					})
				} else {
					addIssue(CampaignAuditIssue{
						Code: "receipt_before_delivery", Sequence: sequence,
						ObserverPublicKey: observerConfig.ObserverPublicKey,
						Detail:            "observer completed current slot before coordinator enabled delivery",
					})
				}
				continue
			}
			if receipt.Status != calibration.TieTrialCompleted {
				addIssue(CampaignAuditIssue{
					Code: "no_pair_after_publication", Sequence: sequence,
					ObserverPublicKey: observerConfig.ObserverPublicKey,
					Detail:            "published delivery phase conflicts with observer NoPair",
				})
				continue
			}
			artifact := artifacts[sequence]
			receiptID, idErr := receipt.ID(config.Plan)
			if idErr != nil {
				return CampaignAuditReport{}, idErr
			}
			confirmation, confirmed := confirmationSets[observerIndex][sequence]
			acknowledged := observerIndex < len(status.ObserverReceiptTails) &&
				!status.ObserverReceiptTails[observerIndex].IsZero()
			if !artifact.present || !auditReceiptMatchesPair(receipt, artifact.pair) {
				addIssue(CampaignAuditIssue{
					Code: "current_receipt_pair_mismatch", Sequence: sequence,
					ObserverPublicKey: observerConfig.ObserverPublicKey,
					Detail:            "current observer receipt does not match campaign artifact",
				})
			}
			if firstCurrent == nil {
				copyReceipt := receipt
				firstCurrent = &copyReceipt
			} else if !auditSameCompletedObservation(*firstCurrent, receipt) {
				addIssue(CampaignAuditIssue{
					Code: "current_observer_divergence", Sequence: sequence,
					ObserverPublicKey: observerConfig.ObserverPublicKey,
					Detail:            "current observer views disagree on blocks or selected tip",
				})
			}
			if acknowledged {
				if status.ObserverReceiptTails[observerIndex] != receiptID || !confirmed ||
					confirmation.PairID != artifact.checkpoint.PairID || confirmation.ReceiptTail != receiptID {
					addIssue(CampaignAuditIssue{
						Code: "invalid_recorded_ack", Sequence: sequence,
						ObserverPublicKey: observerConfig.ObserverPublicKey,
						Detail:            "coordinator ACK does not match observer receipt and confirmation",
					})
				}
			} else if confirmed {
				if confirmation.PairID == artifact.checkpoint.PairID && confirmation.ReceiptTail == receiptID {
					report.RecoverableAcks++
					addIssue(CampaignAuditIssue{
						Code: "unrecorded_observer_ack", Sequence: sequence,
						ObserverPublicKey: observerConfig.ObserverPublicKey,
						ReceiptTail:       receiptID, Recoverable: true,
						Detail: "observer completed confirmation but coordinator has not journaled its ACK",
					})
				} else {
					addIssue(CampaignAuditIssue{
						Code: "invalid_unrecorded_confirmation", Sequence: sequence,
						ObserverPublicKey: observerConfig.ObserverPublicKey,
						Detail:            "unrecorded confirmation does not match current pair and receipt",
					})
				}
			} else {
				addIssue(CampaignAuditIssue{
					Code: "awaiting_observer_confirmation", Sequence: sequence,
					ObserverPublicKey: observerConfig.ObserverPublicKey, Recoverable: true,
					Detail: "observer receipt is durable and awaits exchange confirmation retry",
				})
			}
		}
	}
	report.CampaignComplete = status.Phase == CampaignComplete &&
		report.Disposition == CampaignAuditHealthy &&
		report.VerifiedSuccessfulSlots+report.VerifiedSkippedSlots == report.PlannedSlots
	return report, nil
}

func auditCampaignArtifact(
	store *FileCampaignArtifacts,
	publicationDirectory string,
	sequence uint64,
	requirePublication bool,
	addIssue func(CampaignAuditIssue),
) campaignAuditArtifact {
	pair, checkpoint, err := store.Load(sequence)
	if err != nil {
		addIssue(CampaignAuditIssue{
			Code: "missing_or_invalid_artifact", Sequence: sequence, Detail: err.Error(),
		})
		return campaignAuditArtifact{}
	}
	checkpointID, err := checkpoint.ID(store.plan, store.binding, store.planID)
	if err != nil {
		addIssue(CampaignAuditIssue{
			Code: "invalid_checkpoint", Sequence: sequence, Detail: err.Error(),
		})
		return campaignAuditArtifact{}
	}
	result := campaignAuditArtifact{
		pair: pair, checkpoint: checkpoint, checkpointID: checkpointID, present: true,
	}
	publishedID, publicationErr := readCampaignPublicationID(publicationDirectory, sequence)
	if publicationErr == nil {
		if publishedID != checkpointID {
			addIssue(CampaignAuditIssue{
				Code: "publication_checkpoint_mismatch", Sequence: sequence,
				Detail: "published checkpoint ID does not match immutable artifact",
			})
		} else {
			result.published = true
		}
	} else if requirePublication || !errors.Is(publicationErr, os.ErrNotExist) {
		addIssue(CampaignAuditIssue{
			Code: "missing_or_invalid_publication", Sequence: sequence,
			Detail: publicationErr.Error(),
		})
	}
	return result
}

func readCampaignPublicationID(directory string, sequence uint64) (types.Hash, error) {
	if directory == "" || sequence == 0 {
		return types.Hash{}, ErrCampaignAudit
	}
	encoded, err := readBoundedCampaignFile(
		filepath.Join(directory, campaignSequenceName(sequence)+".published"),
		MaximumCampaignPublicationBytes,
	)
	if err != nil {
		return types.Hash{}, err
	}
	if len(encoded) != types.HashSize*2+1 || encoded[len(encoded)-1] != '\n' {
		return types.Hash{}, ErrCampaignAudit
	}
	decoded, err := hex.DecodeString(string(encoded[:len(encoded)-1]))
	if err != nil || len(decoded) != types.HashSize {
		return types.Hash{}, ErrCampaignAudit
	}
	var identifier types.Hash
	copy(identifier[:], decoded)
	if identifier.IsZero() {
		return types.Hash{}, ErrCampaignAudit
	}
	return identifier, nil
}

func auditReceiptMatchesPair(receipt calibration.TieTrialReceipt, pair Pair) bool {
	testedID, testedErr := pair.Tested.Header.ID()
	controlID, controlErr := pair.Control.Header.ID()
	return testedErr == nil && controlErr == nil && receipt.Sequence == pair.Sequence &&
		receipt.ParentID == pair.Tested.Header.Seal.AnchorParent &&
		receipt.Height == pair.Tested.Header.Seal.Height &&
		receipt.TestedAnchorID == testedID && receipt.ControlAnchorID == controlID
}

func auditSameCompletedObservation(left, right calibration.TieTrialReceipt) bool {
	return left.ParentID == right.ParentID && left.Height == right.Height &&
		left.TestedAnchorID == right.TestedAnchorID &&
		left.ControlAnchorID == right.ControlAnchorID &&
		left.SelectedAnchorID == right.SelectedAnchorID &&
		left.FirstObservedAnchorID == right.FirstObservedAnchorID
}
