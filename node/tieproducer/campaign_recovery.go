package tieproducer

import "github.com/outcomemesh/outcomemesh/core/types"

// CampaignRecoveryResult describes one explicit reconciliation of observer
// confirmations into the coordinator journal. Recovery never advances the
// local chain or closes a slot; the normal coordinator must still perform that
// transition after every expected acknowledgement is durable.
type CampaignRecoveryResult struct {
	Before        CampaignAuditReport
	After         CampaignAuditReport
	RecoveredACKs uint64
}

// RecoverCampaignAcknowledgements journals only acknowledgements proven by an
// exact signed receipt, immutable pair artifact, publication checkpoint, and
// observer confirmation marker. Any blocking audit finding prevents all
// mutation. Operators must stop the campaign coordinator while this explicit
// repair runs, just as they must for any other single-writer journal repair.
func RecoverCampaignAcknowledgements(config CampaignAuditConfig) (CampaignRecoveryResult, error) {
	before, err := AuditCampaignFiles(config)
	if err != nil {
		return CampaignRecoveryResult{}, err
	}
	result := CampaignRecoveryResult{Before: before, After: before}
	if before.Disposition == CampaignAuditBlocked {
		return result, ErrCampaignAudit
	}
	if before.RecoverableAcks == 0 {
		return result, nil
	}
	recoverable := make([]CampaignAuditIssue, 0, before.RecoverableAcks)
	for _, issue := range before.Issues {
		if issue.Code != "unrecorded_observer_ack" || !issue.Recoverable {
			continue
		}
		if issue.Sequence == 0 || types.Hash(issue.ObserverPublicKey).IsZero() ||
			issue.ReceiptTail.IsZero() {
			return result, ErrCampaignAudit
		}
		recoverable = append(recoverable, issue)
	}
	if uint64(len(recoverable)) != before.RecoverableAcks {
		return result, ErrCampaignAudit
	}

	campaign, err := OpenCampaign(CampaignConfig{
		Plan: config.Plan, Binding: config.Binding, ExpectedPlanID: config.ExpectedPlanID,
		StatePath: config.StatePath,
	})
	if err != nil {
		return result, err
	}

	for _, issue := range recoverable {
		if err := campaign.Acknowledge(
			issue.Sequence, issue.ObserverPublicKey, issue.ReceiptTail,
		); err != nil {
			return result, err
		}
		result.RecoveredACKs++
	}
	if err := campaign.Close(); err != nil {
		return result, err
	}
	result.After, err = AuditCampaignFiles(config)
	if err != nil {
		return result, err
	}
	return result, nil
}
