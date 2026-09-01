package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/node/tieproducer"
)

const maximumCampaignAuditObserversBytes = 128 * 1024

type campaignEvidenceFlags struct {
	data                     *string
	planPath                 *string
	planIDText               *string
	coordinatorPublicKeyText *string
	observerPublicKeyText    *string
	statePath                *string
	artifactDirectory        *string
	publishedDirectory       *string
	observersPath            *string
}

func newCampaignEvidenceFlags(command string) (*flag.FlagSet, campaignEvidenceFlags) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	values := campaignEvidenceFlags{
		data:                     flags.String("data", defaultDataDirectory, "coordinator WorkGraph node data directory"),
		planPath:                 flags.String("plan", "", "published signed controlled-tie plan file"),
		planIDText:               flags.String("plan-id", "", "externally published controlled-tie plan ID"),
		coordinatorPublicKeyText: flags.String("coordinator-public-key", "", "trusted plan coordinator Ed25519 public key"),
		observerPublicKeyText:    flags.String("observer-public-key", "", "one trusted observer key used to bind the shared plan"),
		statePath:                flags.String("state", "", "existing coordinator campaign state path (default under data)"),
		artifactDirectory:        flags.String("artifacts", "", "immutable pair/checkpoint directory"),
		publishedDirectory:       flags.String("published", "", "external checkpoint publication directory"),
		observersPath:            flags.String("observers", "", "canonical observer receipt and confirmation path list"),
	}
	return flags, values
}

func (values campaignEvidenceFlags) load() (tieproducer.CampaignAuditConfig, error) {
	if *values.planPath == "" || *values.planIDText == "" || *values.coordinatorPublicKeyText == "" ||
		*values.observerPublicKeyText == "" || *values.artifactDirectory == "" ||
		*values.publishedDirectory == "" || *values.observersPath == "" {
		return tieproducer.CampaignAuditConfig{}, errors.New("published plan binding, campaign state/artifacts/publications, and observer evidence paths are required")
	}
	if *values.statePath == "" {
		*values.statePath = filepath.Join(*values.data, "work-tie-campaign.state")
	}
	observerPublicKey, err := parseHash(*values.observerPublicKeyText)
	if err != nil {
		return tieproducer.CampaignAuditConfig{}, fmt.Errorf("observer-public-key: %w", err)
	}
	plan, binding, planID, err := loadPublishedTiePlan(
		*values.data, *values.planPath, *values.planIDText,
		*values.coordinatorPublicKeyText, observerPublicKey,
	)
	if err != nil {
		return tieproducer.CampaignAuditConfig{}, err
	}
	observers, err := loadCampaignAuditObservers(*values.observersPath, plan)
	if err != nil {
		return tieproducer.CampaignAuditConfig{}, err
	}
	return tieproducer.CampaignAuditConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, StatePath: *values.statePath,
		ArtifactDirectory:    *values.artifactDirectory,
		PublicationDirectory: *values.publishedDirectory, Observers: observers,
	}, nil
}

func runWorkTelemetryTieCampaignAudit(arguments []string) error {
	flags, values := newCampaignEvidenceFlags("work-telemetry-tie-campaign-audit")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	config, err := values.load()
	if err != nil {
		return err
	}
	report, err := tieproducer.AuditCampaignFiles(config)
	if err != nil {
		return err
	}
	fmt.Printf(
		"work_tie_campaign_audit plan=%s disposition=%s state_version=%d phase=%d next_sequence=%d slots=%d verified_success=%d verified_skipped=%d pending_observers=%d recoverable_acks=%d complete=%t issues=%d\n",
		report.PlanID, report.Disposition, report.StateVersion, report.Phase,
		report.NextSequence, report.PlannedSlots, report.VerifiedSuccessfulSlots,
		report.VerifiedSkippedSlots, report.PendingObservers, report.RecoverableAcks,
		report.CampaignComplete, len(report.Issues),
	)
	for _, observer := range report.Observers {
		fmt.Printf(
			"work_tie_campaign_audit_observer observer=%s closed=%d completed=%d no_pair=%d confirmed=%d receipt_tail=%s\n",
			types.Hash(observer.ObserverPublicKey), observer.ClosedSlots,
			observer.CompletedTrials, observer.NoPairSlots, observer.ConfirmedSlots,
			observer.LastReceiptID,
		)
	}
	for _, issue := range report.Issues {
		severity := "blocked"
		if issue.Recoverable {
			severity = "recoverable"
		}
		observer := "-"
		if !types.Hash(issue.ObserverPublicKey).IsZero() {
			observer = types.Hash(issue.ObserverPublicKey).String()
		}
		fmt.Printf(
			"work_tie_campaign_audit_issue severity=%s code=%s sequence=%d observer=%s detail=%q\n",
			severity, issue.Code, issue.Sequence, observer, issue.Detail,
		)
	}
	if report.Disposition == tieproducer.CampaignAuditBlocked {
		return tieproducer.ErrCampaignAudit
	}
	return nil
}

func runWorkTelemetryTieCampaignRecover(arguments []string) error {
	flags, values := newCampaignEvidenceFlags("work-telemetry-tie-campaign-recover")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	config, err := values.load()
	if err != nil {
		return err
	}
	result, err := tieproducer.RecoverCampaignAcknowledgements(config)
	if err != nil {
		return err
	}
	fmt.Printf(
		"work_tie_campaign_recovered plan=%s recovered_acks=%d before=%s after=%s phase=%d next_sequence=%d remaining_recoverable_acks=%d issues=%d\n",
		result.Before.PlanID, result.RecoveredACKs, result.Before.Disposition,
		result.After.Disposition, result.After.Phase, result.After.NextSequence,
		result.After.RecoverableAcks, len(result.After.Issues),
	)
	return nil
}

func loadCampaignAuditObservers(
	path string,
	plan calibration.TiePlan,
) ([]tieproducer.CampaignAuditObserver, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, maximumCampaignAuditObserversBytes+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > maximumCampaignAuditObserversBytes ||
		encoded[len(encoded)-1] != '\n' {
		return nil, errors.New("invalid campaign audit observer list")
	}
	lines := strings.Split(string(encoded[:len(encoded)-1]), "\n")
	expected := plan.ObserverPublicKeys
	if plan.Version != calibration.TiePlanVersion2 {
		expected = [][ed25519.PublicKeySize]byte{plan.ObserverPublicKey}
	}
	if len(lines) != len(expected) {
		return nil, errors.New("campaign audit list must contain every plan observer exactly once")
	}
	observers := make([]tieproducer.CampaignAuditObserver, len(lines))
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 3 || strings.Join(fields, " ") != line ||
			len(fields[1]) > 4096 || len(fields[2]) > 4096 {
			return nil, errors.New("invalid campaign audit observer entry")
		}
		publicKey, err := parseHash(fields[0])
		if err != nil {
			return nil, fmt.Errorf("campaign audit observer %d: %w", index+1, err)
		}
		var observer [ed25519.PublicKeySize]byte
		copy(observer[:], publicKey[:])
		if observer != expected[index] {
			return nil, errors.New("campaign audit observers are not in canonical plan order")
		}
		observers[index] = tieproducer.CampaignAuditObserver{
			ObserverPublicKey: observer, ReceiptPath: fields[1],
			ConfirmationDirectory: fields[2],
		}
	}
	return observers, nil
}
