package tieproducer

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/calibration"
)

func TestAuditCampaignFilesVerifiesCompleteMixedCampaign(t *testing.T) {
	fixture := newCampaignAuditFixture(t, true, false)
	report, err := AuditCampaignFiles(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if report.Disposition != CampaignAuditHealthy || !report.CampaignComplete ||
		report.StateVersion != CampaignStateVersion1 || report.VerifiedSuccessfulSlots != 1 ||
		report.VerifiedSkippedSlots != 1 || report.PendingObservers != 0 ||
		report.RecoverableAcks != 0 || len(report.Issues) != 0 {
		t.Fatalf("complete audit report=%+v", report)
	}
	for _, observer := range report.Observers {
		if observer.ClosedSlots != 2 || observer.CompletedTrials != 1 ||
			observer.NoPairSlots != 1 || observer.ConfirmedSlots != 1 ||
			observer.LastReceiptID.IsZero() {
			t.Fatalf("observer audit=%+v", observer)
		}
	}
}

func TestAuditCampaignFilesClassifiesRecoverableUnrecordedAck(t *testing.T) {
	fixture := newCampaignAuditFixture(t, false, false)
	report, err := AuditCampaignFiles(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if report.Disposition != CampaignAuditRecoverable || report.CampaignComplete ||
		report.NextSequence != 1 || report.Phase != CampaignDelivering ||
		report.RecoverableAcks != 1 || report.PendingObservers != 1 ||
		!auditHasIssue(report, "unrecorded_observer_ack", true) {
		t.Fatalf("recoverable audit report=%+v", report)
	}
}

func TestRecoverCampaignAcknowledgementsJournalsOnlyProvenConfirmation(t *testing.T) {
	fixture := newCampaignAuditFixture(t, false, false)
	result, err := RecoverCampaignAcknowledgements(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if result.RecoveredACKs != 1 || result.Before.RecoverableAcks != 1 ||
		result.After.RecoverableAcks != 0 || result.After.Disposition != CampaignAuditHealthy {
		t.Fatalf("recovery result=%+v", result)
	}
	status, err := LoadCampaignStatus(CampaignConfig{
		Plan: fixture.config.Plan, Binding: fixture.config.Binding,
		ExpectedPlanID: fixture.config.ExpectedPlanID, StatePath: fixture.config.StatePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Phase != CampaignDelivering || status.AcknowledgedCount != 1 ||
		status.ObserverReceiptTails[0].IsZero() || !status.ObserverReceiptTails[1].IsZero() {
		t.Fatalf("recovered campaign status=%+v", status)
	}
}

func TestRecoverCampaignAcknowledgementsRefusesBlockedEvidence(t *testing.T) {
	fixture := newCampaignAuditFixture(t, true, false)
	if err := os.Remove(filepath.Join(fixture.config.ArtifactDirectory, "0000000001.omtpair")); err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.ReadFile(fixture.config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := RecoverCampaignAcknowledgements(fixture.config)
	if !errors.Is(err, ErrCampaignAudit) || result.Before.Disposition != CampaignAuditBlocked ||
		result.RecoveredACKs != 0 {
		t.Fatalf("blocked recovery result=%+v err=%v", result, err)
	}
	stateAfter, readErr := os.ReadFile(fixture.config.StatePath)
	if readErr != nil || !bytes.Equal(stateBefore, stateAfter) {
		t.Fatalf("blocked recovery mutated state err=%v", readErr)
	}
}

func TestAuditCampaignFilesBlocksDivergenceAndMissingArtifact(t *testing.T) {
	t.Run("observer divergence", func(t *testing.T) {
		fixture := newCampaignAuditFixture(t, true, true)
		report, err := AuditCampaignFiles(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		if report.Disposition != CampaignAuditBlocked || report.CampaignComplete ||
			!auditHasIssue(report, "observer_divergence", false) {
			t.Fatalf("divergent audit report=%+v", report)
		}
	})
	t.Run("missing artifact", func(t *testing.T) {
		fixture := newCampaignAuditFixture(t, true, false)
		if err := os.Remove(filepath.Join(fixture.config.ArtifactDirectory, "0000000001.omtpair")); err != nil {
			t.Fatal(err)
		}
		report, err := AuditCampaignFiles(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		if report.Disposition != CampaignAuditBlocked || report.CampaignComplete ||
			!auditHasIssue(report, "missing_or_invalid_artifact", false) {
			t.Fatalf("missing-artifact audit report=%+v", report)
		}
	})
}

func TestLoadCampaignStatusDoesNotMigrateLegacyState(t *testing.T) {
	plan, binding, _ := campaignPlan(t)
	planID, _ := plan.ID()
	statePath := filepath.Join(t.TempDir(), "campaign.state")
	legacy := campaignState{
		Version: CampaignStateVersion0, PlanID: planID,
		NextSequence: 1, Phase: CampaignAwaitingPair,
	}
	encoded, err := encodeCampaignState(legacy, plan, planID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := LoadCampaignStatus(CampaignConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, StatePath: statePath,
	})
	if err != nil || status.StateVersion != CampaignStateVersion0 {
		t.Fatalf("legacy status=%+v err=%v", status, err)
	}
	after, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(after, encoded) {
		t.Fatalf("read-only status rewrote legacy journal err=%v", err)
	}
}

type campaignAuditFixture struct {
	config CampaignAuditConfig
}

func newCampaignAuditFixture(
	t testing.TB,
	complete bool,
	diverge bool,
) campaignAuditFixture {
	t.Helper()
	plan, binding, keys := campaignPlan(t)
	planID, _ := plan.ID()
	root := t.TempDir()
	statePath := filepath.Join(root, "campaign.state")
	artifactDirectory := filepath.Join(root, "artifacts")
	publicationDirectory := filepath.Join(root, "published")
	if err := os.MkdirAll(publicationDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	campaign, err := OpenCampaign(CampaignConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, StatePath: statePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewFileCampaignArtifacts(artifactDirectory, plan, binding, planID)
	if err != nil {
		t.Fatal(err)
	}
	pair, checkpoint := campaignPair(t, plan, binding, keys.coordinator, 1)
	if err := store.Store(pair, checkpoint); err != nil {
		t.Fatal(err)
	}
	checkpointID, _ := checkpoint.ID(plan, binding, planID)
	if err := os.WriteFile(
		filepath.Join(publicationDirectory, "0000000001.published"),
		[]byte(checkpointID.String()+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := campaign.StagePair(pair, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := campaign.ConfirmPublication(1, checkpointID); err != nil {
		t.Fatal(err)
	}

	observerKeys := campaignAuditObserverKeys()
	observers := make([]CampaignAuditObserver, len(observerKeys))
	for index, observerKey := range observerKeys {
		observerPublicKey := observerKey.Public().(ed25519.PublicKey)
		if !bytes.Equal(observerPublicKey, plan.ObserverPublicKeys[index][:]) {
			t.Fatal("audit observer key order does not match campaign plan")
		}
		observerBinding := binding
		copy(observerBinding.ObserverPublicKey[:], observerPublicKey)
		receiptPath := filepath.Join(root, "observer-"+string(rune('a'+index))+".omtr")
		confirmationDirectory := filepath.Join(root, "confirmed-"+string(rune('a'+index)))
		observers[index] = CampaignAuditObserver{
			ObserverPublicKey: plan.ObserverPublicKeys[index], ReceiptPath: receiptPath,
			ConfirmationDirectory: confirmationDirectory,
		}
		if !complete && index == 1 {
			continue
		}
		receipts := campaignAuditReceipts(t, plan, pair, observerKey, diverge && index == 1, complete)
		if _, err := calibration.SaveTieReceiptFile(receiptPath, plan, receipts, observerBinding); err != nil {
			t.Fatal(err)
		}
		files, err := NewFileObserverCampaign(
			publicationDirectory, confirmationDirectory, plan, observerBinding, planID,
		)
		if err != nil {
			t.Fatal(err)
		}
		firstReceiptID, _ := receipts[0].ID(plan)
		if err := files.Confirm(1, checkpoint.PairID, firstReceiptID); err != nil {
			t.Fatal(err)
		}
		if complete {
			if err := campaign.Acknowledge(1, plan.ObserverPublicKeys[index], firstReceiptID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if complete {
		if err := campaign.Advance(1); err != nil {
			t.Fatal(err)
		}
		if err := campaign.SkipExpired(
			2, plan.Slots[1].EndedAt+calibration.TieReceiptClosureGraceSeconds,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := campaign.Close(); err != nil {
		t.Fatal(err)
	}
	return campaignAuditFixture{config: CampaignAuditConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, StatePath: statePath,
		ArtifactDirectory: artifactDirectory, PublicationDirectory: publicationDirectory,
		Observers: observers,
	}}
}

func campaignAuditObserverKeys() []ed25519.PrivateKey {
	keys := []ed25519.PrivateKey{
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize)),
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize)),
	}
	sort.Slice(keys, func(left, right int) bool {
		return bytes.Compare(
			keys[left].Public().(ed25519.PublicKey), keys[right].Public().(ed25519.PublicKey),
		) < 0
	})
	return keys
}

func campaignAuditReceipts(
	t testing.TB,
	plan calibration.TiePlan,
	pair Pair,
	observerKey ed25519.PrivateKey,
	diverge bool,
	complete bool,
) []calibration.TieTrialReceipt {
	t.Helper()
	testedID, _ := pair.Tested.Header.ID()
	controlID, _ := pair.Control.Header.ID()
	selectedID := testedID
	if diverge {
		selectedID = controlID
	}
	firstObservedID := testedID
	if plan.Slots[0].FirstRole == calibration.TieRoleControl {
		firstObservedID = controlID
	}
	first, err := calibration.SignTieTrialReceipt(observerKey, calibration.TieTrialReceipt{
		Version: calibration.TieReceiptVersion2, Sequence: 1, Status: calibration.TieTrialCompleted,
		ParentID: pair.Tested.Header.Seal.AnchorParent, Height: pair.Tested.Header.Seal.Height,
		TestedAnchorID: testedID, ControlAnchorID: controlID,
		TestedObservedAt: plan.Slots[0].StartedAt, ControlObservedAt: plan.Slots[0].StartedAt + 1,
		SelectedAnchorID: selectedID, FirstObservedAnchorID: firstObservedID,
	}, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		return []calibration.TieTrialReceipt{first}
	}
	firstID, _ := first.ID(plan)
	second, err := calibration.SignTieTrialReceipt(observerKey, calibration.TieTrialReceipt{
		Version: calibration.TieReceiptVersion2, Sequence: 2,
		Status: calibration.TieTrialNoPair, PreviousID: firstID,
	}, plan)
	if err != nil {
		t.Fatal(err)
	}
	return []calibration.TieTrialReceipt{first, second}
}

func auditHasIssue(report CampaignAuditReport, code string, recoverable bool) bool {
	for _, issue := range report.Issues {
		if issue.Code == code && issue.Recoverable == recoverable {
			return true
		}
	}
	return false
}
