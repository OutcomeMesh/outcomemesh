package tieproducer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

func TestFileObserverCampaignRequiresPublicationAndPersistsConfirmation(t *testing.T) {
	plan, binding, keys := campaignPlan(t)
	planID, _ := plan.ID()
	publicationDirectory := t.TempDir()
	confirmationDirectory := t.TempDir()
	files, err := NewFileObserverCampaign(
		publicationDirectory, confirmationDirectory, plan, binding, planID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := files.LoadPublishedCheckpoint(1); !IsMissingObserverCampaignFile(err) {
		t.Fatalf("unpublished checkpoint error=%v", err)
	}
	pairID := types.DomainHash("test/tieproducer/observer-campaign/pair")
	checkpoint, err := calibration.SignTiePairCheckpoint(
		keys.coordinator, plan, binding, planID, 1, pairID,
	)
	if err != nil {
		t.Fatal(err)
	}
	checkpointID, _ := checkpoint.ID(plan, binding, planID)
	checkpointPath := filepath.Join(publicationDirectory, campaignSequenceName(1)+".omtcp")
	if err := os.WriteFile(checkpointPath, checkpoint.CanonicalBytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := files.LoadPublishedCheckpoint(1); !IsMissingObserverCampaignFile(err) {
		t.Fatalf("staged-only checkpoint error=%v", err)
	}
	publishedPath := filepath.Join(publicationDirectory, campaignSequenceName(1)+".published")
	if err := os.WriteFile(publishedPath, []byte(checkpointID.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, loadedID, err := files.LoadPublishedCheckpoint(1)
	if err != nil || loaded != checkpoint || loadedID != checkpointID {
		t.Fatalf("loaded=%+v id=%s err=%v", loaded, loadedID, err)
	}

	receiptTail := types.DomainHash("test/tieproducer/observer-campaign/receipt")
	if err := files.Confirm(1, pairID, receiptTail); err != nil {
		t.Fatal(err)
	}
	if err := files.Confirm(1, pairID, receiptTail); err != nil {
		t.Fatalf("idempotent confirmation error=%v", err)
	}
	confirmation, err := files.LoadConfirmation(1)
	if err != nil || confirmation.PlanID != planID || confirmation.Sequence != 1 ||
		confirmation.PairID != pairID || confirmation.ReceiptTail != receiptTail {
		t.Fatalf("confirmation=%+v err=%v", confirmation, err)
	}
	if err := files.Confirm(
		1, pairID, types.DomainHash("test/tieproducer/observer-campaign/conflict"),
	); !errors.Is(err, ErrCampaignState) {
		t.Fatalf("conflicting confirmation error=%v", err)
	}
}

func TestFileObserverCampaignRejectsPublicationMismatchAndCorruptConfirmation(t *testing.T) {
	plan, binding, keys := campaignPlan(t)
	planID, _ := plan.ID()
	publicationDirectory := t.TempDir()
	files, err := NewFileObserverCampaign(
		publicationDirectory, t.TempDir(), plan, binding, planID,
	)
	if err != nil {
		t.Fatal(err)
	}
	pairID := types.DomainHash("test/tieproducer/observer-campaign/mismatch-pair")
	checkpoint, err := calibration.SignTiePairCheckpoint(
		keys.coordinator, plan, binding, planID, 1, pairID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(publicationDirectory, campaignSequenceName(1)+".omtcp"),
		checkpoint.CanonicalBytes(), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	wrongID := types.DomainHash("test/tieproducer/observer-campaign/wrong-checkpoint")
	if err := os.WriteFile(
		filepath.Join(publicationDirectory, campaignSequenceName(1)+".published"),
		[]byte(wrongID.String()+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := files.LoadPublishedCheckpoint(1); err == nil {
		t.Fatal("mismatched publication was accepted")
	}
	receiptTail := types.DomainHash("test/tieproducer/observer-campaign/corrupt-receipt")
	if err := files.Confirm(1, pairID, receiptTail); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(files.ConfirmationPath(1))
	if err != nil {
		t.Fatal(err)
	}
	encoded[len(encoded)-1] ^= 0x01
	if err := os.WriteFile(files.ConfirmationPath(1), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := files.LoadConfirmation(1); !errors.Is(err, ErrCampaignState) {
		t.Fatalf("corrupt confirmation error=%v", err)
	}
}
