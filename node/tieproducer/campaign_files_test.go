package tieproducer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

func TestFileCampaignArtifactsAreImmutableAndRestartLoadable(t *testing.T) {
	plan, binding, keys := campaignPlan(t)
	planID, _ := plan.ID()
	directory := t.TempDir()
	store, err := NewFileCampaignArtifacts(directory, plan, binding, planID)
	if err != nil {
		t.Fatal(err)
	}
	pair, checkpoint := campaignPair(t, plan, binding, keys.coordinator, 1)
	if err := store.Store(pair, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(pair, checkpoint); err != nil {
		t.Fatalf("idempotent artifact store: %v", err)
	}
	loadedPair, loadedCheckpoint, err := store.Load(1)
	if err != nil || loadedCheckpoint != checkpoint {
		t.Fatalf("loaded pair=%+v checkpoint=%+v err=%v", loadedPair, loadedCheckpoint, err)
	}
	loadedID, _ := loadedPair.ID(plan, binding, planID)
	if loadedID != checkpoint.PairID {
		t.Fatalf("loaded pair ID=%s checkpoint pair=%s", loadedID, checkpoint.PairID)
	}
	for _, path := range []string{store.PairPath(1), store.CheckpointPath(1)} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("artifact path=%s mode=%v err=%v", path, info.Mode(), err)
		}
	}

	conflicting := checkpoint
	conflicting, err = calibration.SignTiePairCheckpoint(
		keys.coordinator, plan, binding, planID, 1,
		types.DomainHash("test/tieproducer/campaign-files/conflicting-pair"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Store(pair, conflicting); !errors.Is(err, ErrCampaignState) {
		t.Fatalf("conflicting artifact error=%v", err)
	}
	if err := os.WriteFile(store.CheckpointPath(1), make([]byte, calibration.TiePairCheckpointBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(1); err == nil {
		t.Fatal("corrupt checkpoint file was loaded")
	}
}

func TestFileCampaignPublicationGateRequiresExactExternalID(t *testing.T) {
	directory := t.TempDir()
	gate := FileCampaignPublicationGate{Directory: directory, PollInterval: time.Millisecond}
	checkpointID := types.DomainHash("test/tieproducer/campaign-files/checkpoint")
	publicationPath := filepath.Join(directory, campaignSequenceName(1)+".published")
	if err := os.WriteFile(publicationPath, []byte(checkpointID.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := gate.WaitPublished(context.Background(), 1, checkpointID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicationPath, []byte(types.DomainHash("other").String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := gate.WaitPublished(context.Background(), 1, checkpointID); !errors.Is(err, ErrCampaignState) {
		t.Fatalf("wrong publication error=%v", err)
	}
	if err := os.Remove(publicationPath); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := gate.WaitPublished(cancelled, 1, checkpointID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled publication wait error=%v", err)
	}
}
