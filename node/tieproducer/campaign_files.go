package tieproducer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

const MaximumCampaignPublicationBytes = types.HashSize*2 + 1

type FileCampaignArtifacts struct {
	directory string
	plan      calibration.TiePlan
	binding   calibration.TiePlanBinding
	planID    types.Hash
}

func NewFileCampaignArtifacts(
	directory string,
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
	expectedPlanID types.Hash,
) (*FileCampaignArtifacts, error) {
	if directory == "" || expectedPlanID.IsZero() {
		return nil, ErrCampaignConfig
	}
	if err := plan.Verify(binding); err != nil {
		return nil, err
	}
	planID, err := plan.ID()
	if err != nil {
		return nil, err
	}
	if planID != expectedPlanID {
		return nil, ErrCampaignConfig
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, err
	}
	ownedPlan := plan
	ownedPlan.Slots = append([]calibration.TiePlanSlot(nil), plan.Slots...)
	ownedPlan.ObserverPublicKeys = append(
		[][ed25519.PublicKeySize]byte(nil), plan.ObserverPublicKeys...,
	)
	return &FileCampaignArtifacts{
		directory: directory, plan: ownedPlan, binding: binding, planID: planID,
	}, nil
}

func (store *FileCampaignArtifacts) Store(
	pair Pair,
	checkpoint calibration.TiePairCheckpoint,
) error {
	if store == nil {
		return ErrCampaignConfig
	}
	if err := pair.Validate(store.plan, store.binding, store.planID); err != nil {
		return err
	}
	if err := checkpoint.Verify(store.plan, store.binding, store.planID); err != nil {
		return err
	}
	pairID, err := pair.ID(store.plan, store.binding, store.planID)
	if err != nil {
		return err
	}
	if pair.Sequence != checkpoint.Sequence || pairID != checkpoint.PairID {
		return ErrCampaignState
	}
	pairBytes, err := pair.CanonicalBytes(store.plan, store.binding, store.planID)
	if err != nil {
		return err
	}
	if err := writeImmutableCampaignFile(
		store.PairPath(pair.Sequence), pairBytes, MaximumPairArtifactBytes,
	); err != nil {
		return err
	}
	return writeImmutableCampaignFile(
		store.CheckpointPath(pair.Sequence), checkpoint.CanonicalBytes(),
		calibration.TiePairCheckpointBytes,
	)
}

func (store *FileCampaignArtifacts) Load(
	sequence uint64,
) (Pair, calibration.TiePairCheckpoint, error) {
	if store == nil || sequence == 0 || sequence > uint64(len(store.plan.Slots)) {
		return Pair{}, calibration.TiePairCheckpoint{}, ErrCampaignConfig
	}
	pairBytes, err := readBoundedCampaignFile(store.PairPath(sequence), MaximumPairArtifactBytes)
	if err != nil {
		return Pair{}, calibration.TiePairCheckpoint{}, err
	}
	pair, err := DecodePair(pairBytes, store.plan, store.binding, store.planID)
	if err != nil {
		return Pair{}, calibration.TiePairCheckpoint{}, err
	}
	checkpointBytes, err := readBoundedCampaignFile(
		store.CheckpointPath(sequence), calibration.TiePairCheckpointBytes,
	)
	if err != nil {
		return Pair{}, calibration.TiePairCheckpoint{}, err
	}
	checkpoint, err := calibration.DecodeTiePairCheckpoint(checkpointBytes)
	if err != nil {
		return Pair{}, calibration.TiePairCheckpoint{}, err
	}
	if err := checkpoint.Verify(store.plan, store.binding, store.planID); err != nil {
		return Pair{}, calibration.TiePairCheckpoint{}, err
	}
	pairID, err := pair.ID(store.plan, store.binding, store.planID)
	if err != nil || pair.Sequence != sequence || checkpoint.Sequence != sequence || checkpoint.PairID != pairID {
		return Pair{}, calibration.TiePairCheckpoint{}, ErrCampaignState
	}
	return pair, checkpoint, nil
}

func (store *FileCampaignArtifacts) PairPath(sequence uint64) string {
	return filepath.Join(store.directory, campaignSequenceName(sequence)+".omtpair")
}

func (store *FileCampaignArtifacts) CheckpointPath(sequence uint64) string {
	return filepath.Join(store.directory, campaignSequenceName(sequence)+".omtcp")
}

type FileCampaignPublicationGate struct {
	Directory    string
	PollInterval time.Duration
}

func (gate FileCampaignPublicationGate) WaitPublished(
	ctx context.Context,
	sequence uint64,
	checkpointID types.Hash,
) error {
	if ctx == nil || gate.Directory == "" || gate.PollInterval <= 0 ||
		gate.PollInterval > time.Minute || sequence == 0 || checkpointID.IsZero() {
		return ErrCampaignConfig
	}
	path := filepath.Join(gate.Directory, campaignSequenceName(sequence)+".published")
	want := []byte(checkpointID.String() + "\n")
	for {
		encoded, err := readBoundedCampaignFile(path, MaximumCampaignPublicationBytes)
		switch {
		case err == nil:
			if !bytes.Equal(encoded, want) {
				return ErrCampaignState
			}
			return nil
		case !errors.Is(err, os.ErrNotExist):
			return err
		}
		timer := time.NewTimer(gate.PollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func campaignSequenceName(sequence uint64) string {
	return fmt.Sprintf("%010d", sequence)
}

func writeImmutableCampaignFile(path string, encoded []byte, maximum int) error {
	if path == "" || len(encoded) == 0 || len(encoded) > maximum {
		return ErrCampaignState
	}
	if current, err := readBoundedCampaignFile(path, maximum); err == nil {
		if bytes.Equal(current, encoded) {
			return syncCampaignDirectory(filepath.Dir(path))
		}
		return ErrCampaignState
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".outcomemesh-tie-campaign-artifact-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	written, err := temporary.Write(encoded)
	if err != nil {
		return err
	}
	if written != len(encoded) {
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			current, readErr := readBoundedCampaignFile(path, maximum)
			if readErr == nil && bytes.Equal(current, encoded) {
				return syncCampaignDirectory(directory)
			}
			return errors.Join(ErrCampaignState, readErr)
		}
		return err
	}
	return syncCampaignDirectory(directory)
}

func syncCampaignDirectory(directory string) error {
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}

func readBoundedCampaignFile(path string, maximum int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > maximum {
		return nil, ErrCampaignState
	}
	return encoded, nil
}
