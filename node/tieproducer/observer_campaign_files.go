package tieproducer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

const (
	ObserverCampaignConfirmationVersion0 uint16 = 0
	observerCampaignConfirmationBytes           = 2 + types.HashSize + 8 + types.HashSize + types.HashSize + types.HashSize
)

const observerCampaignConfirmationChecksumDomain = "OMESH/testnet/calibration/tie-observer-confirmation/checksum/v0"

// ObserverCampaignConfirmation records the second durable boundary of a QUIC
// delivery. The receipt already proves local admission; this marker is written
// only after the observer reads the coordinator's confirmation of that receipt.
type ObserverCampaignConfirmation struct {
	Version     uint16
	PlanID      types.Hash
	Sequence    uint64
	PairID      types.Hash
	ReceiptTail types.Hash
}

type FileObserverCampaign struct {
	publicationDirectory  string
	confirmationDirectory string
	plan                  calibration.TiePlan
	binding               calibration.TiePlanBinding
	planID                types.Hash
	writeImmutable        func(string, []byte, int) error
}

func NewFileObserverCampaign(
	publicationDirectory string,
	confirmationDirectory string,
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
	expectedPlanID types.Hash,
) (*FileObserverCampaign, error) {
	if publicationDirectory == "" || confirmationDirectory == "" || expectedPlanID.IsZero() {
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
	if err := os.MkdirAll(confirmationDirectory, 0o700); err != nil {
		return nil, err
	}
	ownedPlan := plan
	ownedPlan.Slots = append([]calibration.TiePlanSlot(nil), plan.Slots...)
	ownedPlan.ObserverPublicKeys = append(
		[][ed25519.PublicKeySize]byte(nil), plan.ObserverPublicKeys...,
	)
	return &FileObserverCampaign{
		publicationDirectory: publicationDirectory, confirmationDirectory: confirmationDirectory,
		plan: ownedPlan, binding: binding, planID: planID,
		writeImmutable: writeImmutableCampaignFile,
	}, nil
}

// LoadPublishedCheckpoint accepts a checkpoint only when its separately
// published identifier is present and byte-exact. A staged checkpoint alone is
// never an instruction to admit its pair.
func (files *FileObserverCampaign) LoadPublishedCheckpoint(
	sequence uint64,
) (calibration.TiePairCheckpoint, types.Hash, error) {
	if files == nil || sequence == 0 || sequence > uint64(len(files.plan.Slots)) {
		return calibration.TiePairCheckpoint{}, types.Hash{}, ErrCampaignConfig
	}
	publishedPath := filepath.Join(
		files.publicationDirectory, campaignSequenceName(sequence)+".published",
	)
	published, err := readBoundedCampaignFile(publishedPath, MaximumCampaignPublicationBytes)
	if err != nil {
		return calibration.TiePairCheckpoint{}, types.Hash{}, err
	}
	if len(published) != types.HashSize*2+1 || published[len(published)-1] != '\n' {
		return calibration.TiePairCheckpoint{}, types.Hash{}, ErrCampaignState
	}
	checkpointIDBytes, err := hex.DecodeString(string(published[:len(published)-1]))
	if err != nil || len(checkpointIDBytes) != types.HashSize {
		return calibration.TiePairCheckpoint{}, types.Hash{}, ErrCampaignState
	}
	var checkpointID types.Hash
	copy(checkpointID[:], checkpointIDBytes)
	if checkpointID.IsZero() {
		return calibration.TiePairCheckpoint{}, types.Hash{}, ErrCampaignState
	}
	checkpointPath := filepath.Join(
		files.publicationDirectory, campaignSequenceName(sequence)+".omtcp",
	)
	checkpoint, err := calibration.LoadTiePairCheckpointFile(
		checkpointPath, files.plan, files.binding, files.planID, checkpointID,
	)
	if err != nil {
		return calibration.TiePairCheckpoint{}, types.Hash{}, err
	}
	if checkpoint.Sequence != sequence {
		return calibration.TiePairCheckpoint{}, types.Hash{}, ErrCampaignState
	}
	return checkpoint, checkpointID, nil
}

func (files *FileObserverCampaign) ConfirmationPath(sequence uint64) string {
	return filepath.Join(
		files.confirmationDirectory, campaignSequenceName(sequence)+".confirmed",
	)
}

func (files *FileObserverCampaign) LoadConfirmation(
	sequence uint64,
) (ObserverCampaignConfirmation, error) {
	if files == nil || sequence == 0 || sequence > uint64(len(files.plan.Slots)) {
		return ObserverCampaignConfirmation{}, ErrCampaignConfig
	}
	encoded, err := readBoundedCampaignFile(
		files.ConfirmationPath(sequence), observerCampaignConfirmationBytes,
	)
	if err != nil {
		return ObserverCampaignConfirmation{}, err
	}
	confirmation, err := decodeObserverCampaignConfirmation(encoded)
	if err != nil {
		return ObserverCampaignConfirmation{}, err
	}
	if confirmation.PlanID != files.planID || confirmation.Sequence != sequence {
		return ObserverCampaignConfirmation{}, ErrCampaignState
	}
	return confirmation, nil
}

func (files *FileObserverCampaign) Confirm(
	sequence uint64,
	pairID types.Hash,
	receiptTail types.Hash,
) error {
	if files == nil || sequence == 0 || sequence > uint64(len(files.plan.Slots)) ||
		pairID.IsZero() || receiptTail.IsZero() {
		return ErrCampaignConfig
	}
	confirmation := ObserverCampaignConfirmation{
		Version: ObserverCampaignConfirmationVersion0, PlanID: files.planID,
		Sequence: sequence, PairID: pairID, ReceiptTail: receiptTail,
	}
	encoded, err := encodeObserverCampaignConfirmation(confirmation)
	if err != nil {
		return err
	}
	if files.writeImmutable == nil {
		return ErrCampaignConfig
	}
	return files.writeImmutable(
		files.ConfirmationPath(sequence), encoded, observerCampaignConfirmationBytes,
	)
}

func encodeObserverCampaignConfirmation(confirmation ObserverCampaignConfirmation) ([]byte, error) {
	if confirmation.Version != ObserverCampaignConfirmationVersion0 || confirmation.PlanID.IsZero() ||
		confirmation.Sequence == 0 || confirmation.PairID.IsZero() || confirmation.ReceiptTail.IsZero() {
		return nil, ErrCampaignState
	}
	encoder := codec.NewEncoder(observerCampaignConfirmationBytes)
	encoder.U16(confirmation.Version)
	encoder.Fixed(confirmation.PlanID[:])
	encoder.U64(confirmation.Sequence)
	encoder.Fixed(confirmation.PairID[:])
	encoder.Fixed(confirmation.ReceiptTail[:])
	checksum := types.DomainHash(observerCampaignConfirmationChecksumDomain, encoder.Bytes())
	encoder.Fixed(checksum[:])
	return encoder.Bytes(), nil
}

func decodeObserverCampaignConfirmation(input []byte) (ObserverCampaignConfirmation, error) {
	if len(input) != observerCampaignConfirmationBytes {
		return ObserverCampaignConfirmation{}, ErrCampaignState
	}
	decoder := codec.NewDecoder(input)
	var confirmation ObserverCampaignConfirmation
	var err error
	if confirmation.Version, err = decoder.U16(); err != nil {
		return ObserverCampaignConfirmation{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return ObserverCampaignConfirmation{}, decodeErr
	} else {
		copy(confirmation.PlanID[:], value)
	}
	if confirmation.Sequence, err = decoder.U64(); err != nil {
		return ObserverCampaignConfirmation{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return ObserverCampaignConfirmation{}, decodeErr
	} else {
		copy(confirmation.PairID[:], value)
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return ObserverCampaignConfirmation{}, decodeErr
	} else {
		copy(confirmation.ReceiptTail[:], value)
	}
	payloadBytes := len(input) - decoder.Remaining()
	checksum, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return ObserverCampaignConfirmation{}, err
	}
	if err := decoder.Finish(); err != nil {
		return ObserverCampaignConfirmation{}, err
	}
	wantChecksum := types.DomainHash(observerCampaignConfirmationChecksumDomain, input[:payloadBytes])
	if !bytes.Equal(checksum, wantChecksum[:]) || confirmation.Version != ObserverCampaignConfirmationVersion0 ||
		confirmation.PlanID.IsZero() || confirmation.Sequence == 0 || confirmation.PairID.IsZero() ||
		confirmation.ReceiptTail.IsZero() {
		return ObserverCampaignConfirmation{}, ErrCampaignState
	}
	return confirmation, nil
}

func IsMissingObserverCampaignFile(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}
