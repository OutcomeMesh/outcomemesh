package tieproducer

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

const (
	CampaignStateVersion0     uint16 = 0
	CampaignStateVersion1     uint16 = 1
	MaximumCampaignStateBytes        = 256 * 1024
)

const (
	campaignStateChecksumDomainV0 = "OMESH/testnet/calibration/tie-campaign/state-checksum/v0"
	campaignStateChecksumDomainV1 = "OMESH/testnet/calibration/tie-campaign/state-checksum/v1"
)

var (
	ErrCampaignConfig = errors.New("invalid controlled-tie campaign configuration")
	ErrCampaignState  = errors.New("invalid controlled-tie campaign state")
	ErrCampaignPhase  = errors.New("invalid controlled-tie campaign phase")
	ErrCampaignClosed = errors.New("controlled-tie campaign is closed")
	ErrCampaignSkip   = errors.New("controlled-tie campaign slot is not safely skippable")
)

type CampaignPhase uint8

const (
	CampaignAwaitingPair CampaignPhase = iota
	CampaignAwaitingPublication
	CampaignDelivering
	CampaignAwaitingAdvance
	CampaignComplete
)

type CampaignConfig struct {
	Plan           calibration.TiePlan
	Binding        calibration.TiePlanBinding
	ExpectedPlanID types.Hash
	StatePath      string
}

type CampaignStatus struct {
	StateVersion         uint16
	PlanID               types.Hash
	PlannedSlots         uint64
	NextSequence         uint64
	Phase                CampaignPhase
	PairID               types.Hash
	CheckpointID         types.Hash
	ObserverCount        uint64
	AcknowledgedCount    uint64
	ObserverReceiptTails []types.Hash
	SkippedSlots         uint64
	SkippedSequences     []uint64
}

// LoadCampaignStatus verifies and reports an existing campaign journal without
// creating, migrating, or rewriting it. Operator audit paths must remain
// observational even when the journal is legacy or incomplete.
func LoadCampaignStatus(config CampaignConfig) (CampaignStatus, error) {
	if config.StatePath == "" || config.ExpectedPlanID.IsZero() {
		return CampaignStatus{}, ErrCampaignConfig
	}
	if err := config.Plan.Verify(config.Binding); err != nil {
		return CampaignStatus{}, err
	}
	planID, err := config.Plan.ID()
	if err != nil {
		return CampaignStatus{}, err
	}
	if planID != config.ExpectedPlanID {
		return CampaignStatus{}, ErrCampaignConfig
	}
	encoded, err := readCampaignState(config.StatePath)
	if err != nil {
		return CampaignStatus{}, err
	}
	state, err := decodeCampaignState(encoded, config.Plan, planID)
	if err != nil {
		return CampaignStatus{}, err
	}
	return campaignStatus(config.Plan, state), nil
}

type campaignState struct {
	Version      uint16
	PlanID       types.Hash
	NextSequence uint64
	Phase        CampaignPhase
	PairID       types.Hash
	CheckpointID types.Hash
	ReceiptTails []types.Hash
	Skipped      []uint64
}

// Campaign is a small durable coordinator journal. Pair artifacts and signed
// observer manifests remain separate evidence files; this journal only makes
// the operational transition boundaries replayable after a crash.
type Campaign struct {
	mu        sync.Mutex
	plan      calibration.TiePlan
	binding   calibration.TiePlanBinding
	planID    types.Hash
	path      string
	state     campaignState
	saveState func(string, []byte) error
	closed    bool
}

func OpenCampaign(config CampaignConfig) (*Campaign, error) {
	if config.StatePath == "" || config.ExpectedPlanID.IsZero() {
		return nil, ErrCampaignConfig
	}
	if err := config.Plan.Verify(config.Binding); err != nil {
		return nil, err
	}
	if config.Plan.Version != calibration.TiePlanVersion1 &&
		config.Plan.Version != calibration.TiePlanVersion2 {
		return nil, ErrCampaignConfig
	}
	planID, err := config.Plan.ID()
	if err != nil {
		return nil, err
	}
	if planID != config.ExpectedPlanID {
		return nil, ErrCampaignConfig
	}
	ownedPlan := config.Plan
	ownedPlan.Slots = append([]calibration.TiePlanSlot(nil), config.Plan.Slots...)
	ownedPlan.ObserverPublicKeys = append(
		[][ed25519.PublicKeySize]byte(nil), config.Plan.ObserverPublicKeys...,
	)
	campaign := &Campaign{
		plan: ownedPlan, binding: config.Binding, planID: planID, path: config.StatePath,
		saveState: saveCampaignState,
	}
	encoded, readErr := readCampaignState(config.StatePath)
	switch {
	case readErr == nil:
		campaign.state, err = decodeCampaignState(encoded, campaign.plan, planID)
		if err != nil {
			return nil, err
		}
		if campaign.state.Version == CampaignStateVersion0 {
			campaign.state.Version = CampaignStateVersion1
			if err := campaign.saveLocked(campaign.state); err != nil {
				return nil, err
			}
		}
	case errors.Is(readErr, os.ErrNotExist):
		campaign.state = campaignState{
			Version: CampaignStateVersion1, PlanID: planID,
			NextSequence: 1, Phase: CampaignAwaitingPair,
		}
		if err := campaign.saveLocked(campaign.state); err != nil {
			return nil, err
		}
	default:
		return nil, readErr
	}
	return campaign, nil
}

// StagePair durably binds the exact validated artifact to its signed
// coordinator checkpoint. Repeating the same transition after a crash is
// idempotent; a conflicting artifact for the slot is rejected.
func (campaign *Campaign) StagePair(pair Pair, checkpoint calibration.TiePairCheckpoint) error {
	if campaign == nil {
		return ErrCampaignConfig
	}
	campaign.mu.Lock()
	defer campaign.mu.Unlock()
	if campaign.closed {
		return ErrCampaignClosed
	}
	if err := pair.Validate(campaign.plan, campaign.binding, campaign.planID); err != nil {
		return err
	}
	if err := checkpoint.Verify(campaign.plan, campaign.binding, campaign.planID); err != nil {
		return err
	}
	pairID, err := pair.ID(campaign.plan, campaign.binding, campaign.planID)
	if err != nil {
		return err
	}
	checkpointID, err := checkpoint.ID(campaign.plan, campaign.binding, campaign.planID)
	if err != nil {
		return err
	}
	if pair.Sequence != campaign.state.NextSequence || checkpoint.Sequence != pair.Sequence ||
		checkpoint.PairID != pairID {
		return ErrCampaignState
	}
	if campaign.state.Phase != CampaignAwaitingPair {
		if campaign.state.PairID == pairID && campaign.state.CheckpointID == checkpointID &&
			campaign.state.NextSequence == pair.Sequence {
			return nil
		}
		return ErrCampaignPhase
	}
	next := campaign.state
	next.Phase = CampaignAwaitingPublication
	next.PairID = pairID
	next.CheckpointID = checkpointID
	next.ReceiptTails = make([]types.Hash, campaign.observerCount())
	return campaign.saveLocked(next)
}

// ConfirmPublication is called only after the checkpoint ID has appeared in
// the campaign's independently operated publication channel.
func (campaign *Campaign) ConfirmPublication(sequence uint64, publishedCheckpointID types.Hash) error {
	if campaign == nil || sequence == 0 || publishedCheckpointID.IsZero() {
		return ErrCampaignConfig
	}
	campaign.mu.Lock()
	defer campaign.mu.Unlock()
	if campaign.closed {
		return ErrCampaignClosed
	}
	if sequence != campaign.state.NextSequence || publishedCheckpointID != campaign.state.CheckpointID {
		return ErrCampaignState
	}
	if campaign.state.Phase == CampaignDelivering || campaign.state.Phase == CampaignAwaitingAdvance {
		return nil
	}
	if campaign.state.Phase != CampaignAwaitingPublication {
		return ErrCampaignPhase
	}
	next := campaign.state
	next.Phase = CampaignDelivering
	return campaign.saveLocked(next)
}

// Acknowledge persists one authenticated observer's durable receipt tail.
// Different observers may arrive in any order, but the state is always encoded
// in the canonical key order fixed by the plan.
func (campaign *Campaign) Acknowledge(
	sequence uint64,
	observerPublicKey [ed25519.PublicKeySize]byte,
	receiptTail types.Hash,
) error {
	if campaign == nil || sequence == 0 || types.Hash(observerPublicKey).IsZero() || receiptTail.IsZero() {
		return ErrCampaignConfig
	}
	campaign.mu.Lock()
	defer campaign.mu.Unlock()
	if campaign.closed {
		return ErrCampaignClosed
	}
	if sequence != campaign.state.NextSequence ||
		(campaign.state.Phase != CampaignDelivering && campaign.state.Phase != CampaignAwaitingAdvance) {
		return ErrCampaignPhase
	}
	observerIndex := campaign.observerIndex(observerPublicKey)
	if observerIndex < 0 || observerIndex >= len(campaign.state.ReceiptTails) {
		return ErrCampaignState
	}
	current := campaign.state.ReceiptTails[observerIndex]
	if !current.IsZero() {
		if current == receiptTail {
			return nil
		}
		return ErrCampaignState
	}
	next := campaign.state
	next.ReceiptTails = append([]types.Hash(nil), campaign.state.ReceiptTails...)
	next.ReceiptTails[observerIndex] = receiptTail
	if allCampaignReceiptsPresent(next.ReceiptTails) {
		next.Phase = CampaignAwaitingAdvance
	}
	return campaign.saveLocked(next)
}

// Advance closes a fully acknowledged slot. Local chain admission or sync is
// deliberately outside this journal and must complete before this call.
func (campaign *Campaign) Advance(sequence uint64) error {
	if campaign == nil || sequence == 0 {
		return ErrCampaignConfig
	}
	campaign.mu.Lock()
	defer campaign.mu.Unlock()
	if campaign.closed {
		return ErrCampaignClosed
	}
	if sequence+1 == campaign.state.NextSequence &&
		(campaign.state.Phase == CampaignAwaitingPair || campaign.state.Phase == CampaignComplete) {
		return nil
	}
	if campaign.state.Phase != CampaignAwaitingAdvance || sequence != campaign.state.NextSequence {
		return ErrCampaignPhase
	}
	next := campaignState{
		Version: CampaignStateVersion1, PlanID: campaign.planID,
		NextSequence: sequence + 1, Phase: CampaignAwaitingPair,
		Skipped: append([]uint64(nil), campaign.state.Skipped...),
	}
	if sequence == uint64(len(campaign.plan.Slots)) {
		next.Phase = CampaignComplete
	}
	return campaign.saveLocked(next)
}

// SkipExpired advances a slot only before observer delivery is enabled and
// only after every observer has had the same fixed receipt-closure grace. It is
// safe for AwaitingPublication because no Deliver call can yet have occurred;
// once the phase is Delivering, a lost acknowledgement is indistinguishable
// from a remotely admitted pair and automatic continuation is forbidden.
func (campaign *Campaign) SkipExpired(sequence uint64, now uint64) error {
	if campaign == nil || sequence == 0 || now == 0 {
		return ErrCampaignConfig
	}
	campaign.mu.Lock()
	defer campaign.mu.Unlock()
	if campaign.closed {
		return ErrCampaignClosed
	}
	if sequence+1 == campaign.state.NextSequence &&
		campaignSequenceSkipped(campaign.state.Skipped, sequence) {
		return nil
	}
	if sequence != campaign.state.NextSequence {
		return ErrCampaignState
	}
	if campaign.state.Phase != CampaignAwaitingPair &&
		campaign.state.Phase != CampaignAwaitingPublication {
		return ErrCampaignPhase
	}
	slot := campaign.plan.Slots[sequence-1]
	if slot.EndedAt > ^uint64(0)-calibration.TieReceiptClosureGraceSeconds ||
		now < slot.EndedAt+calibration.TieReceiptClosureGraceSeconds {
		return ErrCampaignSkip
	}
	next := campaignState{
		Version: CampaignStateVersion1, PlanID: campaign.planID,
		NextSequence: sequence + 1, Phase: CampaignAwaitingPair,
		Skipped: append(append([]uint64(nil), campaign.state.Skipped...), sequence),
	}
	if sequence == uint64(len(campaign.plan.Slots)) {
		next.Phase = CampaignComplete
	}
	return campaign.saveLocked(next)
}

func (campaign *Campaign) Status() (CampaignStatus, error) {
	if campaign == nil {
		return CampaignStatus{}, ErrCampaignConfig
	}
	campaign.mu.Lock()
	defer campaign.mu.Unlock()
	if campaign.closed {
		return CampaignStatus{}, ErrCampaignClosed
	}
	return campaign.statusLocked(), nil
}

func (campaign *Campaign) Close() error {
	if campaign == nil {
		return ErrCampaignConfig
	}
	campaign.mu.Lock()
	defer campaign.mu.Unlock()
	if campaign.closed {
		return ErrCampaignClosed
	}
	campaign.closed = true
	return nil
}

func (campaign *Campaign) statusLocked() CampaignStatus {
	return campaignStatus(campaign.plan, campaign.state)
}

func campaignStatus(plan calibration.TiePlan, state campaignState) CampaignStatus {
	observerCount := 1
	if plan.Version == calibration.TiePlanVersion2 {
		observerCount = len(plan.ObserverPublicKeys)
	}
	status := CampaignStatus{
		StateVersion: state.Version, PlanID: state.PlanID, PlannedSlots: uint64(len(plan.Slots)),
		NextSequence: state.NextSequence, Phase: state.Phase,
		PairID: state.PairID, CheckpointID: state.CheckpointID,
		ObserverCount:        uint64(observerCount),
		ObserverReceiptTails: append([]types.Hash(nil), state.ReceiptTails...),
		SkippedSlots:         uint64(len(state.Skipped)),
		SkippedSequences:     append([]uint64(nil), state.Skipped...),
	}
	for _, tail := range state.ReceiptTails {
		if !tail.IsZero() {
			status.AcknowledgedCount++
		}
	}
	return status
}

func (campaign *Campaign) observerCount() int {
	if campaign.plan.Version == calibration.TiePlanVersion2 {
		return len(campaign.plan.ObserverPublicKeys)
	}
	return 1
}

func (campaign *Campaign) observerIndex(observer [ed25519.PublicKeySize]byte) int {
	if campaign.plan.Version != calibration.TiePlanVersion2 {
		if observer == campaign.plan.ObserverPublicKey {
			return 0
		}
		return -1
	}
	for index, expected := range campaign.plan.ObserverPublicKeys {
		if observer == expected {
			return index
		}
	}
	return -1
}

func (campaign *Campaign) saveLocked(next campaignState) error {
	encoded, err := encodeCampaignState(next, campaign.plan, campaign.planID)
	if err != nil {
		return err
	}
	if campaign.saveState == nil {
		return ErrCampaignConfig
	}
	if err := campaign.saveState(campaign.path, encoded); err != nil {
		return err
	}
	campaign.state = next
	return nil
}

func encodeCampaignState(state campaignState, plan calibration.TiePlan, planID types.Hash) ([]byte, error) {
	if err := validateCampaignState(state, plan, planID); err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(
		128 + len(state.ReceiptTails)*types.HashSize + len(state.Skipped)*8,
	)
	encodeCampaignStatePayload(encoder, state)
	checksum := types.DomainHash(campaignStateChecksumDomain(state.Version), encoder.Bytes())
	encoder.Fixed(checksum[:])
	encoded := encoder.Bytes()
	if len(encoded) > MaximumCampaignStateBytes {
		return nil, ErrCampaignState
	}
	return encoded, nil
}

func decodeCampaignState(input []byte, plan calibration.TiePlan, planID types.Hash) (campaignState, error) {
	if len(input) == 0 || len(input) > MaximumCampaignStateBytes {
		return campaignState{}, ErrCampaignState
	}
	decoder := codec.NewDecoder(input)
	var state campaignState
	var err error
	if state.Version, err = decoder.U16(); err != nil {
		return campaignState{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return campaignState{}, decodeErr
	} else {
		copy(state.PlanID[:], value)
	}
	if state.NextSequence, err = decoder.U64(); err != nil {
		return campaignState{}, err
	}
	phase, err := decoder.U8()
	if err != nil {
		return campaignState{}, err
	}
	state.Phase = CampaignPhase(phase)
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return campaignState{}, decodeErr
	} else {
		copy(state.PairID[:], value)
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return campaignState{}, decodeErr
	} else {
		copy(state.CheckpointID[:], value)
	}
	count, err := decoder.ListLength(calibration.MaximumTieObservers)
	if err != nil {
		return campaignState{}, err
	}
	state.ReceiptTails = make([]types.Hash, count)
	for index := range state.ReceiptTails {
		value, decodeErr := decoder.Fixed(types.HashSize)
		if decodeErr != nil {
			return campaignState{}, decodeErr
		}
		copy(state.ReceiptTails[index][:], value)
	}
	if state.Version == CampaignStateVersion1 {
		skippedCount, decodeErr := decoder.ListLength(calibration.MaximumTiePlanSlots)
		if decodeErr != nil {
			return campaignState{}, decodeErr
		}
		state.Skipped = make([]uint64, skippedCount)
		for index := range state.Skipped {
			sequence, sequenceErr := decoder.U64()
			if sequenceErr != nil {
				return campaignState{}, sequenceErr
			}
			state.Skipped[index] = sequence
		}
	}
	payloadBytes := len(input) - decoder.Remaining()
	checksumBytes, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return campaignState{}, err
	}
	if err := decoder.Finish(); err != nil {
		return campaignState{}, err
	}
	wantChecksum := types.DomainHash(campaignStateChecksumDomain(state.Version), input[:payloadBytes])
	if !bytes.Equal(checksumBytes, wantChecksum[:]) {
		return campaignState{}, ErrCampaignState
	}
	if err := validateCampaignState(state, plan, planID); err != nil {
		return campaignState{}, err
	}
	return state, nil
}

func encodeCampaignStatePayload(encoder *codec.Encoder, state campaignState) {
	encoder.U16(state.Version)
	encoder.Fixed(state.PlanID[:])
	encoder.U64(state.NextSequence)
	encoder.U8(uint8(state.Phase))
	encoder.Fixed(state.PairID[:])
	encoder.Fixed(state.CheckpointID[:])
	encoder.Uvarint(uint64(len(state.ReceiptTails)))
	for _, tail := range state.ReceiptTails {
		encoder.Fixed(tail[:])
	}
	if state.Version == CampaignStateVersion1 {
		encoder.Uvarint(uint64(len(state.Skipped)))
		for _, sequence := range state.Skipped {
			encoder.U64(sequence)
		}
	}
}

func validateCampaignState(state campaignState, plan calibration.TiePlan, planID types.Hash) error {
	if (state.Version != CampaignStateVersion0 && state.Version != CampaignStateVersion1) ||
		planID.IsZero() || state.PlanID != planID ||
		state.NextSequence == 0 || state.NextSequence > uint64(len(plan.Slots))+1 ||
		state.Phase > CampaignComplete {
		return ErrCampaignState
	}
	if state.Version == CampaignStateVersion0 && len(state.Skipped) != 0 {
		return ErrCampaignState
	}
	var previousSkipped uint64
	for _, sequence := range state.Skipped {
		if sequence == 0 || sequence >= state.NextSequence || sequence <= previousSkipped {
			return ErrCampaignState
		}
		previousSkipped = sequence
	}
	observerCount := 1
	if plan.Version == calibration.TiePlanVersion2 {
		observerCount = len(plan.ObserverPublicKeys)
	}
	switch state.Phase {
	case CampaignAwaitingPair:
		if state.NextSequence > uint64(len(plan.Slots)) || !state.PairID.IsZero() ||
			!state.CheckpointID.IsZero() || len(state.ReceiptTails) != 0 {
			return ErrCampaignState
		}
	case CampaignAwaitingPublication:
		if state.NextSequence > uint64(len(plan.Slots)) || state.PairID.IsZero() ||
			state.CheckpointID.IsZero() || len(state.ReceiptTails) != observerCount ||
			anyCampaignReceiptPresent(state.ReceiptTails) {
			return ErrCampaignState
		}
	case CampaignDelivering:
		if state.NextSequence > uint64(len(plan.Slots)) || state.PairID.IsZero() ||
			state.CheckpointID.IsZero() || len(state.ReceiptTails) != observerCount ||
			allCampaignReceiptsPresent(state.ReceiptTails) {
			return ErrCampaignState
		}
	case CampaignAwaitingAdvance:
		if state.NextSequence > uint64(len(plan.Slots)) || state.PairID.IsZero() ||
			state.CheckpointID.IsZero() || len(state.ReceiptTails) != observerCount ||
			!allCampaignReceiptsPresent(state.ReceiptTails) {
			return ErrCampaignState
		}
	case CampaignComplete:
		if state.NextSequence != uint64(len(plan.Slots))+1 || !state.PairID.IsZero() ||
			!state.CheckpointID.IsZero() || len(state.ReceiptTails) != 0 {
			return ErrCampaignState
		}
	default:
		return ErrCampaignState
	}
	return nil
}

func campaignStateChecksumDomain(version uint16) string {
	if version == CampaignStateVersion1 {
		return campaignStateChecksumDomainV1
	}
	return campaignStateChecksumDomainV0
}

func campaignSequenceSkipped(sequences []uint64, sequence uint64) bool {
	return len(sequences) != 0 && sequences[len(sequences)-1] == sequence
}

func anyCampaignReceiptPresent(tails []types.Hash) bool {
	for _, tail := range tails {
		if !tail.IsZero() {
			return true
		}
	}
	return false
}

func allCampaignReceiptsPresent(tails []types.Hash) bool {
	if len(tails) == 0 {
		return false
	}
	for _, tail := range tails {
		if tail.IsZero() {
			return false
		}
	}
	return true
}

func saveCampaignState(path string, encoded []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".outcomemesh-tie-campaign-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
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
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}

func readCampaignState(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, MaximumCampaignStateBytes+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaximumCampaignStateBytes {
		return nil, ErrCampaignState
	}
	return encoded, nil
}
