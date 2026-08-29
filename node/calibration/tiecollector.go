package calibration

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
)

var (
	ErrTieCollectorConfig = errors.New("invalid controlled-tie collector configuration")
	ErrTieCollectorClosed = errors.New("controlled-tie collector is closed")
)

// A router callback is synchronous with Submit but may wait behind an earlier
// ordered callback. Delay NoPair closure briefly so a block observed inside the
// slot is not discarded merely because the writer goroutine acquired its lock
// just after the slot boundary.
const TieReceiptClosureGraceSeconds uint64 = 60

type TieAdmission struct {
	ID         types.Hash
	ParentID   types.Hash
	Height     uint64
	ObservedAt uint64
	Miner      types.Address
	SelectedID types.Hash
}

type TieCollectorConfig struct {
	Plan        TiePlan
	Binding     TiePlanBinding
	PrivateKey  ed25519.PrivateKey
	ReceiptPath string
	PendingPath string
}

type TieCollectorStatus struct {
	PlanID          types.Hash
	PlannedSlots    uint64
	ClosedSlots     uint64
	CompletedTrials uint64
	NoPairSlots     uint64
	NextSequence    uint64
	LastReceiptID   types.Hash
	Complete        bool
	InvalidCurrent  bool
}

// TieCollector turns the activation router's ordered post-commit admissions
// into one receipt per precommitted slot. Partial candidates are fsynced before
// a completed receipt, and a stale pending file is reconciled from the signed
// receipt tail after a crash.
type TieCollector struct {
	mu          sync.Mutex
	plan        TiePlan
	binding     TiePlanBinding
	planID      types.Hash
	privateKey  ed25519.PrivateKey
	receiptPath string
	pendingPath string
	receipts    []TieTrialReceipt
	aggregate   TieReceiptAggregate
	pending     tiePendingState
	lastNow     uint64
	closed      bool
}

func OpenTieCollector(config TieCollectorConfig, now uint64) (*TieCollector, error) {
	if len(config.PrivateKey) != ed25519.PrivateKeySize || config.ReceiptPath == "" ||
		config.PendingPath == "" || config.ReceiptPath == config.PendingPath || now == 0 {
		return nil, ErrTieCollectorConfig
	}
	if err := config.Plan.Verify(config.Binding); err != nil {
		return nil, err
	}
	if config.Plan.Version != TiePlanVersion1 && config.Plan.Version != TiePlanVersion2 {
		return nil, ErrTieCollectorConfig
	}
	if !bytes.Equal(config.PrivateKey.Public().(ed25519.PublicKey), config.Binding.ObserverPublicKey[:]) {
		return nil, ErrTieCollectorConfig
	}
	planID, err := config.Plan.ID()
	if err != nil {
		return nil, err
	}
	ownedPlan := config.Plan
	ownedPlan.Slots = append([]TiePlanSlot(nil), config.Plan.Slots...)
	collector := &TieCollector{
		plan: ownedPlan, binding: config.Binding, planID: planID,
		privateKey:  append(ed25519.PrivateKey(nil), config.PrivateKey...),
		receiptPath: config.ReceiptPath, pendingPath: config.PendingPath, lastNow: now,
	}
	loadedPlan, receipts, aggregate, receiptErr := LoadTieReceiptFile(config.ReceiptPath, config.Binding)
	if receiptErr == nil {
		loadedPlanID, idErr := loadedPlan.ID()
		if idErr != nil || loadedPlanID != planID {
			return nil, ErrTieCollectorConfig
		}
		collector.receipts = receipts
		collector.aggregate = aggregate
	} else if !errors.Is(receiptErr, os.ErrNotExist) {
		return nil, receiptErr
	}
	pending, pendingErr := loadTiePending(config.PendingPath, collector.plan, planID)
	switch {
	case pendingErr == nil:
		collector.pending = pending
	case errors.Is(pendingErr, os.ErrNotExist) && receiptErr != nil:
		collector.pending = newTiePending(planID, 1, types.Hash{})
		if err := saveTiePending(config.PendingPath, collector.pending, collector.plan, planID); err != nil {
			return nil, err
		}
	case errors.Is(pendingErr, os.ErrNotExist):
		return nil, ErrPending
	default:
		return nil, pendingErr
	}
	nextSequence := uint64(len(collector.receipts)) + 1
	var previousID types.Hash
	if len(collector.receipts) != 0 {
		previousID = collector.aggregate.LastReceiptID
	}
	if collector.pending.Sequence <= uint64(len(collector.receipts)) {
		collector.pending = newTiePending(planID, nextSequence, previousID)
		if err := saveTiePending(config.PendingPath, collector.pending, collector.plan, planID); err != nil {
			return nil, err
		}
	} else if collector.pending.Sequence != nextSequence || collector.pending.PreviousID != previousID {
		return nil, ErrPending
	}
	if _, err := collector.completePendingPairLocked(); err != nil {
		return nil, err
	}
	if err := collector.advanceLocked(now); err != nil {
		return nil, err
	}
	return collector, nil
}

func (collector *TieCollector) Observe(admission TieAdmission) (bool, error) {
	if collector == nil || admission.ID.IsZero() || admission.ParentID.IsZero() ||
		admission.Miner.IsZero() || admission.ObservedAt == 0 {
		return false, ErrObservation
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.closed {
		return false, ErrTieCollectorClosed
	}
	if admission.ObservedAt > collector.lastNow {
		if err := collector.advanceLocked(admission.ObservedAt); err != nil {
			return false, err
		}
	}
	if collector.completeLocked() {
		return false, nil
	}
	slot := collector.plan.Slots[collector.pending.Sequence-1]
	if admission.ObservedAt < slot.StartedAt {
		return false, nil
	}
	if admission.ObservedAt >= slot.EndedAt {
		return false, nil
	}
	var target *tieCandidate
	var role TieTrialRole
	switch admission.Miner {
	case collector.plan.TestedMiner:
		target = &collector.pending.Tested
		role = TieRoleTested
	case collector.plan.ControlMiner:
		target = &collector.pending.Control
		role = TieRoleControl
	default:
		return false, nil
	}
	candidate := tieCandidate{
		Present: true, ID: admission.ID, ParentID: admission.ParentID, Height: admission.Height,
		ObservedAt: admission.ObservedAt, SelectedID: admission.SelectedID,
	}
	if *target == candidate {
		return false, nil
	}
	if !collector.pending.Tested.Present && !collector.pending.Control.Present {
		collector.pending.FirstRole = role
		if role != slot.FirstRole {
			collector.pending.Invalid = true
		}
	}
	if target.Present {
		collector.pending.Invalid = true
	} else {
		*target = candidate
	}
	collector.pending.LatestSelectedID = admission.SelectedID
	if collector.pending.Tested.Present && collector.pending.Control.Present &&
		!validLiveTiePair(collector.pending, collector.plan) {
		collector.pending.Invalid = true
	}
	if err := saveTiePending(collector.pendingPath, collector.pending, collector.plan, collector.planID); err != nil {
		return false, err
	}
	if completed, err := collector.completePendingPairLocked(); err != nil {
		return false, err
	} else if completed {
		if err := collector.advanceLocked(collector.lastNow); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (collector *TieCollector) completePendingPairLocked() (bool, error) {
	if collector.completeLocked() || !collector.pending.Tested.Present ||
		!collector.pending.Control.Present || collector.pending.Invalid {
		return false, nil
	}
	if !validLiveTiePair(collector.pending, collector.plan) ||
		(collector.pending.LatestSelectedID != collector.pending.Tested.ID &&
			collector.pending.LatestSelectedID != collector.pending.Control.ID) {
		collector.pending.Invalid = true
		return false, saveTiePending(collector.pendingPath, collector.pending, collector.plan, collector.planID)
	}
	receipt := TieTrialReceipt{
		Version: collector.receiptVersion(), Sequence: collector.pending.Sequence, Status: TieTrialCompleted,
		PreviousID: collector.pending.PreviousID, ParentID: collector.pending.Tested.ParentID,
		Height: collector.pending.Tested.Height, TestedAnchorID: collector.pending.Tested.ID,
		ControlAnchorID:   collector.pending.Control.ID,
		TestedObservedAt:  collector.pending.Tested.ObservedAt,
		ControlObservedAt: collector.pending.Control.ObservedAt,
		SelectedAnchorID:  collector.pending.LatestSelectedID,
	}
	if collector.pending.FirstRole == TieRoleTested {
		receipt.FirstObservedAnchorID = collector.pending.Tested.ID
	} else {
		receipt.FirstObservedAnchorID = collector.pending.Control.ID
	}
	if err := collector.appendReceiptLocked(receipt); err != nil {
		return false, err
	}
	return true, nil
}

func (collector *TieCollector) Advance(now uint64) error {
	if collector == nil {
		return ErrTieCollectorConfig
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.closed {
		return ErrTieCollectorClosed
	}
	return collector.advanceLocked(now)
}

func (collector *TieCollector) Status() (TieCollectorStatus, error) {
	if collector == nil {
		return TieCollectorStatus{}, ErrTieCollectorConfig
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.closed {
		return TieCollectorStatus{}, ErrTieCollectorClosed
	}
	return TieCollectorStatus{
		PlanID: collector.planID, PlannedSlots: uint64(len(collector.plan.Slots)),
		ClosedSlots: uint64(len(collector.receipts)), CompletedTrials: collector.aggregate.CompletedTrials,
		NoPairSlots: collector.aggregate.NoPairSlots, NextSequence: collector.pending.Sequence,
		LastReceiptID: collector.aggregate.LastReceiptID, Complete: collector.completeLocked(),
		InvalidCurrent: collector.pending.Invalid,
	}, nil
}

func (collector *TieCollector) Close(now uint64) error {
	if collector == nil {
		return ErrTieCollectorConfig
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.closed {
		return ErrTieCollectorClosed
	}
	err := collector.advanceLocked(now)
	collector.closed = true
	return err
}

func (collector *TieCollector) advanceLocked(now uint64) error {
	if now < collector.lastNow {
		return ErrClock
	}
	collector.lastNow = now
	for !collector.completeLocked() {
		slot := collector.plan.Slots[collector.pending.Sequence-1]
		if now < slot.EndedAt || now-slot.EndedAt < TieReceiptClosureGraceSeconds {
			return nil
		}
		receipt := TieTrialReceipt{
			Version: collector.receiptVersion(), Sequence: collector.pending.Sequence,
			Status: TieTrialNoPair, PreviousID: collector.pending.PreviousID,
		}
		if err := collector.appendReceiptLocked(receipt); err != nil {
			return err
		}
	}
	return nil
}

func (collector *TieCollector) appendReceiptLocked(unsigned TieTrialReceipt) error {
	receipt, err := SignTieTrialReceipt(collector.privateKey, unsigned, collector.plan)
	if err != nil {
		return err
	}
	next := append(append([]TieTrialReceipt(nil), collector.receipts...), receipt)
	encoded, err := encodeTieReceiptManifest(collector.plan, next)
	if err != nil {
		return err
	}
	if err := savePrivateFile(collector.receiptPath, ".outcomemesh-tie-receipts-*", encoded); err != nil {
		return err
	}
	aggregate := collector.aggregate
	if len(collector.receipts) == 0 {
		aggregate = TieReceiptAggregate{PlanID: collector.planID, PlannedSlots: uint64(len(collector.plan.Slots))}
	}
	identifier := types.DomainHash(receipt.idDomain(), receipt.CanonicalBytes())
	if aggregate.ReceiptCount == 0 {
		aggregate.FirstReceiptID = identifier
	}
	aggregate.LastReceiptID = identifier
	aggregate.ReceiptCount++
	if receipt.Status == TieTrialCompleted {
		aggregate.CompletedTrials++
		adopted, adoptedErr := receipt.Adopted()
		if adoptedErr != nil {
			return adoptedErr
		}
		if adopted {
			aggregate.TestedAdoptions++
		}
	} else {
		aggregate.NoPairSlots++
	}
	aggregate.ConservativeAdoptions = aggregate.TestedAdoptions + aggregate.NoPairSlots
	aggregate.Complete = aggregate.ReceiptCount == aggregate.PlannedSlots
	collector.receipts = next
	collector.aggregate = aggregate
	collector.pending = newTiePending(collector.planID, uint64(len(next))+1, aggregate.LastReceiptID)
	return saveTiePending(collector.pendingPath, collector.pending, collector.plan, collector.planID)
}

func (collector *TieCollector) completeLocked() bool {
	return len(collector.receipts) == len(collector.plan.Slots)
}

func (collector *TieCollector) receiptVersion() uint16 {
	if collector.plan.Version == TiePlanVersion2 {
		return TieReceiptVersion2
	}
	return TieReceiptVersion1
}

func validLiveTiePair(pending tiePendingState, plan TiePlan) bool {
	return !pending.Invalid && pending.Tested.Present && pending.Control.Present &&
		pending.Tested.ID != pending.Control.ID && pending.Tested.ParentID == pending.Control.ParentID &&
		pending.Tested.Height == pending.Control.Height &&
		absoluteDifference(pending.Tested.ObservedAt, pending.Control.ObservedAt) <= plan.MaximumPairDelaySeconds
}
