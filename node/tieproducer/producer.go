// Package tieproducer creates controlled equal-work sibling anchors for a
// precommitted calibration slot and admits them in the signed delivery order.
package tieproducer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/node/workminer"
	"github.com/outcomemesh/outcomemesh/node/workround"
	"github.com/outcomemesh/outcomemesh/node/worksession"
	"github.com/outcomemesh/outcomemesh/storage"
)

var (
	ErrConfiguration = errors.New("invalid controlled-tie producer configuration")
	ErrOutsideSlot   = errors.New("controlled-tie producer is outside the planned slot")
	ErrPair          = errors.New("controlled-tie producer did not create an exact sibling pair")
)

// Source is the exact activation-router surface used by a producer. Admission
// time and Submit must come from the same router clock so slot checks cannot be
// performed against a different clock.
type Source interface {
	AdmissionTime() (uint64, error)
	Tip() (storage.Tip, error)
	PrepareWork(types.Hash, uint64, []outcome.Transaction) (*workblock.Payload, workblock.Position, error)
	Submit(activation.Block) (storage.Tip, error)
}

type Config struct {
	Plan              calibration.TiePlan
	Binding           calibration.TiePlanBinding
	ExpectedPlanID    types.Hash
	Sequence          uint64
	TestedStartNonce  uint64
	ControlStartNonce uint64
}

type MinedAnchor struct {
	ID                 types.Hash
	WinningNonce       uint64
	WeakShares         uint64
	IncludedShares     uint64
	CapacityRejections uint64
}

type Result struct {
	Sequence      uint64
	ParentID      types.Hash
	Height        uint64
	FirstRole     calibration.TieTrialRole
	Tested        MinedAnchor
	Control       MinedAnchor
	FirstSelected types.Hash
	FinalSelected types.Hash
}

type roleResult struct {
	role  calibration.TieTrialRole
	mined workminer.Result
	err   error
}

// Produce mines both role-labelled anchors from two isolated work pools over
// one immutable payload. Neither anchor is submitted until both exist. The only
// branch that determines submission order reads the signed slot FirstRole; IDs
// are never compared, sorted, or used to choose an order.
func Produce(ctx context.Context, source Source, config Config) (Result, error) {
	if ctx == nil || source == nil || config.ExpectedPlanID.IsZero() || config.Sequence == 0 {
		return Result{}, ErrConfiguration
	}
	if err := config.Plan.Verify(config.Binding); err != nil {
		return Result{}, err
	}
	if config.Plan.Version != calibration.TiePlanVersion1 || config.Sequence > uint64(len(config.Plan.Slots)) {
		return Result{}, ErrConfiguration
	}
	planID, err := config.Plan.ID()
	if err != nil {
		return Result{}, err
	}
	if planID != config.ExpectedPlanID {
		return Result{}, ErrConfiguration
	}
	slot := config.Plan.Slots[config.Sequence-1]
	now, err := source.AdmissionTime()
	if err != nil {
		return Result{}, err
	}
	if now < slot.StartedAt || now >= slot.EndedAt {
		return Result{}, ErrOutsideSlot
	}
	parent, err := source.Tip()
	if err != nil {
		return Result{}, err
	}
	if parent.Height == ^uint64(0) || parent.Height+1 < config.Plan.ActivationHeight {
		return Result{}, ErrConfiguration
	}
	timestamp := now
	if timestamp <= parent.Timestamp {
		if parent.Timestamp == ^uint64(0) {
			return Result{}, ErrConfiguration
		}
		timestamp = parent.Timestamp + 1
	}
	payload, _, err := source.PrepareWork(parent.ID, timestamp, nil)
	if err != nil {
		return Result{}, err
	}
	remaining := slot.EndedAt - now
	mineContext, cancel := context.WithTimeout(ctx, secondsDuration(remaining))
	defer cancel()
	pair := make(chan roleResult, 2)
	go mineRole(mineContext, payload, config.Plan.TestedMiner, config.TestedStartNonce, calibration.TieRoleTested, pair)
	go mineRole(mineContext, payload, config.Plan.ControlMiner, config.ControlStartNonce, calibration.TieRoleControl, pair)

	var tested, control workminer.Result
	for completed := 0; completed < 2; completed++ {
		mined := <-pair
		if mined.err != nil {
			cancel()
		}
		switch mined.role {
		case calibration.TieRoleTested:
			tested = mined.mined
		case calibration.TieRoleControl:
			control = mined.mined
		default:
			return Result{}, ErrPair
		}
		if mined.err != nil {
			// Still drain the second worker before returning so no mining goroutine
			// can outlive the caller or retain the payload.
			if completed == 0 {
				other := <-pair
				if other.err != nil && !errors.Is(other.err, context.Canceled) {
					return Result{}, errors.Join(mined.err, other.err)
				}
			}
			return Result{}, mined.err
		}
	}

	result, err := validatePair(config, parent, tested, control)
	if err != nil {
		return Result{}, err
	}
	admissionTime, err := source.AdmissionTime()
	if err != nil {
		return Result{}, err
	}
	if admissionTime < slot.StartedAt || admissionTime >= slot.EndedAt {
		return Result{}, ErrOutsideSlot
	}

	first := tested.Block
	second := control.Block
	if slot.FirstRole == calibration.TieRoleControl {
		first, second = control.Block, tested.Block
	}
	firstRouted, err := activation.Work(first, config.Plan.ActivationHeight)
	if err != nil {
		return Result{}, err
	}
	secondRouted, err := activation.Work(second, config.Plan.ActivationHeight)
	if err != nil {
		return Result{}, err
	}
	firstTip, err := source.Submit(firstRouted)
	if err != nil {
		return Result{}, fmt.Errorf("submit first precommitted role: %w", err)
	}
	secondAdmissionTime, err := source.AdmissionTime()
	if err != nil {
		return Result{}, err
	}
	if secondAdmissionTime >= slot.EndedAt || secondAdmissionTime < admissionTime ||
		secondAdmissionTime-admissionTime > config.Plan.MaximumPairDelaySeconds {
		return Result{}, ErrOutsideSlot
	}
	finalTip, err := source.Submit(secondRouted)
	if err != nil {
		return Result{}, fmt.Errorf("submit second precommitted role: %w", err)
	}
	result.FirstSelected = firstTip.ID
	result.FinalSelected = finalTip.ID
	return result, nil
}

func mineRole(
	ctx context.Context,
	payload *workblock.Payload,
	miner types.Address,
	startNonce uint64,
	role calibration.TieTrialRole,
	result chan<- roleResult,
) {
	round, err := workround.New(payload, worksession.DefaultConfig())
	if err != nil {
		result <- roleResult{role: role, err: err}
		return
	}
	inclusionRoot, err := workgraph.InclusionRoot(nil)
	if err != nil {
		result <- roleResult{role: role, err: err}
		return
	}
	mined, err := round.Mine(ctx, miner, inclusionRoot, startNonce, nil)
	result <- roleResult{role: role, mined: mined, err: err}
}

func validatePair(
	config Config,
	parent storage.Tip,
	tested workminer.Result,
	control workminer.Result,
) (Result, error) {
	testedID, testedErr := tested.Block.Header.ID()
	controlID, controlErr := control.Block.Header.ID()
	if testedErr != nil || controlErr != nil || testedID.IsZero() || controlID.IsZero() || testedID == controlID {
		return Result{}, ErrPair
	}
	testedSeal := tested.Block.Header.Seal
	controlSeal := control.Block.Header.Seal
	if testedSeal.Miner != config.Plan.TestedMiner || controlSeal.Miner != config.Plan.ControlMiner ||
		testedSeal.AnchorParent != parent.ID || controlSeal.AnchorParent != parent.ID ||
		testedSeal.Height != parent.Height+1 || controlSeal.Height != parent.Height+1 ||
		testedSeal.Height != controlSeal.Height || testedSeal.Timestamp != controlSeal.Timestamp ||
		testedSeal.PayloadRoot != controlSeal.PayloadRoot {
		return Result{}, ErrPair
	}
	return Result{
		Sequence: config.Sequence, ParentID: parent.ID, Height: testedSeal.Height,
		FirstRole: config.Plan.Slots[config.Sequence-1].FirstRole,
		Tested: MinedAnchor{
			ID: testedID, WinningNonce: tested.WinningNonce, WeakShares: tested.WeakShares,
			IncludedShares: uint64(len(tested.Block.Shares)), CapacityRejections: tested.CapacityRejections,
		},
		Control: MinedAnchor{
			ID: controlID, WinningNonce: control.WinningNonce, WeakShares: control.WeakShares,
			IncludedShares: uint64(len(control.Block.Shares)), CapacityRejections: control.CapacityRejections,
		},
	}, nil
}

func secondsDuration(seconds uint64) time.Duration {
	return time.Duration(seconds) * time.Second
}
