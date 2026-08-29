// Package tieproducer creates controlled equal-work sibling anchors for a
// precommitted calibration slot and admits them in the signed delivery order.
package tieproducer

import (
	"bytes"
	"context"
	"encoding/binary"
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

type MiningSource interface {
	AdmissionTime() (uint64, error)
	Tip() (storage.Tip, error)
	PrepareWork(types.Hash, uint64, []outcome.Transaction) (*workblock.Payload, workblock.Position, error)
}

// AdmissionSource keeps admission time and Submit on the same router clock so
// slot checks cannot be performed against a different clock.
type AdmissionSource interface {
	AdmissionTime() (uint64, error)
	Tip() (storage.Tip, error)
	Submit(activation.Block) (storage.Tip, error)
}

type Source interface {
	MiningSource
	AdmissionSource
}

type Config struct {
	Plan           calibration.TiePlan
	Binding        calibration.TiePlanBinding
	ExpectedPlanID types.Hash
	Sequence       uint64
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
	pair, result, err := MinePair(ctx, source, config)
	if err != nil {
		return Result{}, err
	}
	firstSelected, finalSelected, err := admitPair(source, config, pair)
	if err != nil {
		return Result{}, err
	}
	result.FirstSelected = firstSelected
	result.FinalSelected = finalSelected
	return result, nil
}

// MinePair creates a portable pair without admitting either block. This is the
// coordinator path used when observers are operated by separate parties.
func MinePair(ctx context.Context, source MiningSource, config Config) (Pair, Result, error) {
	if ctx == nil || source == nil {
		return Pair{}, Result{}, ErrConfiguration
	}
	planID, err := validateConfig(config)
	if err != nil {
		return Pair{}, Result{}, err
	}
	slot := config.Plan.Slots[config.Sequence-1]
	now, err := source.AdmissionTime()
	if err != nil {
		return Pair{}, Result{}, err
	}
	if now < slot.StartedAt || now >= slot.EndedAt {
		return Pair{}, Result{}, ErrOutsideSlot
	}
	parent, err := source.Tip()
	if err != nil {
		return Pair{}, Result{}, err
	}
	if parent.Height == ^uint64(0) || parent.Height+1 < config.Plan.ActivationHeight {
		return Pair{}, Result{}, ErrConfiguration
	}
	timestamp := slot.StartedAt
	if timestamp <= parent.Timestamp {
		if parent.Timestamp == ^uint64(0) {
			return Pair{}, Result{}, ErrConfiguration
		}
		timestamp = parent.Timestamp + 1
	}
	payload, _, err := source.PrepareWork(parent.ID, timestamp, nil)
	if err != nil {
		return Pair{}, Result{}, err
	}
	remaining := slot.EndedAt - now
	mineContext, cancel := context.WithTimeout(ctx, secondsDuration(remaining))
	defer cancel()
	results := make(chan roleResult, 2)
	go mineRole(mineContext, payload, config.Plan.TestedMiner,
		StartNonce(planID, config.Sequence, calibration.TieRoleTested), calibration.TieRoleTested, results)
	go mineRole(mineContext, payload, config.Plan.ControlMiner,
		StartNonce(planID, config.Sequence, calibration.TieRoleControl), calibration.TieRoleControl, results)

	var tested, control workminer.Result
	for completed := 0; completed < 2; completed++ {
		mined := <-results
		if mined.err != nil {
			cancel()
		}
		switch mined.role {
		case calibration.TieRoleTested:
			tested = mined.mined
		case calibration.TieRoleControl:
			control = mined.mined
		default:
			return Pair{}, Result{}, ErrPair
		}
		if mined.err != nil {
			// Still drain the second worker before returning so no mining goroutine
			// can outlive the caller or retain the payload.
			if completed == 0 {
				other := <-results
				if other.err != nil && !errors.Is(other.err, context.Canceled) {
					return Pair{}, Result{}, errors.Join(mined.err, other.err)
				}
			}
			return Pair{}, Result{}, mined.err
		}
	}
	pair := Pair{
		Version: PairVersion0, PlanID: planID, Sequence: config.Sequence,
		Tested: tested.Block, Control: control.Block,
	}
	if err := pair.Validate(config.Plan, config.Binding, config.ExpectedPlanID); err != nil {
		return Pair{}, Result{}, err
	}
	result, err := minedPairResult(config, parent, tested, control)
	if err != nil {
		return Pair{}, Result{}, err
	}
	return pair, result, nil
}

// AdmitPair is the observer-side path for a previously mined portable pair.
func AdmitPair(ctx context.Context, source Source, config Config, pair Pair) (Result, error) {
	if ctx == nil || source == nil {
		return Result{}, ErrConfiguration
	}
	if _, err := validateConfig(config); err != nil {
		return Result{}, err
	}
	if err := pair.Validate(config.Plan, config.Binding, config.ExpectedPlanID); err != nil {
		return Result{}, err
	}
	expected, _, err := MinePair(ctx, source, config)
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(expected.Tested.CanonicalBytes(), pair.Tested.CanonicalBytes()) ||
		!bytes.Equal(expected.Control.CanonicalBytes(), pair.Control.CanonicalBytes()) {
		return Result{}, ErrPair
	}
	result, err := artifactPairResult(config, pair)
	if err != nil {
		return Result{}, err
	}
	firstSelected, finalSelected, err := admitPair(source, config, pair)
	if err != nil {
		return Result{}, err
	}
	result.FirstSelected = firstSelected
	result.FinalSelected = finalSelected
	return result, nil
}

func admitPair(source AdmissionSource, config Config, pair Pair) (types.Hash, types.Hash, error) {
	slot := config.Plan.Slots[config.Sequence-1]
	admissionTime, err := source.AdmissionTime()
	if err != nil {
		return types.Hash{}, types.Hash{}, err
	}
	if admissionTime < slot.StartedAt || admissionTime >= slot.EndedAt {
		return types.Hash{}, types.Hash{}, ErrOutsideSlot
	}
	parent, err := source.Tip()
	if err != nil {
		return types.Hash{}, types.Hash{}, err
	}
	if parent.ID != pair.Tested.Header.Seal.AnchorParent || parent.Height+1 != pair.Tested.Header.Seal.Height {
		return types.Hash{}, types.Hash{}, ErrPair
	}
	first := pair.Tested
	second := pair.Control
	if slot.FirstRole == calibration.TieRoleControl {
		first, second = pair.Control, pair.Tested
	}
	firstRouted, err := activation.Work(first, config.Plan.ActivationHeight)
	if err != nil {
		return types.Hash{}, types.Hash{}, err
	}
	secondRouted, err := activation.Work(second, config.Plan.ActivationHeight)
	if err != nil {
		return types.Hash{}, types.Hash{}, err
	}
	firstTip, err := source.Submit(firstRouted)
	if err != nil {
		return types.Hash{}, types.Hash{}, fmt.Errorf("submit first precommitted role: %w", err)
	}
	secondAdmissionTime, err := source.AdmissionTime()
	if err != nil {
		return types.Hash{}, types.Hash{}, err
	}
	if secondAdmissionTime >= slot.EndedAt || secondAdmissionTime < admissionTime ||
		secondAdmissionTime-admissionTime > config.Plan.MaximumPairDelaySeconds {
		return types.Hash{}, types.Hash{}, ErrOutsideSlot
	}
	finalTip, err := source.Submit(secondRouted)
	if err != nil {
		return types.Hash{}, types.Hash{}, fmt.Errorf("submit second precommitted role: %w", err)
	}
	return firstTip.ID, finalTip.ID, nil
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

func minedPairResult(
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

func artifactPairResult(config Config, pair Pair) (Result, error) {
	testedID, testedErr := pair.Tested.Header.ID()
	controlID, controlErr := pair.Control.Header.ID()
	if testedErr != nil || controlErr != nil {
		return Result{}, ErrPair
	}
	return Result{
		Sequence: config.Sequence, ParentID: pair.Tested.Header.Seal.AnchorParent,
		Height: pair.Tested.Header.Seal.Height, FirstRole: config.Plan.Slots[config.Sequence-1].FirstRole,
		Tested: MinedAnchor{ID: testedID, WinningNonce: pair.Tested.Header.Seal.Nonce,
			IncludedShares: uint64(len(pair.Tested.Shares))},
		Control: MinedAnchor{ID: controlID, WinningNonce: pair.Control.Header.Seal.Nonce,
			IncludedShares: uint64(len(pair.Control.Shares))},
	}, nil
}

func validateConfig(config Config) (types.Hash, error) {
	if config.ExpectedPlanID.IsZero() || config.Sequence == 0 {
		return types.Hash{}, ErrConfiguration
	}
	if err := config.Plan.Verify(config.Binding); err != nil {
		return types.Hash{}, err
	}
	if config.Plan.Version != calibration.TiePlanVersion1 || config.Sequence > uint64(len(config.Plan.Slots)) {
		return types.Hash{}, ErrConfiguration
	}
	planID, err := config.Plan.ID()
	if err != nil {
		return types.Hash{}, err
	}
	if planID != config.ExpectedPlanID {
		return types.Hash{}, ErrConfiguration
	}
	return planID, nil
}

// StartNonce derives the only valid initial nonce for one planned role. The
// published plan ID and sequence make the search path immutable before the
// parent and resulting anchor IDs exist.
func StartNonce(planID types.Hash, sequence uint64, role calibration.TieTrialRole) uint64 {
	var sequenceBytes [8]byte
	binary.BigEndian.PutUint64(sequenceBytes[:], sequence)
	hash := types.DomainHash(
		"OMESH/testnet/calibration/tie-producer/start-nonce/v0",
		planID[:], sequenceBytes[:], []byte{byte(role)},
	)
	return binary.BigEndian.Uint64(hash[:8])
}

func secondsDuration(seconds uint64) time.Duration {
	return time.Duration(seconds) * time.Second
}
