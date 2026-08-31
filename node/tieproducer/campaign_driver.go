package tieproducer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

var ErrCampaignDriver = errors.New("invalid controlled-tie campaign driver")

type CampaignArtifactStore interface {
	Store(Pair, calibration.TiePairCheckpoint) error
	Load(sequence uint64) (Pair, calibration.TiePairCheckpoint, error)
}

type CampaignPublicationGate interface {
	WaitPublished(context.Context, uint64, types.Hash) error
}

type CampaignDeliverer interface {
	Deliver(
		context.Context,
		[ed25519.PublicKeySize]byte,
		Pair,
		calibration.TiePairCheckpoint,
	) (types.Hash, error)
}

type CampaignClock interface {
	WaitUntil(context.Context, uint64) error
}

type CampaignDriverConfig struct {
	Plan                  calibration.TiePlan
	Binding               calibration.TiePlanBinding
	ExpectedPlanID        types.Hash
	CoordinatorPrivateKey ed25519.PrivateKey
	Campaign              *Campaign
	Source                Source
	Artifacts             CampaignArtifactStore
	Publication           CampaignPublicationGate
	Deliverer             CampaignDeliverer
	Clock                 CampaignClock
}

// DriveCampaign runs every successful slot through the durable campaign state
// machine. It can be called again after any error or process crash: completed
// transitions are loaded from Campaign and only missing work is repeated.
func DriveCampaign(ctx context.Context, config CampaignDriverConfig) error {
	if ctx == nil || config.Campaign == nil || config.Source == nil || config.Artifacts == nil ||
		config.Publication == nil || config.Deliverer == nil || config.Clock == nil ||
		len(config.CoordinatorPrivateKey) != ed25519.PrivateKeySize || config.ExpectedPlanID.IsZero() {
		return ErrCampaignDriver
	}
	if err := config.Plan.Verify(config.Binding); err != nil {
		return err
	}
	if config.Plan.Version != calibration.TiePlanVersion1 &&
		config.Plan.Version != calibration.TiePlanVersion2 {
		return ErrCampaignDriver
	}
	planID, err := config.Plan.ID()
	if err != nil {
		return err
	}
	if planID != config.ExpectedPlanID ||
		!equalPublicKey(config.CoordinatorPrivateKey.Public().(ed25519.PublicKey), config.Plan.CoordinatorPublicKey) {
		return ErrCampaignDriver
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		status, err := config.Campaign.Status()
		if err != nil {
			return err
		}
		if status.PlanID != planID || status.PlannedSlots != uint64(len(config.Plan.Slots)) ||
			status.NextSequence == 0 || status.NextSequence > uint64(len(config.Plan.Slots))+1 {
			return ErrCampaignDriver
		}
		if status.Phase == CampaignComplete {
			return nil
		}
		sequence := status.NextSequence
		switch status.Phase {
		case CampaignAwaitingPair:
			slot := config.Plan.Slots[sequence-1]
			if err := config.Clock.WaitUntil(ctx, slot.StartedAt); err != nil {
				return err
			}
			pair, _, err := MinePair(ctx, config.Source, Config{
				Plan: config.Plan, Binding: config.Binding,
				ExpectedPlanID: planID, Sequence: sequence,
			})
			if err != nil {
				return err
			}
			pairID, err := pair.ID(config.Plan, config.Binding, planID)
			if err != nil {
				return err
			}
			checkpoint, err := calibration.SignTiePairCheckpoint(
				config.CoordinatorPrivateKey, config.Plan, config.Binding,
				planID, sequence, pairID,
			)
			if err != nil {
				return err
			}
			if err := config.Artifacts.Store(pair, checkpoint); err != nil {
				return err
			}
			if err := config.Campaign.StagePair(pair, checkpoint); err != nil {
				return err
			}
		case CampaignAwaitingPublication:
			if _, _, err := loadCampaignArtifact(config, status); err != nil {
				return err
			}
			if err := config.Publication.WaitPublished(ctx, sequence, status.CheckpointID); err != nil {
				return err
			}
			if err := config.Campaign.ConfirmPublication(sequence, status.CheckpointID); err != nil {
				return err
			}
		case CampaignDelivering:
			pair, checkpoint, err := loadCampaignArtifact(config, status)
			if err != nil {
				return err
			}
			if err := deliverCampaignObservers(ctx, config, status, pair, checkpoint); err != nil {
				return err
			}
		case CampaignAwaitingAdvance:
			pair, _, err := loadCampaignArtifact(config, status)
			if err != nil {
				return err
			}
			if err := ensureCampaignLocalAdvance(config.Source, config, pair); err != nil {
				return err
			}
			if err := config.Campaign.Advance(sequence); err != nil {
				return err
			}
		default:
			return ErrCampaignDriver
		}
	}
}

type campaignDeliveryResult struct {
	observer [ed25519.PublicKeySize]byte
	tail     types.Hash
	err      error
}

func deliverCampaignObservers(
	ctx context.Context,
	config CampaignDriverConfig,
	status CampaignStatus,
	pair Pair,
	checkpoint calibration.TiePairCheckpoint,
) error {
	observers := campaignObservers(config.Plan)
	if len(status.ObserverReceiptTails) != len(observers) {
		return ErrCampaignDriver
	}
	missing := make([][ed25519.PublicKeySize]byte, 0, len(observers))
	for index, observer := range observers {
		if status.ObserverReceiptTails[index].IsZero() {
			missing = append(missing, observer)
		}
	}
	if len(missing) == 0 {
		return ErrCampaignDriver
	}
	results := make(chan campaignDeliveryResult, len(missing))
	for _, observer := range missing {
		observer := observer
		go func() {
			tail, err := config.Deliverer.Deliver(ctx, observer, pair, checkpoint)
			results <- campaignDeliveryResult{observer: observer, tail: tail, err: err}
		}()
	}
	var resultErr error
	for range missing {
		result := <-results
		if result.err != nil {
			resultErr = errors.Join(resultErr, result.err)
			continue
		}
		if result.tail.IsZero() {
			resultErr = errors.Join(resultErr, ErrCampaignDriver)
			continue
		}
		if err := config.Campaign.Acknowledge(
			status.NextSequence, result.observer, result.tail,
		); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}
	return resultErr
}

type RealCampaignClock struct{}

func (RealCampaignClock) WaitUntil(ctx context.Context, unixSeconds uint64) error {
	if ctx == nil || unixSeconds == 0 {
		return ErrCampaignDriver
	}
	for {
		now := time.Now().Unix()
		if now < 0 {
			return ErrCampaignDriver
		}
		if uint64(now) >= unixSeconds {
			return nil
		}
		remaining := unixSeconds - uint64(now)
		if remaining > 60 {
			remaining = 60
		}
		timer := time.NewTimer(time.Duration(remaining) * time.Second)
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

func loadCampaignArtifact(
	config CampaignDriverConfig,
	status CampaignStatus,
) (Pair, calibration.TiePairCheckpoint, error) {
	pair, checkpoint, err := config.Artifacts.Load(status.NextSequence)
	if err != nil {
		return Pair{}, calibration.TiePairCheckpoint{}, err
	}
	if err := pair.Validate(config.Plan, config.Binding, config.ExpectedPlanID); err != nil {
		return Pair{}, calibration.TiePairCheckpoint{}, err
	}
	if err := checkpoint.Verify(config.Plan, config.Binding, config.ExpectedPlanID); err != nil {
		return Pair{}, calibration.TiePairCheckpoint{}, err
	}
	pairID, err := pair.ID(config.Plan, config.Binding, config.ExpectedPlanID)
	if err != nil {
		return Pair{}, calibration.TiePairCheckpoint{}, err
	}
	checkpointID, err := checkpoint.ID(config.Plan, config.Binding, config.ExpectedPlanID)
	if err != nil {
		return Pair{}, calibration.TiePairCheckpoint{}, err
	}
	if pair.Sequence != status.NextSequence || checkpoint.Sequence != status.NextSequence ||
		checkpoint.PairID != pairID || status.PairID != pairID || status.CheckpointID != checkpointID {
		return Pair{}, calibration.TiePairCheckpoint{}, ErrCampaignDriver
	}
	return pair, checkpoint, nil
}

func ensureCampaignLocalAdvance(source Source, config CampaignDriverConfig, pair Pair) error {
	tip, err := source.Tip()
	if err != nil {
		return err
	}
	testedID, testedErr := pair.Tested.Header.ID()
	controlID, controlErr := pair.Control.Header.ID()
	if testedErr != nil || controlErr != nil {
		return ErrCampaignDriver
	}
	height := pair.Tested.Header.Seal.Height
	if tip.Height == height && (tip.ID == testedID || tip.ID == controlID) {
		return nil
	}
	if tip.ID != pair.Tested.Header.Seal.AnchorParent || tip.Height == ^uint64(0) || tip.Height+1 != height {
		return ErrCampaignDriver
	}
	_, _, err = admitPair(source, Config{
		Plan: config.Plan, Binding: config.Binding,
		ExpectedPlanID: config.ExpectedPlanID, Sequence: pair.Sequence,
	}, pair)
	return err
}

func campaignObservers(plan calibration.TiePlan) [][ed25519.PublicKeySize]byte {
	if plan.Version == calibration.TiePlanVersion2 {
		return append([][ed25519.PublicKeySize]byte(nil), plan.ObserverPublicKeys...)
	}
	return [][ed25519.PublicKeySize]byte{plan.ObserverPublicKey}
}

func equalPublicKey(publicKey ed25519.PublicKey, expected [ed25519.PublicKeySize]byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	for index := range expected {
		if publicKey[index] != expected[index] {
			return false
		}
	}
	return true
}
