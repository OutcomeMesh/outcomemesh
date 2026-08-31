package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/node/tieexchange"
	"github.com/outcomemesh/outcomemesh/node/tieproducer"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

const maximumCampaignObserverRoutesBytes = 128 * 1024

type campaignObserverRoute struct {
	ObserverPublicKey [ed25519.PublicKeySize]byte
	TransportPeerID   types.Hash
	Address           string
}

func runWorkTelemetryTieCampaign(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("work-telemetry-tie-campaign", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "coordinator WorkGraph node data directory")
	transportKeyPath := flags.String("key", "", "coordinator QUIC transport Ed25519 seed file")
	coordinatorKeyPath := flags.String("coordinator-key", "", "plan coordinator Ed25519 seed file")
	planPath := flags.String("plan", "", "published signed controlled-tie plan file")
	planIDText := flags.String("plan-id", "", "externally published controlled-tie plan ID")
	coordinatorPublicKeyText := flags.String("coordinator-public-key", "", "trusted plan coordinator Ed25519 public key")
	observerPublicKeyText := flags.String("observer-public-key", "", "one trusted observer key used to bind the shared plan")
	observerRoutesPath := flags.String("observers", "", "canonical observer receipt-key, transport-ID, and address routes")
	statePath := flags.String("state", "", "crash-safe campaign state path (default under data)")
	artifactDirectory := flags.String("artifacts", "", "immutable generated pair/checkpoint directory")
	publishedDirectory := flags.String("published", "", "independent external checkpoint confirmation directory")
	publicationPoll := flags.Duration("publication-poll", time.Second, "external checkpoint polling interval")
	deliveryTimeout := flags.Duration("delivery-timeout", 2*time.Minute, "per-observer QUIC delivery timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *transportKeyPath == "" || *coordinatorKeyPath == "" || *planPath == "" ||
		*planIDText == "" || *coordinatorPublicKeyText == "" || *observerPublicKeyText == "" ||
		*observerRoutesPath == "" || *artifactDirectory == "" || *publishedDirectory == "" ||
		*publicationPoll <= 0 || *publicationPoll > time.Minute ||
		*deliveryTimeout < time.Second || *deliveryTimeout > 10*time.Minute {
		return errors.New("transport/coordinator keys, published plan binding, observer routes, separate artifact/publication directories, and bounded timeouts are required")
	}
	if *statePath == "" {
		*statePath = filepath.Join(*data, "work-tie-campaign.state")
	}
	artifactsAbsolute, err := filepath.Abs(*artifactDirectory)
	if err != nil {
		return err
	}
	publishedAbsolute, err := filepath.Abs(*publishedDirectory)
	if err != nil {
		return err
	}
	if filepath.Clean(artifactsAbsolute) == filepath.Clean(publishedAbsolute) {
		return errors.New("artifact output and external publication directories must differ")
	}
	observerPublicKey, err := parseHash(*observerPublicKeyText)
	if err != nil {
		return fmt.Errorf("observer-public-key: %w", err)
	}
	plan, binding, planID, err := loadPublishedTiePlan(
		*data, *planPath, *planIDText, *coordinatorPublicKeyText, observerPublicKey,
	)
	if err != nil {
		return err
	}
	coordinatorKey, err := loadPrivateKey(*coordinatorKeyPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(coordinatorKey.Public().(ed25519.PublicKey), plan.CoordinatorPublicKey[:]) {
		return errors.New("coordinator private key does not match the published plan")
	}
	transportKey, err := loadPrivateKey(*transportKeyPath)
	if err != nil {
		return err
	}
	transportPeerID := types.DomainHash("OMESH/p2p/ed25519/v0", transportKey.Public().(ed25519.PublicKey))
	planCoordinatorTransportID := types.DomainHash("OMESH/p2p/ed25519/v0", plan.CoordinatorPublicKey[:])
	if transportPeerID == planCoordinatorTransportID {
		return errors.New("campaign transport and plan coordinator must use separate Ed25519 keys")
	}
	routes, err := loadCampaignObserverRoutes(*observerRoutesPath, plan)
	if err != nil {
		return err
	}
	for observer, route := range routes {
		observerAsTransportID := types.DomainHash("OMESH/p2p/ed25519/v0", observer[:])
		if transportPeerID == observerAsTransportID || transportPeerID == route.TransportPeerID {
			return errors.New("campaign coordinator transport, observer transport, plan, and receipt keys must remain separate")
		}
	}
	campaign, err := tieproducer.OpenCampaign(tieproducer.CampaignConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, StatePath: *statePath,
	})
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, campaign.Close()) }()
	artifactStore, err := tieproducer.NewFileCampaignArtifacts(*artifactDirectory, plan, binding, planID)
	if err != nil {
		return err
	}
	reportingArtifacts := &reportingCampaignArtifacts{
		store: artifactStore, plan: plan, binding: binding, planID: planID,
	}
	_, nodeStore, router, _, err := openWorkNode(*data)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, nodeStore.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, router.Close()) }()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	host, err := libp2ptransport.New(ctx, transportKey, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, host.Close()) }()
	deliverer := &quicCampaignDeliverer{
		host: host, routes: routes, plan: plan, binding: binding,
		planID: planID, timeout: *deliveryTimeout,
	}
	status, err := campaign.Status()
	if err != nil {
		return err
	}
	fmt.Printf(
		"work_tie_campaign_started transport_peer_id=%s plan=%s next_sequence=%d phase=%d observers=%d state=%s artifacts=%s published=%s\n",
		host.ID(), planID, status.NextSequence, status.Phase, status.ObserverCount,
		*statePath, *artifactDirectory, *publishedDirectory,
	)
	err = tieproducer.DriveCampaign(ctx, tieproducer.CampaignDriverConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID,
		CoordinatorPrivateKey: coordinatorKey, Campaign: campaign, Source: router,
		Artifacts: reportingArtifacts,
		Publication: tieproducer.FileCampaignPublicationGate{
			Directory: *publishedDirectory, PollInterval: *publicationPoll,
		},
		Deliverer: deliverer, Clock: tieproducer.RealCampaignClock{},
	})
	if err != nil {
		return err
	}
	status, err = campaign.Status()
	if err != nil {
		return err
	}
	fmt.Printf(
		"work_tie_campaign_complete plan=%s slots=%d next_sequence=%d state=%s\n",
		planID, status.PlannedSlots, status.NextSequence, *statePath,
	)
	return nil
}

type reportingCampaignArtifacts struct {
	store   *tieproducer.FileCampaignArtifacts
	plan    calibration.TiePlan
	binding calibration.TiePlanBinding
	planID  types.Hash
}

func (store *reportingCampaignArtifacts) Store(
	pair tieproducer.Pair,
	checkpoint calibration.TiePairCheckpoint,
) error {
	if err := store.store.Store(pair, checkpoint); err != nil {
		return err
	}
	checkpointID, err := checkpoint.ID(store.plan, store.binding, store.planID)
	if err != nil {
		return err
	}
	fmt.Printf(
		"work_tie_campaign_pair_ready plan=%s sequence=%d pair=%s checkpoint=%s pair_file=%s checkpoint_file=%s\n",
		store.planID, pair.Sequence, checkpoint.PairID, checkpointID,
		store.store.PairPath(pair.Sequence), store.store.CheckpointPath(pair.Sequence),
	)
	return nil
}

func (store *reportingCampaignArtifacts) Load(
	sequence uint64,
) (tieproducer.Pair, calibration.TiePairCheckpoint, error) {
	return store.store.Load(sequence)
}

type quicCampaignDeliverer struct {
	host    *libp2ptransport.Host
	routes  map[[ed25519.PublicKeySize]byte]campaignObserverRoute
	plan    calibration.TiePlan
	binding calibration.TiePlanBinding
	planID  types.Hash
	timeout time.Duration
}

func (deliverer *quicCampaignDeliverer) Deliver(
	ctx context.Context,
	observer [ed25519.PublicKeySize]byte,
	pair tieproducer.Pair,
	checkpoint calibration.TiePairCheckpoint,
) (types.Hash, error) {
	route, exists := deliverer.routes[observer]
	if !exists {
		return types.Hash{}, tieproducer.ErrCampaignDriver
	}
	if err := checkpoint.Verify(deliverer.plan, deliverer.binding, deliverer.planID); err != nil {
		return types.Hash{}, err
	}
	pairID, err := pair.ID(deliverer.plan, deliverer.binding, deliverer.planID)
	if err != nil || checkpoint.PairID != pairID || checkpoint.Sequence != pair.Sequence {
		return types.Hash{}, errors.Join(tieproducer.ErrCampaignDriver, err)
	}
	artifact, err := pair.CanonicalBytes(deliverer.plan, deliverer.binding, deliverer.planID)
	if err != nil {
		return types.Hash{}, err
	}
	var observerHash types.Hash
	copy(observerHash[:], observer[:])
	deliveryContext, cancel := context.WithTimeout(ctx, deliverer.timeout)
	defer cancel()
	acknowledgement, remoteID, err := exchangeTiePairQUIC(
		deliveryContext, deliverer.host, route.Address, route.TransportPeerID, observerHash,
		tieexchange.Binding{PlanID: deliverer.planID, PairID: pairID, Sequence: pair.Sequence},
		artifact, deliverer.timeout,
	)
	if err != nil {
		return types.Hash{}, err
	}
	fmt.Printf(
		"work_tie_campaign_observer_ack transport_peer_id=%s observer_peer_id=%s plan=%s sequence=%d pair=%s observer=%s receipt_tail=%s\n",
		deliverer.host.ID(), remoteID, deliverer.planID, pair.Sequence,
		pairID, observerHash, acknowledgement.ReceiptTail,
	)
	return acknowledgement.ReceiptTail, nil
}

func loadCampaignObserverRoutes(
	path string,
	plan calibration.TiePlan,
) (map[[ed25519.PublicKeySize]byte]campaignObserverRoute, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, maximumCampaignObserverRoutesBytes+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > maximumCampaignObserverRoutesBytes || encoded[len(encoded)-1] != '\n' {
		return nil, errors.New("invalid campaign observer routes")
	}
	lines := strings.Split(string(encoded[:len(encoded)-1]), "\n")
	expected := plan.ObserverPublicKeys
	if plan.Version != calibration.TiePlanVersion2 {
		expected = [][ed25519.PublicKeySize]byte{plan.ObserverPublicKey}
	}
	if len(lines) != len(expected) {
		return nil, errors.New("campaign routes must contain every plan observer exactly once")
	}
	routes := make(map[[ed25519.PublicKeySize]byte]campaignObserverRoute, len(lines))
	peerIDs := make(map[types.Hash]struct{}, len(lines))
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 3 || strings.Join(fields, " ") != line || len(fields[2]) > 1024 {
			return nil, errors.New("invalid campaign observer route")
		}
		observerHash, err := parseHash(fields[0])
		if err != nil {
			return nil, fmt.Errorf("observer route %d public key: %w", index+1, err)
		}
		peerID, err := parseHash(fields[1])
		if err != nil {
			return nil, fmt.Errorf("observer route %d peer ID: %w", index+1, err)
		}
		var observer [ed25519.PublicKeySize]byte
		copy(observer[:], observerHash[:])
		if observer != expected[index] {
			return nil, errors.New("campaign observer routes are not in canonical plan order")
		}
		if _, duplicate := peerIDs[peerID]; duplicate {
			return nil, errors.New("campaign observer transport peer IDs must be unique")
		}
		peerIDs[peerID] = struct{}{}
		routes[observer] = campaignObserverRoute{
			ObserverPublicKey: observer, TransportPeerID: peerID, Address: fields[2],
		}
	}
	return routes, nil
}
