package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/discovery"
	"github.com/outcomemesh/outcomemesh/node/peers"
	"github.com/outcomemesh/outcomemesh/node/routing"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workround"
)

const workAutoPeerProbeTimeout = 10 * time.Second

type workAutoPeerConfig struct {
	Count            int
	AttemptLimit     int
	ActivationHeight uint64
	ASNMapPath       string
	ASNMaxAge        time.Duration
	MaxPerASN        int
}

func selectAutomaticWorkPeers(
	ctx context.Context,
	data string,
	networkID uint32,
	host *libp2ptransport.Host,
	round *workround.Round,
	manager *peers.Manager,
	excluded []workPeerTarget,
	config workAutoPeerConfig,
) ([]workPeerTarget, []routing.Result, error) {
	if ctx == nil || data == "" || networkID == 0 || host == nil || round == nil || manager == nil ||
		config.Count <= 0 || config.Count > maxWorkMiningPeers || config.AttemptLimit < config.Count ||
		config.AttemptLimit > discovery.MaxBookRecords || config.ActivationHeight == 0 || config.ASNMapPath == "" ||
		config.ASNMaxAge <= 0 || config.ASNMaxAge > routing.MaxASNTableAge ||
		config.MaxPerASN <= 0 || config.MaxPerASN > discovery.MaxBookRecords {
		return nil, nil, errors.New("invalid automatic WorkGraph peer selection")
	}
	now := func() uint64 {
		current := time.Now().Unix()
		if current < 0 {
			return 0
		}
		return uint64(current)
	}
	book, err := openPeerBook(data, networkID, now())
	if err != nil {
		return nil, nil, err
	}
	asnTable, err := routing.NewManagedASNTable(config.ASNMapPath, config.ASNMaxAge, time.Now)
	if err != nil {
		return nil, nil, err
	}
	policy := routing.DefaultPolicy()
	policy.ASNResolver = asnTable
	policy.MaxPerASN = config.MaxPerASN
	router, err := routing.NewWithPolicy(book, manager, host.ID(), now, policy)
	if err != nil {
		return nil, nil, err
	}
	seen := make(map[types.Hash]struct{}, len(excluded)+config.Count)
	for _, target := range excluded {
		seen[target.id] = struct{}{}
	}
	selected := make([]workPeerTarget, 0, config.Count)
	results := router.RunUntil(
		ctx, config.AttemptLimit, config.Count,
		func(record discovery.Record) bool {
			if !record.Supports(discovery.FeatureWorkGraphV1, config.ActivationHeight) {
				return false
			}
			id, err := record.PeerID()
			if err != nil {
				return false
			}
			if _, duplicate := seen[id]; duplicate {
				return false
			}
			return len(workPeerTargetsFromRecord(record)) > 0
		},
		func(connectorContext context.Context, record discovery.Record) error {
			candidates := workPeerTargetsFromRecord(record)
			var failures []error
			for _, target := range candidates {
				probeContext, cancel := context.WithTimeout(connectorContext, workAutoPeerProbeTimeout)
				started := time.Now()
				stream, peerID, err := host.OpenWorkGraphStream(probeContext, target.address, &target.id)
				if err != nil {
					cancel()
					failures = append(failures, err)
					continue
				}
				stopReset := context.AfterFunc(probeContext, func() { _ = stream.Reset() })
				if err := manager.Acquire(peerID); err != nil {
					stopReset()
					cancel()
					_ = stream.Reset()
					failures = append(failures, err)
					continue
				}
				limited := &peerLimitedStream{Stream: stream, manager: manager, peerID: peerID}
				err = round.Probe(probeContext, limited)
				manager.Release(peerID)
				stopReset()
				cancel()
				if err != nil {
					failures = append(failures, err)
					continue
				}
				if err := manager.ObserveLatency(peerID, time.Since(started)); err != nil {
					return err
				}
				selected = append(selected, target)
				seen[target.id] = struct{}{}
				return nil
			}
			if len(failures) == 0 {
				return errors.New("peer has no direct QUIC-v1 WorkGraph address")
			}
			return errors.Join(failures...)
		},
	)
	if len(selected) != config.Count {
		return nil, results, fmt.Errorf(
			"automatic WorkGraph selection found %d/%d compatible peers after %d attempts",
			len(selected), config.Count, len(results),
		)
	}
	return selected, results, nil
}

func workPeerTargetsFromRecord(record discovery.Record) []workPeerTarget {
	id, err := record.PeerID()
	if err != nil {
		return nil
	}
	result := make([]workPeerTarget, 0, len(record.Addresses))
	for _, address := range record.Addresses {
		derived, err := libp2ptransport.PeerIDFromAddress(address)
		if err == nil && derived == id {
			result = append(result, workPeerTarget{address: address, id: id})
		}
	}
	return result
}
