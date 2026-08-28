package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/chainsession"
	"github.com/outcomemesh/outcomemesh/node/discovery"
	"github.com/outcomemesh/outcomemesh/node/peers"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/wire"
)

const (
	workDiscoveryLifetime        = time.Hour
	workDiscoveryRefreshInterval = 30 * time.Minute
	maxWorkDiscoverySuccesses    = 3
)

const workDiscoveryFeatures = discovery.FeatureVersionedChainV1 |
	discovery.FeatureWorkGraphV1 |
	discovery.FeatureChainNotifyV1 |
	discovery.FeaturePeerExchangeV1

type workDiscoveryRefreshResult struct {
	PeerID  types.Hash
	Records int
	Err     error
}

func workDiscoverySuggestedSequence() uint64 {
	value := time.Now().UnixNano()
	if value <= 0 {
		return 1
	}
	return uint64(value)
}

func publishWorkDiscoveryRecord(
	book *discovery.Book,
	privateKey ed25519.PrivateKey,
	self types.Hash,
	networkID uint32,
	activationHeight uint64,
	addresses []string,
	now uint64,
	suggestedSequence uint64,
) (uint64, error) {
	if book == nil || len(privateKey) != ed25519.PrivateKeySize || self.IsZero() ||
		networkID == 0 || activationHeight == 0 || now == 0 ||
		now > ^uint64(0)-uint64(workDiscoveryLifetime/time.Second) {
		return 0, errors.New("invalid WorkGraph discovery publication")
	}
	if suggestedSequence == 0 {
		suggestedSequence = now
	}
	sequence, err := book.NextSequence(self, suggestedSequence)
	if err != nil {
		return 0, err
	}
	record, err := discovery.SignActivation(
		privateKey, networkID, sequence, now+uint64(workDiscoveryLifetime/time.Second),
		activationHeight, workDiscoveryFeatures, addresses,
	)
	if err != nil {
		return 0, err
	}
	if err := book.MergeBatch([]discovery.Record{record}, now); err != nil {
		return 0, err
	}
	return sequence, nil
}

func renewWorkDiscoveryRecords(
	ctx context.Context,
	data string,
	book *discovery.Book,
	privateKey ed25519.PrivateKey,
	self types.Hash,
	networkID uint32,
	activationHeight uint64,
	addresses []string,
) <-chan error {
	return renewWorkDiscoveryRecordsAt(
		ctx, data, book, privateKey, self, networkID, activationHeight, addresses,
		workDiscoveryRefreshInterval,
	)
}

func renewWorkDiscoveryRecordsAt(
	ctx context.Context,
	data string,
	book *discovery.Book,
	privateKey ed25519.PrivateKey,
	self types.Hash,
	networkID uint32,
	activationHeight uint64,
	addresses []string,
	interval time.Duration,
) <-chan error {
	result := make(chan error, 1)
	go func() {
		defer close(result)
		if interval <= 0 {
			result <- errors.New("invalid WorkGraph discovery renewal interval")
			return
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := unixNow()
				if _, err := publishWorkDiscoveryRecord(
					book, privateKey, self, networkID, activationHeight, addresses,
					now, workDiscoverySuggestedSequence(),
				); err != nil {
					result <- err
					return
				}
				if err := savePeerBook(data, book, now); err != nil {
					result <- err
					return
				}
			}
		}
	}()
	return result
}

func refreshWorkPeerBook(
	ctx context.Context,
	data string,
	networkID uint32,
	activationHeight uint64,
	host *libp2ptransport.Host,
	chainSession *chainsession.Node,
	manager *peers.Manager,
	book *discovery.Book,
	explicit []workPeerTarget,
	attemptLimit int,
) ([]workDiscoveryRefreshResult, error) {
	if ctx == nil || data == "" || networkID == 0 || activationHeight == 0 || host == nil ||
		chainSession == nil || manager == nil || book == nil || attemptLimit <= 0 ||
		attemptLimit > discovery.MaxBookRecords {
		return nil, errors.New("invalid WorkGraph peerbook refresh")
	}
	type candidate struct {
		id        types.Hash
		addresses []string
	}
	queue := make([]candidate, 0, len(explicit)+wire.MaxPeerRecords)
	queued := make(map[types.Hash]struct{}, len(explicit)+wire.MaxPeerRecords)
	appendTarget := func(target workPeerTarget) {
		if target.id.IsZero() || target.id == host.ID() || target.address == "" {
			return
		}
		if _, exists := queued[target.id]; exists {
			return
		}
		queued[target.id] = struct{}{}
		queue = append(queue, candidate{id: target.id, addresses: []string{target.address}})
	}
	appendRecord := func(record discovery.Record) {
		if !record.Supports(
			discovery.FeatureVersionedChainV1|discovery.FeaturePeerExchangeV1,
			activationHeight,
		) {
			return
		}
		id, err := record.PeerID()
		if err != nil || id == host.ID() {
			return
		}
		if _, exists := queued[id]; exists {
			return
		}
		targets := workPeerTargetsFromRecord(record)
		addresses := make([]string, 0, len(targets))
		for _, target := range targets {
			addresses = append(addresses, target.address)
		}
		if len(addresses) == 0 {
			return
		}
		queued[id] = struct{}{}
		queue = append(queue, candidate{id: id, addresses: addresses})
	}
	for _, target := range explicit {
		appendTarget(target)
	}
	now := unixNow()
	for _, record := range book.List(now, discovery.MaxBookRecords) {
		appendRecord(record)
	}

	results := make([]workDiscoveryRefreshResult, 0, min(attemptLimit, len(queue)))
	successes := 0
	for len(queue) > 0 && len(results) < attemptLimit && successes < maxWorkDiscoverySuccesses {
		current := queue[0]
		queue = queue[1:]
		result := workDiscoveryRefreshResult{PeerID: current.id}
		var failures []error
		for _, address := range current.addresses {
			requestContext, cancel := context.WithTimeout(ctx, workAutoPeerProbeTimeout)
			started := time.Now()
			stream, peerID, err := host.OpenVersionedChainStream(requestContext, address, &current.id)
			if err != nil {
				cancel()
				failures = append(failures, err)
				continue
			}
			stopReset := context.AfterFunc(requestContext, func() { _ = stream.Reset() })
			if err := manager.Acquire(peerID); err != nil {
				stopReset()
				cancel()
				_ = stream.Reset()
				failures = append(failures, err)
				continue
			}
			limited := &peerLimitedStream{Stream: stream, manager: manager, peerID: peerID}
			records, discoverErr := chainSession.Discover(requestContext, limited, wire.MaxPeerRecords)
			manager.Release(peerID)
			stopReset()
			cancel()
			recordPeerSession(manager, peerID, discoverErr)
			if discoverErr != nil {
				failures = append(failures, discoverErr)
				continue
			}
			if err := manager.ObserveLatency(peerID, time.Since(started)); err != nil {
				return results, err
			}
			result.Records = len(records)
			for _, record := range records {
				appendRecord(record)
			}
			if err := savePeerBook(data, book, unixNow()); err != nil {
				return results, err
			}
			successes++
			failures = nil
			break
		}
		if len(failures) > 0 {
			result.Err = errors.Join(failures...)
		}
		results = append(results, result)
	}
	return results, nil
}
