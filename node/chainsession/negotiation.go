package chainsession

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/storage"
)

var (
	ErrConfiguration = errors.New("invalid versioned chain session configuration")
	ErrNetwork       = errors.New("versioned chain peer belongs to a different network")
	ErrGenesis       = errors.New("versioned chain peer has a different genesis")
	ErrActivation    = errors.New("versioned chain peer has a different activation height")
	ErrNegotiation   = errors.New("versioned chain session has no compatible capability")
)

type Config struct {
	NetworkID        uint32
	GenesisID        types.Hash
	ActivationHeight uint64
	Features         uint64
	MaxFrameBytes    uint32
}

func DefaultConfig(networkID uint32, genesisID types.Hash, activationHeight uint64) Config {
	return Config{
		NetworkID: networkID, GenesisID: genesisID, ActivationHeight: activationHeight,
		Features:      wire.ChainFeatureVersionedSyncV1 | wire.ChainFeaturePeerDiscoveryV1,
		MaxFrameBytes: uint32(wire.MaxVersionedFrameBodyBytes),
	}
}

type Protocol struct {
	config Config
}

type Limits struct {
	MaxFrameBytes uint32
	Features      uint64
}

func New(config Config) (*Protocol, error) {
	defaults := DefaultConfig(config.NetworkID, config.GenesisID, config.ActivationHeight)
	if config.Features == 0 {
		config.Features = defaults.Features
	}
	if config.MaxFrameBytes == 0 {
		config.MaxFrameBytes = defaults.MaxFrameBytes
	}
	if config.NetworkID == 0 || config.GenesisID.IsZero() || config.ActivationHeight == 0 ||
		config.Features&wire.ChainFeatureVersionedSyncV1 == 0 ||
		config.MaxFrameBytes < wire.MinVersionedChainFrameBodyBytes ||
		config.MaxFrameBytes > uint32(wire.MaxVersionedFrameBodyBytes) {
		return nil, ErrConfiguration
	}
	return &Protocol{config: config}, nil
}

func (protocol *Protocol) Hello(tip storage.Tip) (wire.ChainHello, error) {
	if protocol == nil {
		return wire.ChainHello{}, ErrConfiguration
	}
	if err := tip.Validate(); err != nil {
		return wire.ChainHello{}, err
	}
	result := wire.ChainHello{
		Version: wire.Version1, NetworkID: protocol.config.NetworkID,
		GenesisID: protocol.config.GenesisID, ActivationHeight: protocol.config.ActivationHeight,
		Features: protocol.config.Features, TipID: tip.ID, StateRoot: tip.StateRoot,
		TipHeight: tip.Height, CumulativeWork: append([]byte(nil), tip.CumulativeWork...),
		MaxFrameBytes: protocol.config.MaxFrameBytes,
	}
	if err := result.Validate(); err != nil {
		return wire.ChainHello{}, err
	}
	return result, nil
}

// Negotiate validates the immutable chain identity before intersecting the
// allocation ceiling. Session handlers must pass Limits.MaxFrameBytes to every
// ReadMessageLimit call after the hello exchange.
func (protocol *Protocol) Negotiate(remote wire.ChainHello) (Limits, error) {
	if protocol == nil {
		return Limits{}, ErrConfiguration
	}
	if err := remote.Validate(); err != nil {
		return Limits{}, err
	}
	if remote.NetworkID != protocol.config.NetworkID {
		return Limits{}, ErrNetwork
	}
	if remote.GenesisID != protocol.config.GenesisID {
		return Limits{}, ErrGenesis
	}
	if remote.ActivationHeight != protocol.config.ActivationHeight {
		return Limits{}, ErrActivation
	}
	if remote.Features&protocol.config.Features&wire.ChainFeatureVersionedSyncV1 == 0 {
		return Limits{}, ErrNegotiation
	}
	maximum := min(remote.MaxFrameBytes, protocol.config.MaxFrameBytes)
	if maximum < wire.MinVersionedChainFrameBodyBytes {
		return Limits{}, ErrNegotiation
	}
	return Limits{MaxFrameBytes: maximum, Features: remote.Features & protocol.config.Features}, nil
}

// PeerIsBetter applies the same cumulative-hard-work and smaller-ID tie break
// as storage without trusting the remote height or state root for fork choice.
func (protocol *Protocol) PeerIsBetter(local storage.Tip, remote wire.ChainHello) (bool, error) {
	if _, err := protocol.Negotiate(remote); err != nil {
		return false, err
	}
	if err := local.Validate(); err != nil {
		return false, err
	}
	order := new(big.Int).SetBytes(remote.CumulativeWork).Cmp(new(big.Int).SetBytes(local.CumulativeWork))
	if order != 0 {
		return order > 0, nil
	}
	return bytes.Compare(remote.TipID[:], local.ID[:]) < 0, nil
}
