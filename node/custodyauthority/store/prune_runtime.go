package store

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

var (
	ErrPruneRuntime        = errors.New("invalid prune command runtime configuration")
	ErrPruneServiceStarted = errors.New("prune command service already started")
)

// Command runtimes deliberately use transport keys distinct from every declared
// authority, consumer and evidence key. This is role separation, not copy fencing.
func validatePruneRuntimePeers(assignment custodyauthority.Assignment, self, remote types.Hash) error {
	if _, err := assignment.ID(); err != nil {
		return err
	}
	if self.IsZero() || remote.IsZero() || self == remote {
		return ErrPruneRuntime
	}
	keys := [][ed25519.PublicKeySize]byte{assignment.AuthorityPublicKey, assignment.ReplicaPublicKey}
	keys = append(keys, assignment.Auditors...)
	for _, consumer := range assignment.Consumers {
		keys = append(keys, consumer.PublicKey)
	}
	for _, key := range keys {
		id, _ := transport.PeerIDFromPublicKey(key[:])
		if id == self || id == remote {
			return ErrPruneRuntime
		}
	}
	return nil
}

// Validate and copy before any listener is created. No key is generated, loaded
// from a default location, logged or stored in the command journals. Go/libp2p
// memory ownership is not a guarantee of private-key zeroization.
func pruneRuntimeKey(key ed25519.PrivateKey, expected types.Hash) (ed25519.PrivateKey, error) {
	if len(key) != ed25519.PrivateKeySize || expected.IsZero() {
		return nil, ErrPruneRuntime
	}
	canonical := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(key, canonical) != 1 {
		return nil, ErrPruneRuntime
	}
	id, err := transport.PeerIDFromPublicKey(canonical.Public().(ed25519.PublicKey))
	if err != nil || id != expected {
		return nil, errors.Join(ErrPruneRuntime, err)
	}
	return canonical, nil
}

func newPruneRuntimeHost(ctx context.Context, assignment custodyauthority.Assignment, self, remote types.Hash, key ed25519.PrivateKey, config libp2ptransport.Config) (*libp2ptransport.Host, error) {
	if ctx == nil {
		return nil, ErrPruneRuntime
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validatePruneRuntimePeers(assignment, self, remote); err != nil {
		return nil, err
	}
	ownedKey, err := pruneRuntimeKey(key, self)
	if err != nil {
		return nil, err
	}
	host, err := libp2ptransport.New(ctx, ownedKey, config, nil)
	if err != nil {
		return nil, err
	}
	if host.ID() != self {
		return nil, errors.Join(ErrPruneRuntime, host.Close())
	}
	return host, nil
}
