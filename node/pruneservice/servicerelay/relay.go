// Package servicerelay carries a complete signed Prune exchange to the local
// kernel-authenticated owner. It has no service key, consumer key or store handle.
package servicerelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayclient"
	client "github.com/outcomemesh/outcomemesh/node/pruneservice/serviceclient"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func PeerID(key [32]byte) types.Hash { return types.DomainHash("OMESH/p2p/ed25519/v0", key[:]) }
func ValidateTransport(d wire.Descriptor, key [32]byte) error {
	if _, err := d.CanonicalBytes(); err != nil {
		return err
	}
	if key == ([32]byte{}) {
		return wire.ErrAccess
	}
	s := d.Policy.Service
	roles := append([][32]byte{d.Transport, d.Policy.Owner, d.Policy.Controller, d.Policy.Guard, s.Service, s.Issuer, s.Guard}, d.Policy.Witnesses...)
	for _, r := range roles {
		if key == r {
			return wire.ErrAccess
		}
	}
	return nil
}

type approval func(context.Context, wire.Challenge) (custodyfence.Command, error)
type forwardCall func(context.Context, wire.Request, approval) (wire.Response, error)
type Service struct {
	mu         sync.Mutex
	wg         sync.WaitGroup
	host       *libp2ptransport.Host
	run        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	closing    bool
	closeErr   error
	descriptor wire.Descriptor
	timeout    time.Duration
	slots      chan struct{}
	forward    forwardCall // private test seam; production always uses Unix credentials
}

func Start(ctx context.Context, socket string, d wire.Descriptor, key ed25519.PrivateKey, config libp2ptransport.Config, peers [][32]byte, timeout time.Duration) (*Service, error) {
	if !gatewayclient.Supported() || uint32(os.Geteuid()) != d.ParticipantUID || !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || len(socket) > 100 {
		return nil, wire.ErrAccess
	}
	raw, err := d.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	d, err = wire.DecodeDescriptor(raw)
	if err != nil {
		return nil, err
	}
	return start(ctx, d, key, config, peers, timeout, func(ctx context.Context, q wire.Request, a approval) (wire.Response, error) {
		return client.Call(ctx, socket, d, q, a)
	})
}

func start(ctx context.Context, d wire.Descriptor, key ed25519.PrivateKey, config libp2ptransport.Config, peers [][32]byte, timeout time.Duration, forward forwardCall) (*Service, error) {
	if ctx == nil || ctx.Err() != nil || timeout < remotewire.MinimumTimeout || timeout > wire.ExchangeDeadline || forward == nil || len(peers) == 0 || len(peers) > 32 || len(key) != ed25519.PrivateKeySize {
		return nil, wire.ErrAccess
	}
	derived := ed25519.NewKeyFromSeed(key[:32])
	same := bytes.Equal(key, derived)
	clear(derived)
	if !same {
		return nil, wire.ErrAccess
	}
	var local [32]byte
	copy(local[:], key[32:])
	if err := ValidateTransport(d, local); err != nil {
		return nil, err
	}
	ids := make([]types.Hash, 0, len(peers))
	seen := map[[32]byte]bool{local: true}
	for _, p := range peers {
		if seen[p] || ValidateTransport(d, p) != nil {
			return nil, wire.ErrAccess
		}
		seen[p] = true
		ids = append(ids, PeerID(p))
	}
	raw, _ := d.CanonicalBytes()
	d, err := wire.DecodeDescriptor(raw)
	if err != nil {
		return nil, err
	}
	run, cancel := context.WithCancel(ctx)
	host, err := libp2ptransport.New(run, key, config, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	s := &Service{host: host, run: run, cancel: cancel, done: make(chan struct{}), descriptor: d, timeout: timeout, slots: make(chan struct{}, 8), forward: forward}
	if err = host.SetPruneServiceHandler(ids, s.handle); err != nil {
		cancel()
		return nil, errors.Join(err, host.Close())
	}
	return s, nil
}
func (s *Service) Addresses() []string { return s.host.Addresses() }
func (s *Service) ID() types.Hash      { return s.host.ID() }
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		<-s.done
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.closeErr
	}
	s.closing = true
	s.cancel()
	s.mu.Unlock()
	err := s.host.Close()
	s.wg.Wait()
	s.mu.Lock()
	s.closeErr = err
	close(s.done)
	s.mu.Unlock()
	return err
}
func (s *Service) handle(_ context.Context, _ types.Hash, stream network.Stream) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		_ = stream.Reset()
		return
	}
	select {
	case s.slots <- struct{}{}:
	default:
		s.mu.Unlock()
		_ = stream.Reset()
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()
	defer func() { <-s.slots }()
	defer stream.Close()
	run, done, err := remotewire.BoundStream(s.run, stream, s.timeout)
	if err != nil {
		_ = stream.Reset()
		return
	}
	defer done()
	if err = s.exchange(run, stream); err != nil {
		_ = stream.Reset()
	}
}
func (s *Service) exchange(ctx context.Context, stream remotewire.Stream) error {
	raw, err := wire.ReadExpectedFrame(stream, wire.RequestFrame)
	if err != nil {
		return err
	}
	q, err := wire.DecodeRequest(raw)
	if err != nil || q.Authorize(s.descriptor) != nil {
		return wire.ErrAccess
	}
	approved := false
	r, err := s.forward(ctx, q, func(ctx context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		if approved || ctx.Err() != nil {
			return custodyfence.Command{}, wire.ErrAccess
		}
		approved = true
		if err := ch.Verify(s.descriptor, q); err != nil {
			return custodyfence.Command{}, err
		}
		scope, draft, err := ch.Candidate.Draft()
		if err != nil {
			return custodyfence.Command{}, err
		}
		raw, err := ch.CanonicalBytes()
		if err != nil {
			return custodyfence.Command{}, err
		}
		if err = wire.WriteFrame(stream, wire.ChallengeFrame, raw); err != nil {
			return custodyfence.Command{}, err
		}
		raw, err = wire.ReadExpectedFrame(stream, wire.ApprovalFrame)
		if err != nil {
			return custodyfence.Command{}, err
		}
		command, err := custodyfence.DecodeCommand(raw)
		if err != nil {
			return custodyfence.Command{}, err
		}
		draft.Signature = command.Signature
		if command != draft || command.Verify(scope) != nil {
			return custodyfence.Command{}, wire.ErrAccess
		}
		if err = wire.RequireEOF(stream); err != nil {
			return custodyfence.Command{}, err
		}
		return command, ctx.Err()
	})
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = r.Verify(s.descriptor, q); err != nil {
		return err
	}
	raw, err = r.CanonicalBytes()
	if err != nil {
		return err
	}
	if err = wire.WriteFrame(stream, wire.ResponseFrame, raw); err != nil {
		return err
	}
	if err = stream.CloseWrite(); err != nil {
		return err
	}
	if !approved {
		return wire.RequireEOF(stream)
	}
	return nil
}

// Call pins both transport identities and the full issuer-approved descriptor.
// The request must already be retained by the caller. There is no automatic retry.
func Call(ctx context.Context, host *libp2ptransport.Host, address string, local, remote [32]byte, d wire.Descriptor, q wire.Request, timeout time.Duration, approve func(context.Context, wire.Challenge) (custodyfence.Command, error)) (wire.Response, error) {
	if ctx == nil || host == nil || address == "" || local == remote || host.ID() != PeerID(local) || ValidateTransport(d, local) != nil || ValidateTransport(d, remote) != nil || q.Authorize(d) != nil || timeout < remotewire.MinimumTimeout || timeout > wire.ExchangeDeadline {
		return wire.Response{}, wire.ErrAccess
	}
	run, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stream, peer, err := host.OpenPruneServiceStream(run, address, PeerID(remote))
	if err != nil {
		return wire.Response{}, err
	}
	if peer != PeerID(remote) {
		_ = stream.Reset()
		return wire.Response{}, wire.ErrAccess
	}
	return client.Exchange(run, stream, d, q, timeout, approve)
}
