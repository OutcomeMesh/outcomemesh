// Package witnessnet serves independently retained witness journals over an
// opt-in authenticated QUIC protocol. It never executes custody work.
package witnessnet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnesswire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

type Service struct {
	mu       sync.Mutex
	op       sync.Mutex
	wg       sync.WaitGroup
	witness  *custodyfence.Witness
	scope    custodyfence.Scope
	public   [32]byte
	host     *libp2ptransport.Host
	run      context.Context
	cancel   context.CancelFunc
	timeout  time.Duration
	closing  bool
	done     chan struct{}
	closeErr error
	hook     func(string) error // private test-only reply-loss boundary
}

// Start takes exclusive lifetime ownership of an already opened original
// witness. No root, assignment, key or recovery pin is created or adopted.
// Transport and signing keys must be separate. The caller must not use w again.
func Start(ctx context.Context, w *custodyfence.Witness, s custodyfence.Scope, pin types.Hash, key ed25519.PrivateKey, config libp2ptransport.Config, clients []types.Hash, timeout time.Duration) (*Service, error) {
	if ctx == nil || w == nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:32])) || timeout < remotewire.MinimumTimeout || timeout > remotewire.MaximumTimeout {
		return nil, witnesswire.ErrProtocol
	}
	b, err := s.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	s, err = custodyfence.DecodeScope(b)
	if err != nil {
		return nil, err
	}
	id, _ := s.ID()
	x, _, err := w.Snapshot()
	if err != nil || id != pin || x.ScopeID != pin {
		return nil, errors.Join(witnesswire.ErrProtocol, err)
	}
	var transportKey [32]byte
	copy(transportKey[:], key.Public().(ed25519.PublicKey))
	for _, k := range append(append([][32]byte{s.Owner, s.Controller}, s.Witnesses...), [32]byte{}) {
		if transportKey == k {
			return nil, witnesswire.ErrProtocol
		}
	}
	// The signed observation identifies the retained member without exposing its
	// private key. It is bound to this bootstrap inspection, not an effect grant.
	probe, err := w.Observe(types.DomainHash("OMESH/custody-fence/server/bootstrap/v0", pin[:]))
	if err != nil {
		return nil, err
	}
	if err := probe.Verify(s, probe.RequestID, probe.Witness); err != nil {
		return nil, err
	}
	run, cancel := context.WithCancel(ctx)
	host, err := libp2ptransport.New(run, key, config, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	service := &Service{witness: w, scope: s, public: probe.Witness, host: host, run: run, cancel: cancel, timeout: timeout, done: make(chan struct{})}
	if err := host.SetCustodyWitnessHandler(clients, service.handle); err != nil {
		cancel()
		return nil, errors.Join(err, host.Close())
	}
	return service, nil
}
func (s *Service) Addresses() []string { return s.host.Addresses() }
func (s *Service) ID() types.Hash      { return s.host.ID() }
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closing {
		done := s.done
		s.mu.Unlock()
		<-done
		s.mu.Lock()
		err := s.closeErr
		s.mu.Unlock()
		return err
	}
	s.closing = true
	s.cancel()
	s.mu.Unlock()
	err := s.host.Close()
	s.wg.Wait()
	err = errors.Join(err, s.witness.Close())
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
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()
	defer stream.Close()
	ctx, cleanup, err := remotewire.BoundStream(s.run, stream, s.timeout)
	if err != nil {
		_ = stream.Reset()
		return
	}
	defer cleanup()
	r, err := witnesswire.ReadRequest(stream)
	if err != nil {
		_ = stream.Reset()
		return
	}
	if err := remotewire.RequireEOF(stream); err != nil {
		_ = stream.Reset()
		return
	}
	if err := r.Validate(s.scope); err != nil {
		_ = stream.Reset()
		return
	}
	s.op.Lock()
	defer s.op.Unlock()
	if err := ctx.Err(); err != nil {
		_ = stream.Reset()
		return
	}
	response := witnesswire.Response{Version: r.Version}
	switch r.Kind {
	case witnesswire.Review:
		_, pin, e := s.witness.Snapshot()
		err = e
		if err == nil && pin != r.Expected {
			err = custodyfence.ErrTransition
		}
	case witnesswire.Vote:
		response.Vote, err = s.witness.VoteAt(r.Expected, r.Command)
	case witnesswire.Commit:
		err = s.witness.CommitAt(r.Expected, r.Certificate)
	default:
		err = witnesswire.ErrProtocol
	}
	if err != nil {
		_ = stream.Reset()
		return
	}
	id, _ := r.ID()
	response.Observation, err = s.witness.Observe(id)
	if err == nil {
		err = witnesswire.ValidateResponse(s.scope, r, response, s.public)
	}
	if err == nil && s.hook != nil {
		err = s.hook("persisted-before-reply")
	}
	if err != nil || ctx.Err() != nil {
		_ = stream.Reset()
		return
	}
	if err := witnesswire.WriteResponse(stream, response); err != nil {
		_ = stream.Reset()
		return
	}
	if err := stream.CloseWrite(); err != nil {
		_ = stream.Reset()
	}
}
