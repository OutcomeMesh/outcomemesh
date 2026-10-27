package custodyv2

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

// Service owns one original Target until all authenticated handlers have drained.
// Starting it does not prepare a session, consume a claim or sign a proof.
type Service struct {
	mu       sync.Mutex
	op       sync.Mutex
	wg       sync.WaitGroup
	target   *Target
	host     *libp2ptransport.Host
	run      context.Context
	cancel   context.CancelFunc
	timeout  time.Duration
	closing  bool
	done     chan struct{}
	closeErr error
	hook     func(string) error // private tests only: completed effect, missing reply
}

func Start(ctx context.Context, t *Target, key ed25519.PrivateKey, config libp2ptransport.Config, timeout time.Duration) (*Service, error) {
	if ctx == nil || t == nil || !matches(key, t.r.ctx.Assignment.Base.RemoteTransportPublicKey) || timeout < remotewire.MinimumTimeout || timeout > remotewire.MaximumTimeout {
		return nil, ErrProtocol
	}
	t.r.mu.Lock()
	e := t.r.check()
	t.r.mu.Unlock()
	if e != nil {
		return nil, e
	}
	client, e := transport.PeerIDFromPublicKey(t.r.ctx.Plan.ClientTransportPublicKey[:])
	if e != nil {
		return nil, e
	}
	run, cancel := context.WithCancel(ctx)
	host, e := libp2ptransport.New(run, key, config, nil)
	if e != nil {
		cancel()
		return nil, e
	}
	s := &Service{target: t, host: host, run: run, cancel: cancel, timeout: timeout, done: make(chan struct{})}
	if e := host.SetCustodyV2Handler([]types.Hash{client}, s.handle); e != nil {
		cancel()
		return nil, errors.Join(e, host.Close())
	}
	return s, nil
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
		e := s.closeErr
		s.mu.Unlock()
		return e
	}
	s.closing = true
	s.cancel()
	s.mu.Unlock()
	e := s.host.Close()
	s.wg.Wait()
	e = errors.Join(e, s.target.Close())
	s.mu.Lock()
	s.closeErr = e
	close(s.done)
	s.mu.Unlock()
	return e
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
	ctx, cleanup, e := remotewire.BoundStream(s.run, stream, s.timeout)
	if e != nil {
		_ = stream.Reset()
		return
	}
	defer cleanup()
	request, e := ReadRequest(stream)
	if e != nil {
		_ = stream.Reset()
		return
	}
	if e := remotewire.RequireEOF(stream); e != nil {
		_ = stream.Reset()
		return
	}
	if e := request.Validate(s.target.r.ctx); e != nil {
		_ = stream.Reset()
		return
	}
	s.op.Lock()
	defer s.op.Unlock()
	if ctx.Err() != nil {
		_ = stream.Reset()
		return
	}
	id, _ := request.ID()
	r := Response{Version: Version2, Operation: request.Operation, RequestID: id}
	switch request.Operation {
	case Prepare:
		r.Candidate, e = s.target.Prepare()
	case Execute:
		r.Result, e = s.target.Execute(ctx, request.Prefix[0], uint64(time.Now().Unix()))
		if e == nil {
			r.Result, r.Command, e = s.target.ResultCommand(request.Prefix)
		}
	case RecoverResult:
		r.Result, r.Command, e = s.target.ResultCommand(request.Prefix)
	default:
		e = ErrProtocol
	}
	if e == nil {
		e = ValidateResponse(s.target.r.ctx, request, r)
	}
	if e == nil && s.hook != nil {
		e = s.hook("effect-retained-before-reply")
	}
	if e != nil || ctx.Err() != nil {
		_ = stream.Reset()
		return
	}
	if e := WriteResponse(stream, r); e != nil {
		_ = stream.Reset()
		return
	}
	if e := stream.CloseWrite(); e != nil {
		_ = stream.Reset()
	}
}
