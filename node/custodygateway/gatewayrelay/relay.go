// Package gatewayrelay forwards one authenticated network request to the local
// isolated gateway. It has no owner, source, archive or role signing key access.
package gatewayrelay

import (
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
	client "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayclient"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

var ErrUnconfirmed = errors.New("gateway delivery unconfirmed; retain the exact signed attempt")

// DecodeAttempt authorizes the complete envelope before any local connection.
// Only typed Runtime envelopes cross this endpoint; inspect/read/revoke remain
// explicit local operations and cannot use the relay as an archive proxy.
func DecodeAttempt(d wire.Descriptor, raw []byte) (wire.Request, []byte, error) {
	q, payload, e := wire.DecodeRuntimeRequest(raw)
	if e != nil {
		return wire.Request{}, nil, e
	}
	if e = q.Authorize(d); e != nil {
		return wire.Request{}, nil, e
	}
	return q, payload, nil
}

// Exchange owns an authenticated, independently peer-pinned stream and makes
// exactly one attempt. Even a signed reply must have complete EOF. After any
// attempted write, a failure leaves execution unknown; it never grants retry
// with a new nonce/position or permits a refund.
func Exchange(ctx context.Context, stream remotewire.Stream, d wire.Descriptor, raw []byte, timeout time.Duration) (response wire.Response, returnErr error) {
	if stream == nil {
		return response, wire.ErrAccess
	}
	defer func() {
		if e := stream.Close(); e != nil {
			response = wire.Response{}
			returnErr = errors.Join(ErrUnconfirmed, returnErr, e)
		}
	}()
	q, _, e := DecodeAttempt(d, raw)
	if e != nil || timeout > client.Deadline {
		return response, errors.Join(wire.ErrArtifact, e)
	}
	run, done, e := remotewire.BoundStream(ctx, stream, timeout)
	if e != nil {
		return response, e
	}
	defer done()
	fail := func(e error) (wire.Response, error) {
		return wire.Response{}, errors.Join(ErrUnconfirmed, e, run.Err())
	}
	if e = client.WriteFrame(stream, raw); e != nil {
		return fail(e)
	}
	if e = stream.CloseWrite(); e != nil {
		return fail(e)
	}
	packet, e := client.ReadFrame(stream, wire.MaximumResponseBytes)
	if e != nil {
		return fail(e)
	}
	r, e := wire.DecodeResponse(packet)
	if e != nil {
		return fail(e)
	}
	if e = r.Verify(d, q); e != nil {
		return fail(e)
	}
	if e = remotewire.RequireEOF(stream); e != nil {
		return fail(e)
	}
	if e = run.Err(); e != nil {
		return fail(e)
	}
	return r, nil
}

type Service struct {
	mu         sync.Mutex
	wg         sync.WaitGroup
	host       *libp2ptransport.Host
	run        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	closing    bool
	closeErr   error
	socket     string
	descriptor wire.Descriptor
	timeout    time.Duration
	// Private test seam: production always calls the Unix peer-UID client.
	forward func(context.Context, wire.Request, []byte) (wire.Response, error)
}

func Start(ctx context.Context, socket string, d wire.Descriptor, key ed25519.PrivateKey, config libp2ptransport.Config, peers []types.Hash, timeout time.Duration) (*Service, error) {
	if !client.Supported() || uint32(os.Geteuid()) != d.ParticipantUID || !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || len(socket) > 100 {
		return nil, wire.ErrAccess
	}
	return start(ctx, socket, d, key, config, peers, timeout, nil)
}

func start(ctx context.Context, socket string, d wire.Descriptor, key ed25519.PrivateKey, config libp2ptransport.Config, peers []types.Hash, timeout time.Duration, forward func(context.Context, wire.Request, []byte) (wire.Response, error)) (*Service, error) {
	if ctx == nil || ctx.Err() != nil || timeout < remotewire.MinimumTimeout || timeout > client.Deadline {
		return nil, wire.ErrAccess
	}
	// Snapshot descriptor slices: later caller mutation cannot change the ACL.
	b, e := d.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	d, e = wire.DecodeDescriptor(b)
	if e != nil {
		return nil, e
	}
	if forward == nil {
		forward = func(ctx context.Context, q wire.Request, payload []byte) (wire.Response, error) {
			return client.CallRuntime(ctx, socket, d, q, payload)
		}
	}
	run, cancel := context.WithCancel(ctx)
	host, e := libp2ptransport.New(run, key, config, nil)
	if e != nil {
		cancel()
		return nil, e
	}
	s := &Service{host: host, run: run, cancel: cancel, done: make(chan struct{}), socket: socket, descriptor: d, timeout: timeout, forward: forward}
	if e = host.SetCustodyGatewayHandler(peers, s.handle); e != nil {
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
		s.mu.Unlock()
		<-s.done
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.closeErr
	}
	s.closing = true
	s.cancel()
	s.mu.Unlock()
	e := s.host.Close()
	s.wg.Wait()
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
	run, done, e := remotewire.BoundStream(s.run, stream, s.timeout)
	if e != nil {
		_ = stream.Reset()
		return
	}
	defer done()
	raw, e := client.ReadFrame(stream, wire.MaximumServiceRequestBytes)
	if e != nil {
		_ = stream.Reset()
		return
	}
	if e = remotewire.RequireEOF(stream); e != nil {
		_ = stream.Reset()
		return
	}
	q, payload, e := DecodeAttempt(s.descriptor, raw)
	if e != nil || run.Err() != nil {
		_ = stream.Reset()
		return
	}
	r, e := s.forward(run, q, payload)
	if e == nil {
		e = r.Verify(s.descriptor, q)
	}
	if e != nil || run.Err() != nil {
		_ = stream.Reset()
		return
	}
	packet, e := r.CanonicalBytes()
	if e != nil {
		_ = stream.Reset()
		return
	}
	if e = client.WriteFrame(stream, packet); e != nil {
		_ = stream.Reset()
		return
	}
	if e = stream.CloseWrite(); e != nil {
		_ = stream.Reset()
	}
}
