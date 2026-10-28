package custodyv2

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

// AdmissionDeliveryService owns an explicitly enrolled proof inbox until its
// handlers drain. No required owner or execution session is created here.
type AdmissionDeliveryService struct {
	mu       sync.Mutex
	op       sync.Mutex
	wg       sync.WaitGroup
	inbox    *AdmissionInbox
	host     *libp2ptransport.Host
	run      context.Context
	cancel   context.CancelFunc
	timeout  time.Duration
	closing  bool
	done     chan struct{}
	closeErr error
	hook     func(string) error // test-only retained-ACK/reply-loss boundary
}

func StartAdmissionDelivery(ctx context.Context, inbox *AdmissionInbox, key ed25519.PrivateKey, config libp2ptransport.Config, timeout time.Duration) (*AdmissionDeliveryService, error) {
	return startAdmissionDelivery(ctx, inbox, key, config, timeout, Version2)
}
func StartEnrolledAdmissionDelivery(ctx context.Context, inbox *AdmissionInbox, key ed25519.PrivateKey, config libp2ptransport.Config, timeout time.Duration) (*AdmissionDeliveryService, error) {
	return startAdmissionDelivery(ctx, inbox, key, config, timeout, PolicyVersionEnrolled)
}
func startAdmissionDelivery(ctx context.Context, inbox *AdmissionInbox, key ed25519.PrivateKey, config libp2ptransport.Config, timeout time.Duration, version uint16) (*AdmissionDeliveryService, error) {
	if inbox != nil && inbox.Enrollment().Version != version {
		return nil, ErrAdmissionDelivery
	}
	if ctx == nil || inbox == nil || len(key) != ed25519.PrivateKeySize || timeout < remotewire.MinimumTimeout || timeout > remotewire.MaximumTimeout {
		return nil, ErrProtocol
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := inbox.Check(); e != nil {
		return nil, e
	}
	enrollment := inbox.Enrollment()
	peer, e := transport.PeerIDFromPublicKey(key.Public().(ed25519.PublicKey))
	if e != nil || peer != enrollment.RecipientPeerID {
		return nil, errors.Join(ErrProtocol, e)
	}
	run, cancel := context.WithCancel(ctx)
	host, e := libp2ptransport.New(run, key, config, nil)
	if e != nil {
		cancel()
		return nil, e
	}
	s := &AdmissionDeliveryService{inbox: inbox, host: host, run: run, cancel: cancel, timeout: timeout, done: make(chan struct{})}
	setHandler := host.SetAdmissionDeliveryHandler
	if version == PolicyVersionEnrolled {
		setHandler = host.SetEnrolledAdmissionDeliveryHandler
	}
	if e := setHandler(enrollment.SenderPeerID, s.handle); e != nil {
		cancel()
		return nil, errors.Join(e, host.Close())
	}
	return s, nil
}

func (s *AdmissionDeliveryService) Addresses() []string { return s.host.Addresses() }
func (s *AdmissionDeliveryService) ID() types.Hash      { return s.host.ID() }
func (s *AdmissionDeliveryService) Close() error {
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
	e = errors.Join(e, s.inbox.Close())
	s.mu.Lock()
	s.closeErr = e
	close(s.done)
	s.mu.Unlock()
	return e
}

func (s *AdmissionDeliveryService) handle(_ context.Context, peer types.Hash, stream network.Stream) {
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
	if peer != s.inbox.Enrollment().SenderPeerID {
		_ = stream.Reset()
		return
	}
	delivery, e := ReadAdmissionDelivery(stream)
	if e != nil {
		_ = stream.Reset()
		return
	}
	// A frame with trailing bytes or an incomplete half-close has no durable
	// delivery effect, even if all bytes inside its first frame were valid.
	if e := remotewire.RequireEOF(stream); e != nil {
		_ = stream.Reset()
		return
	}
	s.op.Lock()
	defer s.op.Unlock()
	if ctx.Err() != nil {
		_ = stream.Reset()
		return
	}
	receipt, e := s.inbox.Receive(ctx, delivery)
	if e == nil && s.hook != nil {
		e = s.hook("receipt-retained-before-reply")
	}
	if e != nil || ctx.Err() != nil {
		_ = stream.Reset()
		return
	}
	if e := WriteAdmissionDeliveryReceipt(stream, receipt); e != nil {
		_ = stream.Reset()
		return
	}
	if e := stream.CloseWrite(); e != nil {
		_ = stream.Reset()
	}
}

// DeliverAdmission sends only a previously persisted immutable outbox intent.
// It neither retries automatically nor converts a delivery acknowledgement into
// admission/currentness/physical execution permission. A cached valid receipt
// is returned without opening a network channel, including when h is nil.
func DeliverAdmission(ctx context.Context, h *libp2ptransport.Host, outbox *AdmissionOutbox, timeout time.Duration) (AdmissionDeliveryReceipt, error) {
	return deliverAdmission(ctx, h, outbox, timeout, Version2)
}
func DeliverEnrolledAdmission(ctx context.Context, h *libp2ptransport.Host, outbox *AdmissionOutbox, timeout time.Duration) (AdmissionDeliveryReceipt, error) {
	return deliverAdmission(ctx, h, outbox, timeout, PolicyVersionEnrolled)
}
func deliverAdmission(ctx context.Context, h *libp2ptransport.Host, outbox *AdmissionOutbox, timeout time.Duration, version uint16) (AdmissionDeliveryReceipt, error) {
	if outbox != nil && outbox.Delivery().Version != version {
		return AdmissionDeliveryReceipt{}, ErrAdmissionDelivery
	}
	if ctx == nil || outbox == nil || timeout < remotewire.MinimumTimeout || timeout > remotewire.MaximumTimeout {
		return AdmissionDeliveryReceipt{}, ErrProtocol
	}
	if e := ctx.Err(); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	if e := outbox.Check(); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	delivery := outbox.Delivery()
	if e := delivery.Validate(); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	if receipt, e := outbox.ReadReceipt(); e == nil {
		return receipt, receipt.Verify(delivery)
	} else if !errors.Is(e, os.ErrNotExist) {
		return AdmissionDeliveryReceipt{}, e
	}
	if h == nil || h.ID() != delivery.Enrollment.SenderPeerID {
		return AdmissionDeliveryReceipt{}, ErrProtocol
	}
	run, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	openStream := h.OpenAdmissionDeliveryStream
	if version == PolicyVersionEnrolled {
		openStream = h.OpenEnrolledAdmissionDeliveryStream
	}
	stream, peer, e := openStream(run, outbox.Route(), delivery.Enrollment.RecipientPeerID)
	if e != nil {
		return AdmissionDeliveryReceipt{}, errors.Join(ErrUncertain, e)
	}
	if peer != delivery.Enrollment.RecipientPeerID {
		_ = stream.Reset()
		_ = stream.Close()
		return AdmissionDeliveryReceipt{}, ErrUncertain
	}
	receipt, e := exchangeAdmissionDelivery(run, stream, delivery, timeout)
	if e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	if e := outbox.Confirm(run, receipt); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	return receipt, nil
}
