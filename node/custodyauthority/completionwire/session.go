package completionwire

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

const (
	MinimumTimeout = 100 * time.Millisecond
	MaximumTimeout = 2 * time.Minute
	DefaultTimeout = 15 * time.Second
)

type Stream interface {
	io.ReadWriteCloser
	CloseWrite() error
	SetDeadline(time.Time) error
}

// BoundStream installs a wall-clock I/O deadline and interrupts blocked I/O on
// context cancellation. Cleanup waits for the cancellation callback to retire.
// It does not interrupt an already committed storage decision or close tickets.
func BoundStream(ctx context.Context, stream Stream, timeout time.Duration) (context.Context, func(), error) {
	if ctx == nil || stream == nil || timeout < MinimumTimeout || timeout > MaximumTimeout {
		return nil, nil, ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	deadline, _ := bounded.Deadline()
	if err := stream.SetDeadline(deadline); err != nil {
		cancel()
		return nil, nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(bounded, func() {
		_ = stream.SetDeadline(time.Now())
		close(done)
	})
	return bounded, func() {
		cancel()
		if !stop() {
			<-done
		}
	}, nil
}

// Exchange owns and closes one pre-authenticated, identity-pinned stream. It
// sends only the supplied Complete entry, with a fresh random nonce per exchange.
// It never discovers another authority, refreshes a signature, retries, signs or
// durably records the response. Retain the exact entry independently before use.
func Exchange(ctx context.Context, stream Stream, entry custodyauthority.Entry, timeout time.Duration) (Acknowledgement, error) {
	if stream == nil {
		return Acknowledgement{}, ErrProtocol
	}
	defer stream.Close()
	var nonce types.Hash
	if _, err := rand.Read(nonce[:]); err != nil {
		return Acknowledgement{}, err
	}
	r := Request{Nonce: nonce, Entry: entry}
	if _, err := r.CanonicalBytes(); err != nil {
		return Acknowledgement{}, err
	}
	id, _ := entry.ID()
	bounded, cleanup, err := BoundStream(ctx, stream, timeout)
	if err != nil {
		return Acknowledgement{}, err
	}
	defer cleanup()
	uncertain := func(err error) (Acknowledgement, error) {
		return Acknowledgement{}, errors.Join(ErrUnconfirmed, err, bounded.Err())
	}
	if err := WriteRequest(stream, r); err != nil {
		return uncertain(err)
	}
	if err := stream.CloseWrite(); err != nil {
		return uncertain(err)
	}
	a, err := ReadAcknowledgement(stream)
	if err != nil {
		return uncertain(err)
	}
	if a.Nonce != nonce || a.EntryID != id {
		return uncertain(ErrProtocol)
	}
	if err := RequireEOF(stream); err != nil {
		return uncertain(err)
	}
	if err := bounded.Err(); err != nil {
		return uncertain(err)
	}
	return a, nil
}
