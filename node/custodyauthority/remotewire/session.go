package remotewire

import (
	"context"
	"errors"
	"io"
	"time"
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
	stop := context.AfterFunc(bounded, func() { defer close(done); _ = stream.SetDeadline(time.Now()) })
	return bounded, func() {
		cancel()
		if !stop() {
			<-done
		}
	}, nil
}

// Exchange owns one already authenticated, independently pinned stream. The
// caller supplies a fresh channel nonce without changing Plan.Nonce or Begin.
// It must validate the request's external assignment/pins before dispatch and
// ValidateResponse under its original owner before any authority/result use.
// This function checks exact reply bindings/signature and complete EOF; it
// never retries, signs, persists, executes, applies a drain or clears a hold.
func Exchange(ctx context.Context, stream Stream, r Request, timeout time.Duration) (response Response, returnErr error) {
	if stream == nil {
		return Response{}, ErrProtocol
	}
	defer func() {
		if err := stream.Close(); err != nil {
			response = Response{}
			returnErr = errors.Join(ErrUnconfirmed, returnErr, err)
		}
	}()
	if _, err := r.CanonicalBytes(); err != nil {
		return Response{}, err
	}
	bounded, cleanup, err := BoundStream(ctx, stream, timeout)
	if err != nil {
		return Response{}, err
	}
	defer cleanup()
	uncertain := func(err error) (Response, error) { return Response{}, errors.Join(ErrUnconfirmed, err, bounded.Err()) }
	if err := WriteRequest(stream, r); err != nil {
		return uncertain(err)
	}
	if err := stream.CloseWrite(); err != nil {
		return uncertain(err)
	}
	s, err := ReadResponse(stream)
	if err != nil {
		return uncertain(err)
	}
	if err := validateContext(r, s); err != nil {
		return uncertain(err)
	}
	if err := RequireEOF(stream); err != nil {
		return uncertain(err)
	}
	if err := bounded.Err(); err != nil {
		return uncertain(err)
	}
	return s, nil
}
