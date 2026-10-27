package witnesswire

import (
	"context"
	"errors"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

var ErrUnconfirmed = errors.New("witness response unconfirmed; retain original pins and exact attempted command")

// Exchange owns and closes one already authenticated, externally pinned stream.
// No retry, witness enrollment, pin adoption or execution is implicit.
func Exchange(ctx context.Context, stream remotewire.Stream, s custodyfence.Scope, witness [32]byte, r Request, timeout time.Duration) (response Response, returnErr error) {
	if stream == nil {
		return response, ErrProtocol
	}
	defer func() {
		if err := stream.Close(); err != nil {
			response = Response{}
			returnErr = errors.Join(ErrUnconfirmed, returnErr, err)
		}
	}()
	if err := r.Validate(s); err != nil {
		return response, err
	}
	bounded, cleanup, err := remotewire.BoundStream(ctx, stream, timeout)
	if err != nil {
		return response, err
	}
	defer cleanup()
	unknown := func(err error) (Response, error) { return Response{}, errors.Join(ErrUnconfirmed, err, bounded.Err()) }
	if err := WriteRequest(stream, r); err != nil {
		return unknown(err)
	}
	if err := stream.CloseWrite(); err != nil {
		return unknown(err)
	}
	received, err := ReadResponse(stream)
	if err != nil {
		return unknown(err)
	}
	if err := ValidateResponse(s, r, received, witness); err != nil {
		return unknown(err)
	}
	if err := remotewire.RequireEOF(stream); err != nil {
		return unknown(err)
	}
	if err := bounded.Err(); err != nil {
		return unknown(err)
	}
	return received, nil
}
