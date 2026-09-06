package main

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/outcomemesh/outcomemesh/node/tieexchange"
)

const tiePairCompletionTimeout = 5 * time.Second

type tiePairCompletionStream interface {
	io.Reader
	CloseWrite() error
	SetReadDeadline(time.Time) error
}

// awaitTiePairCoordinatorClose runs after the final acknowledgement was written.
// Write and Close only queue QUIC frames; neither means the coordinator read
// them. The coordinator sends write-side EOF after validating that acknowledgement;
// the observer keeps its host and current slot alive until that EOF arrives.
func awaitTiePairCoordinatorClose(ctx context.Context, stream tiePairCompletionStream) error {
	stop, err := setTiePairCompletionDeadline(ctx, stream)
	if err != nil {
		return err
	}
	defer stop()
	var unexpected [1]byte
	read, err := io.ReadFull(stream, unexpected[:])
	if read == 0 && errors.Is(err, io.EOF) {
		return nil
	}
	return errors.Join(tieexchange.ErrProtocol, err)
}

// retireTiePairCoordinatorStream is called only after validating the final
// acknowledgement. Half-close, then keep the host alive while the observer
// consumes that EOF. The observer may close its whole host immediately after
// seeing it; an error in this bounded drain does not retract the already valid
// durable acknowledgement or cause a second delivery. No fifth message is added.
func retireTiePairCoordinatorStream(ctx context.Context, stream tiePairCompletionStream) {
	stop, err := setTiePairCompletionDeadline(ctx, stream)
	if err != nil {
		return
	}
	defer stop()
	if err := stream.CloseWrite(); err != nil {
		return
	}
	var unexpected [1]byte
	_, _ = io.ReadFull(stream, unexpected[:])
}

func setTiePairCompletionDeadline(ctx context.Context, stream tiePairCompletionStream) (func(), error) {
	if ctx == nil || stream == nil {
		return nil, tieexchange.ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(tiePairCompletionTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := stream.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = stream.SetReadDeadline(time.Now()) })
	return func() { stop() }, nil
}
