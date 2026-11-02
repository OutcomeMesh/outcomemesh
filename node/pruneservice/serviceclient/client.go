// Package serviceclient exchanges public Prune artifacts with an isolated owner.
// It never opens the owner's key, original journals, or storage directories.
package serviceclient

import (
	"context"
	"errors"
	"net"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayclient"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

// Call approves only the service's exact live candidate. An already retained
// response returns without invoking approve. Successful verification establishes
// historical evidence, not present storage availability or a reusable permit.
func Call(ctx context.Context, socket string, d wire.Descriptor, q wire.Request,
	approve func(context.Context, wire.Challenge) (custodyfence.Command, error),
) (wire.Response, error) {
	if ctx == nil || !gatewayclient.Supported() || !filepath.IsAbs(socket) || q.Authorize(d) != nil {
		return wire.Response{}, wire.ErrAccess
	}
	bounded, cancel := context.WithTimeout(ctx, wire.ExchangeDeadline)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(bounded, "unix", socket)
	if err != nil {
		return wire.Response{}, err
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return wire.Response{}, wire.ErrAccess
	}
	uid, err := gatewayclient.PeerUID(unixConn)
	if err != nil || uid != d.OwnerUID {
		return wire.Response{}, errors.Join(wire.ErrAccess, err)
	}
	return exchange(bounded, unixConn, d, q, approve)
}

func exchange(ctx context.Context, conn *net.UnixConn, d wire.Descriptor, q wire.Request,
	approve func(context.Context, wire.Challenge) (custodyfence.Command, error),
) (wire.Response, error) {
	if err := ctx.Err(); err != nil {
		return wire.Response{}, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return wire.Response{}, wire.ErrAccess
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return wire.Response{}, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	raw, err := q.CanonicalBytes()
	if err != nil {
		return wire.Response{}, err
	}
	if err := wire.WriteFrame(conn, wire.RequestFrame, raw); err != nil {
		return wire.Response{}, err
	}
	kind, raw, err := wire.ReadFrame(conn)
	if err != nil {
		return wire.Response{}, err
	}
	switch kind {
	case wire.ResponseFrame:
		if err := conn.CloseWrite(); err != nil {
			return wire.Response{}, err
		}
		return finish(ctx, conn, d, q, raw)
	case wire.ChallengeFrame:
		challenge, err := wire.DecodeChallenge(raw)
		if err != nil {
			return wire.Response{}, err
		}
		if err := challenge.Verify(d, q); err != nil {
			return wire.Response{}, err
		}
		if approve == nil {
			return wire.Response{}, wire.ErrAccess
		}
		scope, expected, err := challenge.Candidate.Draft()
		if err != nil {
			return wire.Response{}, err
		}
		command, err := approval(ctx, challenge, approve)
		if err != nil {
			return wire.Response{}, err
		}
		expected.Signature = command.Signature
		if command != expected || command.Verify(scope) != nil {
			return wire.Response{}, wire.ErrAccess
		}
		raw, err = command.CanonicalBytes()
		if err != nil {
			return wire.Response{}, err
		}
		if err := ctx.Err(); err != nil {
			return wire.Response{}, err
		}
		if err := wire.WriteFrame(conn, wire.ApprovalFrame, raw); err != nil {
			return wire.Response{}, err
		}
		if err := conn.CloseWrite(); err != nil {
			return wire.Response{}, err
		}
		kind, raw, err = wire.ReadFrame(conn)
		if err != nil {
			return wire.Response{}, err
		}
		if kind != wire.ResponseFrame {
			return wire.Response{}, wire.ErrArtifact
		}
		return finish(ctx, conn, d, q, raw)
	default:
		return wire.Response{}, wire.ErrArtifact
	}
}

func finish(ctx context.Context, conn *net.UnixConn, d wire.Descriptor, q wire.Request, raw []byte) (wire.Response, error) {
	if err := wire.RequireEOF(conn); err != nil {
		return wire.Response{}, err
	}
	r, err := wire.DecodeResponse(raw)
	if err != nil {
		return wire.Response{}, err
	}
	if err := r.Verify(d, q); err != nil {
		return wire.Response{}, err
	}
	if err := ctx.Err(); err != nil {
		return wire.Response{}, err
	}
	return r, nil
}

// A caller's approval callback cannot extend the exchange lifetime. Its context
// is cancelled when Call returns; a late signature is never sent to the owner.
func approval(ctx context.Context, challenge wire.Challenge,
	approve func(context.Context, wire.Challenge) (custodyfence.Command, error),
) (custodyfence.Command, error) {
	type result struct {
		command custodyfence.Command
		err     error
	}
	ready := make(chan result, 1)
	go func() {
		command, err := approve(ctx, challenge)
		ready <- result{command, err}
	}()
	select {
	case <-ctx.Done():
		return custodyfence.Command{}, ctx.Err()
	case r := <-ready:
		return r.command, r.err
	}
}
