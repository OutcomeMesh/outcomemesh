// Package gatewayclient accesses the isolated gateway without importing or
// opening any owner key, source location or storage directory.
package gatewayclient

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
)

const Deadline = 10 * time.Second

func ReadFrame(r io.Reader, limit uint32) ([]byte, error) {
	var head [4]byte
	if _, e := io.ReadFull(r, head[:]); e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(head[:])
	if n == 0 || n > limit {
		return nil, wire.ErrArtifact
	}
	b := make([]byte, int(n))
	_, e := io.ReadFull(r, b)
	return b, e
}
func WriteFrame(w io.Writer, b []byte) error {
	if len(b) == 0 || len(b) > wire.MaximumResponseBytes {
		return wire.ErrArtifact
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(b)))
	for _, p := range [][]byte{head[:], b} {
		for len(p) > 0 {
			n, e := w.Write(p)
			if e != nil {
				return e
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			p = p[n:]
		}
	}
	return nil
}
func Call(ctx context.Context, socket string, d wire.Descriptor, q wire.Request) (wire.Response, error) {
	var zero wire.Response
	if ctx == nil || !Supported() || q.Authorize(d) != nil {
		return zero, wire.ErrAccess
	}
	raw, e := q.CanonicalBytes()
	if e != nil {
		return zero, e
	}
	dialer := net.Dialer{Timeout: Deadline}
	c, e := dialer.DialContext(ctx, "unix", socket)
	if e != nil {
		return zero, e
	}
	defer c.Close()
	unixConn, ok := c.(*net.UnixConn)
	if !ok {
		return zero, wire.ErrAccess
	}
	uid, e := PeerUID(unixConn)
	if e != nil || uid != d.OwnerUID {
		return zero, errors.Join(wire.ErrAccess, e)
	}
	deadline := time.Now().Add(Deadline)
	if v, ok := ctx.Deadline(); ok && v.Before(deadline) {
		deadline = v
	}
	if e = c.SetDeadline(deadline); e != nil {
		return zero, e
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if e = WriteFrame(c, raw); e != nil {
		return zero, e
	}
	response, e := ReadFrame(c, wire.MaximumResponseBytes)
	if e != nil {
		return zero, e
	}
	r, e := wire.DecodeResponse(response)
	if e != nil {
		return zero, e
	}
	if e = r.Verify(d, q); e != nil {
		return zero, e
	}
	return r, nil
}
