package gatewayrelay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	client "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayclient"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func fixture(t testing.TB) (wire.Descriptor, []byte, wire.Response) {
	t.Helper()
	d, e := (wire.Descriptor{RootID: f.Hash("root"), SourceID: f.Hash("source"), GenesisID: f.Hash("genesis"), GenesisDescriptorID: f.Hash("descriptor"), EnrollmentID: f.Hash("enrollment"), Gateway: f.Public(1), Issuer: f.Public(2), Clients: [][32]byte{f.Public(3)}, OwnerUID: 0, ParticipantUID: 65534, EventLimit: 16}).Sign(f.Key(2))
	if e != nil {
		t.Fatal(e)
	}
	id, _ := d.ID()
	payload := []byte("opaque typed payload; gateway checks its contents")
	q, e := (wire.Request{DescriptorID: id, Nonce: f.Hash("attempt"), Kind: wire.Runtime, ChunkID: wire.RuntimePayloadID(payload)}).Sign(f.Key(3))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := wire.EncodeRuntimeRequest(q, payload)
	if e != nil {
		t.Fatal(e)
	}
	r, e := (wire.Response{Request: q, SourceID: d.SourceID, Data: []byte("retained-result")}).Sign(d, f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	return d, raw, r
}
func host(t testing.TB, seed byte) *libp2ptransport.Host {
	t.Helper()
	h, e := libp2ptransport.New(t.Context(), f.Key(seed), libp2ptransport.DefaultConfig(), nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { h.Close() })
	return h
}
func TestGatewayRelayQUICAuthenticatesAndPreservesExactAttempt(t *testing.T) {
	d, raw, r := fixture(t)
	h := host(t, 20)
	var calls atomic.Int32
	s, e := start(t.Context(), "", d, f.Key(21), libp2ptransport.DefaultConfig(), []types.Hash{h.ID()}, time.Second, func(_ context.Context, q wire.Request, p []byte) (wire.Response, error) {
		calls.Add(1)
		encoded, _ := wire.EncodeRuntimeRequest(q, p)
		if !bytes.Equal(encoded, raw) {
			return wire.Response{}, wire.ErrArtifact
		}
		return r, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	attempt := func(h *libp2ptransport.Host, packet []byte, trailing bool) error {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		st, _, e := h.OpenCustodyGatewayStream(ctx, s.Addresses()[0], s.ID())
		if e != nil {
			return e
		}
		if trailing {
			defer st.Close()
			if e = client.WriteFrame(st, packet); e != nil {
				return e
			}
			_, _ = st.Write([]byte{1})
			_ = st.CloseWrite()
			_, e = client.ReadFrame(st, wire.MaximumResponseBytes)
			return e
		}
		reply, e := Exchange(ctx, st, d, packet, time.Second)
		if e == nil {
			a, _ := reply.CanonicalBytes()
			b, _ := r.CanonicalBytes()
			if !bytes.Equal(a, b) {
				t.Fatal("changed signed response")
			}
		}
		return e
	}
	if e = attempt(host(t, 22), raw, false); e == nil {
		t.Fatal("unlisted network peer")
	}
	if e = attempt(h, raw, true); e == nil {
		t.Fatal("trailing frame")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached gateway")
	}
	// Relay restarts/retries must not invent a nonce or alter the signed request.
	for i := 0; i < 2; i++ {
		if e = attempt(h, raw, false); e != nil {
			t.Fatal(e)
		}
	}
	if calls.Load() != 2 {
		t.Fatal(calls.Load())
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if st, _, e := h.OpenCustodyV2Stream(ctx, s.Addresses()[0], s.ID()); e == nil {
		st.Close()
		t.Fatal("legacy protocol enabled")
	}
	if st, _, e := h.OpenCustodyGatewayStream(ctx, s.Addresses()[0], f.Hash("wrong-peer")); e == nil {
		st.Close()
		t.Fatal("wrong peer pin")
	}
}
func TestGatewayRelayEightInflightAndCancellationDrain(t *testing.T) {
	d, raw, _ := fixture(t)
	h := host(t, 20)
	entered := make(chan struct{}, 8)
	s, e := start(t.Context(), "", d, f.Key(21), libp2ptransport.DefaultConfig(), []types.Hash{h.ID()}, time.Second, func(ctx context.Context, _ wire.Request, _ []byte) (wire.Response, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return wire.Response{}, ctx.Err()
	})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for i := 0; i < 8; i++ {
		st, _, e := h.OpenCustodyGatewayStream(ctx, s.Addresses()[0], s.ID())
		if e != nil {
			t.Fatal(e)
		}
		defer st.Close()
		if e = client.WriteFrame(st, raw); e != nil {
			t.Fatal(e)
		}
		st.CloseWrite()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("handler did not enter")
		}
	}
	st, _, e := h.OpenCustodyGatewayStream(ctx, s.Addresses()[0], s.ID())
	if e != nil {
		t.Fatal(e)
	}
	_, e = Exchange(ctx, st, d, raw, time.Second)
	if e == nil {
		t.Fatal("ninth handler admitted")
	}
	done := make(chan error, 2)
	go func() { done <- s.Close() }()
	go func() { done <- s.Close() }()
	for i := 0; i < 2; i++ {
		select {
		case e := <-done:
			if e != nil {
				t.Fatal(e)
			}
		case <-ctx.Done():
			t.Fatal("shutdown did not drain")
		}
	}
}

type scriptedStream struct {
	io.Reader
	writes               bytes.Buffer
	closeErr, errorWrite error
	closed               bool
}

func (s *scriptedStream) Write(p []byte) (int, error) {
	if s.errorWrite != nil {
		return 0, s.errorWrite
	}
	return s.writes.Write(p)
}
func (s *scriptedStream) Close() error                { s.closed = true; return s.closeErr }
func (s *scriptedStream) CloseWrite() error           { return nil }
func (s *scriptedStream) SetDeadline(time.Time) error { return nil }
func TestGatewayRelayUnconfirmedRepliesNeverReturnEvidence(t *testing.T) {
	d, raw, r := fixture(t)
	packet, _ := r.CanonicalBytes()
	var frame bytes.Buffer
	client.WriteFrame(&frame, packet)
	for _, tc := range []struct {
		name               string
		data               []byte
		closeErr, writeErr error
	}{
		{"lost", nil, nil, nil}, {"truncated", frame.Bytes()[:20], nil, nil}, {"trailing", append(append([]byte{}, frame.Bytes()...), 1), nil, nil},
		{"close", frame.Bytes(), io.ErrClosedPipe, nil}, {"write", nil, nil, io.ErrClosedPipe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scriptedStream{Reader: bytes.NewReader(tc.data), closeErr: tc.closeErr, errorWrite: tc.writeErr}
			got, e := Exchange(t.Context(), s, d, raw, time.Second)
			if !errors.Is(e, ErrUnconfirmed) || len(got.Data) != 0 || !s.closed {
				t.Fatal(got, e)
			}
		})
	}
	// Foreign valid response must fail the request binding, not only its signature.
	q := r.Request
	q.Nonce = f.Hash("other")
	q, _ = q.Sign(f.Key(3))
	r.Request = q
	r, _ = r.Sign(d, f.Key(1))
	packet, _ = r.CanonicalBytes()
	frame.Reset()
	client.WriteFrame(&frame, packet)
	s := &scriptedStream{Reader: bytes.NewReader(frame.Bytes())}
	if _, e := Exchange(t.Context(), s, d, raw, time.Second); !errors.Is(e, ErrUnconfirmed) {
		t.Fatal(e)
	}
}
func TestGatewayRelayMalformedEnvelopeRejectedBeforeForward(t *testing.T) {
	d, raw, _ := fixture(t)
	q, _, _ := DecodeAttempt(d, raw)
	bare, _ := q.CanonicalBytes()
	for _, b := range [][]byte{nil, bare, raw[:10], append(append([]byte{}, raw...), 0)} {
		if _, _, e := DecodeAttempt(d, b); e == nil {
			t.Fatal("malformed envelope")
		}
	}
	other := d
	other.RootID = f.Hash("other")
	other, _ = other.Sign(f.Key(2))
	if _, _, e := DecodeAttempt(other, raw); e == nil {
		t.Fatal("foreign descriptor")
	}
	s := &scriptedStream{Reader: bytes.NewReader(nil)}
	if _, e := Exchange(t.Context(), s, d, bare, time.Second); e == nil || s.writes.Len() != 0 {
		t.Fatal("invalid local input written")
	}
	var oversized [4]byte
	binary.BigEndian.PutUint32(oversized[:], wire.MaximumServiceRequestBytes+1)
	if _, e := client.ReadFrame(bytes.NewReader(oversized[:]), wire.MaximumServiceRequestBytes); e == nil {
		t.Fatal("oversized")
	}
}
func FuzzGatewayRelayAttempt(fz *testing.F) {
	d, raw, _ := fixture(fz)
	fz.Add(raw)
	fz.Add([]byte("OMCGXRQ5"))
	fz.Fuzz(func(t *testing.T, b []byte) {
		q, p, e := DecodeAttempt(d, b)
		if e != nil {
			return
		}
		out, e := wire.EncodeRuntimeRequest(q, p)
		if e != nil || !bytes.Equal(out, b) || q.Authorize(d) != nil {
			t.Fatal("noncanonical accepted", e)
		}
	})
}
