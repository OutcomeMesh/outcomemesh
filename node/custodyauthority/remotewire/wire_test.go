package remotewire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
)

func controlKey(value byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{value}, ed25519.SeedSize))
}
func controlPublic(value byte) [32]byte {
	return [32]byte(controlKey(value).Public().(ed25519.PublicKey))
}
func controlHash(value byte) (id types.Hash) {
	for i := range id {
		id[i] = value
	}
	return id
}

func controlFixture(t testing.TB) (custodyauthority.Assignment, Request, Response) {
	t.Helper()
	a0 := custodyauthority.Assignment{NetworkID: 77, GenesisID: controlHash(11), ActivationHeight: 2, BaseID: controlHash(12), ManifestID: controlHash(13),
		StatementID: controlHash(14), InitialReceiptID: controlHash(15), CustodyPolicyID: controlHash(16), IncarnationID: controlHash(17),
		AuthorityPublicKey: controlPublic(1), ReplicaPublicKey: controlPublic(2), Auditors: [][32]byte{controlPublic(3)},
		Consumers: []custodyauthority.Consumer{{PublicKey: controlPublic(4), Purposes: custodyauthority.AllPurposes}}, MaximumOperations: 16, MaximumPending: 4}
	a, err := custodyauthority.WithRemoteParticipant(a0, controlPublic(5), controlPublic(6))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := a.ID()
	command := custodyauthority.Command{Version: custodyauthority.Version1, AssignmentID: id, ExpectedHead: id, Kind: custodyauthority.Admit, Purpose: custodyauthority.Serve, OperationID: controlHash(21)}
	command, err = command.Sign(controlKey(4))
	if err != nil {
		t.Fatal(err)
	}
	admission, err := custodyauthority.SignEntry(command, controlKey(1))
	if err != nil {
		t.Fatal(err)
	}
	plan := remoteworker.Plan{AssignmentID: id, Admission: admission, AuthorityTransportPublicKey: controlPublic(8), AuditorTransportPublicKey: controlPublic(7), PriorReceiptID: a.InitialReceiptID, Nonce: controlHash(22)}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	admissionID, _ := admission.ID()
	begin, err := custodyauthority.BuildRemoteBeginCommand(a, admission, planID, custodyauthority.Position{Sequence: 1, HeadID: admissionID})
	if err != nil {
		t.Fatal(err)
	}
	begin, err = begin.Sign(controlKey(5))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.SignEntry(begin, controlKey(1))
	if err != nil {
		t.Fatal(err)
	}
	beginID, _ := entry.ID()
	r := Request{Kind: Start, Nonce: controlHash(23), Plan: plan, Begin: entry}
	seal := remoteworker.Seal{PlanID: planID, BeginID: beginID, SealingID: controlHash(24), Disposition: remoteworker.RetainedResult, ResultID: controlHash(25)}
	sealID, _ := seal.ID()
	drain, err := custodyauthority.BuildRemoteDrainedCommand(a, entry, sealID, custodyauthority.Position{Sequence: 2, HeadID: beginID})
	if err != nil {
		t.Fatal(err)
	}
	drain, err = drain.Sign(controlKey(5))
	if err != nil {
		t.Fatal(err)
	}
	s := Response{Status: StatusDrained, Nonce: r.Nonce, PlanID: planID, BeginID: beginID, Seal: seal, Drain: drain}
	return a, r, s
}

func TestControlCanonicalGoldenAndFrames(t *testing.T) {
	a, r, s := controlFixture(t)
	if err := r.Validate(a, s.PlanID, s.BeginID); err != nil {
		t.Fatal(err)
	}
	if err := ValidateResponse(a, r, s); err != nil {
		t.Fatal(err)
	}
	request, err := r.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := s.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(request) != 1023 || len(reply) != 526 {
		t.Fatal("unexpected control frame sizes", len(request), len(reply))
	}
	if id, _ := r.Plan.ID(); id.String() != "29e1f46f85cf0d4a6b9b883c0c0e227659961e46eef1bd473b326770f0779929" {
		t.Fatal("embedded plan vector changed", id)
	}
	decoded, err := DecodeRequest(request)
	if err != nil || decoded != r {
		t.Fatal("request roundtrip", err)
	}
	parsed, err := DecodeResponse(reply)
	if err != nil || parsed != s {
		t.Fatal("drained roundtrip", err)
	}
	// Independent byte vector pins the complete status-only envelope, including
	// its magic, version, status and all three mandatory exchange bindings.
	started := Response{Status: StatusStarted, Nonce: controlHash(1), PlanID: controlHash(2), BeginID: controlHash(3)}
	const startedHex = "4f4d435243525350000001010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303"
	golden, err := hex.DecodeString(startedHex)
	if err != nil {
		t.Fatal(err)
	}
	b, err := started.CanonicalBytes()
	if err != nil || !bytes.Equal(b, golden) {
		t.Fatalf("started golden changed: %x %v", b, err)
	}
	if decoded, err := DecodeResponse(golden); err != nil || decoded != started {
		t.Fatal("golden decode", err)
	}
	for _, vector := range []struct {
		bytes  []byte
		decode func([]byte) error
	}{
		{request, func(b []byte) error { _, err := DecodeRequest(b); return err }},
		{reply, func(b []byte) error { _, err := DecodeResponse(b); return err }},
		{golden, func(b []byte) error { _, err := DecodeResponse(b); return err }},
	} {
		for i := range len(vector.bytes) {
			if vector.decode(vector.bytes[:i]) == nil {
				t.Fatal("accepted truncation", i)
			}
		}
		for _, bad := range [][]byte{nil, append(bytes.Clone(vector.bytes), 0), bytes.Repeat([]byte{1}, MaxFrameBytes+1)} {
			if vector.decode(bad) == nil {
				t.Fatal("accepted malformed control envelope")
			}
		}
	}
	for _, kind := range []Kind{Start, Seal, Reconcile} {
		r.Kind = kind
		if err := r.Validate(a, s.PlanID, s.BeginID); err != nil {
			t.Fatal(kind, err)
		}
		if err := ValidateResponse(a, r, s); err != nil {
			t.Fatal(kind, err)
		}
	}
	var framed bytes.Buffer
	if err := WriteRequest(&framed, r); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(framed.Bytes()[:4]) != uint32(len(request)) {
		t.Fatal("bad bounded length prefix")
	}
	if decoded, err := ReadRequest(&framed); err != nil || decoded != r {
		t.Fatal("framed request", err)
	}
	if err := RequireEOF(&framed); err != nil {
		t.Fatal(err)
	}
	if err := WriteResponse(&framed, s); err != nil {
		t.Fatal(err)
	}
	if decoded, err := ReadResponse(&framed); err != nil || decoded != s {
		t.Fatal("framed response", err)
	}
}

func TestControlRejectsScopePinsAndReplySubstitution(t *testing.T) {
	a, r, s := controlFixture(t)
	for _, pins := range [][2]types.Hash{{{}, s.BeginID}, {s.PlanID, {}}, {controlHash(90), s.BeginID}, {s.PlanID, controlHash(91)}} {
		if r.Validate(a, pins[0], pins[1]) == nil {
			t.Fatal("accepted independent pin substitution")
		}
	}
	other := a
	other.IncarnationID = controlHash(92)
	if r.Validate(other, s.PlanID, s.BeginID) == nil {
		t.Fatal("accepted another assignment")
	}
	if ValidateResponse(other, r, s) == nil {
		t.Fatal("accepted response under another assignment")
	}
	for _, mutate := range []func(*Request){
		func(r *Request) { r.Version = 1 }, func(r *Request) { r.Kind = 0 }, func(r *Request) { r.Kind = 99 }, func(r *Request) { r.Nonce = types.Hash{} },
		func(r *Request) { r.Plan.Nonce = controlHash(93) }, func(r *Request) { r.Begin.Signature[0] ^= 1 }, func(r *Request) { r.Begin.Command.Signature[0] ^= 1 },
	} {
		bad := r
		mutate(&bad)
		if bad.Validate(a, s.PlanID, s.BeginID) == nil {
			t.Fatal("accepted malformed request")
		}
	}
	for _, mutate := range []func(*Response){
		func(s *Response) { s.Version = 1 }, func(s *Response) { s.Status = 0 }, func(s *Response) { s.Nonce[0] ^= 1 }, func(s *Response) { s.PlanID[0] ^= 1 }, func(s *Response) { s.BeginID[0] ^= 1 },
		func(s *Response) { s.Seal.ResultID[0] ^= 1 }, func(s *Response) { s.Seal.SealingID[0] ^= 1 }, func(s *Response) { s.Drain.Signature[0] ^= 1 },
	} {
		bad := s
		mutate(&bad)
		if ValidateResponse(a, r, bad) == nil {
			t.Fatal("accepted mutated response")
		}
	}
	// Re-sign each altered command: these failures must come from exact scope
	// binding rather than a stale cryptographic signature.
	for _, mutate := range []func(*custodyauthority.Command){
		func(c *custodyauthority.Command) { c.AssignmentID = controlHash(94) }, func(c *custodyauthority.Command) { c.ExpectedSequence++ },
		func(c *custodyauthority.Command) { c.ExpectedHead = controlHash(95) }, func(c *custodyauthority.Command) { c.TicketID = controlHash(96) },
		func(c *custodyauthority.Command) { c.OperationID = controlHash(97) }, func(c *custodyauthority.Command) { c.EvidenceID = controlHash(98) },
	} {
		bad := s
		mutate(&bad.Drain)
		var err error
		bad.Drain, err = bad.Drain.Sign(controlKey(5))
		if err != nil {
			t.Fatal(err)
		}
		if ValidateResponse(a, r, bad) == nil {
			t.Fatal("accepted re-signed substitution")
		}
	}
	bad := s
	bad.Drain.ActorPublicKey = [32]byte{}
	var err error
	bad.Drain, err = bad.Drain.Sign(controlKey(9))
	if err != nil {
		t.Fatal(err)
	}
	if ValidateResponse(a, r, bad) == nil {
		t.Fatal("accepted another B signer")
	}
	started := Response{Status: StatusStarted, Nonce: r.Nonce, PlanID: s.PlanID, BeginID: s.BeginID}
	if err := ValidateResponse(a, r, started); err != nil {
		t.Fatal(err)
	}
	r.Kind = Seal
	if ValidateResponse(a, r, started) == nil {
		t.Fatal("Seal accepted advisory Started reply")
	}
	started.Seal = s.Seal
	if _, err := started.CanonicalBytes(); err == nil {
		t.Fatal("status-only reply carried hidden terminal data")
	}
}

type oneByteWriter struct {
	bytes.Buffer
	zero bool
}

func (w *oneByteWriter) Write(b []byte) (int, error) {
	if w.zero {
		return 0, nil
	}
	return w.Buffer.Write(b[:1])
}

type eofWithError struct{}

func (eofWithError) Read([]byte) (int, error) { return 0, errors.Join(io.EOF, io.ErrClosedPipe) }

func TestControlBoundedFramingAndCompleteEOF(t *testing.T) {
	_, r, s := controlFixture(t)
	w := &oneByteWriter{}
	if err := WriteRequest(w, r); err != nil {
		t.Fatal(err)
	}
	if read, err := ReadRequest(bytes.NewReader(w.Bytes())); err != nil || read != r {
		t.Fatal(err)
	}
	if err := WriteResponse(&oneByteWriter{zero: true}, s); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	for _, n := range []uint32{0, MaxFrameBytes + 1, ^uint32(0)} {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		reader := bytes.NewReader(append(b[:], 1))
		if _, err := ReadRequest(reader); err == nil || reader.Len() != 1 {
			t.Fatal("unbounded request body read", n, err)
		}
		reader = bytes.NewReader(append(b[:], 1))
		if _, err := ReadResponse(reader); err == nil || reader.Len() != 1 {
			t.Fatal("unbounded reply body read", n, err)
		}
	}
	b, _ := r.CanonicalBytes()
	// Plan length begins at byte 43; the otherwise equivalent overlong
	// unsigned varint must not admit a second byte representation.
	overlong := append(bytes.Clone(b[:44]), 0x84, 0)
	overlong = append(overlong, b[45:]...)
	if _, err := DecodeRequest(overlong); err == nil {
		t.Fatal("accepted overlong plan length")
	}
	for _, reader := range []io.Reader{bytes.NewReader([]byte{1}), eofWithError{}, nil} {
		if RequireEOF(reader) == nil {
			t.Fatal("accepted incomplete or trailing EOF")
		}
	}
	if err := RequireEOF(bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRequest(nil); err == nil {
		t.Fatal("nil request reader")
	}
	if _, err := ReadResponse(nil); err == nil {
		t.Fatal("nil reply reader")
	}
	if err := WriteRequest(nil, r); err == nil {
		t.Fatal("nil request writer")
	}
	if err := WriteResponse(nil, s); err == nil {
		t.Fatal("nil reply writer")
	}
}

type controlExchangeStream struct {
	written  bytes.Buffer
	reply    *bytes.Reader
	response Response
	mode     string
	closed   bool
}

func (s *controlExchangeStream) Read(b []byte) (int, error) {
	if s.reply == nil {
		return 0, io.EOF
	}
	return s.reply.Read(b)
}
func (s *controlExchangeStream) Write(b []byte) (int, error) {
	if s.mode == "write" {
		return 0, io.ErrClosedPipe
	}
	return s.written.Write(b)
}
func (s *controlExchangeStream) Close() error {
	s.closed = true
	if s.mode == "close" {
		return io.ErrClosedPipe
	}
	return nil
}
func (s *controlExchangeStream) SetDeadline(time.Time) error {
	if s.mode == "deadline" {
		return io.ErrClosedPipe
	}
	return nil
}
func (s *controlExchangeStream) CloseWrite() error {
	if s.mode == "close-write" {
		return io.ErrClosedPipe
	}
	r, err := ReadRequest(bytes.NewReader(s.written.Bytes()))
	if err != nil {
		return err
	}
	response := s.response
	switch s.mode {
	case "nonce":
		response.Nonce[0] ^= 1
	case "plan":
		response.PlanID[0] ^= 1
	case "begin":
		response.BeginID[0] ^= 1
	case "started":
		response = Response{Status: StatusStarted, Nonce: r.Nonce, PlanID: s.response.PlanID, BeginID: s.response.BeginID}
	}
	var b bytes.Buffer
	if err := WriteResponse(&b, response); err != nil {
		return err
	}
	raw := b.Bytes()
	switch s.mode {
	case "lost":
		raw = nil
	case "partial":
		raw = raw[:30]
	case "extra":
		raw = append(raw, 1)
	}
	s.reply = bytes.NewReader(raw)
	return nil
}

func TestControlExchangeRetainsUncertaintyAndNeverRetries(t *testing.T) {
	a, r, response := controlFixture(t)
	for _, mode := range []string{"ok", "nonce", "plan", "begin", "lost", "partial", "extra", "close-write", "write", "close", "deadline", "started"} {
		t.Run(mode, func(t *testing.T) {
			s := &controlExchangeStream{response: response, mode: mode}
			request := r
			if mode == "started" {
				request.Kind = Seal
			}
			reply, err := Exchange(t.Context(), s, request, DefaultTimeout)
			if !s.closed {
				t.Fatal("stream not retired")
			}
			if mode == "ok" {
				if err != nil || reply != response {
					t.Fatal(err)
				}
				if err := ValidateResponse(a, request, reply); err != nil {
					t.Fatal(err)
				}
			} else if mode == "deadline" {
				if err == nil || reply != (Response{}) {
					t.Fatal("deadline setup accepted", err)
				}
			} else if !errors.Is(err, ErrUnconfirmed) || reply != (Response{}) {
				t.Fatal("incomplete reply treated as confirmed", err)
			}
			if mode != "write" && mode != "deadline" {
				reader := bytes.NewReader(s.written.Bytes())
				if _, err := ReadRequest(reader); err != nil || reader.Len() != 0 {
					t.Fatal("request retried or changed", err)
				}
			}
		})
	}
}

type blockingControlStream struct {
	mu       sync.Mutex
	deadline time.Time
	ready    chan struct{}
	once     sync.Once
	closed   bool
}

func (s *blockingControlStream) Read([]byte) (int, error)    { <-s.ready; return 0, io.ErrClosedPipe }
func (s *blockingControlStream) Write(b []byte) (int, error) { return len(b), nil }
func (s *blockingControlStream) CloseWrite() error           { return nil }
func (s *blockingControlStream) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.once.Do(func() { close(s.ready) })
	return nil
}
func (s *blockingControlStream) SetDeadline(d time.Time) error {
	s.mu.Lock()
	s.deadline = d
	s.mu.Unlock()
	if !d.After(time.Now()) {
		s.once.Do(func() { close(s.ready) })
	}
	return nil
}

func TestControlBoundStreamCancellationAndTimeoutLimits(t *testing.T) {
	_, r, _ := controlFixture(t)
	for _, timeout := range []time.Duration{0, MinimumTimeout - time.Nanosecond, MaximumTimeout + time.Nanosecond} {
		s := &controlExchangeStream{}
		if _, _, err := BoundStream(t.Context(), s, timeout); err == nil {
			t.Fatal("accepted timeout", timeout)
		}
	}
	if _, _, err := BoundStream(nil, &controlExchangeStream{}, DefaultTimeout); err == nil {
		t.Fatal("nil context")
	}
	if _, _, err := BoundStream(t.Context(), nil, DefaultTimeout); err == nil {
		t.Fatal("nil stream")
	}
	ctx, cancel := context.WithCancel(t.Context())
	stream := &blockingControlStream{ready: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, err := Exchange(ctx, stream, r, DefaultTimeout); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation left read blocked")
	}
}

func FuzzDecodeRemoteControl(f *testing.F) {
	_, r, s := controlFixture(f)
	request, _ := r.CanonicalBytes()
	reply, _ := s.CanonicalBytes()
	started, _ := (Response{Status: StatusStarted, Nonce: r.Nonce, PlanID: s.PlanID, BeginID: s.BeginID}).CanonicalBytes()
	f.Add(request, reply)
	f.Add(request, started)
	f.Add([]byte{}, []byte{})
	f.Add(request[:10], reply[:10])
	f.Fuzz(func(t *testing.T, request, reply []byte) {
		if r, err := DecodeRequest(request); err == nil {
			b, err := r.CanonicalBytes()
			if err != nil || !bytes.Equal(b, request) {
				t.Fatal("noncanonical request", err)
			}
		}
		if s, err := DecodeResponse(reply); err == nil {
			b, err := s.CanonicalBytes()
			if err != nil || !bytes.Equal(b, reply) {
				t.Fatal("noncanonical reply", err)
			}
		}
	})
}
