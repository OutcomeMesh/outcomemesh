package completionwire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func hash(b byte) types.Hash        { var h types.Hash; h[0] = b; return h }
func key(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }
func request(t testing.TB) Request {
	t.Helper()
	c := custodyauthority.Command{AssignmentID: hash(1), ExpectedSequence: 2, ExpectedHead: hash(3), Kind: custodyauthority.Complete, TicketID: hash(4), EvidenceID: hash(5)}
	c, err := c.Sign(key(6))
	if err != nil {
		t.Fatal(err)
	}
	e, err := custodyauthority.SignEntry(c, key(7))
	if err != nil {
		t.Fatal(err)
	}
	return Request{Nonce: hash(8), Entry: e}
}

func TestCompletionCanonicalFrames(t *testing.T) {
	r := request(t)
	encoded, err := r.CanonicalBytes()
	if err != nil || len(encoded) != 424 {
		t.Fatal(err)
	}
	decoded, err := DecodeRequest(encoded)
	if err != nil || decoded != r {
		t.Fatal(err)
	}
	id, _ := r.Entry.ID()
	a := Acknowledgement{Nonce: r.Nonce, EntryID: id}
	ack, err := a.CanonicalBytes()
	if err != nil || len(ack) != 74 {
		t.Fatal(err)
	}
	if h := types.DomainHash("OMESH/test/prune-completion-frame/v0", encoded); h.String() != "73ddee3fb193a291bd22ddf2f91fee75cf6b7102688c5504b1a4b6d2e34bc00e" {
		t.Fatal("request vector changed", h)
	}
	if h := types.DomainHash("OMESH/test/prune-completion-frame/v0", ack); h.String() != "f0e51761c7ae9ab94c17722517fc7b93d9827240fe34fca3f2290d0c43f565f1" {
		t.Fatal("acknowledgement vector changed", h)
	}
	if decoded, err := DecodeAcknowledgement(ack); err != nil || decoded != a {
		t.Fatal(err)
	}
	for i := range len(encoded) {
		if _, err := DecodeRequest(encoded[:i]); err == nil {
			t.Fatal("truncated request", i)
		}
	}
	for i := range len(ack) {
		if _, err := DecodeAcknowledgement(ack[:i]); err == nil {
			t.Fatal("truncated ack", i)
		}
	}
	for _, offset := range []int{0, 8, 9, 42, len(encoded) - 1} {
		bad := bytes.Clone(encoded)
		bad[offset] ^= 1
		if _, err := DecodeRequest(bad); err == nil {
			t.Fatal("invalid envelope/signature", offset)
		}
	}
	for _, body := range [][]byte{append(bytes.Clone(encoded), 0), append(bytes.Clone(ack), 0)} {
		if _, err := DecodeRequest(body); err == nil {
			t.Fatal("trailing request")
		}
		if _, err := DecodeAcknowledgement(body); err == nil {
			t.Fatal("trailing ack")
		}
	}
	bad := bytes.Clone(encoded)
	clear(bad[10:42])
	if _, err := DecodeRequest(bad); err == nil {
		t.Fatal("zero nonce")
	}
	for _, from := range []int{10, 42} {
		bad := bytes.Clone(ack)
		clear(bad[from : from+32])
		if _, err := DecodeAcknowledgement(bad); err == nil {
			t.Fatal("zero ack binding")
		}
	}
	if err := RequireEOF(bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	if err := RequireEOF(bytes.NewReader([]byte{1})); err == nil {
		t.Fatal("trailing byte accepted")
	}
	if _, err := ReadRequest(nil); err == nil {
		t.Fatal("nil reader")
	}
	if _, err := ReadAcknowledgement(nil); err == nil {
		t.Fatal("nil reader")
	}
	if err := RequireEOF(nil); err == nil {
		t.Fatal("nil eof")
	}
	if err := WriteRequest(nil, r); err == nil {
		t.Fatal("nil writer")
	}
	if err := WriteAcknowledgement(nil, a); err == nil {
		t.Fatal("nil writer")
	}
}

type shortWriter struct {
	bytes.Buffer
	zero bool
}

func (w *shortWriter) Write(b []byte) (int, error) {
	if w.zero {
		return 0, nil
	}
	return w.Buffer.Write(b[:1])
}
func TestCompletionFrameIO(t *testing.T) {
	r := request(t)
	encoded, _ := r.CanonicalBytes()
	w := &shortWriter{}
	if err := WriteRequest(w, r); err != nil || !bytes.Equal(w.Bytes(), encoded) {
		t.Fatal(err)
	}
	if err := WriteRequest(&shortWriter{zero: true}, r); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	read, err := ReadRequest(bytes.NewReader(w.Bytes()))
	if err != nil || read != r {
		t.Fatal(err)
	}
	bad := bytes.Clone(encoded)
	bad[0] ^= 1
	reader := bytes.NewReader(bad)
	if _, err := ReadRequest(reader); err == nil || reader.Len() != len(encoded)-10 {
		t.Fatal("wrong magic consumed body")
	}
}

func TestCompletionRejectsOtherCoSignedCommands(t *testing.T) {
	r := request(t)
	for _, kind := range []custodyauthority.Kind{custodyauthority.Admit, custodyauthority.Stop, custodyauthority.Retire} {
		command := r.Entry.Command
		command.Kind, command.TicketID = kind, types.Hash{}
		if kind == custodyauthority.Admit {
			command.OperationID, command.Purpose, command.EvidenceID = hash(9), custodyauthority.Prune, types.Hash{}
		}
		command, err := command.Sign(key(6))
		if err != nil {
			t.Fatal(err)
		}
		entry, err := custodyauthority.SignEntry(command, key(7))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (Request{Nonce: r.Nonce, Entry: entry}).CanonicalBytes(); !errors.Is(err, ErrProtocol) {
			t.Fatal("other command encoded", kind, err)
		}
		body, _ := entry.CanonicalBytes()
		encoded := append(append(append([]byte(nil), requestMagic...), r.Nonce[:]...), body...)
		if _, err := DecodeRequest(encoded); !errors.Is(err, ErrProtocol) {
			t.Fatal("other co-signed command decoded", kind, err)
		}
	}
}

type exchangeStream struct {
	written       bytes.Buffer
	reply         *bytes.Reader
	mode          string
	closed        bool
	closeWriteErr error
}

func (s *exchangeStream) Read(b []byte) (int, error) {
	if s.reply == nil {
		return 0, io.EOF
	}
	return s.reply.Read(b)
}
func (s *exchangeStream) Write(b []byte) (int, error) { return s.written.Write(b) }
func (s *exchangeStream) Close() error                { s.closed = true; return nil }
func (s *exchangeStream) SetDeadline(time.Time) error { return nil }
func (s *exchangeStream) CloseWrite() error {
	if s.closeWriteErr != nil {
		return s.closeWriteErr
	}
	r, err := DecodeRequest(s.written.Bytes())
	if err != nil {
		return err
	}
	id, _ := r.Entry.ID()
	a := Acknowledgement{Nonce: r.Nonce, EntryID: id}
	if s.mode == "nonce" {
		a.Nonce[0] ^= 1
	}
	if s.mode == "entry" {
		a.EntryID[0] ^= 1
	}
	b, _ := a.CanonicalBytes()
	if s.mode == "lost" {
		b = nil
	}
	if s.mode == "partial" {
		b = b[:40]
	}
	if s.mode == "extra" {
		b = append(b, 1)
	}
	s.reply = bytes.NewReader(b)
	return nil
}

func TestExchangeRejectsUnboundIncompleteOrTrailingReplies(t *testing.T) {
	entry := request(t).Entry
	for _, mode := range []string{"ok", "nonce", "entry", "lost", "partial", "extra", "close-write"} {
		t.Run(mode, func(t *testing.T) {
			s := &exchangeStream{mode: mode}
			if mode == "close-write" {
				s.closeWriteErr = io.ErrClosedPipe
			}
			a, err := Exchange(t.Context(), s, entry, DefaultTimeout)
			if !s.closed {
				t.Fatal("stream not retired")
			}
			if mode == "ok" {
				if err != nil || a.EntryID.IsZero() {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrUnconfirmed) || a != (Acknowledgement{}) {
				t.Fatal("ambiguous reply accepted", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Exchange(ctx, &exchangeStream{}, entry, DefaultTimeout); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, timeout := range []time.Duration{0, MaximumTimeout + 1} {
		if _, err := Exchange(t.Context(), &exchangeStream{}, entry, timeout); err == nil {
			t.Fatal("invalid timeout")
		}
	}
}

func FuzzCompletionFrames(f *testing.F) {
	r := request(f)
	b, _ := r.CanonicalBytes()
	id, _ := r.Entry.ID()
	a, _ := (Acknowledgement{Nonce: r.Nonce, EntryID: id}).CanonicalBytes()
	f.Add(b)
	f.Add(a)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		if r, err := DecodeRequest(input); err == nil {
			b, err := r.CanonicalBytes()
			if err != nil || !bytes.Equal(input, b) {
				t.Fatal("noncanonical request")
			}
		}
		if a, err := DecodeAcknowledgement(input); err == nil {
			b, err := a.CanonicalBytes()
			if err != nil || !bytes.Equal(input, b) {
				t.Fatal("noncanonical ack")
			}
		}
	})
}
