package custodyv2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const deliveryNetworkTimeout = 10 * time.Second

type deliveryNetworkFixture struct {
	x          requiredRuntimeFixture
	path       string
	enrollment AdmissionDeliveryEnrollment
	delivery   AdmissionDelivery
}

func newDeliveryNetworkFixture(t testing.TB) deliveryNetworkFixture {
	t.Helper()
	x := newRequiredRuntimeFixture(t)
	path := filepath.Join(x.root, "delivery-inbox")
	bid, _ := x.binding.ID()
	public := f.Public(15)
	peer, _ := transport.PeerIDFromPublicKey(public[:])
	e, err := CreateAdmissionInbox(path, x.c, x.pin, bid, AdmissionDeliveryTarget, x.s, peer)
	if err != nil {
		t.Fatal(err)
	}
	d := AdmissionDelivery{Version: Version2, Enrollment: e, Context: x.c, Binding: x.binding}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	return deliveryNetworkFixture{x: x, path: path, enrollment: e, delivery: d}
}

func (z deliveryNetworkFixture) open(t testing.TB) *AdmissionInbox {
	t.Helper()
	inbox, e := OpenAdmissionInbox(z.path, z.x.c, z.x.pin, z.x.s, z.enrollment, f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = inbox.Close() })
	return inbox
}

func (z deliveryNetworkFixture) start(t testing.TB, listen string) *AdmissionDeliveryService {
	t.Helper()
	config := libp2ptransport.DefaultConfig()
	if listen != "" {
		config.Listen = []string{listen}
	}
	s, e := StartAdmissionDelivery(t.Context(), z.open(t), f.Key(15), config, deliveryNetworkTimeout)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func (z deliveryNetworkFixture) outbox(t testing.TB, path, address string, create bool) *AdmissionOutbox {
	t.Helper()
	if create {
		if e := CreateAdmissionOutbox(path, z.delivery, address); e != nil {
			t.Fatal(e)
		}
	}
	o, e := OpenAdmissionOutbox(path, z.delivery, address)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func (z deliveryNetworkFixture) noEffect(t testing.TB) {
	t.Helper()
	for _, path := range []string{z.x.s.Journal, z.x.ajournal} {
		_, state, e := workarchive.OpenExistingCustodyJournalWithLimits(t.Context(), path, z.x.c.Manifest, z.x.c.Initial, z.x.c.CustodyPolicy, workarchive.DefaultCustodyJournalLimits())
		if e != nil || state.Sequence != 0 {
			t.Fatal("proof delivery changed original source", state.Sequence, e)
		}
	}
	for _, path := range []string{z.x.targetPath, z.x.acceptorPath} {
		if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("proof delivery created a required runtime owner", path, e)
		}
	}
}

func TestAdmissionDeliveryQUICLostReplyColdExactRetry(t *testing.T) {
	z := newDeliveryNetworkFixture(t)
	// No current chunk is available; delivery must still retain public proof
	// without opening the object store or preparing any execution session.
	chunk := filepath.Join(z.x.s.Objects, "chunk-"+z.x.c.Manifest.Chunks[0].ID.String()+".omwc")
	if e := os.Remove(chunk); e != nil {
		t.Fatal(e)
	}
	s := z.start(t, "")
	address := s.Addresses()[0]
	path := filepath.Join(z.x.root, "delivery-outbox")
	o := z.outbox(t, path, address, true)
	client := openClient(t, 46)
	s.op.Lock()
	s.hook = func(stage string) error { return errors.New("lost durable acknowledgement") }
	s.op.Unlock()
	if _, e := DeliverAdmission(t.Context(), client, o, deliveryNetworkTimeout); !errors.Is(e, ErrUncertain) {
		t.Fatal("lost reply was not unknown", e)
	}
	retained, e := s.inbox.ReadReceipt()
	if e != nil || retained.Verify(z.delivery) != nil {
		t.Fatal("receiver lost durable original receipt", e)
	}
	if _, e := o.ReadReceipt(); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("outbox advanced without authenticated reply", e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	if e := o.Close(); e != nil {
		t.Fatal(e)
	}
	_ = client.Close()
	z.noEffect(t)
	// Original stores and exact route survive cold restart. No replacement
	// enrollment or public proof is invented to resolve the unknown delivery.
	s = z.start(t, strings.Split(address, "/p2p/")[0])
	if s.Addresses()[0] != address {
		t.Fatal("restart changed pinned route", s.Addresses(), address)
	}
	o = z.outbox(t, path, address, false)
	client = openClient(t, 46)
	recovered, e := DeliverAdmission(t.Context(), client, o, deliveryNetworkTimeout)
	if e != nil || recovered != retained {
		t.Fatal("exact retry changed retained receipt", e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	_ = client.Close()
	// Confirmation is durable: cached recovery performs no handshake at all.
	if cached, e := DeliverAdmission(t.Context(), nil, o, deliveryNetworkTimeout); e != nil || cached != retained {
		t.Fatal("offline receipt recovery failed", e)
	}
	if e := o.Close(); e != nil {
		t.Fatal(e)
	}
	z.noEffect(t)
}

func TestAdmissionDeliveryQUICRejectsForeignMalformedAndLegacyTraffic(t *testing.T) {
	z := newDeliveryNetworkFixture(t)
	s := z.start(t, "")
	client := openClient(t, 46)
	other := openClient(t, 99)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	try := func(h *libp2ptransport.Host, send func(io.Writer) error, closeWrite bool) {
		t.Helper()
		stream, _, e := h.OpenAdmissionDeliveryStream(ctx, s.Addresses()[0], s.ID())
		if e != nil {
			return // ACL may reset before protocol negotiation completes.
		}
		defer stream.Close()
		// An unfinished request is aborted, not converted into a valid EOF by
		// the test's cleanup after its local read deadline.
		defer stream.Reset()
		_, cleanup, e := remotewire.BoundStream(ctx, stream, 150*time.Millisecond)
		if e != nil {
			t.Fatal(e)
		}
		defer cleanup()
		_ = send(stream)
		if closeWrite {
			_ = stream.CloseWrite()
		}
		if _, e := ReadAdmissionDeliveryReceipt(stream); e == nil {
			t.Fatal("invalid traffic returned acknowledgement")
		}
	}
	try(other, func(w io.Writer) error { return WriteAdmissionDelivery(w, z.delivery) }, true)
	try(client, func(w io.Writer) error {
		if e := WriteAdmissionDelivery(w, z.delivery); e != nil {
			return e
		}
		_, e := w.Write([]byte{1})
		return e
	}, true)
	try(client, func(w io.Writer) error { return WriteAdmissionDelivery(w, z.delivery) }, false)
	try(client, func(w io.Writer) error {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], MaximumAdmissionDeliveryBytes+1)
		_, e := w.Write(h[:])
		return e
	}, true)
	foreign := z.delivery
	foreign.Enrollment.Nonce = f.Hash("different-enrollment")
	try(client, func(w io.Writer) error { return WriteAdmissionDelivery(w, foreign) }, true)
	if _, e := s.inbox.ReadReceipt(); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("refused traffic wrote receipt", e)
	}
	if _, e := s.inbox.Delivery(); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("refused traffic wrote delivery", e)
	}
	if stream, _, e := client.OpenCustodyV2Stream(ctx, s.Addresses()[0], s.ID()); e == nil {
		_ = stream.Close()
		t.Fatal("proof service exposed execution protocol")
	}
	if stream, _, e := client.OpenRemoteCustodyControlStream(ctx, s.Addresses()[0], s.ID()); e == nil {
		_ = stream.Close()
		t.Fatal("proof service exposed legacy control")
	}
	if stream, _, e := client.OpenAdmissionDeliveryStream(ctx, s.Addresses()[0], client.ID()); e == nil {
		_ = stream.Close()
		t.Fatal("wrong recipient peer accepted")
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	z.noEffect(t)
}

type deliveryExchangeStream struct {
	read       *bytes.Reader
	written    bytes.Buffer
	closeError error
	halfClosed bool
}

func (s *deliveryExchangeStream) Read(b []byte) (int, error)  { return s.read.Read(b) }
func (s *deliveryExchangeStream) Write(b []byte) (int, error) { return s.written.Write(b) }
func (s *deliveryExchangeStream) Close() error                { return s.closeError }
func (s *deliveryExchangeStream) CloseWrite() error           { s.halfClosed = true; return nil }
func (*deliveryExchangeStream) SetDeadline(time.Time) error   { return nil }

func TestAdmissionDeliveryWireRequiresWholePinnedReceipt(t *testing.T) {
	z := newDeliveryNetworkFixture(t)
	r, e := (AdmissionDeliveryReceipt{}).Sign(z.delivery, f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	var encoded bytes.Buffer
	if e := WriteAdmissionDeliveryReceipt(&encoded, r); e != nil {
		t.Fatal(e)
	}
	foreign := z.delivery
	foreign.Enrollment.Nonce = f.Hash("receipt-for-another-enrollment")
	foreignReceipt, e := (AdmissionDeliveryReceipt{}).Sign(foreign, f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	var foreignEncoded bytes.Buffer
	if e := WriteAdmissionDeliveryReceipt(&foreignEncoded, foreignReceipt); e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct {
		name string
		raw  []byte
		err  error
	}{
		{"complete", encoded.Bytes(), nil},
		{"trailing", append(append([]byte{}, encoded.Bytes()...), 0), nil},
		{"short", encoded.Bytes()[:encoded.Len()-1], nil},
		{"foreign-valid-signature", foreignEncoded.Bytes(), nil},
		{"close-unknown", encoded.Bytes(), errors.New("stream close failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := &deliveryExchangeStream{read: bytes.NewReader(test.raw), closeError: test.err}
			got, e := exchangeAdmissionDelivery(t.Context(), s, z.delivery, time.Second)
			if test.name == "complete" {
				if e != nil || got != r || !s.halfClosed {
					t.Fatal("complete receipt rejected", e)
				}
			} else if !errors.Is(e, ErrUncertain) {
				t.Fatal("incomplete acknowledgement was confirmed", e)
			}
		})
	}
	var frame bytes.Buffer
	if e := WriteAdmissionDelivery(&frame, z.delivery); e != nil {
		t.Fatal(e)
	}
	d, e := ReadAdmissionDelivery(&frame)
	want, _ := z.delivery.ID()
	got, _ := d.ID()
	if e != nil || want != got {
		t.Fatal("typed delivery frame changed proof", e)
	}
	for _, n := range []uint32{0, MaximumAdmissionDeliveryBytes + 1, ^uint32(0)} {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], n)
		if _, e := ReadAdmissionDelivery(bytes.NewReader(h[:])); e == nil {
			t.Fatal("unbounded frame accepted", n)
		}
	}
}

func TestAdmissionDeliveryQUICClientRequiresOriginalSenderAndHealthyOutbox(t *testing.T) {
	z := newDeliveryNetworkFixture(t)
	s := z.start(t, "")
	path := filepath.Join(z.x.root, "outbox")
	o := z.outbox(t, path, s.Addresses()[0], true)
	other := openClient(t, 99)
	if _, e := DeliverAdmission(t.Context(), other, o, deliveryNetworkTimeout); e == nil {
		t.Fatal("unenrolled sender dispatched outbox")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := DeliverAdmission(ctx, openClient(t, 46), o, deliveryNetworkTimeout); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled dispatch accepted", e)
	}
	if _, e := s.inbox.Delivery(); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("refused sender/cancellation created a delivery", e)
	}
	client := openClient(t, 46)
	if _, e := DeliverAdmission(t.Context(), client, o, deliveryNetworkTimeout); e != nil {
		t.Fatal(e)
	}
	if e := o.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := DeliverAdmission(t.Context(), nil, o, deliveryNetworkTimeout); e == nil {
		t.Fatal("closed outbox returned cached acknowledgement")
	}
	_ = s.Close()
	z.noEffect(t)
}
