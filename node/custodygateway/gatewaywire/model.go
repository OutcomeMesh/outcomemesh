// Package gatewaywire contains public, bounded gateway artifacts. A response is
// historical evidence of one completed gateway operation, never an execution grant.
package gatewaywire

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"math"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

const (
	Domain                       = "OMESH/custody-gateway/v1/"
	MaximumClients               = 8
	MaximumDescriptorBytes       = 1024
	MaximumRequestBytes          = 241
	MaximumDataBytes             = 64 << 20
	MaximumResponseBytes         = MaximumDataBytes + 1024
	MaximumEvents                = 256
	MaximumJournalBytes          = 256 << 20
	Inspect                uint8 = 1
	ReadChunk              uint8 = 2
	Revoke                 uint8 = 3
)

var ErrArtifact = errors.New("invalid custody gateway artifact")
var ErrAccess = errors.New("custody gateway access refused")

type Position struct {
	Sequence uint64
	Head     types.Hash
}

func (p Position) Valid() bool {
	return (p.Sequence == 0) == p.Head.IsZero() && p.Sequence <= MaximumEvents
}

type Descriptor struct {
	Guard                                                                     [32]byte
	RootID, SourceID, GenesisID, GenesisDescriptorID, EnrollmentID, ObjectsID types.Hash
	Gateway, Issuer                                                           [32]byte
	Clients                                                                   [][32]byte
	OwnerUID, ParticipantUID                                                  uint32
	EventLimit                                                                uint32
	Signature                                                                 [64]byte
}

func (d Descriptor) body() ([]byte, error) {
	if d.RootID.IsZero() || d.SourceID.IsZero() || d.GenesisID.IsZero() || d.GenesisDescriptorID.IsZero() || d.EnrollmentID.IsZero() || types.Hash(d.Gateway).IsZero() || types.Hash(d.Issuer).IsZero() || d.Gateway == d.Issuer || d.ParticipantUID == 0 || d.OwnerUID == d.ParticipantUID || d.EventLimit < 2 || d.EventLimit > MaximumEvents || len(d.Clients) == 0 || len(d.Clients) > MaximumClients {
		return nil, ErrArtifact
	}
	e := codec.NewEncoder(512)
	if d.Guard == ([32]byte{}) {
		e.Fixed([]byte("OMCGDSC1"))
	} else {
		if d.Guard == d.Gateway || d.Guard == d.Issuer {
			return nil, ErrArtifact
		}
		e.Fixed([]byte("OMCGDSG1"))
	}
	for _, h := range []types.Hash{d.RootID, d.SourceID, d.GenesisID, d.GenesisDescriptorID, d.EnrollmentID, d.ObjectsID} {
		e.Fixed(h[:])
	}
	e.Fixed(d.Gateway[:])
	e.Fixed(d.Issuer[:])
	e.U32(d.OwnerUID)
	e.U32(d.ParticipantUID)
	e.U32(d.EventLimit)
	e.U8(uint8(len(d.Clients)))
	for i, k := range d.Clients {
		if types.Hash(k).IsZero() || k == d.Gateway || k == d.Issuer || k == d.Guard || i > 0 && bytes.Compare(d.Clients[i-1][:], k[:]) >= 0 {
			return nil, ErrArtifact
		}
		e.Fixed(k[:])
	}
	if d.Guard != ([32]byte{}) {
		e.Fixed(d.Guard[:])
	}
	return e.Bytes(), nil
}
func (d Descriptor) Sign(key ed25519.PrivateKey) (Descriptor, error) {
	b, e := d.body()
	if e != nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), d.Issuer[:]) {
		return Descriptor{}, ErrArtifact
	}
	h := types.DomainHash(Domain+"descriptor/sign", b)
	copy(d.Signature[:], ed25519.Sign(key, h[:]))
	return d, nil
}
func (d Descriptor) CanonicalBytes() ([]byte, error) {
	b, e := d.body()
	if e != nil {
		return nil, e
	}
	h := types.DomainHash(Domain+"descriptor/sign", b)
	if !ed25519.Verify(d.Issuer[:], h[:], d.Signature[:]) {
		return nil, ErrArtifact
	}
	return append(b, d.Signature[:]...), nil
}
func (d Descriptor) ID() (types.Hash, error) {
	b, e := d.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(Domain+"descriptor/id", b), nil
}

type Request struct {
	DescriptorID types.Hash
	Before       Position
	Nonce        types.Hash
	Kind         uint8
	ChunkID      types.Hash
	Actor        [32]byte
	Signature    [64]byte
}

func (q Request) body() ([]byte, error) {
	if q.DescriptorID.IsZero() || !q.Before.Valid() || q.Before.Sequence >= MaximumEvents || q.Nonce.IsZero() || types.Hash(q.Actor).IsZero() || q.Kind < Inspect || q.Kind > Runtime || (q.Kind == ReadChunk || q.Kind == Runtime) == q.ChunkID.IsZero() {
		return nil, ErrArtifact
	}
	e := codec.NewEncoder(MaximumRequestBytes)
	e.Fixed([]byte("OMCGRQS1"))
	e.Fixed(q.DescriptorID[:])
	e.U64(q.Before.Sequence)
	e.Fixed(q.Before.Head[:])
	e.Fixed(q.Nonce[:])
	e.U8(q.Kind)
	e.Fixed(q.ChunkID[:])
	e.Fixed(q.Actor[:])
	return e.Bytes(), nil
}
func (q Request) Sign(key ed25519.PrivateKey) (Request, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Request{}, ErrArtifact
	}
	copy(q.Actor[:], key.Public().(ed25519.PublicKey))
	b, e := q.body()
	if e != nil {
		return Request{}, e
	}
	h := types.DomainHash(Domain+"request/sign", b)
	copy(q.Signature[:], ed25519.Sign(key, h[:]))
	return q, nil
}
func (q Request) CanonicalBytes() ([]byte, error) {
	b, e := q.body()
	if e != nil {
		return nil, e
	}
	h := types.DomainHash(Domain+"request/sign", b)
	if !ed25519.Verify(q.Actor[:], h[:], q.Signature[:]) {
		return nil, ErrArtifact
	}
	return append(b, q.Signature[:]...), nil
}
func (q Request) Authorize(d Descriptor) error {
	id, e := d.ID()
	if e != nil || id != q.DescriptorID {
		return ErrAccess
	}
	if _, e = q.CanonicalBytes(); e != nil {
		return ErrAccess
	}
	if q.Kind == Revoke {
		if q.Actor == d.Issuer {
			return nil
		}
		return ErrAccess
	}
	for _, k := range d.Clients {
		if k == q.Actor {
			return nil
		}
	}
	return ErrAccess
}

type Response struct {
	Replacement *guard.ReplacementReceipt
	GuardSeal   [64]byte
	Request     Request
	SourceID    types.Hash
	Data        []byte
	Signature   [64]byte
}

func (r Response) body() ([]byte, error) {
	q, e := r.Request.CanonicalBytes()
	if e != nil || r.SourceID.IsZero() || len(r.Data) > MaximumDataBytes || r.Request.Kind == Revoke && len(r.Data) != 0 || r.Request.Kind != Revoke && len(r.Data) == 0 {
		return nil, ErrArtifact
	}
	e2 := codec.NewEncoder(len(r.Data) + 512)
	e2.Fixed([]byte("OMCGRSP1"))
	e2.Fixed(q)
	e2.Fixed(r.SourceID[:])
	e2.BytesField(r.Data)
	if r.Replacement != nil {
		b, err := r.Replacement.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		// The replacement certificate is part of the new response's signed body.
		e2.Fixed(b)
		b = e2.Bytes()
		copy(b[:8], []byte("OMCGRSR1"))
		return b, nil
	}
	return e2.Bytes(), nil
}
func (r Response) Sign(d Descriptor, key ed25519.PrivateKey) (Response, error) {
	signer := d.Gateway
	if r.Replacement != nil {
		principal, err := r.Replacement.Principal(d.Guard, r.Replacement.Request.Successor)
		if err != nil || principal != d.Gateway {
			return Response{}, ErrArtifact
		}
		signer = r.Replacement.Request.Successor
	}
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), signer[:]) || r.Request.Authorize(d) != nil || r.SourceID != d.SourceID {
		return Response{}, ErrArtifact
	}
	b, e := r.body()
	if e != nil {
		return Response{}, e
	}
	h := types.DomainHash(Domain+"response/sign", b)
	copy(r.Signature[:], ed25519.Sign(key, h[:]))
	return r, nil
}
func (r Response) CanonicalBytes() ([]byte, error) {
	b, e := r.body()
	if e != nil {
		return nil, e
	}
	raw := append(b, r.Signature[:]...)
	if r.GuardSeal != ([64]byte{}) {
		if r.Replacement != nil {
			copy(raw[:8], []byte("OMCGRSG2"))
		} else {
			copy(raw[:8], []byte("OMCGRSG1"))
		}
		raw = append(raw, r.GuardSeal[:]...)
	}
	return raw, nil
}
func (r Response) Verify(d Descriptor, q Request) error {
	want, e := q.CanonicalBytes()
	got, e2 := r.Request.CanonicalBytes()
	b, e3 := r.body()
	if e != nil || e2 != nil || e3 != nil || !bytes.Equal(want, got) || q.Authorize(d) != nil || r.SourceID != d.SourceID || q.Before.Sequence == math.MaxUint64 || q.Before.Sequence >= uint64(d.EventLimit) {
		return ErrArtifact
	}
	h := types.DomainHash(Domain+"response/sign", b)
	signer := d.Gateway
	if r.Replacement != nil {
		principal, err := r.Replacement.Principal(d.Guard, r.Replacement.Request.Successor)
		if err != nil || principal != d.Gateway {
			return ErrArtifact
		}
		signer = r.Replacement.Request.Successor
	}
	if !ed25519.Verify(signer[:], h[:], r.Signature[:]) {
		return ErrArtifact
	}
	if d.Guard != ([32]byte{}) {
		q, err := r.GuardRequest(d)
		if err != nil || q.VerifySeal(d.Guard, r.GuardSeal) != nil {
			return ErrArtifact
		}
	} else if r.Replacement != nil || r.GuardSeal != ([64]byte{}) {
		return ErrArtifact
	}
	return nil
}

func (r Response) GuardRequest(d Descriptor) (guard.Request, error) {
	r.GuardSeal = [64]byte{}
	b, err := r.CanonicalBytes()
	if err != nil {
		return guard.Request{}, err
	}
	signer := d.Gateway
	if r.Replacement != nil {
		principal, err := r.Replacement.Principal(d.Guard, r.Replacement.Request.Successor)
		if err != nil || principal != d.Gateway {
			return guard.Request{}, ErrArtifact
		}
		signer = r.Replacement.Request.Successor
	}
	return guard.Request{Kind: guard.Gateway, Subject: signer, Namespace: r.Request.DescriptorID, Slot: r.Request.Before.Sequence, Choice: types.DomainHash(guard.Domain+"gateway-response", b)}, nil
}
func (r Response) Position() (Position, error) {
	b, e := r.body()
	if e != nil {
		return Position{}, e
	}
	return Position{r.Request.Before.Sequence + 1, types.DomainHash(Domain+"event/id", b)}, nil
}

// reader accumulates decoding errors; canonical re-encoding rejects ignored,
// truncated and trailing input without allocating from untrusted counts.
type reader struct {
	d   *codec.Decoder
	err error
}

func (r *reader) fixed(p []byte) {
	b, e := r.d.Fixed(len(p))
	if e != nil {
		r.err = e
	}
	copy(p, b)
}
func (r *reader) u8() uint8 {
	v, e := r.d.U8()
	if e != nil {
		r.err = e
	}
	return v
}
func (r *reader) u32() uint32 {
	v, e := r.d.U32()
	if e != nil {
		r.err = e
	}
	return v
}
func (r *reader) u64() uint64 {
	v, e := r.d.U64()
	if e != nil {
		r.err = e
	}
	return v
}
func DecodeDescriptor(raw []byte) (Descriptor, error) {
	var d Descriptor
	if len(raw) > MaximumDescriptorBytes {
		return d, ErrArtifact
	}
	r := reader{d: codec.NewDecoder(raw)}
	var magic [8]byte
	r.fixed(magic[:])
	for _, p := range []*types.Hash{&d.RootID, &d.SourceID, &d.GenesisID, &d.GenesisDescriptorID, &d.EnrollmentID, &d.ObjectsID} {
		r.fixed(p[:])
	}
	r.fixed(d.Gateway[:])
	r.fixed(d.Issuer[:])
	d.OwnerUID = r.u32()
	d.ParticipantUID = r.u32()
	d.EventLimit = r.u32()
	n := int(r.u8())
	if n > MaximumClients {
		return Descriptor{}, ErrArtifact
	}
	d.Clients = make([][32]byte, n)
	for i := range d.Clients {
		r.fixed(d.Clients[i][:])
	}
	if string(magic[:]) == "OMCGDSG1" {
		r.fixed(d.Guard[:])
		if d.Guard == ([32]byte{}) {
			return Descriptor{}, ErrArtifact
		}
	}
	r.fixed(d.Signature[:])
	b, e := d.CanonicalBytes()
	if r.err != nil || e != nil || !bytes.Equal(b, raw) {
		return Descriptor{}, ErrArtifact
	}
	return d, nil
}
func DecodeRequest(raw []byte) (Request, error) {
	var q Request
	if len(raw) != MaximumRequestBytes {
		return q, ErrArtifact
	}
	r := reader{d: codec.NewDecoder(raw)}
	var magic [8]byte
	r.fixed(magic[:])
	r.fixed(q.DescriptorID[:])
	q.Before.Sequence = r.u64()
	r.fixed(q.Before.Head[:])
	r.fixed(q.Nonce[:])
	q.Kind = r.u8()
	r.fixed(q.ChunkID[:])
	r.fixed(q.Actor[:])
	r.fixed(q.Signature[:])
	b, e := q.CanonicalBytes()
	if r.err != nil || e != nil || !bytes.Equal(b, raw) {
		return Request{}, ErrArtifact
	}
	return q, nil
}
func DecodeResponse(raw []byte) (Response, error) {
	var r Response
	if len(raw) > MaximumResponseBytes {
		return r, ErrArtifact
	}
	d := codec.NewDecoder(raw)
	magic, e := d.Fixed(8)
	replaced := string(magic) == "OMCGRSR1" || string(magic) == "OMCGRSG2"
	sealed := string(magic) == "OMCGRSG1" || string(magic) == "OMCGRSG2"
	if e != nil || string(magic) != "OMCGRSP1" && !replaced && !sealed {
		return r, ErrArtifact
	}
	q, e := d.Fixed(MaximumRequestBytes)
	if e != nil {
		return r, e
	}
	r.Request, e = DecodeRequest(q)
	if e != nil {
		return r, e
	}
	s, e := d.Fixed(32)
	if e != nil {
		return r, e
	}
	copy(r.SourceID[:], s)
	r.Data, e = d.BytesField(MaximumDataBytes)
	if e != nil {
		return r, e
	}
	if replaced {
		b, err := d.Fixed(guard.ReplacementReceiptBytes)
		if err != nil {
			return r, err
		}
		proof, err := guard.DecodeReplacementReceipt(b)
		if err != nil {
			return r, err
		}
		r.Replacement = &proof
	}
	sig, e := d.Fixed(64)
	if e != nil {
		return r, e
	}
	copy(r.Signature[:], sig)
	if sealed {
		b, err := d.Fixed(guard.SealBytes)
		if err != nil {
			return r, err
		}
		copy(r.GuardSeal[:], b)
		if r.GuardSeal == ([64]byte{}) {
			return Response{}, ErrArtifact
		}
	}
	b, e := r.CanonicalBytes()
	if e != nil || !bytes.Equal(b, raw) {
		return Response{}, ErrArtifact
	}
	return r, nil
}
