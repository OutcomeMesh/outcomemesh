// Package servicewire defines public, bounded artifacts for one isolated Prune
// execution. A retained response is historical evidence, never a live permit.
package servicewire

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
)

const (
	Domain                 = "OMESH/prune-service/v0/"
	MaximumDescriptorBytes = prunefence.MaximumPolicyBytes + 512
	RequestBytes           = 8 + 2 + 32 + 4 + 32 + 32 + 32 + 64
	MaximumChallengeBytes  = prunefence.MaximumCandidateBytes + 256
	ExchangeDeadline       = 2 * time.Minute
)

var ErrArtifact = errors.New("invalid isolated Prune service artifact")
var ErrAccess = errors.New("isolated Prune service access refused")

// Position distinguishes an initial owner, one retained request, and one
// retained response. It cannot authorize another execution after completion.
type Position struct {
	Sequence uint32
	Head     types.Hash
}

func (p Position) Valid() bool {
	return p.Sequence <= 2 && (p.Sequence == 0) == p.Head.IsZero()
}

type Descriptor struct {
	RootID, ScopeID, ReviewID, ConfigID types.Hash
	Policy                              prunefence.Policy
	Binding                             prunefence.Binding
	Transport                           [32]byte
	OwnerUID, ParticipantUID            uint32
	Signature                           [64]byte
}

func (d Descriptor) body() ([]byte, error) {
	if d.Policy.Service == nil || d.RootID.IsZero() || d.ScopeID.IsZero() || d.ReviewID.IsZero() || d.ConfigID.IsZero() ||
		d.ParticipantUID == 0 || d.ParticipantUID == d.OwnerUID || d.Transport == ([32]byte{}) {
		return nil, ErrArtifact
	}
	p, err := d.Policy.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	if _, err := d.Binding.ID(); err != nil {
		return nil, err
	}
	s := d.Policy.Service
	if d.Binding.AssignmentID != s.AssignmentID || d.Binding.StoragePairID != s.StoragePairID {
		return nil, ErrArtifact
	}
	keys := append([][32]byte{d.Policy.Owner, d.Policy.Controller, d.Policy.Guard, s.Service, s.Issuer, s.Guard}, d.Policy.Witnesses...)
	for _, key := range keys {
		if key == d.Transport {
			return nil, ErrArtifact
		}
	}
	e := encoder("OMPSDS00", MaximumDescriptorBytes)
	for _, h := range []types.Hash{d.RootID, d.ScopeID, d.ReviewID, d.ConfigID} {
		e.Fixed(h[:])
	}
	e.BytesField(p)
	for _, h := range bindingHashes(d.Binding) {
		e.Fixed(h[:])
	}
	e.Fixed(d.Transport[:])
	e.U32(d.OwnerUID)
	e.U32(d.ParticipantUID)
	return e.Bytes(), nil
}
func (d Descriptor) Sign(key ed25519.PrivateKey) (Descriptor, error) {
	b, err := d.body()
	if err != nil || !keyMatches(key, d.Policy.Service.Issuer) {
		return Descriptor{}, ErrArtifact
	}
	d.Signature = sign("descriptor/sign", b, key)
	return d, nil
}

// SigningReviewID identifies the complete unsigned descriptor for issuer review.
// ReviewID in the descriptor remains the original bootstrap review identifier.
func (d Descriptor) SigningReviewID() (types.Hash, error) {
	b, err := d.body()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(Domain+"descriptor/review", b), nil
}
func (d Descriptor) CanonicalBytes() ([]byte, error) {
	b, err := d.body()
	if err != nil {
		return nil, err
	}
	return signedBytes("descriptor/sign", b, d.Signature, d.Policy.Service.Issuer)
}
func (d Descriptor) ID() (types.Hash, error) {
	b, err := d.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(Domain+"descriptor/id", b), nil
}
func DecodeDescriptor(raw []byte) (Descriptor, error) {
	var v Descriptor
	d, err := decoder(raw, "OMPSDS00", MaximumDescriptorBytes)
	if err != nil {
		return v, err
	}
	if readFixed(d, v.RootID[:], v.ScopeID[:], v.ReviewID[:], v.ConfigID[:]) != nil {
		return v, ErrArtifact
	}
	p, err := d.BytesField(prunefence.MaximumPolicyBytes)
	if err != nil {
		return v, err
	}
	v.Policy, err = prunefence.DecodePolicy(p)
	if err != nil {
		return v, err
	}
	if readFixed(d, v.Binding.RequestID[:], v.Binding.AssignmentID[:], v.Binding.OperationID[:], v.Binding.InventoryID[:], v.Binding.ExecutorBindingID[:], v.Binding.StoragePairID[:], v.Transport[:]) != nil {
		return Descriptor{}, ErrArtifact
	}
	v.OwnerUID, err = d.U32()
	if err != nil {
		return Descriptor{}, err
	}
	v.ParticipantUID, err = d.U32()
	if err != nil {
		return Descriptor{}, err
	}
	if readFixed(d, v.Signature[:]) != nil || d.Finish() != nil {
		return Descriptor{}, ErrArtifact
	}
	b, err := v.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, b) {
		return Descriptor{}, ErrArtifact
	}
	return v, nil
}

type Request struct {
	DescriptorID types.Hash
	Before       Position
	Nonce        [32]byte
	Actor        [32]byte
	Signature    [64]byte
}

func (q Request) body() ([]byte, error) {
	if q.DescriptorID.IsZero() || !q.Before.Valid() || q.Before != (Position{}) || q.Nonce == ([32]byte{}) || q.Actor == ([32]byte{}) {
		return nil, ErrArtifact
	}
	e := encoder("OMPSRQ00", RequestBytes)
	e.Fixed(q.DescriptorID[:])
	putPosition(e, q.Before)
	e.Fixed(q.Nonce[:])
	e.Fixed(q.Actor[:])
	return e.Bytes(), nil
}
func (q Request) Sign(key ed25519.PrivateKey) (Request, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Request{}, ErrArtifact
	}
	copy(q.Actor[:], key[32:])
	if !keyMatches(key, q.Actor) {
		return Request{}, ErrArtifact
	}
	b, err := q.body()
	if err != nil {
		return Request{}, err
	}
	q.Signature = sign("request/sign", b, key)
	return q, nil
}
func (q Request) CanonicalBytes() ([]byte, error) {
	b, err := q.body()
	if err != nil {
		return nil, err
	}
	return signedBytes("request/sign", b, q.Signature, q.Actor)
}
func (q Request) ID() (types.Hash, error) {
	b, err := q.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(Domain+"request/id", b), nil
}
func (q Request) IntentPosition() (Position, error) {
	id, err := q.ID()
	if err != nil {
		return Position{}, err
	}
	return Position{Sequence: 1, Head: id}, nil
}
func (q Request) Authorize(d Descriptor) error {
	id, err := d.ID()
	if err != nil || q.DescriptorID != id || q.Actor != d.Policy.Owner || q.Before != (Position{}) {
		return ErrAccess
	}
	_, err = q.CanonicalBytes()
	return err
}
func DecodeRequest(raw []byte) (Request, error) {
	var q Request
	d, err := decoder(raw, "OMPSRQ00", RequestBytes)
	if err != nil || len(raw) != RequestBytes {
		return q, ErrArtifact
	}
	if readFixed(d, q.DescriptorID[:]) != nil {
		return q, ErrArtifact
	}
	q.Before, err = readPosition(d)
	if err != nil {
		return q, err
	}
	if readFixed(d, q.Nonce[:], q.Actor[:], q.Signature[:]) != nil || d.Finish() != nil {
		return Request{}, ErrArtifact
	}
	b, err := q.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, b) {
		return Request{}, ErrArtifact
	}
	return q, nil
}

type Challenge struct {
	DescriptorID, RequestID types.Hash
	Before                  Position
	Candidate               prunefence.Candidate
	Signature               [64]byte
}

func (c Challenge) body() ([]byte, error) {
	if c.DescriptorID.IsZero() || c.RequestID.IsZero() || c.Before != (Position{Sequence: 1, Head: c.RequestID}) || c.Candidate.Policy.Service == nil {
		return nil, ErrArtifact
	}
	b, err := c.Candidate.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	e := encoder("OMPSCH00", MaximumChallengeBytes)
	e.Fixed(c.DescriptorID[:])
	e.Fixed(c.RequestID[:])
	putPosition(e, c.Before)
	e.BytesField(b)
	return e.Bytes(), nil
}
func (c Challenge) check(d Descriptor, q Request) error {
	if err := q.Authorize(d); err != nil {
		return err
	}
	id, _ := q.ID()
	before, _ := q.IntentPosition()
	if c.DescriptorID != q.DescriptorID || c.RequestID != id || c.Before != before {
		return ErrAccess
	}
	return candidateMatches(d, c.Candidate)
}
func (c Challenge) Sign(d Descriptor, q Request, key ed25519.PrivateKey) (Challenge, error) {
	if c.check(d, q) != nil || !keyMatches(key, d.Policy.Service.Service) {
		return Challenge{}, ErrAccess
	}
	b, err := c.body()
	if err != nil {
		return Challenge{}, err
	}
	c.Signature = sign("challenge/sign", b, key)
	return c, nil
}
func (c Challenge) CanonicalBytes() ([]byte, error) {
	b, err := c.body()
	if err != nil {
		return nil, err
	}
	return signedBytes("challenge/sign", b, c.Signature, c.Candidate.Policy.Service.Service)
}
func (c Challenge) ID() (types.Hash, error) {
	b, err := c.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(Domain+"challenge/id", b), nil
}
func (c Challenge) Verify(d Descriptor, q Request) error {
	if err := c.check(d, q); err != nil {
		return err
	}
	_, err := c.CanonicalBytes()
	return err
}
func DecodeChallenge(raw []byte) (Challenge, error) {
	var c Challenge
	d, err := decoder(raw, "OMPSCH00", MaximumChallengeBytes)
	if err != nil {
		return c, err
	}
	if readFixed(d, c.DescriptorID[:], c.RequestID[:]) != nil {
		return c, ErrArtifact
	}
	c.Before, err = readPosition(d)
	if err != nil {
		return c, err
	}
	b, err := d.BytesField(prunefence.MaximumCandidateBytes)
	if err != nil {
		return c, err
	}
	c.Candidate, err = prunefence.DecodeCandidate(b)
	if err != nil {
		return c, err
	}
	if readFixed(d, c.Signature[:]) != nil || d.Finish() != nil {
		return Challenge{}, ErrArtifact
	}
	b, err = c.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, b) {
		return Challenge{}, ErrArtifact
	}
	return c, nil
}

func candidateMatches(d Descriptor, c prunefence.Candidate) error {
	a, err := d.Policy.CanonicalBytes()
	if err != nil {
		return err
	}
	b, err := c.Policy.CanonicalBytes()
	if err != nil || !bytes.Equal(a, b) || c.Binding != d.Binding {
		return ErrAccess
	}
	_, err = c.CanonicalBytes()
	return err
}
func bindingHashes(b prunefence.Binding) []types.Hash {
	return []types.Hash{b.RequestID, b.AssignmentID, b.OperationID, b.InventoryID, b.ExecutorBindingID, b.StoragePairID}
}
func encoder(magic string, capacity int) *codec.Encoder {
	e := codec.NewEncoder(capacity)
	e.Fixed([]byte(magic))
	e.U16(0)
	return e
}
func decoder(raw []byte, magic string, limit int) (*codec.Decoder, error) {
	if len(raw) > limit {
		return nil, ErrArtifact
	}
	d := codec.NewDecoder(raw)
	m, err := d.Fixed(8)
	if err != nil || string(m) != magic {
		return nil, ErrArtifact
	}
	v, err := d.U16()
	if err != nil || v != 0 {
		return nil, ErrArtifact
	}
	return d, nil
}
func readFixed(d *codec.Decoder, destinations ...[]byte) error {
	for _, dst := range destinations {
		b, err := d.Fixed(len(dst))
		if err != nil {
			return err
		}
		copy(dst, b)
	}
	return nil
}
func putPosition(e *codec.Encoder, p Position) { e.U32(p.Sequence); e.Fixed(p.Head[:]) }
func readPosition(d *codec.Decoder) (Position, error) {
	var p Position
	var err error
	p.Sequence, err = d.U32()
	if err != nil {
		return p, err
	}
	if readFixed(d, p.Head[:]) != nil || !p.Valid() {
		return Position{}, ErrArtifact
	}
	return p, nil
}
func keyMatches(key ed25519.PrivateKey, want [32]byte) bool {
	return len(key) == ed25519.PrivateKeySize && bytes.Equal(key[32:], want[:]) && bytes.Equal(key, ed25519.NewKeyFromSeed(key[:32]))
}
func sign(label string, b []byte, key ed25519.PrivateKey) (s [64]byte) {
	h := types.DomainHash(Domain+label, b)
	copy(s[:], ed25519.Sign(key, h[:]))
	return s
}
func signedBytes(label string, b []byte, signature [64]byte, key [32]byte) ([]byte, error) {
	h := types.DomainHash(Domain+label, b)
	if !ed25519.Verify(key[:], h[:], signature[:]) {
		return nil, ErrArtifact
	}
	return append(b, signature[:]...), nil
}
