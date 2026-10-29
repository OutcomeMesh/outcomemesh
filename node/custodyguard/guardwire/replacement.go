package guardwire

import (
	"bytes"
	"context"
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const ReplacementBytes = 8 + 6*32 + 4 + 32 + 2*64
const ReplacementReceiptBytes = 8 + ReplacementBytes + 32 + 64

// Replacement preserves Subject as the logical owner of every retained slot.
// It is authorized only after permanent revocation, at an exact retained guard
// cursor. EvidenceID names the operator's recovery inventory, not a reset grant.
// This bounded protocol permits one successor per original configured subject.
type Replacement struct {
	GuardID                       types.Hash
	Subject, Successor, Authority [32]byte
	RevocationID, EvidenceID      types.Hash
	Before                        Position
	SuccessorSignature, Signature [64]byte
}

func (q Replacement) body() ([]byte, error) {
	if q.GuardID.IsZero() || types.Hash(q.Subject).IsZero() || types.Hash(q.Successor).IsZero() || types.Hash(q.Authority).IsZero() || q.Subject == q.Successor || q.Subject == q.Authority || q.Successor == q.Authority || q.RevocationID.IsZero() || q.EvidenceID.IsZero() || !q.Before.Valid() || q.Before.Sequence == 0 || q.Before.Sequence >= MaximumEvents {
		return nil, ErrGuard
	}
	e := codec.NewEncoder(ReplacementBytes)
	e.Fixed([]byte("OMCGRPL1"))
	for _, h := range [][32]byte{q.GuardID, q.Subject, q.Successor, q.Authority, q.RevocationID, q.EvidenceID} {
		e.Fixed(h[:])
	}
	e.U32(q.Before.Sequence)
	e.Fixed(q.Before.Head[:])
	return e.Bytes(), nil
}

func (q Replacement) ValidateDraft() error { _, err := q.body(); return err }

func (q Replacement) Accept(key ed25519.PrivateKey) (Replacement, error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key[32:], q.Successor[:]) || q.Signature != ([64]byte{}) {
		return Replacement{}, ErrGuard
	}
	b, err := q.body()
	if err != nil {
		return Replacement{}, err
	}
	h := types.DomainHash(Domain+"replacement/accept", b)
	copy(q.SuccessorSignature[:], ed25519.Sign(key, h[:]))
	return q, nil
}

// ProposalBytes is the successor's signed offer, before offline authorization.
// It cannot be submitted as a replacement command.
func (q Replacement) ProposalBytes() ([]byte, error) {
	b, err := q.body()
	if err != nil || q.Signature != ([64]byte{}) {
		return nil, ErrGuard
	}
	h := types.DomainHash(Domain+"replacement/accept", b)
	if !ed25519.Verify(q.Successor[:], h[:], q.SuccessorSignature[:]) {
		return nil, ErrGuard
	}
	return append(append(b, q.SuccessorSignature[:]...), q.Signature[:]...), nil
}

func (q Replacement) Authorize(key ed25519.PrivateKey) (Replacement, error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key[32:], q.Authority[:]) {
		return Replacement{}, ErrGuard
	}
	if _, err := q.ProposalBytes(); err != nil {
		return Replacement{}, err
	}
	b, _ := q.body()
	h := types.DomainHash(Domain+"replacement/authorize", b, q.SuccessorSignature[:])
	copy(q.Signature[:], ed25519.Sign(key, h[:]))
	return q, nil
}

func (q Replacement) CanonicalBytes() ([]byte, error) {
	b, err := q.body()
	if err != nil {
		return nil, err
	}
	h := types.DomainHash(Domain+"replacement/accept", b)
	a := types.DomainHash(Domain+"replacement/authorize", b, q.SuccessorSignature[:])
	if !ed25519.Verify(q.Successor[:], h[:], q.SuccessorSignature[:]) || !ed25519.Verify(q.Authority[:], a[:], q.Signature[:]) {
		return nil, ErrGuard
	}
	return append(append(b, q.SuccessorSignature[:]...), q.Signature[:]...), nil
}

func decodeReplacement(b []byte, proposal bool) (Replacement, error) {
	var q Replacement
	if len(b) != ReplacementBytes || string(b[:8]) != "OMCGRPL1" {
		return q, ErrGuard
	}
	d := codec.NewDecoder(b[8:])
	for _, p := range []*[32]byte{(*[32]byte)(&q.GuardID), &q.Subject, &q.Successor, &q.Authority, (*[32]byte)(&q.RevocationID), (*[32]byte)(&q.EvidenceID)} {
		v, _ := d.Fixed(32)
		copy(p[:], v)
	}
	q.Before.Sequence, _ = d.U32()
	v, _ := d.Fixed(32)
	copy(q.Before.Head[:], v)
	v, _ = d.Fixed(64)
	copy(q.SuccessorSignature[:], v)
	v, _ = d.Fixed(64)
	copy(q.Signature[:], v)
	var err error
	if proposal {
		_, err = q.ProposalBytes()
	} else {
		_, err = q.CanonicalBytes()
	}
	return q, err
}
func DecodeReplacement(b []byte) (Replacement, error)         { return decodeReplacement(b, false) }
func DecodeReplacementProposal(b []byte) (Replacement, error) { return decodeReplacement(b, true) }

type ReplacementReceipt struct {
	Request   Replacement
	Guard     [32]byte
	Signature [64]byte
}

func (r ReplacementReceipt) body() ([]byte, error) {
	b, err := r.Request.CanonicalBytes()
	if err != nil || types.Hash(r.Guard).IsZero() || r.Guard == r.Request.Subject || r.Guard == r.Request.Successor || r.Guard == r.Request.Authority {
		return nil, ErrGuard
	}
	out := append([]byte("OMCGRPR1"), b...)
	return append(out, r.Guard[:]...), nil
}
func (r ReplacementReceipt) Sign(key ed25519.PrivateKey) (ReplacementReceipt, error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key[32:], r.Guard[:]) {
		return ReplacementReceipt{}, ErrGuard
	}
	b, err := r.body()
	if err != nil {
		return ReplacementReceipt{}, err
	}
	h := types.DomainHash(Domain+"replacement/receipt", b)
	copy(r.Signature[:], ed25519.Sign(key, h[:]))
	return r, nil
}
func (r ReplacementReceipt) CanonicalBytes() ([]byte, error) {
	b, err := r.body()
	if err != nil {
		return nil, err
	}
	h := types.DomainHash(Domain+"replacement/receipt", b)
	if !ed25519.Verify(r.Guard[:], h[:], r.Signature[:]) {
		return nil, ErrGuard
	}
	return append(b, r.Signature[:]...), nil
}
func DecodeReplacementReceipt(b []byte) (ReplacementReceipt, error) {
	var r ReplacementReceipt
	if len(b) != ReplacementReceiptBytes || string(b[:8]) != "OMCGRPR1" {
		return r, ErrGuard
	}
	q, err := DecodeReplacement(b[8 : 8+ReplacementBytes])
	if err != nil {
		return r, err
	}
	r.Request = q
	copy(r.Guard[:], b[8+ReplacementBytes:8+ReplacementBytes+32])
	copy(r.Signature[:], b[len(b)-64:])
	_, err = r.CanonicalBytes()
	return r, err
}
func (r ReplacementReceipt) Verify(guard [32]byte, identity types.Hash, q Replacement) error {
	if r.Guard != guard || r.Request != q || q.GuardID != identity {
		return ErrGuard
	}
	_, err := r.CanonicalBytes()
	return err
}
func (r ReplacementReceipt) After() (Position, error) {
	if _, err := r.CanonicalBytes(); err != nil {
		return Position{}, err
	}
	b, _ := r.Request.CanonicalBytes()
	return Position{Sequence: r.Request.Before.Sequence + 1, Head: types.DomainHash(Domain+"event", r.Request.Before.Head[:], b)}, nil
}

// Principal resolves a signed successor only against the policy's pinned guard.
// Callers must count logical principals, never count both keys as votes.
// Canonical vote ordering remains by the actual signing public key.
func (r ReplacementReceipt) Principal(guard, signer [32]byte) ([32]byte, error) {
	if types.Hash(guard).IsZero() || r.Guard != guard || r.Request.Successor != signer {
		return [32]byte{}, ErrGuard
	}
	if _, err := r.CanonicalBytes(); err != nil {
		return [32]byte{}, err
	}
	return r.Request.Subject, nil
}

type Replacer interface {
	Replace(context.Context, Replacement) (ReplacementReceipt, error)
}

func ObtainReplacement(ctx context.Context, client Replacer, guard [32]byte, identity types.Hash, q Replacement) (ReplacementReceipt, error) {
	if ctx == nil || ctx.Err() != nil || client == nil || q.GuardID != identity {
		return ReplacementReceipt{}, ErrGuard
	}
	if _, err := q.CanonicalBytes(); err != nil {
		return ReplacementReceipt{}, err
	}
	r, err := client.Replace(ctx, q)
	if err != nil {
		return ReplacementReceipt{}, err
	}
	if err = ctx.Err(); err != nil {
		return ReplacementReceipt{}, err
	}
	if err = r.Verify(guard, identity, q); err != nil {
		return ReplacementReceipt{}, err
	}
	return r, nil
}
