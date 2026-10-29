package guardwire

import (
	"bytes"
	"context"
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const RevocationBytes = 8 + 32*4 + 64
const RevocationReceiptBytes = 8 + RevocationBytes + 4 + 32 + 32 + 64
const MaximumEvents = 4096 + 32

type Position struct {
	Sequence uint32
	Head     types.Hash
}

func (p Position) Valid() bool {
	return p.Sequence <= MaximumEvents && (p.Sequence == 0) == p.Head.IsZero()
}

// Revocation permanently disables one subject at one immutable guard identity.
// ReasonID identifies externally retained incident evidence, not a timestamp.
type Revocation struct {
	GuardID            types.Hash
	Subject, Authority [32]byte
	ReasonID           types.Hash
	Signature          [64]byte
}

func (q Revocation) body() ([]byte, error) {
	if q.GuardID.IsZero() || types.Hash(q.Subject).IsZero() || types.Hash(q.Authority).IsZero() || q.Subject == q.Authority || q.ReasonID.IsZero() {
		return nil, ErrGuard
	}
	e := codec.NewEncoder(RevocationBytes)
	e.Fixed([]byte("OMCGRVK1"))
	e.Fixed(q.GuardID[:])
	e.Fixed(q.Subject[:])
	e.Fixed(q.Authority[:])
	e.Fixed(q.ReasonID[:])
	return e.Bytes(), nil
}

func (q Revocation) Sign(key ed25519.PrivateKey) (Revocation, error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key[32:], q.Authority[:]) {
		return Revocation{}, ErrGuard
	}
	b, err := q.body()
	if err != nil {
		return Revocation{}, err
	}
	h := types.DomainHash(Domain+"revocation", b)
	copy(q.Signature[:], ed25519.Sign(key, h[:]))
	return q, nil
}

func (q Revocation) CanonicalBytes() ([]byte, error) {
	b, err := q.body()
	if err != nil {
		return nil, err
	}
	h := types.DomainHash(Domain+"revocation", b)
	if !ed25519.Verify(q.Authority[:], h[:], q.Signature[:]) {
		return nil, ErrGuard
	}
	return append(b, q.Signature[:]...), nil
}

func DecodeRevocation(b []byte) (Revocation, error) {
	var q Revocation
	if len(b) != RevocationBytes || string(b[:8]) != "OMCGRVK1" {
		return q, ErrGuard
	}
	copy(q.GuardID[:], b[8:40])
	copy(q.Subject[:], b[40:72])
	copy(q.Authority[:], b[72:104])
	copy(q.ReasonID[:], b[104:136])
	copy(q.Signature[:], b[136:])
	_, err := q.CanonicalBytes()
	return q, err
}

// Before is the original journal cursor, retained across exact retries. A
// receipt proves a historical revocation; it is not a fresh service cursor.
type RevocationReceipt struct {
	Request   Revocation
	Before    Position
	Guard     [32]byte
	Signature [64]byte
}

func (r RevocationReceipt) body() ([]byte, error) {
	b, err := r.Request.CanonicalBytes()
	if err != nil || !r.Before.Valid() || r.Before.Sequence >= MaximumEvents || types.Hash(r.Guard).IsZero() || r.Guard == r.Request.Subject || r.Guard == r.Request.Authority {
		return nil, ErrGuard
	}
	e := codec.NewEncoder(RevocationReceiptBytes)
	e.Fixed([]byte("OMCGRCP1"))
	e.Fixed(b)
	e.U32(r.Before.Sequence)
	e.Fixed(r.Before.Head[:])
	e.Fixed(r.Guard[:])
	return e.Bytes(), nil
}

func (r RevocationReceipt) Sign(key ed25519.PrivateKey) (RevocationReceipt, error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key[32:], r.Guard[:]) {
		return RevocationReceipt{}, ErrGuard
	}
	b, err := r.body()
	if err != nil {
		return RevocationReceipt{}, err
	}
	h := types.DomainHash(Domain+"revocation-receipt", b)
	copy(r.Signature[:], ed25519.Sign(key, h[:]))
	return r, nil
}

func (r RevocationReceipt) CanonicalBytes() ([]byte, error) {
	b, err := r.body()
	if err != nil {
		return nil, err
	}
	h := types.DomainHash(Domain+"revocation-receipt", b)
	if !ed25519.Verify(r.Guard[:], h[:], r.Signature[:]) {
		return nil, ErrGuard
	}
	return append(b, r.Signature[:]...), nil
}

func DecodeRevocationReceipt(b []byte) (RevocationReceipt, error) {
	var r RevocationReceipt
	if len(b) != RevocationReceiptBytes || string(b[:8]) != "OMCGRCP1" {
		return r, ErrGuard
	}
	q, err := DecodeRevocation(b[8 : 8+RevocationBytes])
	if err != nil {
		return r, err
	}
	r.Request = q
	d := codec.NewDecoder(b[8+RevocationBytes:])
	r.Before.Sequence, _ = d.U32()
	p, _ := d.Fixed(32)
	copy(r.Before.Head[:], p)
	p, _ = d.Fixed(32)
	copy(r.Guard[:], p)
	p, _ = d.Fixed(64)
	copy(r.Signature[:], p)
	_, err = r.CanonicalBytes()
	return r, err
}

func (r RevocationReceipt) Verify(guard [32]byte, identity types.Hash, q Revocation) error {
	if r.Guard != guard || r.Request != q || q.GuardID != identity {
		return ErrGuard
	}
	_, err := r.CanonicalBytes()
	return err
}

func (r RevocationReceipt) After() (Position, error) {
	if _, err := r.CanonicalBytes(); err != nil {
		return Position{}, err
	}
	b, _ := r.Request.CanonicalBytes()
	return Position{Sequence: r.Before.Sequence + 1, Head: types.DomainHash(Domain+"event", r.Before.Head[:], b)}, nil
}

type Revoker interface {
	Revoke(context.Context, Revocation) (RevocationReceipt, error)
}

func ObtainRevocation(ctx context.Context, client Revoker, guard [32]byte, identity types.Hash, q Revocation) (RevocationReceipt, error) {
	if ctx == nil || ctx.Err() != nil || client == nil || q.GuardID != identity {
		return RevocationReceipt{}, ErrGuard
	}
	if _, err := q.CanonicalBytes(); err != nil {
		return RevocationReceipt{}, err
	}
	r, err := client.Revoke(ctx, q)
	if err != nil {
		return RevocationReceipt{}, err
	}
	if err = ctx.Err(); err != nil {
		return RevocationReceipt{}, err
	}
	if err = r.Verify(guard, identity, q); err != nil {
		return RevocationReceipt{}, err
	}
	return r, nil
}
