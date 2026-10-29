// Package guardwire defines the independent choice seal. The guard's key and
// append-only state must remain outside every protected subject's backups.
package guardwire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const Domain = "OMESH/custody-guard/v1/"
const RequestBytes = 8 + 1 + 32 + 32 + 8 + 32 + 64
const SealBytes = 64
const (
	Fence uint8 = 1 + iota
	Effect
	Admission
)

var ErrGuard = errors.New("independent custody guard refused choice")

// Namespace and Slot are derived by the verifier, never selected from a seal.
// ExpectedHead is deliberately NOT part of the slot: forks must collide.
type Request struct {
	Kind      uint8
	Subject   [32]byte
	Namespace types.Hash
	Slot      uint64
	Choice    types.Hash
	Signature [64]byte
}
type Chooser interface {
	Choose(context.Context, Request) ([64]byte, error)
}

func (q Request) body() ([]byte, error) {
	if q.Kind < Fence || q.Kind > Admission || types.Hash(q.Subject).IsZero() || q.Namespace.IsZero() || q.Choice.IsZero() {
		return nil, ErrGuard
	}
	e := codec.NewEncoder(RequestBytes)
	e.Fixed([]byte("OMCGREQ1"))
	e.U8(q.Kind)
	e.Fixed(q.Subject[:])
	e.Fixed(q.Namespace[:])
	e.U64(q.Slot)
	e.Fixed(q.Choice[:])
	return e.Bytes(), nil
}
func (q Request) Sign(key ed25519.PrivateKey) (Request, error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key[32:], q.Subject[:]) {
		return Request{}, ErrGuard
	}
	b, e := q.body()
	if e != nil {
		return Request{}, e
	}
	h := types.DomainHash(Domain+"request", b)
	copy(q.Signature[:], ed25519.Sign(key, h[:]))
	return q, nil
}
func (q Request) CanonicalBytes() ([]byte, error) {
	b, e := q.body()
	if e != nil {
		return nil, e
	}
	h := types.DomainHash(Domain+"request", b)
	if !ed25519.Verify(q.Subject[:], h[:], q.Signature[:]) {
		return nil, ErrGuard
	}
	return append(b, q.Signature[:]...), nil
}
func DecodeRequest(b []byte) (Request, error) {
	var q Request
	if len(b) != RequestBytes {
		return q, ErrGuard
	}
	d := codec.NewDecoder(b)
	m, _ := d.Fixed(8)
	if string(m) != "OMCGREQ1" {
		return q, ErrGuard
	}
	q.Kind, _ = d.U8()
	p, _ := d.Fixed(32)
	copy(q.Subject[:], p)
	p, _ = d.Fixed(32)
	copy(q.Namespace[:], p)
	q.Slot, _ = d.U64()
	p, _ = d.Fixed(32)
	copy(q.Choice[:], p)
	p, _ = d.Fixed(64)
	copy(q.Signature[:], p)
	_, e := q.CanonicalBytes()
	return q, e
}
func (q Request) SlotID() (types.Hash, error) {
	b, e := q.body()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(Domain+"slot", b[:len(b)-32]), nil
}

// SealDigest excludes the subject signature. Consumers already verify the
// artifact signature and reconstruct the whole request from its pinned policy.
func (q Request) SealDigest() (types.Hash, error) {
	b, e := q.body()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(Domain+"seal", b), nil
}
func (q Request) VerifySeal(key [32]byte, seal [64]byte) error {
	h, e := q.SealDigest()
	if e != nil || key == q.Subject || !ed25519.Verify(key[:], h[:], seal[:]) {
		return ErrGuard
	}
	return nil
}
func Obtain(ctx context.Context, client Chooser, key [32]byte, q Request, signer ed25519.PrivateKey) ([64]byte, error) {
	var zero [64]byte
	if ctx == nil || ctx.Err() != nil || client == nil || types.Hash(key).IsZero() {
		return zero, ErrGuard
	}
	q, e := q.Sign(signer)
	if e != nil {
		return zero, e
	}
	seal, e := client.Choose(ctx, q)
	if e != nil {
		return zero, e
	}
	if e = ctx.Err(); e != nil {
		return zero, e
	}
	if e = q.VerifySeal(key, seal); e != nil {
		return zero, e
	}
	return seal, nil
}
