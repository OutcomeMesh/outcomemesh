package workarchive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	CustodyAuditIntentVersion0     uint16 = 0
	MaximumCustodyAuditIntentBytes        = 512
)

var ErrCustodyAuditIntent = errors.New("invalid custody audit intent")
var custodyAuditIntentMagic = [8]byte{'O', 'M', 'C', 'A', 'I', 'N', 'T', '0'}

// CustodyAuditIntent is unsigned preparation, not execution permission. Its
// exact nonce, times and predecessor are retained BEFORE any challenge signing.
// An Audit admission binds its canonical ID; Serve binds the later challenge ID.
type CustodyAuditIntent struct {
	Version           uint16
	AssignmentID      types.Hash
	ConsumerPublicKey [ed25519.PublicKeySize]byte
	AuditorPublicKey  [ed25519.PublicKeySize]byte
	ReplicaPeerID     types.Hash
	PriorSequence     uint64
	PriorHeadID       types.Hash
	PriorReceiptID    types.Hash
	IssuedAt          uint64
	ExpiresAt         uint64
	RenewUntil        uint64
	RequestedSamples  uint16
	Nonce             types.Hash
}

func (intent CustodyAuditIntent) Validate() error {
	if intent.Version != CustodyAuditIntentVersion0 || intent.AssignmentID.IsZero() ||
		intent.ConsumerPublicKey == [32]byte{} || intent.AuditorPublicKey == [32]byte{} ||
		intent.ReplicaPeerID.IsZero() || intent.PriorReceiptID.IsZero() || intent.Nonce.IsZero() ||
		intent.PriorSequence == ^uint64(0) || (intent.PriorSequence == 0) != intent.PriorHeadID.IsZero() ||
		intent.IssuedAt == 0 || intent.ExpiresAt <= intent.IssuedAt ||
		intent.ExpiresAt-intent.IssuedAt > MaximumCustodyChallengeLifetime ||
		intent.RenewUntil <= intent.ExpiresAt || intent.RenewUntil-intent.IssuedAt > MaximumReplicaTermSeconds ||
		intent.RequestedSamples < MinimumCustodySamples || intent.RequestedSamples > MaximumCustodySamples {
		return ErrCustodyAuditIntent
	}
	return nil
}

func (intent CustodyAuditIntent) CanonicalBytes() ([]byte, error) {
	if err := intent.Validate(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder(300)
	e.Fixed(custodyAuditIntentMagic[:])
	e.U16(intent.Version)
	e.Fixed(intent.AssignmentID[:])
	e.Fixed(intent.ConsumerPublicKey[:])
	e.Fixed(intent.AuditorPublicKey[:])
	e.Fixed(intent.ReplicaPeerID[:])
	e.U64(intent.PriorSequence)
	e.Fixed(intent.PriorHeadID[:])
	e.Fixed(intent.PriorReceiptID[:])
	e.U64(intent.IssuedAt)
	e.U64(intent.ExpiresAt)
	e.U64(intent.RenewUntil)
	e.U16(intent.RequestedSamples)
	e.Fixed(intent.Nonce[:])
	return e.Bytes(), nil
}

func DecodeCustodyAuditIntent(input []byte) (CustodyAuditIntent, error) {
	if len(input) == 0 || len(input) > MaximumCustodyAuditIntentBytes {
		return CustodyAuditIntent{}, ErrCustodyAuditIntent
	}
	d := codec.NewDecoder(input)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, custodyAuditIntentMagic[:]) {
		return CustodyAuditIntent{}, ErrCustodyAuditIntent
	}
	var intent CustodyAuditIntent
	if intent.Version, err = d.U16(); err != nil {
		return CustodyAuditIntent{}, errors.Join(ErrCustodyAuditIntent, err)
	}
	for _, dst := range [][]byte{intent.AssignmentID[:], intent.ConsumerPublicKey[:], intent.AuditorPublicKey[:], intent.ReplicaPeerID[:]} {
		b, err := d.Fixed(len(dst))
		if err != nil {
			return CustodyAuditIntent{}, errors.Join(ErrCustodyAuditIntent, err)
		}
		copy(dst, b)
	}
	if intent.PriorSequence, err = d.U64(); err != nil {
		return CustodyAuditIntent{}, errors.Join(ErrCustodyAuditIntent, err)
	}
	for _, dst := range [][]byte{intent.PriorHeadID[:], intent.PriorReceiptID[:]} {
		b, err := d.Fixed(len(dst))
		if err != nil {
			return CustodyAuditIntent{}, errors.Join(ErrCustodyAuditIntent, err)
		}
		copy(dst, b)
	}
	if intent.IssuedAt, err = d.U64(); err != nil {
		return CustodyAuditIntent{}, errors.Join(ErrCustodyAuditIntent, err)
	}
	if intent.ExpiresAt, err = d.U64(); err != nil {
		return CustodyAuditIntent{}, errors.Join(ErrCustodyAuditIntent, err)
	}
	if intent.RenewUntil, err = d.U64(); err != nil {
		return CustodyAuditIntent{}, errors.Join(ErrCustodyAuditIntent, err)
	}
	if intent.RequestedSamples, err = d.U16(); err != nil {
		return CustodyAuditIntent{}, errors.Join(ErrCustodyAuditIntent, err)
	}
	b, err := d.Fixed(types.HashSize)
	if err != nil {
		return CustodyAuditIntent{}, errors.Join(ErrCustodyAuditIntent, err)
	}
	copy(intent.Nonce[:], b)
	if err := d.Finish(); err != nil || intent.Validate() != nil {
		return CustodyAuditIntent{}, ErrCustodyAuditIntent
	}
	return intent, nil
}

func (intent CustodyAuditIntent) ID() (types.Hash, error) {
	b, err := intent.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/workgraph/archive/custody-audit-intent/id/v0", b), nil
}

// PublishCustodyAuditIntent writes exact reviewed unsigned preparation into an
// existing owner-controlled directory separate from the legacy artifact tree.
// It never generates nonce/time, signs a challenge, or grants authority.
func PublishCustodyAuditIntent(ctx context.Context, path string, intent CustodyAuditIntent) error {
	encoded, err := intent.CanonicalBytes()
	if err != nil {
		return err
	}
	return publishCustodyAuditBytes(ctx, path, encoded)
}

func LoadCustodyAuditIntent(path string, pinnedID types.Hash) (CustodyAuditIntent, error) {
	if pinnedID.IsZero() {
		return CustodyAuditIntent{}, ErrCustodyAuditIntent
	}
	b, err := readRegularArchiveFile(path, MaximumCustodyAuditIntentBytes)
	if err != nil {
		return CustodyAuditIntent{}, err
	}
	intent, err := DecodeCustodyAuditIntent(b)
	if err != nil {
		return CustodyAuditIntent{}, err
	}
	id, err := intent.ID()
	if err != nil || id != pinnedID {
		return CustodyAuditIntent{}, errors.Join(ErrCustodyAuditIntent, err)
	}
	return intent, nil
}

// Exact no-replace publication. Parents are never created here. An existing
// destination is fully compared before allocation, including under disk pressure.
func publishCustodyAuditBytes(ctx context.Context, path string, encoded []byte) (returnErr error) {
	if ctx == nil || path == "" || len(encoded) == 0 {
		return ErrCustodyAuditIntent
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := requireCustodyJournalDirectory(parent); err != nil {
		return err
	}
	if b, err := readRegularArchiveFile(path, len(encoded)); err == nil {
		if !bytes.Equal(b, encoded) {
			return ErrCustodyAuditIntent
		}
		return syncDirectory(parent)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(parent, ".outcomemesh-audit-")
	if err != nil {
		return err
	}
	temporary := f.Name()
	closed := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, f.Close())
		}
		if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
			returnErr = errors.Join(returnErr, err)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if n, err := f.Write(encoded); err != nil || n != len(encoded) {
		return errors.Join(io.ErrShortWrite, err)
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		closed = true
		return err
	}
	closed = true
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	b, err := readRegularArchiveFile(path, len(encoded))
	if err != nil || !bytes.Equal(b, encoded) {
		return errors.Join(ErrCustodyAuditIntent, err)
	}
	return nil
}
