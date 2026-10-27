// Package remoteworker retains one B-local remote execution plan and irreversible
// sealing history. Every API in this package is RECORD-ONLY. A signed Begin, a
// Started record, or a Sealed record is not execution permission or proof that
// network handlers physically drained. No network, proof signer, callback,
// timeout, lease, automatic execution, or drain-ack signer is provided here.
package remoteworker

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

const (
	Version0         uint16 = 0
	MaximumPlanBytes        = 10 + 6*types.HashSize + 8 + 10 + custodyauthority.MaximumEntryBytes
	SealBytes               = 10 + 4*types.HashSize + 1
)

var (
	ErrPlan = errors.New("remote worker plan does not match its pinned assignment and Serve admission")
	ErrSeal = errors.New("remote worker seal does not match its immutable sealing branch")
)

// Plan selects immutable historical preparation. ChallengeID is the signed
// admission's OperationID. AssignmentID additionally commits manifest, initial
// receipt, policy, replica key and the separate B control/transport identities.
// The plan never contains Begin: Begin.OperationID commits this plan's ID.
type Plan struct {
	Version                     uint16
	AssignmentID                types.Hash
	Admission                   custodyauthority.Entry
	AuthorityTransportPublicKey [32]byte
	AuditorTransportPublicKey   [32]byte
	PriorSequence               uint64
	PriorHeadID                 types.Hash
	PriorReceiptID              types.Hash
	Nonce                       types.Hash
}

func (p Plan) validateShape() error {
	c := p.Admission.Command
	if p.Version != Version0 || p.AssignmentID.IsZero() || p.Admission.Version != custodyauthority.Version1 || c.Version != custodyauthority.Version1 ||
		c.AssignmentID != p.AssignmentID || c.Kind != custodyauthority.Admit || c.Purpose != custodyauthority.Serve || c.OperationID.IsZero() ||
		p.PriorSequence == ^uint64(0) || (p.PriorSequence == 0) != p.PriorHeadID.IsZero() || p.PriorReceiptID.IsZero() || p.Nonce.IsZero() ||
		types.Hash(p.AuthorityTransportPublicKey).IsZero() || types.Hash(p.AuditorTransportPublicKey).IsZero() || p.AuthorityTransportPublicKey == p.AuditorTransportPublicKey {
		return ErrPlan
	}
	if _, err := p.Admission.CanonicalBytes(); err != nil {
		return errors.Join(ErrPlan, err)
	}
	return nil
}

func (p Plan) Validate(a custodyauthority.Assignment) error {
	if err := p.validateShape(); err != nil {
		return err
	}
	id, err := a.ID()
	if err != nil || a.Version != custodyauthority.Version1 || id != p.AssignmentID || p.Admission.AuthorityPublicKey != a.AuthorityPublicKey ||
		(p.PriorSequence == 0 && p.PriorReceiptID != a.InitialReceiptID) {
		return errors.Join(ErrPlan, err)
	}
	c := p.Admission.Command
	if (c.ExpectedSequence == 0) != (c.ExpectedHead == id) || c.ExpectedSequence >= custodyauthority.MaximumEntries(a) {
		return ErrPlan
	}
	authorized := false
	for _, consumer := range a.Consumers {
		authorized = authorized || consumer.PublicKey == c.ActorPublicKey && consumer.Purposes&custodyauthority.Serve != 0
	}
	if !authorized {
		return ErrPlan
	}
	for _, key := range append(append([][32]byte{a.AuthorityPublicKey, a.ReplicaPublicKey, a.RemoteControlPublicKey, a.RemoteTransportPublicKey}, a.Auditors...), consumerKeys(a)...) {
		if p.AuthorityTransportPublicKey == key || p.AuditorTransportPublicKey == key {
			return ErrPlan
		}
	}
	return nil
}

func consumerKeys(a custodyauthority.Assignment) [][32]byte {
	keys := make([][32]byte, len(a.Consumers))
	for i, c := range a.Consumers {
		keys[i] = c.PublicKey
	}
	return keys
}

func (p Plan) CanonicalBytes() ([]byte, error) {
	if err := p.validateShape(); err != nil {
		return nil, err
	}
	admission, _ := p.Admission.CanonicalBytes()
	e := codec.NewEncoder(MaximumPlanBytes)
	e.Fixed([]byte("OMCRPLAN"))
	e.U16(p.Version)
	e.Fixed(p.AssignmentID[:])
	e.BytesField(admission)
	e.Fixed(p.AuthorityTransportPublicKey[:])
	e.Fixed(p.AuditorTransportPublicKey[:])
	e.U64(p.PriorSequence)
	for _, id := range []types.Hash{p.PriorHeadID, p.PriorReceiptID, p.Nonce} {
		e.Fixed(id[:])
	}
	return e.Bytes(), nil
}

func (p Plan) ID() (types.Hash, error) {
	b, err := p.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-remote-worker/plan/id/v0", b), nil
}

func DecodePlan(b []byte) (Plan, error) {
	if len(b) == 0 || len(b) > MaximumPlanBytes {
		return Plan{}, ErrPlan
	}
	d := codec.NewDecoder(b)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, []byte("OMCRPLAN")) {
		return Plan{}, ErrPlan
	}
	var p Plan
	if p.Version, err = d.U16(); err != nil {
		return Plan{}, ErrPlan
	}
	if !fixed(d, p.AssignmentID[:]) {
		return Plan{}, ErrPlan
	}
	entry, err := d.BytesField(custodyauthority.MaximumEntryBytes)
	if err != nil {
		return Plan{}, ErrPlan
	}
	if p.Admission, err = custodyauthority.DecodeEntry(entry); err != nil {
		return Plan{}, errors.Join(ErrPlan, err)
	}
	if !fixed(d, p.AuthorityTransportPublicKey[:]) || !fixed(d, p.AuditorTransportPublicKey[:]) {
		return Plan{}, ErrPlan
	}
	if p.PriorSequence, err = d.U64(); err != nil {
		return Plan{}, ErrPlan
	}
	for _, id := range []*types.Hash{&p.PriorHeadID, &p.PriorReceiptID, &p.Nonce} {
		if !fixed(d, id[:]) {
			return Plan{}, ErrPlan
		}
	}
	if err := d.Finish(); err != nil {
		return Plan{}, errors.Join(ErrPlan, err)
	}
	if err := p.validateShape(); err != nil {
		return Plan{}, err
	}
	return p, nil
}

type Disposition uint8

const (
	// Unseen means this retained worker branch has no local Start record. It
	// does not assert that A never applied Begin or that no other actor acted.
	Unseen Disposition = 1 + iota
	// NoResult records UNKNOWN outcome after a local Start. It is neither
	// successful custody acceptance nor a signed no-effect disposition.
	NoResult
	// RetainedResult commits a caller-selected immutable result digest. This
	// package does not validate custody proof content or freshness for it.
	RetainedResult
)

type Seal struct {
	Version     uint16
	PlanID      types.Hash
	BeginID     types.Hash
	SealingID   types.Hash
	Disposition Disposition
	ResultID    types.Hash
}

func (s Seal) validateShape() error {
	if s.Version != Version0 || s.PlanID.IsZero() || s.BeginID.IsZero() || s.SealingID.IsZero() {
		return ErrSeal
	}
	switch s.Disposition {
	case Unseen, NoResult:
		if !s.ResultID.IsZero() {
			return ErrSeal
		}
	case RetainedResult:
		if s.ResultID.IsZero() {
			return ErrSeal
		}
	default:
		return ErrSeal
	}
	return nil
}

func (s Seal) validateBinding(plan, begin, sealing types.Hash, started bool) error {
	if err := s.validateShape(); err != nil {
		return err
	}
	if s.PlanID != plan || s.BeginID != begin || s.SealingID != sealing || (s.Disposition == Unseen) == started {
		return ErrSeal
	}
	return nil
}

func (s Seal) CanonicalBytes() ([]byte, error) {
	if err := s.validateShape(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder(SealBytes)
	e.Fixed([]byte("OMCRSEAL"))
	e.U16(s.Version)
	for _, id := range []types.Hash{s.PlanID, s.BeginID, s.SealingID} {
		e.Fixed(id[:])
	}
	e.U8(uint8(s.Disposition))
	e.Fixed(s.ResultID[:])
	return e.Bytes(), nil
}

func (s Seal) ID() (types.Hash, error) {
	b, err := s.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-remote-worker/seal/id/v0", b), nil
}

func DecodeSeal(b []byte) (Seal, error) {
	if len(b) != SealBytes {
		return Seal{}, ErrSeal
	}
	d := codec.NewDecoder(b)
	magic, _ := d.Fixed(8)
	if !bytes.Equal(magic, []byte("OMCRSEAL")) {
		return Seal{}, ErrSeal
	}
	var s Seal
	s.Version, _ = d.U16()
	for _, id := range []*types.Hash{&s.PlanID, &s.BeginID, &s.SealingID} {
		if !fixed(d, id[:]) {
			return Seal{}, ErrSeal
		}
	}
	value, err := d.U8()
	if err != nil {
		return Seal{}, ErrSeal
	}
	s.Disposition = Disposition(value)
	if !fixed(d, s.ResultID[:]) || d.Finish() != nil {
		return Seal{}, ErrSeal
	}
	if err := s.validateShape(); err != nil {
		return Seal{}, err
	}
	return s, nil
}

func fixed(d *codec.Decoder, target []byte) bool {
	b, err := d.Fixed(len(target))
	if err != nil {
		return false
	}
	copy(target, b)
	return true
}
