// Package custodyproof verifies separately pinned, quorum-bound historical
// custody results. It supplies no execution permission, live source acceptance,
// receipt refresh, reward or ordinary-ticket completion.
package custodyproof

import (
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const Version0 uint16 = 0
const MaximumBundleBytes = 64 + 3*(custodyfence.MaximumCertificateBytes+10) + store.MaximumRemoteCustodyTerminalBytes + 10

var ErrResult = errors.New("custody result does not match its independently pinned witness scope and exact evidence")

// Bundle must be verified against an externally selected Scope ID and full
// custody context. Scope and context cannot be inferred from this input.
type Bundle struct {
	Version  uint16
	ScopeID  types.Hash
	Chain    []custodyfence.Certificate
	Terminal store.RemoteCustodyTerminal
}

func (b Bundle) CanonicalBytes() ([]byte, error) {
	if b.Version != Version0 || b.ScopeID.IsZero() || len(b.Chain) < 2 || len(b.Chain) > 3 {
		return nil, ErrResult
	}
	e := codec.NewEncoder(MaximumBundleBytes)
	e.Fixed([]byte("OMCFRS00"))
	e.U16(b.Version)
	e.Fixed(b.ScopeID[:])
	e.U8(uint8(len(b.Chain)))
	for _, cert := range b.Chain {
		if cert.Command.ScopeID != b.ScopeID {
			return nil, ErrResult
		}
		raw, err := cert.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		e.BytesField(raw)
	}
	raw, err := b.Terminal.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	e.BytesField(raw)
	out := e.Bytes()
	if len(out) > MaximumBundleBytes {
		return nil, ErrResult
	}
	return out, nil
}
func (b Bundle) ID() (types.Hash, error) {
	raw, err := b.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-fence/custody-result/id/v0", raw), nil
}
func DecodeBundle(raw []byte) (Bundle, error) {
	var b Bundle
	if len(raw) > MaximumBundleBytes {
		return b, ErrResult
	}
	d := codec.NewDecoder(raw)
	magic, _ := d.Fixed(8)
	if string(magic) != "OMCFRS00" {
		return b, ErrResult
	}
	b.Version, _ = d.U16()
	id, err := d.Fixed(32)
	if err != nil {
		return b, ErrResult
	}
	copy(b.ScopeID[:], id)
	n, err := d.U8()
	if err != nil || n < 2 || n > 3 {
		return Bundle{}, ErrResult
	}
	b.Chain = make([]custodyfence.Certificate, int(n))
	for i := range b.Chain {
		raw, err := d.BytesField(custodyfence.MaximumCertificateBytes)
		if err != nil {
			return Bundle{}, err
		}
		b.Chain[i], err = custodyfence.DecodeCertificate(raw)
		if err != nil {
			return Bundle{}, err
		}
	}
	terminal, err := d.BytesField(store.MaximumRemoteCustodyTerminalBytes)
	if err != nil || d.Finish() != nil {
		return Bundle{}, ErrResult
	}
	b.Terminal, err = store.DecodeRemoteCustodyTerminal(terminal)
	if err != nil {
		return Bundle{}, err
	}
	if _, err := b.CanonicalBytes(); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

// ValidateBinding pins all V1 historical roles, including transport, consumer
// and evidence keys, outside the witness set. This is not a V1 upgrade or proof
// that this scope existed before the historical execution.
func ValidateBinding(s custodyfence.Scope, pin types.Hash, remote store.RemoteCustodyScope, intent workarchive.CustodyAuditIntent, audit custodyauthority.Entry) error {
	id, err := s.ID()
	if err != nil || pin.IsZero() || id != pin {
		return ErrResult
	}
	if err := store.ValidateRemoteCustodyAuditScope(remote, intent, audit); err != nil {
		return err
	}
	iid, _ := intent.ID()
	w := remote.Worker
	a := w.Assignment
	if s.AssignmentID != w.Plan.AssignmentID || s.PlanID != w.PlanID || s.BeginID != w.BeginID || s.IntentID != iid || s.Owner != a.RemoteControlPublicKey || s.Controller != a.AuthorityPublicKey {
		return ErrResult
	}
	roles := [][32]byte{a.AuthorityPublicKey, a.ReplicaPublicKey, a.RemoteControlPublicKey, a.RemoteTransportPublicKey, w.Plan.AuthorityTransportPublicKey, w.Plan.AuditorTransportPublicKey}
	roles = append(roles, a.Auditors...)
	for _, consumer := range a.Consumers {
		roles = append(roles, consumer.PublicKey)
	}
	for _, member := range s.Witnesses {
		for _, role := range roles {
			if member == role {
				return ErrResult
			}
		}
	}
	return nil
}

// Verify authenticates the complete claim/[unknown]/result history and exact
// typed custody entry at its original proof time. A valid quorum over an opaque
// unrelated digest is insufficient. This read-only method does not assert A's
// original current source or current proof freshness; owned acceptance must be
// separately enforced before any effect, completion or credit.
func (b Bundle) Verify(s custodyfence.Scope, pin types.Hash, remote store.RemoteCustodyScope, intent workarchive.CustodyAuditIntent, audit custodyauthority.Entry) error {
	if _, err := b.CanonicalBytes(); err != nil {
		return err
	}
	if b.ScopeID != pin {
		return ErrResult
	}
	if err := ValidateBinding(s, pin, remote, intent, audit); err != nil {
		return err
	}
	if b.Terminal.Intent != intent || b.Terminal.AuditAdmission != audit {
		return ErrResult
	}
	if err := b.Terminal.Validate(remote); err != nil {
		return err
	}
	if b.Chain[0].Command.Kind != custodyfence.Claim || b.Chain[len(b.Chain)-1].Command.Kind != custodyfence.RecordResult || len(b.Chain) == 3 && b.Chain[1].Command.Kind != custodyfence.MarkUnknown {
		return ErrResult
	}
	state, err := custodyfence.NewState(s, pin)
	if err != nil {
		return err
	}
	for _, cert := range b.Chain {
		if err := state.Apply(cert); err != nil {
			return err
		}
	}
	entryID, _ := b.Terminal.Entry.ID()
	x := state.Snapshot()
	if x.Phase != custodyfence.ResultRecorded || x.EvidenceID != entryID || !x.ObligationHeld {
		return ErrResult
	}
	return nil
}
