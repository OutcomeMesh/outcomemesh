package prunefence

import (
	"bytes"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

const (
	MaximumClosureIntentBytes = MaximumPolicyBytes + 80
	MaximumClosureBytes       = MaximumClosureIntentBytes + custodyfence.MaximumCertificateBytes + 32
)

// ClosureIntent identifies the original request-wide slot. Local candidates,
// inventories and session keys cannot create distinct closure proposals.
// It grants neither accounting completion nor permission to touch storage.
type ClosureIntent struct {
	Policy                  Policy
	AssignmentID, RequestID types.Hash
}

func (c ClosureIntent) CanonicalBytes() ([]byte, error) {
	if c.AssignmentID.IsZero() || c.RequestID.IsZero() {
		return nil, ErrFence
	}
	p, err := c.Policy.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	e := codec.NewEncoder(MaximumClosureIntentBytes)
	e.Fixed([]byte("OMPRFI00"))
	e.U16(0)
	e.BytesField(p)
	e.Fixed(c.AssignmentID[:])
	e.Fixed(c.RequestID[:])
	return e.Bytes(), nil
}
func (c ClosureIntent) ID() (types.Hash, error) {
	b, err := c.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(domain+"close-intent/id/v0", b), nil
}
func (c ClosureIntent) Draft() (custodyfence.Scope, custodyfence.Command, error) {
	id, err := c.ID()
	if err != nil {
		return custodyfence.Scope{}, custodyfence.Command{}, err
	}
	s, err := c.Policy.Scope(c.AssignmentID, c.RequestID)
	if err != nil {
		return s, custodyfence.Command{}, err
	}
	sid, _ := s.ID()
	return s, custodyfence.Command{Version: custodyfence.Version1, ScopeID: sid, ExpectedHead: sid, Kind: custodyfence.CloseUnclaimed, EvidenceID: id}, nil
}
func DecodeClosureIntent(raw []byte) (ClosureIntent, error) {
	var c ClosureIntent
	if len(raw) > MaximumClosureIntentBytes {
		return c, ErrFence
	}
	d := codec.NewDecoder(raw)
	magic, _ := d.Fixed(8)
	version, _ := d.U16()
	if string(magic) != "OMPRFI00" || version != 0 {
		return c, ErrFence
	}
	policy, err := d.BytesField(MaximumPolicyBytes)
	if err != nil {
		return c, err
	}
	c.Policy, err = DecodePolicy(policy)
	if err != nil {
		return c, err
	}
	for _, out := range [][]byte{c.AssignmentID[:], c.RequestID[:]} {
		b, err := d.Fixed(32)
		if err != nil {
			return ClosureIntent{}, err
		}
		copy(out, b)
	}
	canonical, err := c.CanonicalBytes()
	if err != nil || d.Finish() != nil || !bytes.Equal(raw, canonical) {
		return ClosureIntent{}, ErrFence
	}
	return c, nil
}

// Closure certifies a controller-authorized CloseUnclaimed quorum at the initial
// scope position. It excludes a competing claim under the witness trust model.
// It is not a PruneCancellation, storage effect or authority completion.
type Closure struct {
	Intent      ClosureIntent
	Certificate custodyfence.Certificate
}

func (c Closure) Verify() error {
	scope, draft, err := c.Intent.Draft()
	if err != nil {
		return err
	}
	draft.Signature = c.Certificate.Command.Signature
	if draft != c.Certificate.Command {
		return ErrFence
	}
	return c.Certificate.Verify(scope)
}
func (c Closure) CanonicalBytes() ([]byte, error) {
	if err := c.Verify(); err != nil {
		return nil, err
	}
	intent, _ := c.Intent.CanonicalBytes()
	certificate, err := c.Certificate.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	e := codec.NewEncoder(MaximumClosureBytes)
	e.Fixed([]byte("OMPRFU00"))
	e.U16(0)
	e.BytesField(intent)
	e.BytesField(certificate)
	return e.Bytes(), nil
}
func (c Closure) ID() (types.Hash, error) {
	b, err := c.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(domain+"close-certificate/id/v0", b), nil
}
func DecodeClosure(raw []byte) (Closure, error) {
	var c Closure
	if len(raw) > MaximumClosureBytes {
		return c, ErrFence
	}
	d := codec.NewDecoder(raw)
	magic, _ := d.Fixed(8)
	version, _ := d.U16()
	if string(magic) != "OMPRFU00" || version != 0 {
		return c, ErrFence
	}
	intent, err := d.BytesField(MaximumClosureIntentBytes)
	if err != nil {
		return c, err
	}
	c.Intent, err = DecodeClosureIntent(intent)
	if err != nil {
		return c, err
	}
	certificate, err := d.BytesField(custodyfence.MaximumCertificateBytes)
	if err != nil {
		return c, err
	}
	c.Certificate, err = custodyfence.DecodeCertificate(certificate)
	if err != nil {
		return c, err
	}
	canonical, err := c.CanonicalBytes()
	if err != nil || d.Finish() != nil || !bytes.Equal(raw, canonical) {
		return Closure{}, ErrFence
	}
	return c, nil
}
