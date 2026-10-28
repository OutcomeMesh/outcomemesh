package custodycutover

import (
	"bytes"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const SourceHandoffPairBytes = 10 + 2*workarchive.CustodySourceHandoffBytes

// SourceHandoffPair is historical agreement of BOTH retained source records.
// Possessing it never establishes live freshness, protected exclusion or activation.
type SourceHandoffPair struct {
	A, B workarchive.CustodySourceHandoff
}

func (p SourceHandoffPair) CanonicalBytes() ([]byte, error) {
	a, b := p.A, p.B
	if a.Role != uint8(Authority) || b.Role != uint8(Target) || a.PlacementID == b.PlacementID {
		return nil, ErrPreparation
	}
	aa, err := a.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	bb, err := b.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	// Only roles and their independently pinned original placement may differ.
	a.Role = b.Role
	a.PlacementID = b.PlacementID
	if a != b {
		return nil, ErrPreparation
	}
	e := codec.NewEncoder(SourceHandoffPairBytes)
	e.Fixed([]byte("OMCSHPR1"))
	e.U16(1)
	e.Fixed(aa)
	e.Fixed(bb)
	return e.Bytes(), nil
}
func DecodeSourceHandoffPair(raw []byte) (SourceHandoffPair, error) {
	var p SourceHandoffPair
	if len(raw) != SourceHandoffPairBytes {
		return p, ErrPreparation
	}
	d := codec.NewDecoder(raw)
	magic, _ := d.Fixed(8)
	v, _ := d.U16()
	a, _ := d.Fixed(workarchive.CustodySourceHandoffBytes)
	b, _ := d.Fixed(workarchive.CustodySourceHandoffBytes)
	var err error
	p.A, err = workarchive.DecodeCustodySourceHandoff(a)
	if err != nil {
		return p, err
	}
	p.B, err = workarchive.DecodeCustodySourceHandoff(b)
	if err != nil {
		return p, err
	}
	again, err := p.CanonicalBytes()
	if err != nil || string(magic) != "OMCSHPR1" || v != 1 || d.Finish() != nil || !bytes.Equal(raw, again) {
		return SourceHandoffPair{}, ErrPreparation
	}
	return p, nil
}
func (p SourceHandoffPair) ID() (types.Hash, error) {
	raw, e := p.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody-source-handoff/v1/pair/id", raw), nil
}
func (p SourceHandoffPair) Verify(g v2.AdmissionGenesis, b v2.EnrollmentBinding, ap, bp SourceHandoffPins) error {
	if _, e := p.CanonicalBytes(); e != nil {
		return e
	}
	aa, e := ReviewSourceHandoff(g, b, ap, Authority)
	if e != nil {
		return e
	}
	bb, e := ReviewSourceHandoff(g, b, bp, Target)
	if e != nil {
		return e
	}
	if p.A != aa || p.B != bb {
		return ErrPreparation
	}
	return nil
}
