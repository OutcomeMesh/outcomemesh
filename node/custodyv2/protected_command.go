package custodyv2

import (
	"bytes"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	gateway "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
)

const (
	ProtectedEndorse uint8 = 1 + iota
	ProtectedPrepare
	ProtectedExecute
	ProtectedResultCommand
	ProtectedAccept
	ProtectedResumeAccept
	ProtectedServe
	ProtectedReadResult
	ProtectedAcceptRetained
	ProtectedResumeRetained
)

type ProtectedCommand struct {
	Kind      uint8
	Admission AdmissionBinding
	Data      []byte
	Now       uint64
}

func (p ProtectedCommand) CanonicalBytes() ([]byte, error) {
	if p.Kind < ProtectedEndorse || p.Kind > ProtectedResumeRetained || p.Now == 0 {
		return nil, ErrProtocol
	}
	var raw []byte
	var e error
	if p.Kind != ProtectedEndorse {
		raw, e = p.Admission.CanonicalBytes()
		if e != nil || len(p.Admission.Chain) == 0 || !ProtectedContext(p.Admission.Chain[len(p.Admission.Chain)-1].Entry.Context) {
			return nil, ErrAdmissionRequired
		}
	}
	out := codec.NewEncoder(len(raw) + len(p.Data) + 32)
	out.Fixed([]byte("OMCGCMD5"))
	out.U8(p.Kind)
	out.U64(p.Now)
	out.BytesField(raw)
	out.BytesField(p.Data)
	b := out.Bytes()
	if len(b) > gateway.MaximumRuntimePayloadBytes {
		return nil, ErrProtocol
	}
	return b, nil
}
func DecodeProtectedCommand(b []byte) (ProtectedCommand, error) {
	var p ProtectedCommand
	if len(b) > gateway.MaximumRuntimePayloadBytes {
		return p, ErrProtocol
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCGCMD5") {
		return p, ErrProtocol
	}
	p.Kind, _ = d.U8()
	p.Now, _ = d.U64()
	raw, e := d.BytesField(gateway.MaximumRuntimePayloadBytes)
	if e != nil {
		return p, e
	}
	if len(raw) > 0 {
		p.Admission, e = DecodeAdmissionBinding(raw)
		if e != nil {
			return p, e
		}
	}
	p.Data, e = d.BytesField(gateway.MaximumRuntimePayloadBytes)
	if e != nil {
		return p, e
	}
	again, e := p.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(again, b) {
		return ProtectedCommand{}, ErrProtocol
	}
	return p, nil
}
func ProtectedContextOf(b AdmissionBinding) (Context, error) {
	if len(b.Chain) == 0 {
		return Context{}, ErrAdmissionRequired
	}
	c := b.Chain[len(b.Chain)-1].Entry.Context
	if !ProtectedContext(c) || b.Verify(c) != nil {
		return Context{}, ErrAdmissionRequired
	}
	return c, nil
}
func AdmissionEntryID(b AdmissionBinding) (types.Hash, error) { return b.admissionID() }
func EncodeProtectedPrefix(q []custodyfence.Certificate) ([]byte, error) {
	if len(q) < 1 || len(q) > 2 {
		return nil, ErrProtocol
	}
	e := codec.NewEncoder(4096)
	e.U8(uint8(len(q)))
	for _, v := range q {
		b, err := v.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		e.BytesField(b)
	}
	return e.Bytes(), nil
}
func DecodeProtectedPrefix(b []byte) ([]custodyfence.Certificate, error) {
	d := codec.NewDecoder(b)
	n, e := d.U8()
	if e != nil || n < 1 || n > 2 {
		return nil, ErrProtocol
	}
	var q []custodyfence.Certificate
	for i := uint8(0); i < n; i++ {
		raw, e := d.BytesField(custodyfence.MaximumCertificateBytes)
		if e != nil {
			return nil, e
		}
		v, e := custodyfence.DecodeCertificate(raw)
		if e != nil {
			return nil, e
		}
		q = append(q, v)
	}
	if d.Finish() != nil {
		return nil, ErrProtocol
	}
	return q, nil
}
func VerifyDeploymentGenesis(g AdmissionGenesis, c Context) error {
	if !ProtectedContext(c) {
		return nil
	}
	d := c.Plan.Deployment
	gid, e := g.ID()
	did, e2 := g.DescriptorID()
	if e != nil || e2 != nil || g.Import == nil || d.GenesisID != gid || d.GenesisDescriptorID != did || d.ImportID != c.Assignment.Policy.ImportID || d.A.Issuer != g.Import.Anchor.Issuer {
		return ErrAdmissionRequired
	}
	for _, k := range append([][32]byte{g.Import.Anchor.Issuer}, g.Import.Anchor.Witnesses...) {
		if c.Plan.ClientTransportPublicKey == k {
			return ErrAdmissionRequired
		}
	}
	return nil
}
