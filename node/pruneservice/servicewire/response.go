package servicewire

import (
	"bytes"
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const MaximumResponseBytes = workchain.MaximumCanonicalPruneEffectBytes + max(prunefence.MaximumResultBytes, prunefence.MaximumSettlementBytes) + 256

// Response retains one complete historical result or observed-effect settlement.
// It cannot reconstruct a live session or grant another storage effect.
type Response struct {
	DescriptorID, RequestID types.Hash
	Effect                  workchain.CanonicalPruneEffect
	Result                  *prunefence.Result
	Settlement              *prunefence.Settlement
	Signature               [64]byte
}

func (r Response) proof() (prunefence.Candidate, byte, []byte, error) {
	if (r.Result == nil) == (r.Settlement == nil) {
		return prunefence.Candidate{}, 0, nil, ErrArtifact
	}
	effectID, err := r.Effect.ID()
	if err != nil {
		return prunefence.Candidate{}, 0, nil, err
	}
	var c prunefence.Candidate
	var proofID types.Hash
	var raw []byte
	kind := byte(1)
	if r.Result != nil {
		c, proofID = r.Result.Claim.Candidate, r.Result.EffectID
		raw, err = r.Result.CanonicalBytes()
	} else {
		kind = 2
		c, proofID = r.Settlement.Proposal.Claim.Candidate, r.Settlement.Proposal.EffectID
		raw, err = r.Settlement.CanonicalBytes()
	}
	if err != nil || effectID != proofID || c.Policy.Service == nil {
		return prunefence.Candidate{}, 0, nil, ErrArtifact
	}
	e := c.Policy.Service
	enrollmentID, err := e.ID()
	if err != nil {
		return prunefence.Candidate{}, 0, nil, err
	}
	op := r.Effect.Operation
	opID, err := op.FenceOperationID()
	if err != nil || opID != c.Binding.OperationID || op.ServiceEnrollmentID != enrollmentID || op.AssignmentID != c.Binding.AssignmentID || op.StorageID != e.StorageID || op.ScheduleID != e.ScheduleID || c.Binding.StoragePairID != e.StoragePairID {
		return prunefence.Candidate{}, 0, nil, ErrArtifact
	}
	return c, kind, raw, nil
}
func (r Response) body() ([]byte, error) {
	if r.DescriptorID.IsZero() || r.RequestID.IsZero() {
		return nil, ErrArtifact
	}
	_, kind, proof, err := r.proof()
	if err != nil {
		return nil, err
	}
	effect, err := r.Effect.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	e := encoder("OMPSRS00", MaximumResponseBytes)
	e.Fixed(r.DescriptorID[:])
	e.Fixed(r.RequestID[:])
	e.BytesField(effect)
	e.U8(kind)
	e.BytesField(proof)
	return e.Bytes(), nil
}
func (r Response) check(d Descriptor, q Request) error {
	if err := q.Authorize(d); err != nil {
		return err
	}
	id, _ := q.ID()
	if r.DescriptorID != q.DescriptorID || r.RequestID != id {
		return ErrAccess
	}
	c, _, _, err := r.proof()
	if err != nil {
		return err
	}
	return candidateMatches(d, c)
}
func (r Response) Sign(d Descriptor, q Request, key ed25519.PrivateKey) (Response, error) {
	if r.check(d, q) != nil || !keyMatches(key, d.Policy.Service.Service) {
		return Response{}, ErrAccess
	}
	b, err := r.body()
	if err != nil {
		return Response{}, err
	}
	r.Signature = sign("response/sign", b, key)
	return r, nil
}
func (r Response) CanonicalBytes() ([]byte, error) {
	b, err := r.body()
	if err != nil {
		return nil, err
	}
	c, _, _, err := r.proof()
	if err != nil {
		return nil, err
	}
	return signedBytes("response/sign", b, r.Signature, c.Policy.Service.Service)
}
func (r Response) Verify(d Descriptor, q Request) error {
	if err := r.check(d, q); err != nil {
		return err
	}
	_, err := r.CanonicalBytes()
	return err
}
func (r Response) ID() (types.Hash, error) {
	b, err := r.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(Domain+"response/id", b), nil
}
func (r Response) Position() (Position, error) {
	id, err := r.ID()
	if err != nil {
		return Position{}, err
	}
	return Position{Sequence: 2, Head: id}, nil
}
func DecodeResponse(raw []byte) (Response, error) {
	var r Response
	d, err := decoder(raw, "OMPSRS00", MaximumResponseBytes)
	if err != nil {
		return r, err
	}
	if readFixed(d, r.DescriptorID[:], r.RequestID[:]) != nil {
		return r, ErrArtifact
	}
	effect, err := d.BytesField(workchain.MaximumCanonicalPruneEffectBytes)
	if err != nil {
		return r, err
	}
	r.Effect, err = workchain.DecodeCanonicalPruneEffect(effect)
	if err != nil {
		return r, err
	}
	kind, err := d.U8()
	if err != nil || kind < 1 || kind > 2 {
		return r, ErrArtifact
	}
	limit := prunefence.MaximumResultBytes
	if kind == 2 {
		limit = prunefence.MaximumSettlementBytes
	}
	proof, err := d.BytesField(uint64(limit))
	if err != nil {
		return r, err
	}
	if kind == 1 {
		p, e := prunefence.DecodeResult(proof)
		if e != nil {
			return Response{}, e
		}
		r.Result = &p
	} else {
		p, e := prunefence.DecodeSettlement(proof)
		if e != nil {
			return Response{}, e
		}
		r.Settlement = &p
	}
	if readFixed(d, r.Signature[:]) != nil || d.Finish() != nil {
		return Response{}, ErrArtifact
	}
	b, err := r.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, b) {
		return Response{}, ErrArtifact
	}
	return r, nil
}
