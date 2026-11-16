package servicewire

import (
	"bytes"
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
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
func (r Response) body() ([]byte, prunefence.Candidate, error) {
	if r.DescriptorID.IsZero() || r.RequestID.IsZero() {
		return nil, prunefence.Candidate{}, ErrArtifact
	}
	c, kind, proof, err := r.proof()
	if err != nil {
		return nil, prunefence.Candidate{}, err
	}
	effect, err := r.Effect.CanonicalBytes()
	if err != nil {
		return nil, prunefence.Candidate{}, err
	}
	e := versionedEncoder("OMPSRS00", MaximumResponseBytes, envelopeVersion(c))
	e.Fixed(r.DescriptorID[:])
	e.Fixed(r.RequestID[:])
	e.BytesField(effect)
	e.U8(kind)
	e.BytesField(proof)
	return e.Bytes(), c, nil
}
func (r Response) check(d Descriptor, q Request, c prunefence.Candidate) error {
	if err := q.Authorize(d); err != nil {
		return err
	}
	id, _ := q.ID()
	if r.DescriptorID != q.DescriptorID || r.RequestID != id {
		return ErrAccess
	}
	return candidateMatches(d, c)
}
func (r Response) Sign(d Descriptor, q Request, key ed25519.PrivateKey) (Response, error) {
	b, c, err := r.body()
	if err != nil {
		return Response{}, err
	}
	if r.check(d, q, c) != nil || !keyMatches(key, c.ServiceSigner()) {
		return Response{}, ErrAccess
	}
	r.Signature = sign(envelopeLabel(c, "response/sign"), b, key)
	return r, nil
}
func (r Response) CanonicalBytes() ([]byte, error) {
	raw, _, err := r.signedBytes()
	return raw, err
}
func (r Response) signedBytes() ([]byte, prunefence.Candidate, error) {
	b, c, err := r.body()
	if err != nil {
		return nil, prunefence.Candidate{}, err
	}
	raw, err := signedBytes(envelopeLabel(c, "response/sign"), b, r.Signature, c.ServiceSigner())
	return raw, c, err
}
func (r Response) Verify(d Descriptor, q Request) error {
	_, c, err := r.signedBytes()
	if err != nil {
		return err
	}
	return r.check(d, q, c)
}

// CheckSuccessorTransports checks the actual result or settlement signer on
// both live delivery and historical replay. Call Verify to authenticate the proof.
func (r Response) CheckSuccessorTransports(transport ...[32]byte) error {
	claim, err := r.claim()
	if err != nil {
		return err
	}
	return checkSuccessorTransports(claim.Candidate, transport)
}

// CheckApproval binds a verified response to the exact signed command sent
// during the current exchange. Direct replay has no fresh approval to compare.
func (r Response) CheckApproval(approved custodyfence.Command) error {
	claim, err := r.claim()
	if err != nil {
		return err
	}
	if claim.Certificate.Command != approved {
		return ErrAccess
	}
	return nil
}

func (r Response) claim() (*prunefence.Claim, error) {
	switch {
	case r.Result != nil && r.Settlement == nil:
		return &r.Result.Claim, nil
	case r.Settlement != nil && r.Result == nil:
		return &r.Settlement.Proposal.Claim, nil
	default:
		return nil, ErrArtifact
	}
}
func (r Response) ID() (types.Hash, error) {
	b, c, err := r.signedBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(Domain+envelopeLabel(c, "response/id"), b), nil
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
	d, err := versionedDecoder(raw, "OMPSRS00", MaximumResponseBytes, 1)
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
