package workarchive

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	CustodyRebaselineProposalVersion0      uint16 = 0
	MaximumCustodyRebaselineReviewLifetime uint64 = 600
	MaximumCustodyRebaselineProposalBytes         = 8 + 2 + 6*types.HashSize + 3*8 + ed25519.PublicKeySize + ed25519.SignatureSize
	custodyRebaselineSignatureDomain              = "OMESH/workgraph/archive/custody-rebaseline-proposal/signature/v0"
	custodyRebaselineIDDomain                     = "OMESH/workgraph/archive/custody-rebaseline-proposal/id/v0"
)

var (
	ErrCustodyRebaseline        = errors.New("invalid custody rebaseline proposal")
	ErrCustodyRebaselineExpired = errors.New("custody rebaseline proposal is outside its review window")
	custodyRebaselineMagic      = [8]byte{'O', 'M', 'W', 'A', 'C', 'R', 'B', 'P'}
)

// CustodyRebaselineProposal is a new replica's short-lived, signed proposal
// following full archive replay. ApplicationID preserves the exact historical
// reconstruction and its source links. NextPolicyID commits the proposed auditor
// set and timing rules. It is NOT a receipt, auditor acceptance, fence, journal
// header, or permission to start. No live protocol consumes this format.
type CustodyRebaselineProposal struct {
	Version           uint16
	ApplicationID     types.Hash
	PreviousReceiptID types.Hash
	ManifestID        types.Hash
	StatementID       types.Hash
	NextPolicyID      types.Hash
	LocationID        types.Hash
	ReplayedAt        uint64
	ReviewUntil       uint64
	RetainUntil       uint64
	ReplicaPublicKey  [ed25519.PublicKeySize]byte
	Signature         [ed25519.SignatureSize]byte
}

func (proposal CustodyRebaselineProposal) validateShape() error {
	if proposal.Version != CustodyRebaselineProposalVersion0 || proposal.ApplicationID.IsZero() ||
		proposal.PreviousReceiptID.IsZero() || proposal.ManifestID.IsZero() || proposal.StatementID.IsZero() ||
		proposal.NextPolicyID.IsZero() || proposal.LocationID.IsZero() || types.Hash(proposal.ReplicaPublicKey).IsZero() ||
		proposal.ReplayedAt == 0 || proposal.ReviewUntil <= proposal.ReplayedAt ||
		proposal.ReviewUntil-proposal.ReplayedAt > MaximumCustodyRebaselineReviewLifetime ||
		proposal.RetainUntil <= proposal.ReviewUntil || proposal.RetainUntil-proposal.ReplayedAt > MaximumReplicaTermSeconds {
		return ErrCustodyRebaseline
	}
	return nil
}

func (proposal CustodyRebaselineProposal) unsignedBytes() ([]byte, error) {
	if err := proposal.validateShape(); err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(MaximumCustodyRebaselineProposalBytes)
	encoder.Fixed(custodyRebaselineMagic[:])
	encoder.U16(proposal.Version)
	for _, id := range []types.Hash{proposal.ApplicationID, proposal.PreviousReceiptID, proposal.ManifestID,
		proposal.StatementID, proposal.NextPolicyID, proposal.LocationID} {
		encoder.Fixed(id[:])
	}
	encoder.U64(proposal.ReplayedAt)
	encoder.U64(proposal.ReviewUntil)
	encoder.U64(proposal.RetainUntil)
	encoder.Fixed(proposal.ReplicaPublicKey[:])
	return encoder.Bytes(), nil
}

func (proposal CustodyRebaselineProposal) signatureMessage() ([]byte, error) {
	unsigned, err := proposal.unsignedBytes()
	if err != nil {
		return nil, err
	}
	id := types.DomainHash(custodyRebaselineSignatureDomain, unsigned)
	return id[:], nil
}

func (proposal CustodyRebaselineProposal) CanonicalBytes() ([]byte, error) {
	message, err := proposal.signatureMessage()
	if err != nil || !ed25519.Verify(proposal.ReplicaPublicKey[:], message, proposal.Signature[:]) {
		return nil, ErrCustodyRebaseline
	}
	unsigned, _ := proposal.unsignedBytes()
	return append(unsigned, proposal.Signature[:]...), nil
}

// DecodeCustodyRebaselineProposal checks canonical bytes and the signature, not
// current time, archive contents, external trust, or participant retirement.
func DecodeCustodyRebaselineProposal(input []byte) (CustodyRebaselineProposal, error) {
	if len(input) != MaximumCustodyRebaselineProposalBytes {
		return CustodyRebaselineProposal{}, ErrCustodyRebaseline
	}
	decoder := codec.NewDecoder(input)
	magic, _ := decoder.Fixed(len(custodyRebaselineMagic))
	var proposal CustodyRebaselineProposal
	proposal.Version, _ = decoder.U16()
	for _, id := range []*types.Hash{&proposal.ApplicationID, &proposal.PreviousReceiptID, &proposal.ManifestID,
		&proposal.StatementID, &proposal.NextPolicyID, &proposal.LocationID} {
		value, _ := decoder.Fixed(types.HashSize)
		copy(id[:], value)
	}
	proposal.ReplayedAt, _ = decoder.U64()
	proposal.ReviewUntil, _ = decoder.U64()
	proposal.RetainUntil, _ = decoder.U64()
	key, _ := decoder.Fixed(ed25519.PublicKeySize)
	copy(proposal.ReplicaPublicKey[:], key)
	signature, _ := decoder.Fixed(ed25519.SignatureSize)
	copy(proposal.Signature[:], signature)
	if !bytes.Equal(magic, custodyRebaselineMagic[:]) || decoder.Finish() != nil {
		return CustodyRebaselineProposal{}, ErrCustodyRebaseline
	}
	if _, err := proposal.CanonicalBytes(); err != nil {
		return CustodyRebaselineProposal{}, err
	}
	return proposal, nil
}

func (proposal CustodyRebaselineProposal) ID() (types.Hash, error) {
	encoded, err := proposal.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(custodyRebaselineIDDomain, encoded), nil
}

// VerifyReviewWindow uses a half-open window. It never refreshes the signed
// timestamp; an expired proposal remains decodable as historical evidence.
func (proposal CustodyRebaselineProposal) VerifyReviewWindow(at uint64) error {
	if _, err := proposal.CanonicalBytes(); err != nil {
		return err
	}
	if at < proposal.ReplayedAt || at >= proposal.ReviewUntil {
		return ErrCustodyRebaselineExpired
	}
	return nil
}
