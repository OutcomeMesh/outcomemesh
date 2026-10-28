package custodyv2

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	a "github.com/outcomemesh/outcomemesh/node/custodyauthority"
	review "github.com/outcomemesh/outcomemesh/node/custodycutover/review"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// PolicyVersionImported carries verified legacy accounting. It intentionally has
// no execution adapter until protected exclusion of old grants is implemented.
const PolicyVersionImported uint16 = 5

var ErrImportInactive = errors.New("imported custody accounting has no activated execution adapter")

// ImportPins are external review pins, never inferred from an incoming proposal.
type ImportPins struct {
	RegistryID, RegistryDescriptorID, LegacyID, ProposalID types.Hash
	Retirement                                             a.Position
}

// NewImportedAdmissionGenesis fixes one successor deterministically from the
// complete signed review. It creates no source, receipt, permission or witness.
func NewImportedAdmissionGenesis(p review.Proposal, pins ImportPins) (AdmissionGenesis, error) {
	raw, err := p.CanonicalBytes()
	if err != nil {
		return AdmissionGenesis{}, err
	}
	p, err = review.DecodeProposal(raw)
	if err != nil {
		return AdmissionGenesis{}, err
	}
	id, _ := p.ID()
	if pins.ProposalID.IsZero() || id != pins.ProposalID {
		return AdmissionGenesis{}, ErrAdmission
	}
	bridge, err := p.Verify(pins.RegistryID, pins.RegistryDescriptorID, pins.LegacyID, pins.Retirement)
	if err != nil {
		return AdmissionGenesis{}, err
	}
	return deriveImportedFields(p, bridge)
}

func deriveImportedGenesis(p review.Proposal) (AdmissionGenesis, error) {
	rid, _ := p.Anchor.ID()
	did, _ := p.Anchor.DescriptorID()
	lid, _ := p.Evidence.Assignment.ID()
	bridge, err := p.Verify(rid, did, lid, p.Evidence.End)
	if err != nil {
		return AdmissionGenesis{}, err
	}
	return deriveImportedFields(p, bridge)
}

// deriveImportedFields follows full proposal verification in both callers.
func deriveImportedFields(p review.Proposal, bridge review.Bridge) (AdmissionGenesis, error) {
	rid, _ := p.Anchor.ID()
	did, _ := p.Anchor.DescriptorID()
	pid, err := p.ID()
	if err != nil {
		return AdmissionGenesis{}, err
	}
	b := p.Successor
	base, err := workarchive.CreateRemoteCustodyAuthorityAssignment(p.Evidence.Manifest, p.Evidence.Initial, p.Evidence.Policy, b.IncarnationID, b.Authority, p.Evidence.Assignment.Consumers, bridge.Spent+bridge.Authorized, b.MaximumPending, b.Control, b.Transport)
	if err != nil {
		return AdmissionGenesis{}, err
	}
	policy := Policy{Version: PolicyVersionImported, Threshold: b.Threshold, Witnesses: append([][32]byte(nil), b.Witnesses...), RegistryID: rid, RegistryDescriptorID: did, ImportID: pid}
	assignment := Assignment{Version: Version2, Base: base, Policy: policy}
	if _, err := assignment.CanonicalBytes(); err != nil {
		return AdmissionGenesis{}, err
	}
	return AdmissionGenesis{Version: PolicyVersionImported, Assignment: assignment, Manifest: p.Evidence.Manifest, Initial: p.Evidence.Initial, CustodyPolicy: p.Evidence.Policy, Import: &p}, nil
}
func (g AdmissionGenesis) validateImported() error {
	if g.Version != PolicyVersionImported || g.Import == nil {
		return ErrAdmission
	}
	expected, err := deriveImportedGenesis(*g.Import)
	if err != nil {
		return err
	}
	if !sameAdmissionFields(g, expected) {
		return ErrAdmission
	}
	return nil
}

// Both values have already been independently validated by their callers. This
// compares all public archive/assignment fields without re-verifying old history.
func sameAdmissionFields(g, expected AdmissionGenesis) bool {
	got, err := g.Assignment.CanonicalBytes()
	if err != nil {
		return false
	}
	want, err := expected.Assignment.CanonicalBytes()
	if err != nil {
		return false
	}
	gm, err := g.Manifest.CanonicalBytes()
	if err != nil {
		return false
	}
	em, err := expected.Manifest.CanonicalBytes()
	if err != nil {
		return false
	}
	p, q := g.CustodyPolicy, expected.CustodyPolicy
	if !bytes.Equal(got, want) || !bytes.Equal(gm, em) || g.Initial != expected.Initial || p.MaximumChallengeLifetime != q.MaximumChallengeLifetime || p.MaximumProofAge != q.MaximumProofAge || p.MaximumRenewalTerm != q.MaximumRenewalTerm || len(p.TrustedAuditors) != len(q.TrustedAuditors) {
		return false
	}
	for i, k := range p.TrustedAuditors {
		if k != q.TrustedAuditors[i] {
			return false
		}
	}
	return true
}
func (g AdmissionGenesis) importedBytes() ([]byte, error) {
	if err := g.validateImported(); err != nil {
		return nil, err
	}
	return encodeImportedProposal(*g.Import)
}
func encodeImportedProposal(p review.Proposal) ([]byte, error) {
	raw, err := p.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	e := codec.NewEncoder(len(raw) + 20)
	e.Fixed([]byte("OMCVAGN5"))
	e.U16(PolicyVersionImported)
	e.BytesField(raw)
	return e.Bytes(), nil
}
func decodeImportedGenesis(raw []byte) (AdmissionGenesis, error) {
	if len(raw) > MaximumAdmissionGenesisBytes {
		return AdmissionGenesis{}, ErrAdmission
	}
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCVAGN5") {
		return AdmissionGenesis{}, ErrAdmission
	}
	v, err := d.U16()
	if err != nil || v != PolicyVersionImported {
		return AdmissionGenesis{}, ErrAdmission
	}
	p, err := d.BytesField(review.MaximumProposalBytes)
	if err != nil || d.Finish() != nil {
		return AdmissionGenesis{}, ErrAdmission
	}
	proposal, err := review.DecodeProposal(p)
	if err != nil {
		return AdmissionGenesis{}, err
	}
	g, err := deriveImportedGenesis(proposal)
	if err != nil {
		return AdmissionGenesis{}, err
	}
	again, err := encodeImportedProposal(proposal)
	if err != nil || !bytes.Equal(raw, again) {
		return AdmissionGenesis{}, ErrAdmission
	}
	return g, nil
}
