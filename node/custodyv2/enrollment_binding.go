package custodyv2

import (
	"bytes"
	"errors"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

var ErrEnrollmentRequired = errors.New("signed custody profile requires the exact retained registry enrollment")

const MaximumEnrollmentBindingBytes = wire.MaximumCertificateBytes + wire.MaximumGenesisBytes + 32

// ValidateRegistryCandidate is shared by registry operators and real owners.
// The registry's namespace and descriptor exist before policy/assignment IDs.
func ValidateRegistryCandidate(g wire.Genesis, initial AdmissionGenesis) error {
	if e := g.Validate(); e != nil {
		return e
	}
	if e := initial.Validate(); e != nil {
		return e
	}
	a := initial.Assignment.Base
	p := initial.Assignment.Policy
	if initial.Initial.Version != workarchive.ReplicaReceiptVersion0 || a.NetworkID != g.NetworkID || a.GenesisID != g.ChainGenesisID || a.MaximumOperations > g.MaximumOperations || a.MaximumPending > g.MaximumPending {
		return ErrEnrollmentRequired
	}
	switch g.Version {
	case wire.Version1:
		if p.Version != PolicyVersionAdmission {
			return ErrEnrollmentRequired
		}
	case wire.Version2:
		id, _ := g.ID()
		did, _ := g.DescriptorID()
		if p.Version != PolicyVersionEnrolled || p.RegistryID != id || p.RegistryDescriptorID != did {
			return ErrEnrollmentRequired
		}
	default:
		return ErrEnrollmentRequired
	}
	roles := [][32]byte{a.AuthorityPublicKey, a.RemoteControlPublicKey, a.ReplicaPublicKey, a.RemoteTransportPublicKey}
	roles = append(roles, a.Auditors...)
	roles = append(roles, initial.CustodyPolicy.TrustedAuditors...)
	for _, c := range a.Consumers {
		roles = append(roles, c.PublicKey)
	}
	roles = append(roles, p.Witnesses...)
	for _, key := range roles {
		if key == g.Issuer {
			return ErrEnrollmentRequired
		}
		for _, w := range g.Witnesses {
			if key == w {
				return ErrEnrollmentRequired
			}
		}
	}
	return nil
}

// EnrollmentBinding contains the complete selected assignment and quorum, not
// an unsigned snapshot or hash-only approval. The candidate bytes are compared
// against this owner's exact admitted Genesis before cryptographic acceptance.
type EnrollmentBinding struct {
	Version     uint16
	Registry    wire.Genesis
	Certificate []byte
}

func (b EnrollmentBinding) CanonicalBytes() ([]byte, error) {
	if b.Version != PolicyVersionEnrolled || b.Registry.Version != wire.Version2 {
		return nil, ErrEnrollmentRequired
	}
	g, e := b.Registry.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	q, e := wire.DecodeCertificate(b.Certificate)
	if e != nil || q.Version != wire.Version2 {
		return nil, ErrEnrollmentRequired
	}
	e2 := codec.NewEncoder(len(g) + len(b.Certificate) + 32)
	e2.Fixed([]byte("OMCVENR4"))
	e2.U16(b.Version)
	e2.BytesField(g)
	e2.BytesField(b.Certificate)
	out := e2.Bytes()
	if len(out) > MaximumEnrollmentBindingBytes {
		return nil, ErrEnrollmentRequired
	}
	return out, nil
}
func DecodeEnrollmentBinding(raw []byte) (EnrollmentBinding, error) {
	var b EnrollmentBinding
	if len(raw) > MaximumEnrollmentBindingBytes {
		return b, ErrEnrollmentRequired
	}
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCVENR4") {
		return b, ErrEnrollmentRequired
	}
	b.Version, _ = d.U16()
	g, e := d.BytesField(wire.MaximumGenesisBytes)
	if e != nil {
		return b, e
	}
	b.Registry, e = wire.DecodeGenesis(g)
	if e != nil {
		return b, e
	}
	b.Certificate, e = d.BytesField(wire.MaximumCertificateBytes)
	if e != nil {
		return b, e
	}
	again, e := b.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(raw, again) {
		return EnrollmentBinding{}, ErrEnrollmentRequired
	}
	return b, nil
}
func (b EnrollmentBinding) ID() (types.Hash, error) {
	raw, e := b.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v4/enrollment-binding/id", raw), nil
}
func (b EnrollmentBinding) Verify(c Context, admission AdmissionBinding) error {
	if c.Assignment.Policy.Version != PolicyVersionEnrolled {
		return ErrEnrollmentRequired
	}
	if e := admission.Verify(c); e != nil {
		return e
	}
	raw, e := b.CanonicalBytes()
	if e != nil {
		return e
	}
	b, e = DecodeEnrollmentBinding(raw)
	if e != nil {
		return e
	}
	if e := ValidateRegistryCandidate(b.Registry, admission.Genesis); e != nil {
		return e
	}
	q, e := wire.DecodeCertificate(b.Certificate)
	if e != nil {
		return e
	}
	expected, e := admission.Genesis.CanonicalBytes()
	if e != nil {
		return e
	}
	if !bytes.Equal(expected, q.Selection.Candidate) {
		return ErrEnrollmentRequired
	}
	return q.Verify(b.Registry, c.Assignment.Base.AuthorityPublicKey, c.Assignment.Base.RemoteControlPublicKey)
}
func freezeEnrollment(c Context, admission *AdmissionBinding, b *EnrollmentBinding) (*EnrollmentBinding, []byte, types.Hash, error) {
	if c.Assignment.Policy.Version != PolicyVersionEnrolled {
		if b != nil {
			return nil, nil, types.Hash{}, ErrEnrollmentRequired
		}
		return nil, nil, types.Hash{}, nil
	}
	if b == nil || admission == nil {
		return nil, nil, types.Hash{}, ErrEnrollmentRequired
	}
	raw, e := b.CanonicalBytes()
	if e != nil {
		return nil, nil, types.Hash{}, e
	}
	x, e := DecodeEnrollmentBinding(raw)
	if e != nil {
		return nil, nil, types.Hash{}, e
	}
	if e = x.Verify(c, *admission); e != nil {
		return nil, nil, types.Hash{}, e
	}
	id, _ := x.ID()
	return &x, raw, id, nil
}
func (r *root) checkEnrollment() error {
	if r.ctx.Assignment.Policy.Version != PolicyVersionEnrolled {
		if r.enrollment != nil || len(r.enrollmentBytes) != 0 || !r.enrollmentID.IsZero() {
			return ErrEnrollmentRequired
		}
		return nil
	}
	if r.enrollment == nil || r.enrollmentID.IsZero() || len(r.enrollmentBytes) == 0 {
		return ErrEnrollmentRequired
	}
	raw, e := readFile(filepath.Join(r.path, "enrollment"), len(r.enrollmentBytes))
	if e != nil || !bytes.Equal(raw, r.enrollmentBytes) {
		return errors.Join(ErrEnrollmentRequired, e)
	}
	return nil
}
