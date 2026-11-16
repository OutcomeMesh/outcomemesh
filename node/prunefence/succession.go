package prunefence

import (
	"bytes"
	"crypto/ed25519"
	"slices"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

const SuccessionBytes = 10 + guardwire.ReplacementReceiptBytes + ed25519.SignatureSize

// ServiceSuccession is the original issuer's authorization to use the guard's
// one successor for one admitted policy and binding. The policy and binding
// are supplied by the verifier, not chosen by the receipt's carrier.
type ServiceSuccession struct {
	Replacement     guardwire.ReplacementReceipt
	IssuerSignature [ed25519.SignatureSize]byte
}

func (s ServiceSuccession) statement(p Policy, b Binding) (types.Hash, []byte, error) {
	if p.Service == nil || b.AssignmentID != p.Service.AssignmentID || b.StoragePairID != p.Service.StoragePairID {
		return types.Hash{}, nil, ErrFence
	}
	q := s.Replacement.Request
	if s.Replacement.Guard != p.Service.Guard || q.Subject != p.Service.Service || q.Successor == p.Service.Issuer {
		return types.Hash{}, nil, ErrFence
	}
	for _, key := range [2][32]byte{q.Successor, q.Authority} {
		if key == p.Owner || key == p.Controller || key == p.Guard || slices.Contains(p.Witnesses, key) {
			return types.Hash{}, nil, ErrFence
		}
	}
	pid, err := p.ID()
	if err != nil {
		return types.Hash{}, nil, err
	}
	bid, err := b.ID()
	if err != nil {
		return types.Hash{}, nil, err
	}
	raw, err := s.Replacement.CanonicalBytes()
	if err != nil {
		return types.Hash{}, nil, err
	}
	return types.DomainHash(domain+"service-succession/statement/v0", pid[:], bid[:], raw), raw, nil
}

// ReviewID commits the unsigned statement that the issuer will sign.
func (s ServiceSuccession) ReviewID(p Policy, b Binding) (types.Hash, error) {
	statement, _, err := s.statement(p, b)
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(domain+"service-succession/review/v0", statement[:]), nil
}

func matchesSuccessionKey(key ed25519.PrivateKey, signer [ed25519.PublicKeySize]byte) bool {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key[ed25519.SeedSize:], signer[:]) {
		return false
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	return bytes.Equal(derived, key)
}

func (s ServiceSuccession) Sign(p Policy, b Binding, key ed25519.PrivateKey) (ServiceSuccession, error) {
	if p.Service == nil || !matchesSuccessionKey(key, p.Service.Issuer) {
		return ServiceSuccession{}, ErrFence
	}
	statement, _, err := s.statement(p, b)
	if err != nil {
		return ServiceSuccession{}, err
	}
	h := types.DomainHash(domain+"service-succession/sign/v0", statement[:])
	copy(s.IssuerSignature[:], ed25519.Sign(key, h[:]))
	return s, nil
}

func (s ServiceSuccession) CanonicalBytes(p Policy, b Binding) ([]byte, error) {
	statement, receipt, err := s.statement(p, b)
	if err != nil {
		return nil, err
	}
	h := types.DomainHash(domain+"service-succession/sign/v0", statement[:])
	if !ed25519.Verify(p.Service.Issuer[:], h[:], s.IssuerSignature[:]) {
		return nil, ErrFence
	}
	e := codec.NewEncoder(SuccessionBytes)
	e.Fixed([]byte("OMPRSU00"))
	e.U16(0)
	e.Fixed(receipt)
	e.Fixed(s.IssuerSignature[:])
	return e.Bytes(), nil
}

func (s ServiceSuccession) Verify(p Policy, b Binding) error {
	_, err := s.CanonicalBytes(p, b)
	return err
}

func (s ServiceSuccession) ID(p Policy, b Binding) (types.Hash, error) {
	raw, err := s.CanonicalBytes(p, b)
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(domain+"service-succession/id/v0", raw), nil
}

func DecodeServiceSuccession(raw []byte, p Policy, b Binding) (ServiceSuccession, error) {
	if len(raw) != SuccessionBytes || string(raw[:10]) != "OMPRSU00\x00\x00" {
		return ServiceSuccession{}, ErrFence
	}
	r, err := guardwire.DecodeReplacementReceipt(raw[10 : SuccessionBytes-ed25519.SignatureSize])
	if err != nil {
		return ServiceSuccession{}, err
	}
	s := ServiceSuccession{Replacement: r}
	copy(s.IssuerSignature[:], raw[SuccessionBytes-ed25519.SignatureSize:])
	if err := s.Verify(p, b); err != nil {
		return ServiceSuccession{}, err
	}
	return s, nil
}
