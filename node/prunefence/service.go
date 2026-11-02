package prunefence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"time"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

const ServiceEnrollmentBytes = 10 + 7*32 + 64
const ServiceGuardDeadline = 10 * time.Second

// ServiceEnrollment is approved before admission. It identifies the original
// Prune storage pair, never an Audit/Serve deployment. The issuer's trust and the
// isolation of the service and guard keys are deployment responsibilities.
type ServiceEnrollment struct {
	AssignmentID, ScheduleID, StorageID, StoragePairID types.Hash
	Service, Issuer, Guard                             [32]byte
	Signature                                          [64]byte
}

func (e ServiceEnrollment) body() ([]byte, error) {
	out := codec.NewEncoder(ServiceEnrollmentBytes)
	out.Fixed([]byte("OMPRSE00"))
	out.U16(0)
	for _, id := range []types.Hash{e.AssignmentID, e.ScheduleID, e.StorageID, e.StoragePairID, types.Hash(e.Service), types.Hash(e.Issuer), types.Hash(e.Guard)} {
		if id.IsZero() {
			return nil, ErrFence
		}
		out.Fixed(id[:])
	}
	if e.Service == e.Issuer || e.Service == e.Guard || e.Issuer == e.Guard {
		return nil, ErrFence
	}
	return out.Bytes(), nil
}
func (e ServiceEnrollment) Sign(key ed25519.PrivateKey) (ServiceEnrollment, error) {
	b, err := e.body()
	if err != nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key[32:], e.Issuer[:]) {
		return ServiceEnrollment{}, ErrFence
	}
	h := types.DomainHash(domain+"service-enrollment/sign/v0", b)
	copy(e.Signature[:], ed25519.Sign(key, h[:]))
	return e, nil
}

// ReviewID commits the complete public enrollment before opening the issuer key.
func (e ServiceEnrollment) ReviewID() (types.Hash, error) {
	b, err := e.body()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(domain+"service-enrollment/review/v0", b), nil
}
func (e ServiceEnrollment) CanonicalBytes() ([]byte, error) {
	b, err := e.body()
	if err != nil {
		return nil, err
	}
	h := types.DomainHash(domain+"service-enrollment/sign/v0", b)
	if !ed25519.Verify(e.Issuer[:], h[:], e.Signature[:]) {
		return nil, ErrFence
	}
	return append(b, e.Signature[:]...), nil
}
func (e ServiceEnrollment) ID() (types.Hash, error) {
	b, err := e.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(domain+"service-enrollment/id/v0", b), nil
}
func DecodeServiceEnrollment(raw []byte) (ServiceEnrollment, error) {
	var e ServiceEnrollment
	if len(raw) != ServiceEnrollmentBytes || string(raw[:8]) != "OMPRSE00" || raw[8] != 0 || raw[9] != 0 {
		return e, ErrFence
	}
	d := codec.NewDecoder(raw[10:])
	for _, dst := range [][]byte{e.AssignmentID[:], e.ScheduleID[:], e.StorageID[:], e.StoragePairID[:], e.Service[:], e.Issuer[:], e.Guard[:]} {
		b, _ := d.Fixed(32)
		copy(dst, b)
	}
	b, _ := d.Fixed(64)
	copy(e.Signature[:], b)
	_, err := e.CanonicalBytes()
	return e, err
}

// ServiceIdentity belongs to the trusted storage owner. Neither this object nor
// a raw storage handle is a transport argument. The chooser must enforce caller
// deadlines and retain its original independent choice/revocation journal.
type ServiceIdentity struct {
	mu         sync.Mutex
	enrollment ServiceEnrollment
	key        ed25519.PrivateKey
	guard      guardwire.Chooser
}

func NewServiceIdentity(e ServiceEnrollment, key ed25519.PrivateKey, guard guardwire.Chooser) (*ServiceIdentity, error) {
	if _, err := e.CanonicalBytes(); err != nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key[32:], e.Service[:]) || guard == nil {
		return nil, ErrFence
	}
	return &ServiceIdentity{enrollment: e, key: append(ed25519.PrivateKey(nil), key...), guard: guard}, nil
}
func (s *ServiceIdentity) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.key)
	s.key = nil
}

// NewSession signs a new volatile session; it cannot reconstruct a historical
// one. Close prevents future sessions, while existing sessions own their copy.
func (s *ServiceIdentity) NewSession(ctx context.Context, p Policy, b Binding) (*Session, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrFence
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) != ed25519.PrivateKeySize || p.Service == nil || *p.Service != s.enrollment {
		return nil, ErrFence
	}
	return newSession(p, b, s.key, s.guard, ctx)
}

// ServiceConsumption is historical evidence of a guard choice at the effect
// boundary. Only the live session can obtain and consume this capability.
type ServiceConsumption struct {
	Nonce [32]byte
	Seal  [64]byte
}

func (c Candidate) serviceRequest(nonce [32]byte) (guardwire.Request, error) {
	b, err := c.CanonicalBytes()
	if err != nil || c.Policy.Service == nil || nonce == ([32]byte{}) {
		return guardwire.Request{}, ErrFence
	}
	e := c.Policy.Service
	return guardwire.Request{Kind: guardwire.Gateway, Subject: e.Service,
		Namespace: types.DomainHash(domain+"service/namespace/v0", e.StorageID[:], e.StoragePairID[:], c.Binding.RequestID[:]),
		Choice:    types.DomainHash(domain+"service/consume/v0", b, nonce[:])}, nil
}
func (p ServiceConsumption) verify(c Candidate) error {
	q, err := c.serviceRequest(p.Nonce)
	if err != nil {
		return err
	}
	return q.VerifySeal(c.Policy.Service.Guard, p.Seal)
}
func (s *Session) consumeService() error {
	defer func() { clear(s.serviceKey); s.serviceKey = nil }()
	if s.ctx == nil || s.ctx.Err() != nil || s.guard == nil {
		return ErrFence
	}
	var proof ServiceConsumption
	if _, err := rand.Read(proof.Nonce[:]); err != nil {
		return err
	}
	q, err := s.candidate.serviceRequest(proof.Nonce)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(s.ctx, ServiceGuardDeadline)
	defer cancel()
	proof.Seal, err = guardwire.Obtain(ctx, s.guard, s.candidate.Policy.Service.Guard, q, s.serviceKey)
	if err != nil {
		return err
	}
	s.consumption = &proof
	return nil
}
