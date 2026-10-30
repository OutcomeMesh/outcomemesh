package custodyv2

import (
	"bytes"
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	gateway "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
)

const ProtectedVersion uint16 = 5
const MaximumProtectedReceiptBytes = ReceiptBytes + RetainedAcceptanceBytes + gateway.MaximumEffectBytes + 64
const MaximumProtectedServeReceiptBytes = ServeReceiptBytes + gateway.MaximumEffectBytes + 32

func ProtectedContext(c Context) bool {
	return c.Assignment.Policy.Version == PolicyVersionImported && c.Plan.Version == ProtectedVersion && c.Plan.Deployment != nil
}
func protectedEncode(magic string, core []byte, effect *gateway.Effect) ([]byte, error) {
	if effect == nil {
		return nil, ErrProtocol
	}
	e, e2 := effect.CanonicalBytes()
	if e2 != nil {
		return nil, e2
	}
	out := codec.NewEncoder(len(core) + len(e) + 24)
	out.Fixed([]byte(magic))
	out.BytesField(core)
	out.Fixed(e)
	return out.Bytes(), nil
}
func protectedDecode(raw []byte, magic string, max int) ([]byte, *gateway.Effect, error) {
	if len(raw) > max+gateway.MaximumEffectBytes+32 {
		return nil, nil, ErrProtocol
	}
	d := codec.NewDecoder(raw)
	if !bytesMagic(d, magic) {
		return nil, nil, ErrProtocol
	}
	b, e := d.BytesField(uint64(max))
	if e != nil {
		return nil, nil, e
	}
	eb, e := d.Fixed(d.Remaining())
	if e != nil || d.Finish() != nil {
		return nil, nil, ErrProtocol
	}
	effect, e := gateway.DecodeEffect(eb)
	return b, &effect, e
}
func bytesMagic(d *codec.Decoder, s string) bool {
	b, e := d.Fixed(len(s))
	return e == nil && string(b) == s
}
func VerifyProtectedEffect(c Context, e *gateway.Effect, kind uint8, artifact, head types.Hash, seq, at uint64) error {
	if !ProtectedContext(c) || e == nil || c.Plan.Deployment.Verify() != nil {
		return ErrProtocol
	}
	d := *c.Plan.Deployment
	did, _ := d.ID()
	scope, err := c.Scope()
	if err != nil {
		return err
	}
	sid, _ := scope.ID()
	key := d.A.Gateway
	if kind == gateway.EffectExecute || kind == gateway.EffectServeB {
		key = d.B.Gateway
	}
	if e.Replacement != nil && !ReplacementRoleAllowed(c, e.Signer) {
		return ErrProtocol
	}
	principal, err := e.Principal(d.Guard)
	if err != nil || principal != key {
		return ErrProtocol
	}
	if _, err = e.CanonicalBytes(); err != nil || e.DeploymentID != did || e.ScopeID != sid || e.Kind != kind || e.ArtifactID != artifact || e.SourceSequence != seq || e.SourceHead != head || e.CheckedAt != at {
		return ErrProtocol
	}
	return e.VerifyGuard(d.Guard)
}
func (r Result) core() Result                { r.Version = Version2; r.Protection = nil; return r }
func (r Result) CoreID() (types.Hash, error) { return r.core().ID() }
func (r Result) protectedBytes() ([]byte, error) {
	b, e := r.core().CanonicalBytes()
	if e != nil {
		return nil, e
	}
	return protectedEncode("OMCVRES5", b, r.Protection)
}
func decodeProtectedResult(raw []byte) (Result, error) {
	b, effect, e := protectedDecode(raw, "OMCVRES5", MaximumResultBytes-gateway.MaximumEffectBytes-32)
	if e != nil {
		return Result{}, e
	}
	if len(b) < 10 || string(b[:8]) != "OMCVRES2" {
		return Result{}, ErrProtocol
	}
	r, e := DecodeResult(b)
	if e != nil || r.Version != Version2 {
		return Result{}, ErrProtocol
	}
	r.Version = ProtectedVersion
	r.Protection = effect
	return r, nil
}

// VerifyRetainedResultCore checks a previously signed session result for recovery
// inside the original guarded service. It is not protected result verification:
// Result.Verify still requires the complete independently sealed service effect.
// This neither authorizes execution nor creates a missing session signature.
func (r Result) VerifyRetainedResultCore(c Context, claim custodyfence.Certificate) error {
	if !ProtectedContext(c) || r.Version != Version2 || r.Protection != nil {
		return ErrProtocol
	}
	scope, err := c.Scope()
	if err != nil || scope.Guard == ([32]byte{}) {
		return ErrProtocol
	}
	return r.verifySessionResult(c, claim)
}

// SignResultSession signs the exact completed core record with its volatile
// winning session. A protected result still requires a separate service effect.
func SignResultSession(r Result, key ed25519.PrivateKey) (Result, error) {
	if !matches(key, r.SessionPublicKey) || r.Version != Version2 || r.Protection != nil {
		return Result{}, ErrSession
	}
	b, e := r.unsignedBytes()
	if e != nil {
		return Result{}, e
	}
	h := types.DomainHash("OMESH/custody/v2/result/session-signature", b)
	copy(r.SessionSignature[:], ed25519.Sign(key, h[:]))
	return r, nil
}
func (r Receipt) core() Receipt {
	r.Version = Version2
	r.Protection = nil
	r.RetainedAcceptance = nil
	return r
}
func (r Receipt) CoreID() (types.Hash, error) {
	id, e := r.core().ID()
	if e != nil || r.RetainedAcceptance == nil {
		return id, e
	}
	a, e := r.RetainedAcceptance.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v5/retained-accepted-source/core", id[:], a), nil
}
func (r Receipt) protectedBytes() ([]byte, error) {
	b, e := r.core().CanonicalBytes()
	if e != nil {
		return nil, e
	}
	if r.RetainedAcceptance == nil {
		return protectedEncode("OMCVACK5", b, r.Protection)
	}
	a, e := r.RetainedAcceptance.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	out := codec.NewEncoder(len(b) + len(a) + 8)
	out.BytesField(b)
	out.Fixed(a)
	return protectedEncode("OMCVLAC5", out.Bytes(), r.Protection)
}
func decodeProtectedReceipt(raw []byte) (Receipt, error) {
	late := len(raw) >= 8 && string(raw[:8]) == "OMCVLAC5"
	magic := "OMCVACK5"
	max := ReceiptBytes
	if late {
		magic = "OMCVLAC5"
		max += RetainedAcceptanceBytes + 8
	}
	b, ef, e := protectedDecode(raw, magic, max)
	if e != nil {
		return Receipt{}, e
	}
	var authorization *RetainedAcceptance
	if late {
		d := codec.NewDecoder(b)
		b, e = d.BytesField(ReceiptBytes)
		if e != nil {
			return Receipt{}, e
		}
		ab, e := d.Fixed(RetainedAcceptanceBytes)
		if e != nil || d.Finish() != nil {
			return Receipt{}, ErrProtocol
		}
		a, e := DecodeRetainedAcceptance(ab)
		if e != nil {
			return Receipt{}, e
		}
		authorization = &a
	}
	if len(b) != ReceiptBytes || string(b[:8]) != "OMCVACK2" {
		return Receipt{}, ErrProtocol
	}
	r, e := DecodeReceipt(b)
	if e != nil {
		return Receipt{}, e
	}
	r.Version = ProtectedVersion
	r.Protection = ef
	r.RetainedAcceptance = authorization
	again, e := r.CanonicalBytes()
	if e != nil || !bytes.Equal(raw, again) {
		return Receipt{}, ErrProtocol
	}
	return r, nil
}
func SignAcceptance(r Receipt, key ed25519.PrivateKey) (Receipt, error) {
	if r.Version != Version2 || r.Protection != nil || r.RetainedAcceptance != nil || !matches(key, r.Authority) {
		return Receipt{}, ErrProtocol
	}
	b, e := r.unsignedBytes()
	if e != nil {
		return Receipt{}, e
	}
	h := types.DomainHash("OMESH/custody/v2/accepted-source/signature", b)
	copy(r.Signature[:], ed25519.Sign(key, h[:]))
	return r, nil
}
func (r ServeReceipt) core() ServeReceipt          { r.Version = Version2; r.Protection = nil; return r }
func (r ServeReceipt) CoreID() (types.Hash, error) { return r.core().ID() }
func (r ServeReceipt) protectedBytes() ([]byte, error) {
	b, e := r.core().CanonicalBytes()
	if e != nil {
		return nil, e
	}
	return protectedEncode("OMCVSAC5", b, r.Protection)
}
func decodeProtectedServeReceipt(raw []byte) (ServeReceipt, error) {
	b, ef, e := protectedDecode(raw, "OMCVSAC5", ServeReceiptBytes)
	if e != nil {
		return ServeReceipt{}, e
	}
	if len(b) != ServeReceiptBytes || string(b[:8]) != "OMCVSAC2" {
		return ServeReceipt{}, ErrProtocol
	}
	r, e := DecodeServeReceipt(b)
	if e != nil {
		return ServeReceipt{}, e
	}
	r.Version = ProtectedVersion
	r.Protection = ef
	return r, nil
}
func SignServeApplication(r ServeReceipt, key ed25519.PrivateKey) (ServeReceipt, error) {
	if r.Version != Version2 || r.Protection != nil || !matches(key, r.Signer) {
		return ServeReceipt{}, ErrProtocol
	}
	b, e := r.unsignedBytes()
	if e != nil {
		return ServeReceipt{}, e
	}
	h := types.DomainHash("OMESH/custody/v2/serve/applied/signature", b)
	copy(r.Signature[:], ed25519.Sign(key, h[:]))
	return r, nil
}

// Full protected admission proof is checked at every live effect and retained.
func VerifyProtectedBinding(b AdmissionBinding, enrollment EnrollmentBinding, d gateway.Deployment) error {
	if len(b.Chain) == 0 {
		return ErrAdmissionRequired
	}
	c := b.Chain[len(b.Chain)-1].Entry.Context
	if VerifyDeploymentGenesis(b.Genesis, c) != nil || !ProtectedContext(c) || b.Verify(c) != nil || enrollment.VerifyImported(b.Genesis) != nil || d.Verify() != nil {
		return ErrAdmissionRequired
	}
	raw, _ := d.CanonicalBytes()
	want, _ := c.Plan.Deployment.CanonicalBytes()
	gid, _ := b.Genesis.ID()
	gdid, _ := b.Genesis.DescriptorID()
	eid, _ := enrollment.ID()
	if !bytes.Equal(raw, want) || d.GenesisID != gid || d.GenesisDescriptorID != gdid || d.EnrollmentID != eid || d.ImportID != c.Assignment.Policy.ImportID || d.Authority != c.Assignment.Base.AuthorityPublicKey || d.Control != c.Assignment.Base.RemoteControlPublicKey {
		return ErrAdmissionRequired
	}
	return nil
}

// ReplacementRoleAllowed prevents a successor from collapsing independently
// signed assignment, witness, service and transport roles into one key.
func ReplacementRoleAllowed(c Context, key [32]byte) bool {
	a := c.Assignment.Base
	roles := [][32]byte{a.AuthorityPublicKey, a.RemoteControlPublicKey, a.RemoteTransportPublicKey, a.ReplicaPublicKey, c.Plan.ServeConsumer, c.Plan.ClientTransportPublicKey}
	roles = append(roles, c.Assignment.Policy.Witnesses...)
	roles = append(roles, a.Auditors...)
	roles = append(roles, c.CustodyPolicy.TrustedAuditors...)
	for _, consumer := range a.Consumers {
		roles = append(roles, consumer.PublicKey)
	}
	if d := c.Plan.Deployment; d != nil {
		roles = append(roles, d.A.Issuer, d.B.Issuer, d.Authority, d.Control, d.Guard, d.A.Gateway, d.B.Gateway)
	}
	if key == ([32]byte{}) {
		return false
	}
	for _, role := range roles {
		if role == key {
			return false
		}
	}
	return true
}
