package custodyv2

import (
	"bytes"
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	gateway "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
)

const ProtectedVersion uint16 = 5
const MaximumProtectedReceiptBytes = ReceiptBytes + gateway.EffectBytes + 32
const MaximumProtectedServeReceiptBytes = ServeReceiptBytes + gateway.EffectBytes + 32

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
	if len(raw) > max+gateway.EffectBytes+32 {
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
	eb, e := d.Fixed(gateway.EffectBytes)
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
	if _, err = e.CanonicalBytes(); err != nil || e.DeploymentID != did || e.ScopeID != sid || e.Kind != kind || e.ArtifactID != artifact || e.SourceSequence != seq || e.SourceHead != head || e.CheckedAt != at || e.Signer != key {
		return ErrProtocol
	}
	return nil
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
	b, effect, e := protectedDecode(raw, "OMCVRES5", MaximumResultBytes-gateway.EffectBytes-32)
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
func (r Receipt) core() Receipt               { r.Version = Version2; r.Protection = nil; return r }
func (r Receipt) CoreID() (types.Hash, error) { return r.core().ID() }
func (r Receipt) protectedBytes() ([]byte, error) {
	b, e := r.core().CanonicalBytes()
	if e != nil {
		return nil, e
	}
	return protectedEncode("OMCVACK5", b, r.Protection)
}
func decodeProtectedReceipt(raw []byte) (Receipt, error) {
	b, ef, e := protectedDecode(raw, "OMCVACK5", ReceiptBytes)
	if e != nil {
		return Receipt{}, e
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
	return r, nil
}
func SignAcceptance(r Receipt, key ed25519.PrivateKey) (Receipt, error) {
	if r.Version != Version2 || r.Protection != nil || !matches(key, r.Authority) {
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
