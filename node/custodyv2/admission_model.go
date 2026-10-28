package custodyv2

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const MaximumAdmissionGenesisBytes = MaximumAssignmentBytes + workarchive.MaximumManifestBytes + workarchive.MaximumReplicaReceiptBytes + 4096
const MaximumAdmissionClosureBytes = MaximumServeCertificateBytes + 2*ServeReceiptBytes + 32
const MaximumAdmissionEntryBytes = MaximumContextBytes + MaximumAdmissionClosureBytes + 256
const AdmissionVoteBytes = 10 + 2*32 + 64
const MaximumAdmissionCertificateBytes = MaximumAdmissionEntryBytes + custodyfence.MaximumWitnesses*AdmissionVoteBytes + 32

var ErrAdmission = errors.New("invalid custody V2 assignment admission or closure")
var ErrAdmissionHead = errors.New("custody V2 admission position differs")
var ErrAdmissionBudget = errors.New("custody V2 assignment operation budget exhausted")
var ErrAdmissionActive = errors.New("custody V2 assignment still has an active job")

// AdmissionGenesis pins the public source and limits for one assignment-wide
// coordinator. This does not activate admission in existing raw V2 runtimes.
// Enrollment and original source ownership remain separate deployment duties.
type AdmissionGenesis struct {
	Version       uint16
	Assignment    Assignment
	Manifest      workarchive.Manifest
	Initial       workarchive.ReplicaReceipt
	CustodyPolicy workarchive.CustodyPolicy
}

func NewAdmissionGenesis(c Context) (AdmissionGenesis, error) {
	if e := c.Validate(); e != nil {
		return AdmissionGenesis{}, e
	}
	if c.Plan.Intent.PriorSequence != 0 || !c.Plan.Intent.PriorHeadID.IsZero() || c.Previous != c.Initial {
		return AdmissionGenesis{}, ErrAdmission
	}
	g := AdmissionGenesis{Version: Version2, Assignment: c.Assignment, Manifest: c.Manifest, Initial: c.Initial, CustodyPolicy: c.CustodyPolicy}
	b, e := g.CanonicalBytes()
	if e != nil {
		return AdmissionGenesis{}, e
	}
	return DecodeAdmissionGenesis(b)
}
func (g AdmissionGenesis) Validate() error {
	if g.Version != Version2 || len(g.CustodyPolicy.TrustedAuditors) > 64 {
		return ErrAdmission
	}
	if _, e := g.Assignment.CanonicalBytes(); e != nil {
		return e
	}
	a := g.Assignment.Base
	derived, e := workarchive.CreateRemoteCustodyAuthorityAssignment(g.Manifest, g.Initial, g.CustodyPolicy, a.IncarnationID, a.AuthorityPublicKey, a.Consumers, a.MaximumOperations, a.MaximumPending, a.RemoteControlPublicKey, a.RemoteTransportPublicKey)
	if e != nil {
		return e
	}
	want, _ := a.ID()
	got, _ := derived.ID()
	if want != got {
		return ErrAdmission
	}
	return nil
}
func (g AdmissionGenesis) CanonicalBytes() ([]byte, error) {
	if e := g.Validate(); e != nil {
		return nil, e
	}
	e := codec.NewEncoder(4096)
	e.Fixed([]byte("OMCVAGN2"))
	e.U16(g.Version)
	for _, v := range []interface{ CanonicalBytes() ([]byte, error) }{g.Assignment, g.Manifest, g.Initial} {
		b, err := v.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		e.BytesField(b)
	}
	e.U64(g.CustodyPolicy.MaximumChallengeLifetime)
	e.U64(g.CustodyPolicy.MaximumProofAge)
	e.U64(g.CustodyPolicy.MaximumRenewalTerm)
	e.U16(uint16(len(g.CustodyPolicy.TrustedAuditors)))
	for _, key := range g.CustodyPolicy.TrustedAuditors {
		e.Fixed(key[:])
	}
	b := e.Bytes()
	if len(b) > MaximumAdmissionGenesisBytes {
		return nil, ErrAdmission
	}
	return b, nil
}
func DecodeAdmissionGenesis(b []byte) (AdmissionGenesis, error) {
	var g AdmissionGenesis
	if len(b) > MaximumAdmissionGenesisBytes {
		return g, ErrAdmission
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVAGN2") {
		return g, ErrAdmission
	}
	g.Version, _ = d.U16()
	values := make([][]byte, 3)
	for i, max := range []uint64{MaximumAssignmentBytes, workarchive.MaximumManifestBytes, workarchive.MaximumReplicaReceiptBytes} {
		v, e := d.BytesField(max)
		if e != nil {
			return g, e
		}
		values[i] = v
	}
	var e error
	g.Assignment, e = DecodeAssignment(values[0])
	if e != nil {
		return g, e
	}
	g.Manifest, e = workarchive.DecodeManifest(values[1])
	if e != nil {
		return g, e
	}
	g.Initial, e = workarchive.DecodeReplicaReceipt(values[2])
	if e != nil {
		return g, e
	}
	g.CustodyPolicy.MaximumChallengeLifetime, _ = d.U64()
	g.CustodyPolicy.MaximumProofAge, _ = d.U64()
	g.CustodyPolicy.MaximumRenewalTerm, _ = d.U64()
	n, e := d.U16()
	if e != nil || n > 64 || d.Remaining() != int(n)*32 {
		return AdmissionGenesis{}, ErrAdmission
	}
	g.CustodyPolicy.TrustedAuditors = make([][32]byte, n)
	for i := range g.CustodyPolicy.TrustedAuditors {
		fixed(d, g.CustodyPolicy.TrustedAuditors[i][:])
	}
	again, e := g.CanonicalBytes()
	if e != nil || !bytes.Equal(b, again) {
		return AdmissionGenesis{}, ErrAdmission
	}
	return g, nil
}

// ID depends only on the outer assignment. Alternate descriptor enrollments
// cannot select another budget namespace for the same assignment. Operators
// retain DescriptorID separately and protect the one enrollment/history.
func (g AdmissionGenesis) ID() (types.Hash, error) {
	if e := g.Validate(); e != nil {
		return types.Hash{}, e
	}
	aid, e := g.Assignment.ID()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/admission/genesis/id", aid[:]), nil
}
func (g AdmissionGenesis) DescriptorID() (types.Hash, error) {
	b, e := g.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/admission/genesis/descriptor", b), nil
}

// MaxAdmissionEntries preserves room for every admitted close even when new
// admission exhausts the two-units-per-job operation budget. Two spare slots
// reserve future terminal capacity; no Stop/Retire transition exists here.
func MaxAdmissionEntries(g AdmissionGenesis) uint64 {
	if g.Version != Version2 || g.Assignment.Version != Version2 {
		return 0
	}
	return uint64(g.Assignment.Base.MaximumOperations) + 2
}

type AdmissionKind uint8

const (
	AdmissionAdmit AdmissionKind = 1 + iota
	AdmissionClose
)

// AdmissionClosure is complete historical evidence for accounting closure. It
// does not establish current source ownership. The future mandatory execution
// adapter must also check its original owner/source before granting any effect.
type AdmissionClosure struct {
	Serve ServeCertificate
	A, B  ServeReceipt
}

func (c AdmissionClosure) Verify(ctx Context) error {
	if e := c.Serve.Verify(ctx); e != nil {
		return e
	}
	if e := c.A.Verify(ctx, c.Serve, ServeAuthority, nil); e != nil {
		return e
	}
	return c.B.Verify(ctx, c.Serve, ServeTarget, &c.A)
}
func (c AdmissionClosure) CanonicalBytes() ([]byte, error) {
	s, e := c.Serve.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	a, e := c.A.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	b, e := c.B.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	out := codec.NewEncoder(len(s) + 2*ServeReceiptBytes + 32)
	out.Fixed([]byte("OMCVACL2"))
	out.U16(Version2)
	out.BytesField(s)
	out.Fixed(a)
	out.Fixed(b)
	return out.Bytes(), nil
}
func DecodeAdmissionClosure(b []byte) (AdmissionClosure, error) {
	var c AdmissionClosure
	if len(b) > MaximumAdmissionClosureBytes {
		return c, ErrAdmission
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVACL2") {
		return c, ErrAdmission
	}
	v, _ := d.U16()
	if v != Version2 {
		return c, ErrAdmission
	}
	s, e := d.BytesField(MaximumServeCertificateBytes)
	if e != nil {
		return c, e
	}
	a, e := d.Fixed(ServeReceiptBytes)
	if e != nil {
		return c, e
	}
	rb, e := d.Fixed(ServeReceiptBytes)
	if e != nil || d.Finish() != nil {
		return c, ErrAdmission
	}
	c.Serve, e = DecodeServeCertificate(s)
	if e != nil {
		return c, e
	}
	c.A, e = DecodeServeReceipt(a)
	if e != nil {
		return c, e
	}
	c.B, e = DecodeServeReceipt(rb)
	if e != nil {
		return c, e
	}
	again, e := c.CanonicalBytes()
	if e != nil || !bytes.Equal(b, again) {
		return AdmissionClosure{}, ErrAdmission
	}
	return c, nil
}

type AdmissionEntry struct {
	Version            uint16
	GenesisID          types.Hash
	ExpectedSequence   uint64
	ExpectedHead       types.Hash
	Kind               AdmissionKind
	Context            Context
	Closure            *AdmissionClosure
	AuthoritySignature [64]byte
}

func (e AdmissionEntry) unsignedBytes() ([]byte, error) {
	if e.Version != Version2 || e.GenesisID.IsZero() || e.ExpectedHead.IsZero() || (e.Kind != AdmissionAdmit && e.Kind != AdmissionClose) || (e.Kind == AdmissionAdmit && e.Closure != nil) || (e.Kind == AdmissionClose && e.Closure == nil) {
		return nil, ErrAdmission
	}
	c, err := e.Context.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	var closure []byte
	if e.Closure != nil {
		closure, err = e.Closure.CanonicalBytes()
		if err != nil {
			return nil, err
		}
	}
	out := codec.NewEncoder(len(c) + len(closure) + 128)
	out.Fixed([]byte("OMCVAEN2"))
	out.U16(e.Version)
	out.Fixed(e.GenesisID[:])
	out.U64(e.ExpectedSequence)
	out.Fixed(e.ExpectedHead[:])
	out.U8(uint8(e.Kind))
	out.BytesField(c)
	out.BytesField(closure)
	b := out.Bytes()
	if len(b)+64 > MaximumAdmissionEntryBytes {
		return nil, ErrAdmission
	}
	return b, nil
}
func (e AdmissionEntry) CanonicalBytes() ([]byte, error) {
	b, err := e.unsignedBytes()
	if err != nil {
		return nil, err
	}
	return append(b, e.AuthoritySignature[:]...), nil
}
func DecodeAdmissionEntry(b []byte) (AdmissionEntry, error) {
	var e AdmissionEntry
	if len(b) > MaximumAdmissionEntryBytes {
		return e, ErrAdmission
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVAEN2") {
		return e, ErrAdmission
	}
	e.Version, _ = d.U16()
	fixed(d, e.GenesisID[:])
	e.ExpectedSequence, _ = d.U64()
	fixed(d, e.ExpectedHead[:])
	kind, _ := d.U8()
	e.Kind = AdmissionKind(kind)
	c, err := d.BytesField(MaximumContextBytes)
	if err != nil {
		return e, err
	}
	closure, err := d.BytesField(MaximumAdmissionClosureBytes)
	if err != nil {
		return e, err
	}
	e.Context, err = DecodeContext(c)
	if err != nil {
		return e, err
	}
	if len(closure) != 0 {
		cl, err := DecodeAdmissionClosure(closure)
		if err != nil {
			return e, err
		}
		e.Closure = &cl
	}
	fixed(d, e.AuthoritySignature[:])
	again, err := e.CanonicalBytes()
	if err != nil || d.Finish() != nil || !bytes.Equal(b, again) {
		return AdmissionEntry{}, ErrAdmission
	}
	return e, nil
}
func (e AdmissionEntry) ID() (types.Hash, error) {
	b, err := e.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody/v2/admission/entry/id", b), nil
}
func (e AdmissionEntry) validateUnsigned(g AdmissionGenesis) error {
	if _, err := e.unsignedBytes(); err != nil {
		return err
	}
	id, err := g.ID()
	if err != nil || id != e.GenesisID || e.ExpectedSequence >= MaxAdmissionEntries(g) {
		return ErrAdmission
	}
	aid, _ := g.Assignment.ID()
	actual, _ := e.Context.Assignment.ID()
	if aid != actual {
		return ErrAdmission
	}
	gb, err := g.CanonicalBytes()
	if err != nil {
		return err
	}
	derived := AdmissionGenesis{Version: Version2, Assignment: e.Context.Assignment, Manifest: e.Context.Manifest, Initial: e.Context.Initial, CustodyPolicy: e.Context.CustodyPolicy}
	cb, err := derived.CanonicalBytes()
	if err != nil || !bytes.Equal(gb, cb) {
		return ErrAdmission
	}
	if e.Closure != nil {
		return e.Closure.Verify(e.Context)
	}
	return nil
}

// ValidateDraft verifies all public bindings before an authority seed is loaded.
func (e AdmissionEntry) ValidateDraft(g AdmissionGenesis) error { return e.validateUnsigned(g) }

func (e AdmissionEntry) Sign(g AdmissionGenesis, key ed25519.PrivateKey) (AdmissionEntry, error) {
	if !matches(key, g.Assignment.Base.AuthorityPublicKey) {
		return AdmissionEntry{}, ErrAdmission
	}
	if err := e.validateUnsigned(g); err != nil {
		return AdmissionEntry{}, err
	}
	b, _ := e.unsignedBytes()
	h := types.DomainHash("OMESH/custody/v2/admission/entry/signature", b)
	copy(e.AuthoritySignature[:], ed25519.Sign(key, h[:]))
	return e, nil
}
func (e AdmissionEntry) Verify(g AdmissionGenesis) error {
	if err := e.validateUnsigned(g); err != nil {
		return err
	}
	b, _ := e.unsignedBytes()
	h := types.DomainHash("OMESH/custody/v2/admission/entry/signature", b)
	k := g.Assignment.Base.AuthorityPublicKey
	if !ed25519.Verify(k[:], h[:], e.AuthoritySignature[:]) {
		return ErrAdmission
	}
	return nil
}

type AdmissionVote struct {
	Version   uint16
	EntryID   types.Hash
	Witness   [32]byte
	Signature [64]byte
}

func (v AdmissionVote) unsignedBytes() ([]byte, error) {
	if v.Version != Version2 || v.EntryID.IsZero() || types.Hash(v.Witness).IsZero() {
		return nil, ErrAdmission
	}
	e := codec.NewEncoder(AdmissionVoteBytes)
	e.Fixed([]byte("OMCVAVT2"))
	e.U16(v.Version)
	e.Fixed(v.EntryID[:])
	e.Fixed(v.Witness[:])
	return e.Bytes(), nil
}
func (v AdmissionVote) CanonicalBytes() ([]byte, error) {
	b, e := v.unsignedBytes()
	if e != nil {
		return nil, e
	}
	h := types.DomainHash("OMESH/custody/v2/admission/vote/signature", b)
	if !ed25519.Verify(v.Witness[:], h[:], v.Signature[:]) {
		return nil, ErrAdmission
	}
	return append(b, v.Signature[:]...), nil
}
func DecodeAdmissionVote(b []byte) (AdmissionVote, error) {
	var v AdmissionVote
	if len(b) != AdmissionVoteBytes {
		return v, ErrAdmission
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVAVT2") {
		return v, ErrAdmission
	}
	v.Version, _ = d.U16()
	fixed(d, v.EntryID[:])
	fixed(d, v.Witness[:])
	fixed(d, v.Signature[:])
	_, e := v.CanonicalBytes()
	return v, e
}

// signAdmissionVote is private: the durable assignment witness adapter must
// publish the complete verified proposal lock before calling this function.
func signAdmissionVote(e AdmissionEntry, key ed25519.PrivateKey) (AdmissionVote, error) {
	if !validKey(key) {
		return AdmissionVote{}, ErrAdmission
	}
	id, err := e.ID()
	if err != nil {
		return AdmissionVote{}, err
	}
	v := AdmissionVote{Version: Version2, EntryID: id}
	copy(v.Witness[:], key.Public().(ed25519.PublicKey))
	b, _ := v.unsignedBytes()
	h := types.DomainHash("OMESH/custody/v2/admission/vote/signature", b)
	copy(v.Signature[:], ed25519.Sign(key, h[:]))
	return v, nil
}

type AdmissionCertificate struct {
	Version uint16
	Entry   AdmissionEntry
	Votes   []AdmissionVote
}

func (c AdmissionCertificate) CanonicalBytes() ([]byte, error) {
	if c.Version != Version2 || c.Entry.Version != Version2 || len(c.Votes) == 0 || len(c.Votes) > custodyfence.MaximumWitnesses {
		return nil, ErrAdmission
	}
	b, e := c.Entry.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	id, _ := c.Entry.ID()
	out := codec.NewEncoder(len(b) + len(c.Votes)*AdmissionVoteBytes + 32)
	out.Fixed([]byte("OMCVAQC2"))
	out.U16(c.Version)
	out.BytesField(b)
	out.U8(uint8(len(c.Votes)))
	for i, v := range c.Votes {
		if v.Version != c.Version || v.EntryID != id || (i > 0 && bytes.Compare(c.Votes[i-1].Witness[:], v.Witness[:]) >= 0) {
			return nil, ErrAdmission
		}
		b, e := v.CanonicalBytes()
		if e != nil {
			return nil, e
		}
		out.Fixed(b)
	}
	return out.Bytes(), nil
}
func DecodeAdmissionCertificate(b []byte) (AdmissionCertificate, error) {
	var c AdmissionCertificate
	if len(b) > MaximumAdmissionCertificateBytes {
		return c, ErrAdmission
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVAQC2") {
		return c, ErrAdmission
	}
	c.Version, _ = d.U16()
	raw, e := d.BytesField(MaximumAdmissionEntryBytes)
	if e != nil {
		return c, e
	}
	c.Entry, e = DecodeAdmissionEntry(raw)
	if e != nil {
		return c, e
	}
	n, e := d.U8()
	if e != nil || n == 0 || n > custodyfence.MaximumWitnesses || d.Remaining() != int(n)*AdmissionVoteBytes {
		return c, ErrAdmission
	}
	c.Votes = make([]AdmissionVote, n)
	for i := range c.Votes {
		b, _ := d.Fixed(AdmissionVoteBytes)
		c.Votes[i], e = DecodeAdmissionVote(b)
		if e != nil {
			return c, e
		}
	}
	again, e := c.CanonicalBytes()
	if e != nil || !bytes.Equal(b, again) {
		return AdmissionCertificate{}, ErrAdmission
	}
	return c, nil
}
func (c AdmissionCertificate) ID() (types.Hash, error) {
	b, e := c.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/admission/certificate/id", b), nil
}
func (c AdmissionCertificate) Verify(g AdmissionGenesis) error {
	if _, e := c.CanonicalBytes(); e != nil {
		return e
	}
	if e := c.Entry.Verify(g); e != nil {
		return e
	}
	if len(c.Votes) < int(g.Assignment.Policy.Threshold) {
		return ErrAdmission
	}
	for _, v := range c.Votes {
		found := false
		for _, key := range g.Assignment.Policy.Witnesses {
			if key == v.Witness {
				found = true
				break
			}
		}
		if !found {
			return ErrAdmission
		}
	}
	return nil
}
