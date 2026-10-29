package custodyv2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	gateway "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
)

const ServeReceiptBytes = 10 + 1 + 4*32 + 3*8 + 32 + 64
const maximumServePendingBytes = MaximumServeCertificateBytes + ServeReceiptBytes + 32
const ServeAuthority uint8 = 1
const ServeTarget uint8 = 2

var ErrServePending = errors.New("Serve decision retained; exact explicit resume required")
var ErrServeClosed = errors.New("Serve decision already applied or pending; execution forbidden")

// ServeReceipt records one original local owner's settlement, never an archive
// deletion permission. B must retain A's applied receipt as well as its own.
type ServeReceipt struct {
	Protection                                     *gateway.Effect
	Version                                        uint16
	Role                                           uint8
	ScopeID, CertificateID, SourceHeadID, ParentID types.Hash
	SourceSequence, MinimumRetainUntil, AppliedAt  uint64
	Signer                                         [32]byte
	Signature                                      [64]byte
}

func (r ServeReceipt) unsignedBytes() ([]byte, error) {
	if r.Version != Version2 || (r.Role != ServeAuthority && r.Role != ServeTarget) || r.ScopeID.IsZero() || r.CertificateID.IsZero() || (r.SourceSequence > 0 && r.SourceHeadID.IsZero()) || r.MinimumRetainUntil == 0 || r.AppliedAt == 0 || types.Hash(r.Signer).IsZero() || (r.Role == ServeAuthority && !r.ParentID.IsZero()) || (r.Role == ServeTarget && r.ParentID.IsZero()) {
		return nil, ErrProtocol
	}
	e := codec.NewEncoder(ServeReceiptBytes)
	e.Fixed([]byte("OMCVSAC2"))
	e.U16(r.Version)
	e.U8(r.Role)
	for _, h := range []types.Hash{r.ScopeID, r.CertificateID, r.SourceHeadID, r.ParentID} {
		e.Fixed(h[:])
	}
	e.U64(r.SourceSequence)
	e.U64(r.MinimumRetainUntil)
	e.U64(r.AppliedAt)
	e.Fixed(r.Signer[:])
	return e.Bytes(), nil
}
func (r ServeReceipt) CanonicalBytes() ([]byte, error) {
	if r.Version == ProtectedVersion {
		return r.protectedBytes()
	}
	if r.Protection != nil {
		return nil, ErrProtocol
	}
	b, e := r.unsignedBytes()
	if e != nil {
		return nil, e
	}
	h := types.DomainHash("OMESH/custody/v2/serve/applied/signature", b)
	if !ed25519.Verify(r.Signer[:], h[:], r.Signature[:]) {
		return nil, ErrProtocol
	}
	return append(b, r.Signature[:]...), nil
}
func DecodeServeReceipt(b []byte) (ServeReceipt, error) {
	var r ServeReceipt
	if len(b) >= 8 && string(b[:8]) == "OMCVSAC5" {
		return decodeProtectedServeReceipt(b)
	}
	if len(b) != ServeReceiptBytes {
		return r, ErrProtocol
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVSAC2") {
		return r, ErrProtocol
	}
	r.Version, _ = d.U16()
	r.Role, _ = d.U8()
	for _, h := range [][]byte{r.ScopeID[:], r.CertificateID[:], r.SourceHeadID[:], r.ParentID[:]} {
		fixed(d, h)
	}
	r.SourceSequence, _ = d.U64()
	r.MinimumRetainUntil, _ = d.U64()
	r.AppliedAt, _ = d.U64()
	fixed(d, r.Signer[:])
	fixed(d, r.Signature[:])
	_, e := r.CanonicalBytes()
	return r, e
}
func (r ServeReceipt) ID() (types.Hash, error) {
	b, e := r.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	domain := "OMESH/custody/v2/serve/applied/id"
	if r.Version == ProtectedVersion {
		domain = "OMESH/custody/v5/serve/applied/id"
	}
	return types.DomainHash(domain, b), nil
}
func (r ServeReceipt) Verify(c Context, cert ServeCertificate, role uint8, parent *ServeReceipt) error {
	if ProtectedContext(c) {
		if r.Version != ProtectedVersion {
			return ErrProtocol
		}
		kind := gateway.EffectServeA
		if role == ServeTarget {
			kind = gateway.EffectServeB
		}
		id, e := r.CoreID()
		if e != nil || VerifyProtectedEffect(c, r.Protection, kind, id, r.SourceHeadID, r.SourceSequence, r.AppliedAt) != nil {
			return ErrProtocol
		}
	} else if r.Version != Version2 || r.Protection != nil {
		return ErrProtocol
	}

	if _, e := r.CanonicalBytes(); e != nil {
		return e
	}
	if e := cert.Verify(c); e != nil {
		return e
	}
	s, _ := c.Scope()
	sid, _ := s.ID()
	cid, _ := cert.ID()
	retain, _ := cert.Proposal.Retention(c)
	head, seq := c.Plan.Intent.PriorHeadID, c.Plan.Intent.PriorSequence
	if cert.Proposal.Outcome == ServeFulfilled {
		b, accepted, e := cert.Proposal.fulfilled()
		if e != nil || r.AppliedAt < accepted.AcceptedAt {
			return ErrProtocol
		}
		head, _ = b.Result.Entry.ID()
		seq = b.Result.Entry.Sequence
	}
	key := c.Assignment.Base.AuthorityPublicKey
	if role == ServeTarget {
		if parent == nil || parent.Verify(c, cert, ServeAuthority, nil) != nil {
			return ErrProtocol
		}
		pid, e := parent.ID()
		if e != nil || r.ParentID != pid || r.AppliedAt < parent.AppliedAt {
			return ErrProtocol
		}
		key = c.Assignment.Base.RemoteControlPublicKey
	} else if role != ServeAuthority || parent != nil {
		return ErrProtocol
	}
	if r.Role != role || r.ScopeID != sid || r.CertificateID != cid || r.SourceHeadID != head || r.SourceSequence != seq || r.MinimumRetainUntil != retain || r.Signer != key {
		return ErrProtocol
	}
	return nil
}

type servePending struct {
	Certificate ServeCertificate
	Parent      *ServeReceipt
	At          uint64
}

func (p servePending) bytes() ([]byte, error) {
	if p.At == 0 {
		return nil, ErrProtocol
	}
	b, e := p.Certificate.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	var parent []byte
	if p.Parent != nil {
		parent, e = p.Parent.CanonicalBytes()
		if e != nil {
			return nil, e
		}
	}
	out := codec.NewEncoder(len(b) + len(parent) + 32)
	out.Fixed([]byte("OMCVSPN2"))
	out.U16(Version2)
	out.U64(p.At)
	out.BytesField(b)
	out.BytesField(parent)
	return out.Bytes(), nil
}
func decodeServePending(b []byte) (servePending, error) {
	var p servePending
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVSPN2") {
		return p, ErrProtocol
	}
	v, _ := d.U16()
	p.At, _ = d.U64()
	if v != Version2 {
		return p, ErrProtocol
	}
	c, e := d.BytesField(MaximumServeCertificateBytes)
	if e != nil {
		return p, e
	}
	parent, e := d.BytesField(ServeReceiptBytes)
	if e != nil || d.Finish() != nil {
		return p, ErrProtocol
	}
	p.Certificate, e = DecodeServeCertificate(c)
	if e != nil {
		return p, e
	}
	if len(parent) != 0 {
		r, e := DecodeServeReceipt(parent)
		if e != nil {
			return p, e
		}
		p.Parent = &r
	}
	again, e := p.bytes()
	if e != nil || !bytes.Equal(b, again) {
		return servePending{}, ErrProtocol
	}
	return p, nil
}
func (r *root) servePending() (servePending, error) {
	b, e := readFile(filepath.Join(r.path, "serve.pending"), maximumServePendingBytes)
	if e != nil {
		return servePending{}, e
	}
	return decodeServePending(b)
}
func (r *root) serveReceipt() (ServeReceipt, error) {
	b, e := readFile(filepath.Join(r.path, "serve.settled"), ServeReceiptBytes)
	if e != nil {
		return ServeReceipt{}, e
	}
	return DecodeServeReceipt(b)
}
func (r *root) noServeAttempt() error {
	for _, n := range []string{"serve.pending", "serve.settled"} {
		if _, e := os.Lstat(filepath.Join(r.path, n)); e == nil {
			return ErrServeClosed
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	return nil
}

type serveCheck func(ServeProposal) error

func (a *Acceptor) checkServe(p ServeProposal) error {
	if p.Outcome == ServeFulfilled {
		b, receipt, e := p.fulfilled()
		if e != nil {
			return e
		}
		own, e := a.receipt()
		if e != nil || own != receipt {
			return errors.Join(ErrProtocol, e)
		}
		pending, _, e := a.pending()
		if e != nil {
			return e
		}
		expected, _ := b.ID()
		actual, _ := pending.ID()
		if actual != expected {
			return ErrProtocol
		}
		return requireEntry(a.r.decision, b.Result.Entry)
	}
	for _, n := range []string{"pending", "accepted"} {
		if _, e := os.Lstat(filepath.Join(a.r.path, n)); !errors.Is(e, os.ErrNotExist) {
			return errors.Join(ErrProtocol, e)
		}
	}
	state, e := a.r.decision.State()
	if e != nil || !atPredecessor(a.r.ctx, state) {
		return errors.Join(ErrProtocol, e)
	}
	return nil
}
func (t *Target) checkServe(p ServeProposal) error {
	if p.Outcome == ServeFulfilled {
		b, _, e := p.fulfilled()
		if e != nil {
			return e
		}
		own, e := t.readResultLocked()
		if e != nil {
			return e
		}
		expected, _ := b.Result.ID()
		actual, _ := own.ID()
		if expected != actual {
			return ErrProtocol
		}
		return requireEntry(t.r.decision, own.Entry)
	}
	for _, n := range []string{"consumed", "result"} {
		if _, e := os.Lstat(filepath.Join(t.r.path, n)); !errors.Is(e, os.ErrNotExist) {
			return errors.Join(ErrProtocol, e)
		}
	}
	state, e := t.r.decision.State()
	if e != nil || !atPredecessor(t.r.ctx, state) {
		return errors.Join(ErrProtocol, e)
	}
	return nil
}
func (r *root) validateServe(role uint8, check serveCheck) error {
	p, e := r.servePending()
	if errors.Is(e, os.ErrNotExist) {
		if _, e := os.Lstat(filepath.Join(r.path, "serve.settled")); !errors.Is(e, os.ErrNotExist) {
			return ErrProtocol
		}
		return nil
	}
	if e != nil {
		return e
	}
	if e := p.Certificate.Verify(r.ctx); e != nil {
		return e
	}
	if e := check(p.Certificate.Proposal); e != nil {
		return e
	}
	want := r.makeServeReceipt(p, role)
	if e := want.validateUnsigned(r.ctx, p.Certificate, role, p.Parent); e != nil {
		return e
	}
	receipt, e := r.serveReceipt()
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if receipt.AppliedAt != p.At {
		return ErrProtocol
	}
	return receipt.Verify(r.ctx, p.Certificate, role, p.Parent)
}

// validateUnsigned checks a locally constructed receipt before signing it.
func (r ServeReceipt) validateUnsigned(c Context, cert ServeCertificate, role uint8, parent *ServeReceipt) error {
	if _, e := r.unsignedBytes(); e != nil {
		return e
	}
	if role == ServeAuthority {
		if parent != nil {
			return ErrProtocol
		}
	} else if role == ServeTarget {
		if parent == nil || parent.Verify(c, cert, ServeAuthority, nil) != nil || r.AppliedAt < parent.AppliedAt {
			return ErrProtocol
		}
	} else {
		return ErrProtocol
	}
	if cert.Proposal.Outcome == ServeFulfilled {
		_, accepted, e := cert.Proposal.fulfilled()
		if e != nil || r.AppliedAt < accepted.AcceptedAt {
			return ErrProtocol
		}
	}
	return nil
}
func (r *root) makeServeReceipt(p servePending, role uint8) ServeReceipt {
	id, _ := p.Certificate.ID()
	retain, _ := p.Certificate.Proposal.Retention(r.ctx)
	receipt := ServeReceipt{Version: Version2, Role: role, ScopeID: r.scopeID, CertificateID: id, SourceHeadID: r.ctx.Plan.Intent.PriorHeadID, SourceSequence: r.ctx.Plan.Intent.PriorSequence, MinimumRetainUntil: retain, AppliedAt: p.At, Signer: r.ctx.Assignment.Base.AuthorityPublicKey}
	if p.Certificate.Proposal.Outcome == ServeFulfilled {
		b, _, _ := p.Certificate.Proposal.fulfilled()
		receipt.SourceHeadID, _ = b.Result.Entry.ID()
		receipt.SourceSequence = b.Result.Entry.Sequence
	}
	if role == ServeTarget {
		receipt.Signer = r.ctx.Assignment.Base.RemoteControlPublicKey
		if p.Parent != nil {
			receipt.ParentID, _ = p.Parent.ID()
		}
	}
	return receipt
}
func (r *root) applyServe(ctx context.Context, cert ServeCertificate, parent *ServeReceipt, now uint64, role uint8, key ed25519.PrivateKey, check serveCheck, resume bool) (ServeReceipt, error) {
	if ctx == nil {
		return ServeReceipt{}, ErrProtocol
	}
	if e := ctx.Err(); e != nil {
		return ServeReceipt{}, e
	}
	b, e := cert.CanonicalBytes()
	if e != nil {
		return ServeReceipt{}, e
	}
	cert, e = DecodeServeCertificate(b)
	if e != nil {
		return ServeReceipt{}, e
	}
	if parent != nil {
		copyParent := *parent
		parent = &copyParent
	}
	if e := r.check(); e != nil {
		return ServeReceipt{}, e
	}
	if e := cert.Verify(r.ctx); e != nil {
		return ServeReceipt{}, e
	}
	if e := check(cert.Proposal); e != nil {
		return ServeReceipt{}, e
	}
	p := servePending{Certificate: cert, Parent: parent, At: now}
	want := r.makeServeReceipt(p, role)
	if e := want.validateUnsigned(r.ctx, cert, role, parent); e != nil {
		return ServeReceipt{}, e
	}
	old, e := r.servePending()
	if e == nil {
		oldID, _ := old.Certificate.ID()
		id, _ := cert.ID()
		parentID := types.Hash{}
		if parent != nil {
			parentID, _ = parent.ID()
		}
		oldParent := types.Hash{}
		if old.Parent != nil {
			oldParent, _ = old.Parent.ID()
		}
		if id != oldID || parentID != oldParent {
			return ServeReceipt{}, ErrServePending
		}
		p = old
		receipt, e := r.serveReceipt()
		if e == nil {
			return receipt, receipt.Verify(r.ctx, cert, role, parent)
		}
		if !errors.Is(e, os.ErrNotExist) {
			return ServeReceipt{}, e
		}
		if !resume {
			return ServeReceipt{}, ErrServePending
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return ServeReceipt{}, e
	} else {
		if resume {
			return ServeReceipt{}, ErrServePending
		}
		raw, e := p.bytes()
		if e != nil {
			return ServeReceipt{}, e
		}
		if e := r.write("serve.pending", raw); e != nil {
			return ServeReceipt{}, e
		}
	}
	if e := ctx.Err(); e != nil {
		return ServeReceipt{}, e
	}
	if e := check(p.Certificate.Proposal); e != nil {
		return ServeReceipt{}, e
	}
	receipt := r.makeServeReceipt(p, role)
	raw, e := receipt.unsignedBytes()
	if e != nil {
		return ServeReceipt{}, e
	}
	h := types.DomainHash("OMESH/custody/v2/serve/applied/signature", raw)
	copy(receipt.Signature[:], ed25519.Sign(key, h[:]))
	if e := receipt.Verify(r.ctx, p.Certificate, role, p.Parent); e != nil {
		return ServeReceipt{}, e
	}
	raw, _ = receipt.CanonicalBytes()
	if e := r.write("serve.settled", raw); e != nil {
		return ServeReceipt{}, e
	}
	return receipt, nil
}
func (a *Acceptor) ApplyServe(ctx context.Context, cert ServeCertificate, now uint64, resume bool) (ServeReceipt, error) {
	a.r.mu.Lock()
	defer a.r.mu.Unlock()
	return a.r.applyServe(ctx, cert, nil, now, ServeAuthority, a.authority, a.checkServe, resume)
}
func (t *Target) ApplyServe(ctx context.Context, cert ServeCertificate, parent ServeReceipt, now uint64, resume bool) (ServeReceipt, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	r, e := t.r.applyServe(ctx, cert, &parent, now, ServeTarget, t.control, t.checkServe, resume)
	if e == nil || t.r.noServeAttempt() != nil {
		clear(t.session)
		t.candidate = nil
	}
	return r, e
}

type ServeStatus struct {
	Pending              bool
	AttemptID, ReceiptID types.Hash
	MinimumRetainUntil   uint64
	ArchiveHeld          bool
}

func (r *root) serveStatus(role uint8, check serveCheck) (ServeStatus, error) {
	state := ServeStatus{Pending: true, MinimumRetainUntil: r.ctx.Previous.RetainUntil, ArchiveHeld: true}
	if e := r.check(); e != nil {
		return state, e
	}
	if e := r.validateServe(role, check); e != nil {
		return state, e
	}
	source, e := r.decision.State()
	if e != nil {
		return state, e
	}
	state.MinimumRetainUntil = max(state.MinimumRetainUntil, source.CurrentReceipt.RetainUntil)
	p, e := r.servePending()
	if errors.Is(e, os.ErrNotExist) {
		return state, nil
	}
	if e != nil {
		return state, e
	}
	state.AttemptID, _ = p.Certificate.ID()
	state.MinimumRetainUntil, _ = p.Certificate.Proposal.Retention(r.ctx)
	receipt, e := r.serveReceipt()
	if errors.Is(e, os.ErrNotExist) {
		return state, nil
	}
	if e != nil {
		return state, e
	}
	state.ReceiptID, _ = receipt.ID()
	state.Pending = false
	return state, nil
}
func (a *Acceptor) ServeStatus() (ServeStatus, error) {
	a.r.mu.Lock()
	defer a.r.mu.Unlock()
	return a.r.serveStatus(ServeAuthority, a.checkServe)
}
func (t *Target) ServeStatus() (ServeStatus, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	return t.r.serveStatus(ServeTarget, t.checkServe)
}
