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
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const ReceiptBytes = 10 + 6*32 + 16 + 32 + 64

var ErrPending = errors.New("custody V2 acceptance attempt is retained; explicit exact resume required")

type Receipt struct {
	Version                                                         uint16
	AssignmentID, PlanID, ScopeID, ResultID, BundleID, SourceHeadID types.Hash
	SourceSequence, AcceptedAt                                      uint64
	Authority                                                       [32]byte
	Signature                                                       [64]byte
}

func (r Receipt) unsignedBytes() ([]byte, error) {
	if r.Version != Version2 || r.AssignmentID.IsZero() || r.PlanID.IsZero() || r.ScopeID.IsZero() || r.ResultID.IsZero() || r.BundleID.IsZero() || r.SourceHeadID.IsZero() || r.SourceSequence == 0 || r.AcceptedAt == 0 || types.Hash(r.Authority).IsZero() {
		return nil, ErrProtocol
	}
	e := codec.NewEncoder(ReceiptBytes)
	e.Fixed([]byte("OMCVACK2"))
	e.U16(r.Version)
	for _, id := range []types.Hash{r.AssignmentID, r.PlanID, r.ScopeID, r.ResultID, r.BundleID, r.SourceHeadID} {
		e.Fixed(id[:])
	}
	e.U64(r.SourceSequence)
	e.U64(r.AcceptedAt)
	e.Fixed(r.Authority[:])
	return e.Bytes(), nil
}
func (r Receipt) CanonicalBytes() ([]byte, error) {
	b, e := r.unsignedBytes()
	if e != nil {
		return nil, e
	}
	h := types.DomainHash("OMESH/custody/v2/accepted-source/signature", b)
	if !ed25519.Verify(r.Authority[:], h[:], r.Signature[:]) {
		return nil, ErrProtocol
	}
	return append(b, r.Signature[:]...), nil
}
func DecodeReceipt(b []byte) (Receipt, error) {
	var r Receipt
	if len(b) != ReceiptBytes {
		return r, ErrProtocol
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVACK2") {
		return r, ErrProtocol
	}
	r.Version, _ = d.U16()
	for _, id := range [][]byte{r.AssignmentID[:], r.PlanID[:], r.ScopeID[:], r.ResultID[:], r.BundleID[:], r.SourceHeadID[:]} {
		fixed(d, id)
	}
	r.SourceSequence, _ = d.U64()
	r.AcceptedAt, _ = d.U64()
	fixed(d, r.Authority[:])
	fixed(d, r.Signature[:])
	if _, e := r.CanonicalBytes(); e != nil {
		return Receipt{}, e
	}
	return r, nil
}
func (r Receipt) ID() (types.Hash, error) {
	b, e := r.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/accepted-source/id", b), nil
}

// Verify is historical: its AcceptedAt is the original checked time, never a
// refreshed proof time or a caller's current live permission.
func (r Receipt) Verify(c Context, b Bundle) error {
	if _, e := r.CanonicalBytes(); e != nil {
		return e
	}
	if e := b.Verify(c); e != nil {
		return e
	}
	aid, _ := c.Assignment.ID()
	pid, _ := c.Plan.ID()
	bid, _ := b.ID()
	rid, _ := b.Result.ID()
	eid, _ := b.Result.Entry.ID()
	if r.AssignmentID != aid || r.PlanID != pid || r.ScopeID != b.Result.ScopeID || r.ResultID != rid || r.BundleID != bid || r.SourceHeadID != eid || r.SourceSequence != c.Plan.Intent.PriorSequence+1 || r.Authority != c.Assignment.Base.AuthorityPublicKey {
		return ErrProtocol
	}
	return fresh(c, b.Result, r.AcceptedAt)
}
func fresh(c Context, r Result, now uint64) error {
	return workarchive.VerifyCustodyResponse(c.Manifest, c.Previous, c.Plan.Challenge, r.Entry.Record.Batch, r.Entry.Record.Proof, c.CustodyPolicy, now)
}

type Acceptor struct {
	r         *root
	authority ed25519.PrivateKey
}

func CreateAcceptor(path string, c Context, pin types.Hash, journal string) error {
	return createRoot(path, c, pin, "acceptor", Sources{Journal: journal})
}
func OpenAcceptor(path string, c Context, pin types.Hash, journal string, key ed25519.PrivateKey) (a *Acceptor, returnErr error) {
	if !matches(key, c.Assignment.Base.AuthorityPublicKey) {
		return nil, ErrProtocol
	}
	r, e := openRoot(path, c, pin, "acceptor", Sources{Journal: journal})
	if e != nil {
		return nil, e
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, r.close())
		}
	}()
	a = &Acceptor{r: r, authority: append(ed25519.PrivateKey(nil), key...)}
	if e := a.validateRetained(); e != nil {
		return nil, e
	}
	if e := a.r.validateServe(ServeAuthority, a.checkServe); e != nil {
		return nil, e
	}
	return a, a.r.stabilize()
}
func (a *Acceptor) Close() error {
	a.r.mu.Lock()
	clear(a.authority)
	a.r.mu.Unlock()
	return a.r.close()
}
func (a *Acceptor) Accept(ctx context.Context, b Bundle, now uint64) (Receipt, error) {
	raw, e := b.CanonicalBytes()
	if e != nil {
		return Receipt{}, e
	}
	b, e = DecodeBundle(raw)
	if e != nil {
		return Receipt{}, e
	}
	a.r.mu.Lock()
	defer a.r.mu.Unlock()
	if e := a.r.check(); e != nil {
		return Receipt{}, e
	}
	if e := b.Verify(a.r.ctx); e != nil {
		return Receipt{}, e
	}
	if existing, e := a.receipt(); e == nil {
		if existing.Verify(a.r.ctx, b) != nil {
			return Receipt{}, ErrProtocol
		}
		return existing, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return Receipt{}, e
	}
	if e := a.r.noServeAttempt(); e != nil {
		return Receipt{}, e
	}
	if _, e := readFile(filepath.Join(a.r.path, "pending"), MaximumBundleBytes+32); e == nil {
		return Receipt{}, ErrPending
	} else if !errors.Is(e, os.ErrNotExist) {
		return Receipt{}, e
	}
	state, e := a.r.decision.State()
	if e != nil || !atPredecessor(a.r.ctx, state) {
		return Receipt{}, errors.Join(ErrProtocol, e)
	}
	if e := fresh(a.r.ctx, b.Result, now); e != nil {
		return Receipt{}, e
	}
	if ctx == nil {
		return Receipt{}, ErrProtocol
	}
	if e := ctx.Err(); e != nil {
		return Receipt{}, e
	}
	pending, e := encodePending(b, now)
	if e != nil {
		return Receipt{}, e
	}
	if e := a.r.write("pending", pending); e != nil {
		return Receipt{}, e
	}
	return a.finish(ctx, b, now, now)
}
func (a *Acceptor) Resume(ctx context.Context, expectedBundle types.Hash, now uint64) (Receipt, error) {
	a.r.mu.Lock()
	defer a.r.mu.Unlock()
	if e := a.r.check(); e != nil {
		return Receipt{}, e
	}
	b, checked, e := a.pending()
	if e != nil {
		return Receipt{}, e
	}
	id, _ := b.ID()
	if expectedBundle.IsZero() || expectedBundle != id {
		return Receipt{}, ErrPending
	}
	if existing, e := a.receipt(); e == nil {
		return existing, existing.Verify(a.r.ctx, b)
	} else if !errors.Is(e, os.ErrNotExist) {
		return Receipt{}, e
	}
	if e := a.r.noServeAttempt(); e != nil {
		return Receipt{}, e
	}
	return a.finish(ctx, b, checked, now)
}
func (a *Acceptor) finish(ctx context.Context, b Bundle, checked, now uint64) (Receipt, error) {
	if ctx == nil {
		return Receipt{}, ErrProtocol
	}
	if e := ctx.Err(); e != nil {
		return Receipt{}, e
	}
	state, e := a.r.decision.State()
	if e != nil {
		return Receipt{}, e
	}
	if atPredecessor(a.r.ctx, state) {
		if e := fresh(a.r.ctx, b.Result, now); e != nil {
			return Receipt{}, e
		}
		entry, appended, e := a.r.decision.Append(b.Result.Entry.Record)
		if e != nil || !appended {
			return Receipt{}, errors.Join(ErrUncertain, e)
		}
		id, _ := entry.ID()
		wanted, _ := b.Result.Entry.ID()
		if id != wanted {
			a.r.failed = true
			return Receipt{}, ErrUncertain
		}
	} else if e := requireEntry(a.r.decision, b.Result.Entry); e != nil {
		return Receipt{}, e
	}
	if a.r.hook != nil {
		if e := a.r.hook("source-accepted-before-receipt"); e != nil {
			return Receipt{}, e
		}
	}
	if e := ctx.Err(); e != nil {
		return Receipt{}, e
	}
	aid, _ := a.r.ctx.Assignment.ID()
	pid, _ := a.r.ctx.Plan.ID()
	rid, _ := b.Result.ID()
	bid, _ := b.ID()
	eid, _ := b.Result.Entry.ID()
	receipt := Receipt{Version: Version2, AssignmentID: aid, PlanID: pid, ScopeID: a.r.scopeID, ResultID: rid, BundleID: bid, SourceHeadID: eid, SourceSequence: b.Result.Entry.Sequence, AcceptedAt: checked, Authority: a.r.ctx.Assignment.Base.AuthorityPublicKey}
	raw, e := receipt.unsignedBytes()
	if e != nil {
		return Receipt{}, e
	}
	h := types.DomainHash("OMESH/custody/v2/accepted-source/signature", raw)
	copy(receipt.Signature[:], ed25519.Sign(a.authority, h[:]))
	raw, e = receipt.CanonicalBytes()
	if e != nil {
		return Receipt{}, e
	}
	if e := a.r.write("accepted", raw); e != nil {
		return Receipt{}, e
	}
	return receipt, nil
}
func (a *Acceptor) ReadReceipt() (Receipt, error) {
	a.r.mu.Lock()
	defer a.r.mu.Unlock()
	if e := a.r.check(); e != nil {
		return Receipt{}, e
	}
	r, e := a.receipt()
	if e != nil {
		return r, e
	}
	b, _, e := a.pending()
	if e != nil {
		return Receipt{}, e
	}
	return r, r.Verify(a.r.ctx, b)
}
func (a *Acceptor) receipt() (Receipt, error) {
	raw, e := readFile(filepath.Join(a.r.path, "accepted"), ReceiptBytes)
	if e != nil {
		return Receipt{}, e
	}
	return DecodeReceipt(raw)
}
func (a *Acceptor) pending() (Bundle, uint64, error) {
	raw, e := readFile(filepath.Join(a.r.path, "pending"), MaximumBundleBytes+32)
	if e != nil {
		return Bundle{}, 0, e
	}
	b, checked, e := decodePending(raw)
	if e != nil {
		return b, checked, e
	}
	if e := b.Verify(a.r.ctx); e != nil {
		return b, checked, e
	}
	return b, checked, fresh(a.r.ctx, b.Result, checked)
}
func (a *Acceptor) validateRetained() error {
	b, checked, e := a.pending()
	if errors.Is(e, os.ErrNotExist) {
		if _, e := os.Lstat(filepath.Join(a.r.path, "accepted")); !errors.Is(e, os.ErrNotExist) {
			return ErrProtocol
		}
		state, e := a.r.decision.State()
		if e != nil || !atPredecessor(a.r.ctx, state) {
			return errors.Join(ErrProtocol, e)
		}
		return nil
	}
	if e != nil {
		return e
	}
	receipt, e := a.receipt()
	if e == nil {
		if receipt.AcceptedAt != checked {
			return ErrProtocol
		}
		if e := receipt.Verify(a.r.ctx, b); e != nil {
			return e
		}
		return requireEntry(a.r.decision, b.Result.Entry)
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	state, e := a.r.decision.State()
	if e != nil {
		return e
	}
	if atPredecessor(a.r.ctx, state) {
		return nil
	}
	return requireEntry(a.r.decision, b.Result.Entry)
}
func encodePending(b Bundle, at uint64) ([]byte, error) {
	raw, e := b.CanonicalBytes()
	if e != nil || at == 0 {
		return nil, ErrProtocol
	}
	out := codec.NewEncoder(len(raw) + 32)
	out.Fixed([]byte("OMCVPEN2"))
	out.U16(Version2)
	out.U64(at)
	out.BytesField(raw)
	return out.Bytes(), nil
}
func decodePending(raw []byte) (Bundle, uint64, error) {
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCVPEN2") {
		return Bundle{}, 0, ErrProtocol
	}
	v, _ := d.U16()
	at, _ := d.U64()
	b, e := d.BytesField(MaximumBundleBytes)
	if e != nil || v != Version2 || at == 0 || d.Finish() != nil {
		return Bundle{}, 0, ErrProtocol
	}
	bundle, e := DecodeBundle(b)
	if e != nil {
		return Bundle{}, 0, e
	}
	again, e := encodePending(bundle, at)
	if e != nil || !bytes.Equal(raw, again) {
		return Bundle{}, 0, ErrProtocol
	}
	return bundle, at, nil
}
