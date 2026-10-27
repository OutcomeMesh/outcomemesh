package custodyv2

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type Target struct {
	r                         *root
	replica, control, session ed25519.PrivateKey
	candidate                 *Candidate
}

func CreateTarget(path string, c Context, pin types.Hash, sources Sources) error {
	return createRoot(path, c, pin, "target", sources)
}
func OpenTarget(path string, c Context, pin types.Hash, sources Sources, replica, control ed25519.PrivateKey) (t *Target, returnErr error) {
	if !matches(replica, c.Assignment.Base.ReplicaPublicKey) || !matches(control, c.Assignment.Base.RemoteControlPublicKey) {
		return nil, ErrProtocol
	}
	r, e := openRoot(path, c, pin, "target", sources)
	if e != nil {
		return nil, e
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, r.close())
		}
	}()
	t = &Target{r: r, replica: append(ed25519.PrivateKey(nil), replica...), control: append(ed25519.PrivateKey(nil), control...)}
	if e := t.validateRetained(); e != nil {
		return nil, e
	}
	return t, t.r.stabilize()
}
func (t *Target) Close() error {
	t.r.mu.Lock()
	clear(t.session)
	clear(t.replica)
	clear(t.control)
	t.r.mu.Unlock()
	return t.r.close()
}
func (t *Target) Prepare() (Candidate, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	if e := t.r.check(); e != nil {
		return Candidate{}, e
	}
	if _, e := readFile(filepath.Join(t.r.path, "consumed"), 4096); e == nil {
		return Candidate{}, ErrConsumed
	} else if !errors.Is(e, os.ErrNotExist) {
		return Candidate{}, e
	}
	if t.candidate != nil {
		return *t.candidate, nil
	}
	public, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return Candidate{}, e
	}
	var pub [32]byte
	copy(pub[:], public)
	s, e := t.r.ctx.Scope()
	if e != nil {
		clear(key)
		return Candidate{}, e
	}
	cmd, e := (custodyfence.Command{Version: custodyfence.Version1, ScopeID: t.r.scopeID, ExpectedHead: t.r.scopeID, Kind: custodyfence.Claim, EvidenceID: SessionID(pub)}).Sign(t.control)
	if e != nil {
		clear(key)
		return Candidate{}, e
	}
	if e := cmd.Verify(s); e != nil {
		clear(key)
		return Candidate{}, e
	}
	candidate := Candidate{Version: Version2, SessionPublicKey: pub, Claim: cmd}
	t.session = key
	t.candidate = &candidate
	return candidate, nil
}

// Execute is the only method that can read chunks, sign a proof or advance B.
// No configurable callback or caller-imported session key can bypass this gate.
func (t *Target) Execute(ctx context.Context, claim custodyfence.Certificate, now uint64) (result Result, returnErr error) {
	if ctx == nil {
		return result, ErrProtocol
	}
	raw, e := claim.CanonicalBytes()
	if e != nil {
		return result, e
	}
	claim, e = custodyfence.DecodeCertificate(raw)
	if e != nil {
		return result, e
	}
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	if e := t.r.check(); e != nil {
		return result, e
	}
	if _, e := readFile(filepath.Join(t.r.path, "consumed"), 4096); e == nil {
		return result, ErrConsumed
	} else if !errors.Is(e, os.ErrNotExist) {
		return result, e
	}
	if t.candidate == nil || !validKey(t.session) || claim.Command != t.candidate.Claim {
		return result, ErrSession
	}
	s, e := t.r.ctx.Scope()
	if e != nil {
		return result, e
	}
	state, e := custodyfence.NewState(s, t.r.scopeID)
	if e != nil {
		return result, e
	}
	if e := state.Apply(claim); e != nil {
		return result, e
	}
	if state.Snapshot().SessionID != SessionID(t.candidate.SessionPublicKey) {
		return result, ErrSession
	}
	current, e := t.r.decision.State()
	if e != nil || !atPredecessor(t.r.ctx, current) {
		return result, errors.Join(ErrProtocol, e)
	}
	if e := ctx.Err(); e != nil {
		return result, e
	}
	if e := t.r.ctx.Plan.Challenge.Verify(t.r.ctx.Manifest, t.r.ctx.Previous, t.r.ctx.CustodyPolicy, now); e != nil {
		return result, e
	}
	used, e := encodeConsumed(*t.candidate, claim)
	if e != nil {
		return result, e
	}
	if e := t.r.write("consumed", used); e != nil {
		return result, e
	}
	defer clear(t.session)
	// From this durable boundary onward even cancellation is an unknown effect.
	// A new process cannot reconstruct the private session, hence cannot retry it.
	if e := ctx.Err(); e != nil {
		return result, e
	}
	if t.r.hook != nil {
		if e := t.r.hook("before-effect"); e != nil {
			return result, e
		}
	}
	c := t.r.ctx
	batch, proof, e := workarchive.AnswerCustodyChallenge(t.r.objects, c.Manifest, c.Previous, c.Plan.Challenge, c.CustodyPolicy, t.replica, now)
	if e != nil {
		return result, e
	}
	renewed, e := workarchive.RenewReplicaReceipt(c.Manifest, c.Previous, c.Plan.Challenge, batch, proof, c.CustodyPolicy, t.replica, now)
	if e != nil {
		return result, e
	}
	record := workarchive.CustodyRecord{Challenge: c.Plan.Challenge, Batch: batch, Proof: proof, RenewedReceipt: renewed}
	entry, appended, e := t.r.decision.Append(record)
	if e != nil || !appended {
		return result, errors.Join(ErrProtocol, e)
	}
	cid, _ := claim.Command.ID()
	result = Result{Version: Version2, ScopeID: t.r.scopeID, ClaimID: cid, SessionPublicKey: t.candidate.SessionPublicKey, Entry: entry}
	b, e := result.unsignedBytes()
	if e != nil {
		return Result{}, e
	}
	h := types.DomainHash("OMESH/custody/v2/result/session-signature", b)
	copy(result.SessionSignature[:], ed25519.Sign(t.session, h[:]))
	if e := result.Verify(c, claim); e != nil {
		return Result{}, e
	}
	b, e = result.CanonicalBytes()
	if e != nil {
		return Result{}, e
	}
	if e := t.r.write("result", b); e != nil {
		return Result{}, e
	}
	return result, nil
}
func (t *Target) ReadResult() (Result, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	if e := t.r.check(); e != nil {
		return Result{}, e
	}
	return t.readResultLocked()
}
func (t *Target) readResultLocked() (Result, error) {
	candidate, claim, e := t.consumed()
	if e != nil {
		return Result{}, e
	}
	raw, e := readFile(filepath.Join(t.r.path, "result"), MaximumResultBytes)
	if e != nil {
		return Result{}, e
	}
	result, e := DecodeResult(raw)
	if e != nil {
		return Result{}, e
	}
	if result.SessionPublicKey != candidate.SessionPublicKey {
		return Result{}, ErrSession
	}
	return result, result.Verify(t.r.ctx, claim)
}

// ResultCommand signs only an already retained result against a quorum prefix.
// It never reads chunks, signs a new proof or creates an execution session.
func (t *Target) ResultCommand(prefix []custodyfence.Certificate) (Result, custodyfence.Command, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	if e := t.r.check(); e != nil {
		return Result{}, custodyfence.Command{}, e
	}
	result, e := t.readResultLocked()
	if e != nil {
		return Result{}, custodyfence.Command{}, e
	}
	if len(prefix) < 1 || len(prefix) > 2 {
		return Result{}, custodyfence.Command{}, ErrProtocol
	}
	s, e := t.r.ctx.Scope()
	if e != nil {
		return Result{}, custodyfence.Command{}, e
	}
	state, e := custodyfence.NewState(s, t.r.scopeID)
	if e != nil {
		return Result{}, custodyfence.Command{}, e
	}
	for _, cert := range prefix {
		if e := state.Apply(cert); e != nil {
			return Result{}, custodyfence.Command{}, e
		}
	}
	x := state.Snapshot()
	if (x.Phase != custodyfence.Claimed && x.Phase != custodyfence.Unknown) || x.ClaimID != result.ClaimID || x.SessionID != SessionID(result.SessionPublicKey) {
		return Result{}, custodyfence.Command{}, ErrProtocol
	}
	rid, _ := result.ID()
	cmd, e := (custodyfence.Command{Version: custodyfence.Version1, ScopeID: t.r.scopeID, ExpectedSequence: x.Position.Sequence, ExpectedHead: x.Position.HeadID, Kind: custodyfence.RecordResult, ClaimID: result.ClaimID, EvidenceID: rid}).Sign(t.control)
	return result, cmd, e
}
func (t *Target) consumed() (Candidate, custodyfence.Certificate, error) {
	b, e := readFile(filepath.Join(t.r.path, "consumed"), 4096)
	if e != nil {
		return Candidate{}, custodyfence.Certificate{}, e
	}
	candidate, claim, e := decodeConsumed(b)
	if e != nil {
		return candidate, claim, e
	}
	if e := candidate.Verify(t.r.ctx); e != nil {
		return candidate, claim, e
	}
	if candidate.Claim != claim.Command {
		return candidate, claim, ErrSession
	}
	s, e := t.r.ctx.Scope()
	if e != nil {
		return candidate, claim, e
	}
	return candidate, claim, claim.Verify(s)
}
func (t *Target) validateRetained() error {
	current, e := t.r.decision.State()
	if e != nil {
		return e
	}
	_, claim, e := t.consumed()
	if errors.Is(e, os.ErrNotExist) {
		if !atPredecessor(t.r.ctx, current) {
			return ErrProtocol
		}
		if _, e := os.Lstat(filepath.Join(t.r.path, "result")); !errors.Is(e, os.ErrNotExist) {
			return ErrProtocol
		}
		return nil
	}
	if e != nil {
		return e
	}
	result, e := t.readResultLocked()
	if e == nil {
		return requireEntry(t.r.decision, result.Entry)
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if atPredecessor(t.r.ctx, current) {
		return nil
	}
	head, exists, e := t.r.decision.Head()
	if e != nil || !exists {
		return errors.Join(ErrProtocol, e)
	}
	if e := head.Verify(t.r.ctx.Manifest, t.r.ctx.CustodyPolicy, t.r.ctx.Plan.Intent.PriorSequence+1, t.r.ctx.Plan.Intent.PriorHeadID, t.r.ctx.Previous); e != nil {
		return e
	}
	wanted, _ := t.r.ctx.Plan.Challenge.ID()
	got, _ := head.Record.Challenge.ID()
	if wanted != got || claim.Command.ScopeID != t.r.scopeID {
		return ErrProtocol
	}
	return nil
}
func encodeConsumed(c Candidate, q custodyfence.Certificate) ([]byte, error) {
	b, e := c.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	raw, e := q.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	out := codec.NewEncoder(4096)
	out.Fixed([]byte("OMCVUSE2"))
	out.U16(Version2)
	out.BytesField(b)
	out.BytesField(raw)
	return out.Bytes(), nil
}
func decodeConsumed(b []byte) (Candidate, custodyfence.Certificate, error) {
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVUSE2") {
		return Candidate{}, custodyfence.Certificate{}, ErrProtocol
	}
	v, _ := d.U16()
	if v != Version2 {
		return Candidate{}, custodyfence.Certificate{}, ErrProtocol
	}
	raw, e := d.BytesField(1024)
	if e != nil {
		return Candidate{}, custodyfence.Certificate{}, e
	}
	c, e := DecodeCandidate(raw)
	if e != nil {
		return c, custodyfence.Certificate{}, e
	}
	raw, e = d.BytesField(custodyfence.MaximumCertificateBytes)
	if e != nil || d.Finish() != nil {
		return c, custodyfence.Certificate{}, ErrProtocol
	}
	q, e := custodyfence.DecodeCertificate(raw)
	return c, q, e
}
func matches(key ed25519.PrivateKey, pub [32]byte) bool {
	return validKey(key) && ed25519.PublicKey(pub[:]).Equal(key.Public())
}
func requireEntry(d *workarchive.CustodyJournalDecision, expected workarchive.CustodyJournalEntry) error {
	head, exists, e := d.Head()
	if e != nil || !exists {
		return errors.Join(ErrProtocol, e)
	}
	id, _ := head.ID()
	want, _ := expected.ID()
	if id != want {
		return ErrProtocol
	}
	return nil
}
