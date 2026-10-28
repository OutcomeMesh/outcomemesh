package custodyv2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

func signedServe(t testing.TB, c Context, p ServeProposal) ServeCertificate {
	t.Helper()
	var e error
	p, e = p.Sign(c, "authority", f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	p, e = p.Sign(c, "consumer", f.Key(4))
	if e != nil {
		t.Fatal(e)
	}
	cmd, e := p.Decision(c, f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	s := ServeCertificate{Version: Version2, Proposal: p, Decision: f.Certificate(cmd, 70, 71, 72)}
	if e := s.Verify(c); e != nil {
		t.Fatal(e)
	}
	return s
}
func unclaimedServe(t testing.TB, c Context) ServeCertificate {
	t.Helper()
	scope, e := c.Scope()
	if e != nil {
		t.Fatal(e)
	}
	sid, _ := scope.ID()
	cmd, e := (custodyfence.Command{Version: scope.Version, ScopeID: sid, ExpectedHead: sid, Kind: custodyfence.CloseUnclaimed, EvidenceID: f.Hash("cancel-before-grant")}).Sign(f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	p, e := NewServeUnclaimed(c, f.Certificate(cmd, 70, 71, 72))
	if e != nil {
		t.Fatal(e)
	}
	return signedServe(t, c, p)
}
func fulfilledServe(t testing.TB, x fixture, target *Target, a *Acceptor) ServeCertificate {
	t.Helper()
	b := x.bundle(t, target)
	r, e := a.Accept(t.Context(), b, x.c.Plan.Challenge.IssuedAt)
	if e != nil {
		t.Fatal(e)
	}
	p, e := NewServeFulfilled(x.c, b, r)
	if e != nil {
		t.Fatal(e)
	}
	return signedServe(t, x.c, p)
}
func TestServeFulfilledOriginalSourcesAndAFirst(t *testing.T) {
	x := newFixture(t)
	target := x.target(t, "target")
	a := x.acceptor(t)
	cert := fulfilledServe(t, x, target, a)
	now := x.c.Plan.Challenge.ExpiresAt + 100000
	if _, e := target.ApplyServe(t.Context(), cert, ServeReceipt{}, now, false); e == nil {
		t.Fatal("B closed without A applied receipt")
	}
	ar, e := a.ApplyServe(t.Context(), cert, now, false)
	if e != nil {
		t.Fatal(e)
	}
	br, e := target.ApplyServe(t.Context(), cert, ar, now, false)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range []ServeReceipt{ar, br} {
		raw, e := r.CanonicalBytes()
		if e != nil {
			t.Fatal(e)
		}
		back, e := DecodeServeReceipt(raw)
		if e != nil || back != r {
			t.Fatal("receipt codec", e)
		}
	}
	for _, state := range []func() (ServeStatus, error){a.ServeStatus, target.ServeStatus} {
		s, e := state()
		if e != nil || s.Pending || !s.ArchiveHeld || s.MinimumRetainUntil <= x.c.Previous.RetainUntil {
			t.Fatal("bad closed retention", s, e)
		}
	}
	repeat, e := a.ApplyServe(t.Context(), cert, now+1, false)
	if e != nil || repeat != ar {
		t.Fatal("A retry changed original receipt", e)
	}
	repeat, e = target.ApplyServe(t.Context(), cert, ar, now+1, false)
	if e != nil || repeat != br {
		t.Fatal("B retry changed original receipt", e)
	}
	for _, r := range []*root{a.r, target.r} {
		s, e := r.decision.State()
		if e != nil || s.Sequence != 1 {
			t.Fatal("settlement advanced source", e)
		}
	}
	_ = a.Close()
	_ = target.Close()
	a = x.reopenA(t)
	target = x.reopen(t, "target")
	if s, e := target.ServeStatus(); e != nil || s.Pending || !s.ArchiveHeld {
		t.Fatal("cold closed", s, e)
	}
	if _, e := target.Prepare(); !errors.Is(e, ErrServeClosed) {
		t.Fatal("closed target issued session", e)
	}
	if r, e := a.ReadReceipt(); e != nil || r.AcceptedAt != x.c.Plan.Challenge.IssuedAt {
		t.Fatal("original receipt lost", e)
	}
	if _, e := target.ReadResult(); e != nil {
		t.Fatal("result lost after settlement", e)
	}
}
func TestServeUnclaimedCancelsExecutionButKeepsArchive(t *testing.T) {
	x := newFixture(t)
	target := x.target(t, "target")
	a := x.acceptor(t)
	if _, e := target.Prepare(); e != nil {
		t.Fatal(e)
	}
	cert := unclaimedServe(t, x.c)
	now := x.c.Plan.Challenge.IssuedAt
	ar, e := a.ApplyServe(t.Context(), cert, now, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := target.ApplyServe(t.Context(), cert, ar, now, false); e != nil {
		t.Fatal(e)
	}
	if len(target.session) != 0 && !bytes.Equal(target.session, make([]byte, len(target.session))) {
		t.Fatal("volatile session retained")
	}
	for _, r := range []*root{a.r, target.r} {
		s, e := r.decision.State()
		if e != nil || s.Sequence != 0 {
			t.Fatal("cancel appended", e)
		}
	}
	s, e := target.ServeStatus()
	if e != nil || s.Pending || !s.ArchiveHeld || s.MinimumRetainUntil != x.c.Previous.RetainUntil {
		t.Fatal(s, e)
	}
	_ = target.Close()
	target = x.reopen(t, "target")
	if _, e := target.Prepare(); !errors.Is(e, ErrServeClosed) {
		t.Fatal("cancel reopened slot", e)
	}
}
func TestServeCrashBoundariesExplicitResume(t *testing.T) {
	for _, role := range []uint8{ServeAuthority, ServeTarget} {
		for _, stage := range []string{"serve.pending-before-sync", "serve.pending-durable", "serve.settled-before-sync", "serve.settled-durable"} {
			t.Run(string(rune('0'+role))+"/"+stage, func(t *testing.T) {
				x := newFixture(t)
				target := x.target(t, "target")
				a := x.acceptor(t)
				cert := fulfilledServe(t, x, target, a)
				now := x.c.Plan.Challenge.IssuedAt
				var parent ServeReceipt
				var e error
				if role == ServeTarget {
					parent, e = a.ApplyServe(t.Context(), cert, now, false)
					if e != nil {
						t.Fatal(e)
					}
				}
				r := a.r
				if role == ServeTarget {
					r = target.r
				}
				r.hook = func(s string) error {
					if s == stage {
						return errors.New("injected persistence failure")
					}
					return nil
				}
				apply := func(resume bool) (ServeReceipt, error) {
					if role == ServeAuthority {
						return a.ApplyServe(t.Context(), cert, now+1, resume)
					}
					return target.ApplyServe(t.Context(), cert, parent, now+1, resume)
				}
				if _, e := apply(false); e == nil {
					t.Fatal("missing failure")
				}
				if _, e := apply(true); !errors.Is(e, ErrUncertain) {
					t.Fatal("poisoned owner continued", e)
				}
				if role == ServeAuthority {
					_ = a.Close()
					a = x.reopenA(t)
				} else {
					_ = target.Close()
					target = x.reopen(t, "target")
				}
				status := a.ServeStatus
				if role == ServeTarget {
					status = target.ServeStatus
				}
				s, e := status()
				if e != nil {
					t.Fatal(e)
				}
				wantPending := stage == "serve.pending-before-sync" || stage == "serve.pending-durable"
				if s.Pending != wantPending {
					t.Fatal("cold open invented settlement", s)
				}
				if wantPending {
					if _, e := apply(false); !errors.Is(e, ErrServePending) {
						t.Fatal("implicit resume", e)
					}
				}
				got, e := apply(true)
				if e != nil || got.AppliedAt != now+1 {
					t.Fatal("exact explicit recovery", e)
				}
				s, e = status()
				if e != nil || s.Pending || !s.ArchiveHeld {
					t.Fatal(s, e)
				}
			})
		}
	}
}
func TestServeRejectsHistoricalReceiptWithoutOriginalAcceptance(t *testing.T) {
	x := newFixture(t)
	target := x.target(t, "target")
	a := x.acceptor(t)
	cert := fulfilledServe(t, x, target, a)
	_ = a.Close()
	other := fixtureWithContext(t, x.c)
	otherA := other.acceptor(t)
	if _, e := otherA.ApplyServe(t.Context(), cert, x.c.Plan.Challenge.ExpiresAt+1, false); e == nil {
		t.Fatal("historical A receipt became current local acceptance")
	}
	if _, e := os.Lstat(filepath.Join(otherA.r.path, "serve.pending")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("invalid proof mutated owner")
	}
	clone := fixtureWithContext(t, x.c)
	otherB := clone.target(t, "target")
	a = x.reopenA(t)
	ar, e := a.ApplyServe(t.Context(), cert, x.c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := otherB.ApplyServe(t.Context(), cert, ar, x.c.Plan.Challenge.IssuedAt, false); e == nil {
		t.Fatal("B clone with no original result settled")
	}
}
func TestServeUnknownHasNoClosingProof(t *testing.T) {
	x := newFixture(t)
	target := x.target(t, "target")
	a := x.acceptor(t)
	candidate, e := target.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	claim := f.Certificate(candidate.Claim, 70, 71, 72)
	target.r.hook = func(s string) error {
		if s == "before-effect" {
			return errors.New("lost process")
		}
		return nil
	}
	if _, e := target.Execute(t.Context(), claim, x.c.Plan.Challenge.IssuedAt); e == nil {
		t.Fatal("expected crash")
	}
	if _, e := NewServeUnclaimed(x.c, claim); e == nil {
		t.Fatal("claim was cancellation")
	}
	id, _ := candidate.Claim.ID()
	cmd, e := (custodyfence.Command{Version: 1, ScopeID: x.pin, ExpectedSequence: 1, ExpectedHead: id, Kind: custodyfence.MarkUnknown, ClaimID: id, EvidenceID: f.Hash("unknown")}).Sign(f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := NewServeUnclaimed(x.c, f.Certificate(cmd, 70, 71, 72)); e == nil {
		t.Fatal("unknown was cancellation")
	}
	for _, state := range []func() (ServeStatus, error){a.ServeStatus, target.ServeStatus} {
		s, e := state()
		if e != nil || !s.Pending || !s.ArchiveHeld {
			t.Fatal("unknown released", s, e)
		}
	}
	// Even an impossible, test-key-forged cancellation quorum cannot erase B's
	// original consumed marker. Genuine honest witnesses cannot produce this QC.
	cert := unclaimedServe(t, x.c)
	ar, e := a.ApplyServe(t.Context(), cert, x.c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := target.ApplyServe(t.Context(), cert, ar, x.c.Plan.Challenge.IssuedAt, false); e == nil {
		t.Fatal("consumed target cancelled")
	}
}
func TestServeTypedWitnessAndPermanentEquivocationLock(t *testing.T) {
	x := newFixture(t)
	cert := unclaimedServe(t, x.c)
	scope, e := x.c.ServeScope()
	if e != nil {
		t.Fatal(e)
	}
	sid, _ := scope.ID()
	before := custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: sid}}
	w, e := custodyfence.Create(filepath.Join(t.TempDir(), "w"), scope, sid, f.Key(70))
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	bad := cert.Proposal
	bad.ConsumerSignature = [64]byte{}
	if _, e := VoteServe(x.c, bad, cert.Decision.Command, w, before); e == nil {
		t.Fatal("unsigned typed proposal voted")
	}
	_, pin, e := w.Snapshot()
	if e != nil || pin != before {
		t.Fatal("bad proposal left vote lock", e)
	}
	vote, e := VoteServe(x.c, cert.Proposal, cert.Decision.Command, w, before)
	if e != nil {
		t.Fatal(e)
	}
	retry, e := VoteServe(x.c, cert.Proposal, cert.Decision.Command, w, before)
	if e != nil || vote != retry {
		t.Fatal("retry changed vote", e)
	}
	alternative := cert.Proposal
	alternative.AuthoritySignature = [64]byte{}
	alternative.ConsumerSignature = [64]byte{}
	// Different complete typed cancellation evidence, same immutable decision scope.
	original, _ := custodyfence.DecodeCertificate(alternative.Evidence)
	original.Command.EvidenceID = f.Hash("other-reason")
	original.Command, _ = original.Command.Sign(f.Key(1))
	original = f.Certificate(original.Command, 70, 71, 72)
	alternative.Evidence, _ = original.CanonicalBytes()
	other := signedServe(t, x.c, alternative)
	if _, e := VoteServe(x.c, other.Proposal, other.Decision.Command, w, before); e == nil {
		t.Fatal("witness equivocated on decision")
	}
	if e := CommitServe(x.c, cert, w, before); e != nil {
		t.Fatal(e)
	}
	if e := CommitServe(x.c, cert, w, before); e != nil {
		t.Fatal("lost commit reply retry", e)
	}
	raw, _ := cert.CanonicalBytes()
	back, e := DecodeServeCertificate(raw)
	if e != nil || back.Verify(x.c) != nil {
		t.Fatal("certificate codec", e)
	}
	for _, mutate := range []func(*ServeCertificate){func(s *ServeCertificate) { s.Version = 1 }, func(s *ServeCertificate) { s.Decision.Votes = s.Decision.Votes[:2] }, func(s *ServeCertificate) { s.Proposal.Outcome = 3 }, func(s *ServeCertificate) { s.Proposal.ContextID = types.Hash{1} }, func(s *ServeCertificate) { s.Decision.Command.EvidenceID = f.Hash("unbound") }} {
		b, _ := DecodeServeCertificate(raw)
		mutate(&b)
		if b.Verify(x.c) == nil {
			t.Fatal("invalid Serve certificate verified")
		}
	}
	for _, b := range [][]byte{raw[:len(raw)-1], append(append([]byte{}, raw...), 0)} {
		if _, e := DecodeServeCertificate(b); e == nil {
			t.Fatal("noncanonical certificate")
		}
	}
}
func FuzzServeDecoders(fz *testing.F) {
	fz.Add([]byte("OMCVSQC2"))
	cert := unclaimedServe(fz, fixtureContext(fz))
	raw, _ := cert.CanonicalBytes()
	fz.Add(raw)
	raw, _ = cert.Proposal.CanonicalBytes()
	fz.Add(raw)
	fz.Fuzz(func(t *testing.T, b []byte) {
		if p, e := DecodeServeProposal(b); e == nil {
			again, _ := p.CanonicalBytes()
			if !bytes.Equal(b, again) {
				t.Fatal("proposal round trip")
			}
		}
		if c, e := DecodeServeCertificate(b); e == nil {
			again, _ := c.CanonicalBytes()
			if !bytes.Equal(b, again) {
				t.Fatal("certificate round trip")
			}
		}
		if r, e := DecodeServeReceipt(b); e == nil {
			again, _ := r.CanonicalBytes()
			if !bytes.Equal(b, again) {
				t.Fatal("receipt round trip")
			}
		}
	})
}

func TestServeExpiredResultAndConflictingResumeStayHeld(t *testing.T) {
	x := newFixture(t)
	target := x.target(t, "target")
	a := x.acceptor(t)
	b := x.bundle(t, target)
	if _, e := a.Accept(t.Context(), b, x.c.Plan.Challenge.ExpiresAt+x.c.CustodyPolicy.MaximumProofAge+1); e == nil {
		t.Fatal("late proof accepted")
	}
	if _, e := NewServeFulfilled(x.c, b, Receipt{}); e == nil {
		t.Fatal("B-only result fulfilled Serve")
	}
	s, e := target.ServeStatus()
	if e != nil || !s.Pending || !s.ArchiveHeld || s.MinimumRetainUntil != b.Result.Entry.Record.RenewedReceipt.RetainUntil {
		t.Fatal("B renewal retention lost", s, e)
	}
	receipt, e := a.Accept(t.Context(), b, x.c.Plan.Challenge.IssuedAt)
	if e != nil {
		t.Fatal(e)
	}
	p, e := NewServeFulfilled(x.c, b, receipt)
	if e != nil {
		t.Fatal(e)
	}
	cert := signedServe(t, x.c, p)
	a.r.hook = func(at string) error {
		if at == "serve.pending-durable" {
			return errors.New("power boundary")
		}
		return nil
	}
	if _, e := a.ApplyServe(t.Context(), cert, x.c.Plan.Challenge.IssuedAt, false); e == nil {
		t.Fatal("failure missing")
	}
	_ = a.Close()
	a = x.reopenA(t)
	other := cert
	other.Decision = f.Certificate(cert.Decision.Command, 70, 71, 73)
	if e := other.Verify(x.c); e != nil {
		t.Fatal(e)
	}
	if _, e := a.ApplyServe(t.Context(), other, x.c.Plan.Challenge.IssuedAt, true); !errors.Is(e, ErrServePending) {
		t.Fatal("resume silently replaced pinned certificate", e)
	}
	s, e = a.ServeStatus()
	if e != nil || !s.Pending {
		t.Fatal("failed resume closed", s, e)
	}
	if _, e := a.ApplyServe(t.Context(), cert, x.c.Plan.Challenge.IssuedAt, true); e != nil {
		t.Fatal(e)
	}
}
func TestServeOriginalExecutionVoteExcludesCancellation(t *testing.T) {
	x := newFixture(t)
	target := x.target(t, "target")
	candidate, e := target.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	scope, _ := x.c.Scope()
	sid, _ := scope.ID()
	before := custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: sid}}
	cancel := unclaimedServe(t, x.c)
	q, e := custodyfence.DecodeCertificate(cancel.Proposal.Evidence)
	if e != nil {
		t.Fatal(e)
	}
	for i := byte(70); i < 73; i++ {
		w, e := custodyfence.Create(filepath.Join(t.TempDir(), "original"), scope, sid, f.Key(i))
		if e != nil {
			t.Fatal(e)
		}
		if _, e := w.VoteAt(before, candidate.Claim); e != nil {
			t.Fatal(e)
		}
		if _, e := w.VoteAt(before, q.Command); e == nil {
			t.Fatal("pending execution vote was cancelled")
		}
		_ = w.Close()
	}
}
