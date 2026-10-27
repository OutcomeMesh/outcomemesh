package custodyv2

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type fixture struct {
	c              Context
	pin            types.Hash
	root, ajournal string
	s              Sources
}

func fixtureContext(t testing.TB) Context {
	t.Helper()
	raw, e := os.ReadFile("testdata/public-fixture/context")
	if e != nil {
		t.Fatal(e)
	}
	c, e := DecodeContext(raw)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func newFixture(t testing.TB) fixture { t.Helper(); return fixtureWithContext(t, fixtureContext(t)) }
func fixtureWithContext(t testing.TB, c Context) fixture {
	t.Helper()
	scope, e := c.Scope()
	if e != nil {
		t.Fatal(e)
	}
	pin, _ := scope.ID()
	root := t.TempDir()
	x := fixture{c: c, pin: pin, root: root, ajournal: filepath.Join(root, "a-journal"), s: Sources{Journal: filepath.Join(root, "b-journal"), Objects: filepath.Join(root, "objects")}}
	for _, p := range []string{x.ajournal, x.s.Journal} {
		if _, _, e := workarchive.OpenOrCreateCustodyJournal(p, c.Manifest, c.Initial, c.CustodyPolicy); e != nil {
			t.Fatal(e)
		}
	}
	objects, e := workarchive.OpenObjectStore(x.s.Objects, workarchive.DefaultObjectStorePolicy())
	if e != nil {
		t.Fatal(e)
	}
	for _, chunk := range c.Manifest.Chunks {
		raw, e := os.ReadFile(filepath.Join("testdata/public-fixture", chunk.ID.String()))
		if e != nil {
			t.Fatal(e)
		}
		if _, e := objects.Put(c.Manifest, chunk.ID, raw); e != nil {
			t.Fatal(e)
		}
	}
	return x
}
func (f fixture) target(t testing.TB, name string) *Target {
	t.Helper()
	p := filepath.Join(f.root, name)
	if e := CreateTarget(p, f.c, f.pin, f.s); e != nil {
		t.Fatal(e)
	}
	return f.reopen(t, name)
}
func (x fixture) reopen(t testing.TB, name string) *Target {
	t.Helper()
	target, e := OpenTarget(filepath.Join(x.root, name), x.c, x.pin, x.s, f.Key(61), f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = target.Close() })
	return target
}
func (x fixture) bundle(t testing.TB, target *Target) Bundle {
	t.Helper()
	candidate, e := target.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	q := f.Certificate(candidate.Claim, 70, 71, 72)
	if _, e := target.Execute(t.Context(), q, x.c.Plan.Challenge.IssuedAt); e != nil {
		t.Fatal(e)
	}
	result, cmd, e := target.ResultCommand([]custodyfence.Certificate{q})
	if e != nil {
		t.Fatal(e)
	}
	b := Bundle{Version: Version2, Result: result, Chain: []custodyfence.Certificate{q, f.Certificate(cmd, 70, 71, 72)}}
	if e := b.Verify(x.c); e != nil {
		t.Fatal(e)
	}
	return b
}
func (x fixture) acceptor(t testing.TB) *Acceptor {
	t.Helper()
	p := filepath.Join(x.root, "acceptor")
	if e := CreateAcceptor(p, x.c, x.pin, x.ajournal); e != nil {
		t.Fatal(e)
	}
	return x.reopenA(t)
}
func (x fixture) reopenA(t testing.TB) *Acceptor {
	t.Helper()
	a, e := OpenAcceptor(filepath.Join(x.root, "acceptor"), x.c, x.pin, x.ajournal, f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}
func TestExecutionCrashBoundariesNeverReauthorize(t *testing.T) {
	for _, stage := range []string{"consumed-before-sync", "consumed-durable", "before-effect", "result-before-sync", "result-durable"} {
		t.Run(stage, func(t *testing.T) {
			x := newFixture(t)
			target := x.target(t, "target")
			candidate, e := target.Prepare()
			if e != nil {
				t.Fatal(e)
			}
			q := f.Certificate(candidate.Claim, 70, 71, 72)
			target.r.hook = func(at string) error {
				if at == stage {
					return errors.New("injected crash")
				}
				return nil
			}
			if _, e := target.Execute(t.Context(), q, x.c.Plan.Challenge.IssuedAt); e == nil {
				t.Fatal("missing failure")
			}
			_ = target.Close()
			target = x.reopen(t, "target")
			if _, e := target.Prepare(); !errors.Is(e, ErrConsumed) {
				t.Fatal("crash granted new session", e)
			}
			if _, e := target.Execute(t.Context(), q, x.c.Plan.Challenge.IssuedAt); !errors.Is(e, ErrConsumed) {
				t.Fatal("crash replayed", e)
			}
			result, e := target.ReadResult()
			if stage == "result-before-sync" || stage == "result-durable" {
				if e != nil || result.Entry.Record.Proof.RespondedAt != x.c.Plan.Challenge.IssuedAt {
					t.Fatal("retained result changed", e)
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				t.Fatal("invented result", e)
			}
		})
	}
}
func TestAcceptanceCrashRequiresExactExplicitResume(t *testing.T) {
	for _, stage := range []string{"pending-before-sync", "pending-durable", "source-accepted-before-receipt", "accepted-before-sync", "accepted-durable"} {
		t.Run(stage, func(t *testing.T) {
			x := newFixture(t)
			target := x.target(t, "target")
			b := x.bundle(t, target)
			a := x.acceptor(t)
			a.r.hook = func(at string) error {
				if at == stage {
					return errors.New("injected crash")
				}
				return nil
			}
			if _, e := a.Accept(t.Context(), b, x.c.Plan.Challenge.IssuedAt); e == nil {
				t.Fatal("missing crash")
			}
			_ = a.Close()
			a = x.reopenA(t)
			state, e := a.r.decision.State()
			if e != nil {
				t.Fatal(e)
			}
			want := uint64(1)
			if stage == "pending-durable" || stage == "pending-before-sync" {
				want = 0
			}
			if state.Sequence != want {
				t.Fatal("open implicitly appended", state.Sequence)
			}
			id, _ := b.ID()
			if _, e := a.Resume(t.Context(), f.Hash("wrong-bundle"), x.c.Plan.Challenge.IssuedAt); !errors.Is(e, ErrPending) {
				t.Fatal("wrong resume pin", e)
			}
			if stage == "pending-durable" || stage == "pending-before-sync" {
				if _, e := a.Accept(t.Context(), b, x.c.Plan.Challenge.IssuedAt); !errors.Is(e, ErrPending) {
					t.Fatal("implicit retry", e)
				}
				if _, e := a.Resume(t.Context(), id, x.c.Plan.Challenge.ExpiresAt+1000); e == nil {
					t.Fatal("expired unaccepted proof resumed")
				}
			}
			// Explicit recovery at the valid original instant is possible in this deterministic fault fixture.
			// For already appended entries even an expired current clock only publishes the historical receipt.
			now := x.c.Plan.Challenge.IssuedAt
			if stage != "pending-durable" && stage != "pending-before-sync" {
				now = x.c.Plan.Challenge.ExpiresAt + 1000
			}
			ack, e := a.Resume(t.Context(), id, now)
			if e != nil {
				t.Fatal(e)
			}
			if e := ack.Verify(x.c, b); e != nil {
				t.Fatal(e)
			}
			if ack.AcceptedAt != x.c.Plan.Challenge.IssuedAt {
				t.Fatal("receipt refreshed")
			}
		})
	}
}
func TestCopiedPermanentKeysCannotUseAnotherLiveSession(t *testing.T) {
	x := newFixture(t)
	one := x.target(t, "one")
	candidate, e := one.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	q := f.Certificate(candidate.Claim, 70, 71, 72)
	_ = one.Close()
	// Same permanent keys, same scope and original source, but a fresh process session.
	two := x.reopen(t, "one")
	other, e := two.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	if other.SessionPublicKey == candidate.SessionPublicKey {
		t.Fatal("session was persisted")
	}
	if _, e := two.Execute(t.Context(), q, x.c.Plan.Challenge.IssuedAt); !errors.Is(e, ErrSession) {
		t.Fatal("copied permanent keys executed old grant", e)
	}
	if _, e := os.Stat(filepath.Join(two.r.path, "consumed")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("wrong session consumed", e)
	}
}
func TestResultSessionSignatureAndFullQuorumAreMandatory(t *testing.T) {
	x := newFixture(t)
	b := x.bundle(t, x.target(t, "target"))
	a := x.acceptor(t)
	for _, mutate := range []func(*Bundle){func(b *Bundle) { b.Result.SessionSignature[0] ^= 1 }, func(b *Bundle) { b.Chain = b.Chain[:1] }, func(b *Bundle) { b.Result.SessionPublicKey = f.Public(61) }, func(b *Bundle) { b.Chain[1].Votes = b.Chain[1].Votes[:2] }} {
		raw, _ := b.CanonicalBytes()
		bad, _ := DecodeBundle(raw)
		mutate(&bad)
		if _, e := a.Accept(t.Context(), bad, x.c.Plan.Challenge.IssuedAt); e == nil {
			t.Fatal("forged result accepted")
		}
		if _, e := os.Stat(filepath.Join(a.r.path, "pending")); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("bad result persisted", e)
		}
	}
	ack, e := a.Accept(t.Context(), b, x.c.Plan.Challenge.IssuedAt)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := ack.CanonicalBytes()
	again, e := a.Accept(context.Background(), b, x.c.Plan.Challenge.ExpiresAt+1000)
	after, _ := again.CanonicalBytes()
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("duplicate changed receipt", e)
	}
}
func TestOriginalPlacementContextAndRoleFilesAreEnforced(t *testing.T) {
	for _, mutation := range []string{"context", "ready", "role-file", "permissions", "symlink"} {
		t.Run(mutation, func(t *testing.T) {
			x := newFixture(t)
			target := x.target(t, "target")
			p := target.r.path
			switch mutation {
			case "context":
				b, _ := os.ReadFile(filepath.Join(p, "context"))
				b[len(b)-1] ^= 1
				_ = os.WriteFile(filepath.Join(p, "context"), b, 0600)
			case "ready":
				_ = os.WriteFile(filepath.Join(p, "ready"), make([]byte, 40), 0600)
			case "role-file":
				_ = os.WriteFile(filepath.Join(p, "accepted"), nil, 0600)
			case "permissions":
				_ = os.Chmod(p, 0755)
			case "symlink":
				_ = os.Rename(x.s.Journal, x.s.Journal+"-moved")
				_ = os.Symlink(x.s.Journal+"-moved", x.s.Journal)
			}
			if _, e := target.Prepare(); e == nil {
				t.Fatal("mutated owner authorized work")
			}
		})
	}
}
func FuzzDecodeV2Artifacts(f *testing.F) {
	raw, _ := os.ReadFile("testdata/public-fixture/context")
	f.Add(raw)
	f.Add([]byte("OMCVREQ2"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeContext(b)
		_, _ = DecodeAssignment(b)
		_, _ = DecodePlan(b)
		_, _ = DecodePolicy(b)
		_, _ = DecodeCandidate(b)
		_, _ = DecodeResult(b)
		_, _ = DecodeBundle(b)
		_, _ = DecodeReceipt(b)
		_, _ = DecodeRequest(b)
		_, _ = DecodeResponse(b)
	})
}

func TestTwoLivePermanentKeyCopiesNeedDifferentQuorumClaims(t *testing.T) {
	x := newFixture(t)
	y := newFixture(t)
	one := x.target(t, "one")
	two := y.target(t, "two")
	a, e := one.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	b, e := two.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	if a.SessionPublicKey == b.SessionPublicKey || a.Claim == b.Claim {
		t.Fatal("independent processes share session")
	}
	scope, _ := x.c.Scope()
	q := custodyfence.Certificate{Version: 1, Command: a.Claim}
	for _, seed := range []byte{70, 71, 72} {
		w, e := custodyfence.Create(filepath.Join(t.TempDir(), "witness"), scope, x.pin, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
		vote, e := w.VoteAt(custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: x.pin}}, a.Claim)
		if e != nil {
			t.Fatal(e)
		}
		q.Votes = append(q.Votes, vote)
		if _, e := w.VoteAt(custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: x.pin}, PendingID: vote.CommandID}, b.Claim); e == nil {
			t.Fatal("witness endorsed conflicting live session")
		}
		_ = w.Close()
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	if e := q.Verify(scope); e != nil {
		t.Fatal(e)
	}
	if _, e := two.Execute(t.Context(), q, y.c.Plan.Challenge.IssuedAt); !errors.Is(e, ErrSession) {
		t.Fatal("losing live copy executed winner claim", e)
	}
	if _, e := one.Execute(t.Context(), q, x.c.Plan.Challenge.IssuedAt); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(two.r.path, "consumed")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("loser changed source", e)
	}
}
func TestSessionCannotReusePersistentParticipantKey(t *testing.T) {
	x := newFixture(t)
	scope, _ := x.c.Scope()
	for _, seed := range []byte{1, 3, 4, 14, 15, 46, 61, 70} {
		pub := f.Public(seed)
		cmd, e := (custodyfence.Command{Version: 1, ScopeID: x.pin, ExpectedHead: x.pin, Kind: custodyfence.Claim, EvidenceID: SessionID(pub)}).Sign(f.Key(14))
		if e != nil {
			t.Fatal(e)
		}
		if cmd.Verify(scope) != nil {
			t.Fatal("fixture shape")
		}
		if (Candidate{Version: Version2, SessionPublicKey: pub, Claim: cmd}).Verify(x.c) == nil {
			t.Fatal("persistent role reused as execution session", seed)
		}
	}
}
func TestV2FixedDomainVectors(t *testing.T) {
	x := newFixture(t)
	assignment, _ := x.c.Assignment.ID()
	plan, _ := x.c.Plan.ID()
	contextID, _ := x.c.ID()
	scope, _ := x.c.Scope()
	candidateKey := f.Public(110)
	command, e := (custodyfence.Command{Version: 1, ScopeID: x.pin, ExpectedHead: x.pin, Kind: custodyfence.Claim, EvidenceID: SessionID(candidateKey)}).Sign(f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	candidate := Candidate{Version: Version2, SessionPublicKey: candidateKey, Claim: command}
	if e := candidate.Verify(x.c); e != nil {
		t.Fatal(e)
	}
	id, _ := command.ID()
	request := Request{Version: Version2, Operation: Execute, ScopeID: x.pin, Nonce: f.Hash("fixed-v2-request"), Prefix: []custodyfence.Certificate{f.Certificate(command, 70, 71, 72)}}
	rid, e := request.ID()
	if e != nil {
		t.Fatal(e)
	}
	if e := request.Validate(x.c); e != nil {
		t.Fatal(e)
	}
	values := map[string]types.Hash{"assignment": assignment, "plan": plan, "context": contextID, "scope": x.pin, "claim": id, "request": rid}
	expected := map[string]string{
		"assignment": "8ec09bf70d7ed849836ba78f668aea18b623ec9fe1a45e8aebb6dcc556ba9246",
		"plan":       "b768a618042f669923a63b29d7386296e45dea2b6ad7ebd5391740b1a48eb54f",
		"context":    "5b17ccd257713e9f31622056669855e6838791b5812a1cabb6ae2c4074cba33d",
		"scope":      "5470a7e3dc200b3f40d064ce61b41b27e15824d8611c4e72fb691ce844c40483",
		"claim":      "4ae54e05028e132dd7d49ff401d38d859df9d7e4e09e8098268a8ab3b7062575",
		"request":    "f3e1de3bd542267870bdad60017cfd4172db702dcd0cc4b73f8bf9239c15cab3",
	}
	for name, id := range values {
		if id.String() != expected[name] {
			t.Fatal("domain vector", name, id)
		}
	}
	legacy := scope
	legacy.Version = 0
	if command.Verify(legacy) == nil {
		t.Fatal("V1 command verified under V0")
	}
	missing := command
	missing.EvidenceID = types.Hash{}
	if _, e := missing.CanonicalBytes(); e == nil {
		t.Fatal("V1 claim omitted session")
	}
}
