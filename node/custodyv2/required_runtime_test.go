package custodyv2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

type requiredRuntimeFixture struct {
	fixture
	binding                  AdmissionBinding
	targetPath, acceptorPath string
}

func requiredRuntimeBinding(t testing.TB, c Context) AdmissionBinding {
	t.Helper()
	g, e := NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	gid, _ := g.ID()
	entry, e := (AdmissionEntry{Version: Version2, GenesisID: gid, ExpectedHead: gid, Kind: AdmissionAdmit, Context: c}).Sign(g, f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	b := AdmissionBinding{Version: Version2, Genesis: g, Chain: []AdmissionCertificate{modelAdmissionCertificate(t, entry)}}
	if e := b.Verify(c); e != nil {
		t.Fatal(e)
	}
	return b
}
func newRequiredRuntimeFixture(t testing.TB) requiredRuntimeFixture {
	t.Helper()
	x := fixtureWithContext(t, requiredProfileContext(t))
	return requiredRuntimeFixture{fixture: x, binding: requiredRuntimeBinding(t, x.c), targetPath: filepath.Join(x.root, "required-target"), acceptorPath: filepath.Join(x.root, "required-acceptor")}
}
func (x requiredRuntimeFixture) createTarget(t testing.TB) *Target {
	t.Helper()
	if e := CreateRequiredTarget(x.targetPath, x.c, x.pin, x.s, x.binding); e != nil {
		t.Fatal(e)
	}
	return x.openTarget(t)
}
func (x requiredRuntimeFixture) openTarget(t testing.TB) *Target {
	t.Helper()
	target, e := OpenRequiredTarget(x.targetPath, x.c, x.pin, x.s, x.binding, f.Key(61), f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = target.Close() })
	return target
}
func (x requiredRuntimeFixture) createAcceptor(t testing.TB) *Acceptor {
	t.Helper()
	if e := CreateRequiredAcceptor(x.acceptorPath, x.c, x.pin, x.ajournal, x.binding); e != nil {
		t.Fatal(e)
	}
	return x.openAcceptor(t)
}
func (x requiredRuntimeFixture) openAcceptor(t testing.TB) *Acceptor {
	t.Helper()
	a, e := OpenRequiredAcceptor(x.acceptorPath, x.c, x.pin, x.ajournal, x.binding, f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}
func requiredRuntimeConsumed(t testing.TB, x requiredRuntimeFixture) []byte {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join(x.targetPath, "consumed"))
	if e != nil {
		t.Fatal(e)
	}
	bid, _ := x.binding.ID()
	eid, _ := x.binding.Chain[len(x.binding.Chain)-1].Entry.ID()
	if len(raw) < 74 || string(raw[:8]) != "OMCVUSE3" || raw[8] != 0 || raw[9] != 3 || !bytes.Equal(raw[10:42], bid[:]) || !bytes.Equal(raw[42:74], eid[:]) {
		t.Fatal("consumption did not bind the exact mandatory admission", len(raw))
	}
	return raw
}
func requiredRuntimeMarker(t testing.TB, x requiredRuntimeFixture) string {
	t.Helper()
	raw, e := x.binding.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(x.targetPath)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		b, e := os.ReadFile(filepath.Join(x.targetPath, entry.Name()))
		if e == nil && bytes.Equal(b, raw) {
			return entry.Name()
		}
	}
	t.Fatal("canonical admission binding not retained in original root")
	return ""
}

func TestRequiredRuntimeExecutesOnlyWithExactAdmittedRoot(t *testing.T) {
	x := newRequiredRuntimeFixture(t)
	rawTarget, rawA := filepath.Join(x.root, "raw-target"), filepath.Join(x.root, "raw-acceptor")
	if e := CreateTarget(rawTarget, x.c, x.pin, x.s); e == nil {
		t.Fatal("raw Target created mandatory job")
	}
	if _, e := os.Lstat(rawTarget); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("refused raw target wrote files", e)
	}
	if e := CreateAcceptor(rawA, x.c, x.pin, x.ajournal); e == nil {
		t.Fatal("raw Acceptor created mandatory job")
	}
	if _, e := os.Lstat(rawA); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("refused raw acceptor wrote files", e)
	}
	target := x.createTarget(t)
	a := x.createAcceptor(t)
	target.r.hook = func(stage string) error {
		if stage == "before-effect" {
			requiredRuntimeConsumed(t, x)
			state, e := target.r.decision.State()
			if e != nil || state.Sequence != 0 {
				t.Fatal("source advanced before admission consumption", state, e)
			}
		}
		return nil
	}
	b := x.bundle(t, target)
	before := requiredRuntimeConsumed(t, x)
	receipt, e := a.Accept(t.Context(), b, x.c.Plan.Challenge.IssuedAt)
	if e != nil {
		t.Fatal(e)
	}
	if e := receipt.Verify(x.c, b); e != nil {
		t.Fatal(e)
	}
	for _, r := range []*root{target.r, a.r} {
		s, e := r.decision.State()
		if e != nil || s.Sequence != 1 {
			t.Fatal("expected exactly one original append", s, e)
		}
	}
	_ = target.Close()
	_ = a.Close()
	if old, e := OpenTarget(x.targetPath, x.c, x.pin, x.s, f.Key(61), f.Key(14)); e == nil {
		_ = old.Close()
		t.Fatal("raw API opened mandatory Target")
	}
	if old, e := OpenAcceptor(x.acceptorPath, x.c, x.pin, x.ajournal, f.Key(1)); e == nil {
		_ = old.Close()
		t.Fatal("raw API opened mandatory Acceptor")
	}
	target = x.openTarget(t)
	a = x.openAcceptor(t)
	if _, e := target.Prepare(); !errors.Is(e, ErrConsumed) {
		t.Fatal("cold mandatory target granted another session", e)
	}
	if _, e := target.Execute(t.Context(), b.Chain[0], x.c.Plan.Challenge.IssuedAt); !errors.Is(e, ErrConsumed) {
		t.Fatal("cold mandatory target repeated effect", e)
	}
	recovered, e := target.ReadResult()
	if e != nil {
		t.Fatal(e)
	}
	want, _ := b.Result.ID()
	got, _ := recovered.ID()
	if got != want || !bytes.Equal(before, requiredRuntimeConsumed(t, x)) {
		t.Fatal("cold recovery changed admission/result")
	}
	cached, e := a.ReadReceipt()
	if e != nil || cached != receipt {
		t.Fatal("cold original acceptance changed", e)
	}
}

func TestRequiredRuntimeCrashPreservesAdmittedConsumption(t *testing.T) {
	for _, stage := range []string{"consumed-before-sync", "consumed-durable", "before-effect", "result-before-sync"} {
		t.Run(stage, func(t *testing.T) {
			x := newRequiredRuntimeFixture(t)
			target := x.createTarget(t)
			candidate, e := target.Prepare()
			if e != nil {
				t.Fatal(e)
			}
			claim := f.Certificate(candidate.Claim, 70, 71, 72)
			target.r.hook = func(at string) error {
				if at == stage {
					return errors.New("injected mandatory runtime crash")
				}
				return nil
			}
			if _, e := target.Execute(t.Context(), claim, x.c.Plan.Challenge.IssuedAt); e == nil {
				t.Fatal("injected crash missing")
			}
			requiredRuntimeConsumed(t, x)
			_ = target.Close()
			target = x.openTarget(t)
			if _, e := target.Prepare(); !errors.Is(e, ErrConsumed) {
				t.Fatal("crash reissued admission/session", e)
			}
			if _, e := target.Execute(t.Context(), claim, x.c.Plan.Challenge.IssuedAt); !errors.Is(e, ErrConsumed) {
				t.Fatal("crash repeated effect", e)
			}
			state, e := target.r.decision.State()
			if e != nil {
				t.Fatal(e)
			}
			want := uint64(0)
			if stage == "result-before-sync" {
				want = 1
			}
			if state.Sequence != want {
				t.Fatal("cold open appended source", state.Sequence)
			}
			result, e := target.ReadResult()
			if stage == "result-before-sync" {
				if e != nil || result.Entry.Sequence != 1 {
					t.Fatal("durable candidate result not recovered", e)
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				t.Fatal("unknown outcome gained a result", e)
			}
			status, e := target.ServeStatus()
			if e != nil || !status.Pending || !status.ArchiveHeld {
				t.Fatal("mandatory unknown/result released Serve", status, e)
			}
		})
	}
}

func TestRequiredRuntimeRejectsIncompleteOrWrongBindingBeforeWrites(t *testing.T) {
	x := newRequiredRuntimeFixture(t)
	other := x.c
	other.Plan.ClientTransportPublicKey = f.Public(48)
	other = modelAdmissionResign(t, other)
	raw, _ := x.binding.CanonicalBytes()
	for _, kind := range []string{"weak", "missing", "wrong-context", "wrong-genesis"} {
		t.Run(kind, func(t *testing.T) {
			bad, e := DecodeAdmissionBinding(raw)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "weak":
				bad.Chain[0].Votes = bad.Chain[0].Votes[:2]
			case "missing":
				bad.Chain = nil
			case "wrong-context":
				bad = requiredRuntimeBinding(t, other)
			case "wrong-genesis":
				bad.Genesis.Assignment.Policy.Version = Version2
			}
			if e := bad.Verify(x.c); e == nil {
				t.Fatal("invalid binding verified")
			}
			tp, ap := filepath.Join(x.root, kind+"-target"), filepath.Join(x.root, kind+"-acceptor")
			if e := CreateRequiredTarget(tp, x.c, x.pin, x.s, bad); e == nil {
				t.Fatal("invalid target binding accepted")
			}
			if e := CreateRequiredAcceptor(ap, x.c, x.pin, x.ajournal, bad); e == nil {
				t.Fatal("invalid acceptor binding accepted")
			}
			for _, p := range []string{tp, ap} {
				if _, e := os.Lstat(p); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("invalid binding wrote owner root", p, e)
				}
			}
		})
	}
}

func TestRequiredRuntimeRootBindingIsImmutableAndNotLegacy(t *testing.T) {
	x := newRequiredRuntimeFixture(t)
	target := x.createTarget(t)
	name := requiredRuntimeMarker(t, x)
	_ = target.Close()
	raw, _ := x.binding.CanonicalBytes()
	alternate, e := DecodeAdmissionBinding(raw)
	if e != nil {
		t.Fatal(e)
	}
	alternate.Chain[0].Votes = nil
	for _, seed := range []byte{70, 71, 73} {
		vote, e := signAdmissionVote(alternate.Chain[0].Entry, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
		alternate.Chain[0].Votes = append(alternate.Chain[0].Votes, vote)
	}
	sort.Slice(alternate.Chain[0].Votes, func(i, j int) bool {
		return bytes.Compare(alternate.Chain[0].Votes[i].Witness[:], alternate.Chain[0].Votes[j].Witness[:]) < 0
	})
	if e := alternate.Verify(x.c); e != nil {
		t.Fatal(e)
	}
	otherRaw, _ := alternate.CanonicalBytes()
	if bytes.Equal(raw, otherRaw) {
		t.Fatal("alternate proof subset unchanged")
	}
	if e := os.WriteFile(filepath.Join(x.targetPath, name), otherRaw, 0600); e != nil {
		t.Fatal(e)
	}
	if t2, e := OpenRequiredTarget(x.targetPath, x.c, x.pin, x.s, x.binding, f.Key(61), f.Key(14)); e == nil {
		_ = t2.Close()
		t.Fatal("substituted retained binding accepted")
	}
	if e := os.WriteFile(filepath.Join(x.targetPath, name), raw, 0600); e != nil {
		t.Fatal(e)
	}
	target = x.openTarget(t)
	_ = target.Close()
	legacy := newFixture(t)
	lp := filepath.Join(legacy.root, "legacy")
	if e := CreateTarget(lp, legacy.c, legacy.pin, legacy.s); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(lp, name), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if old, e := OpenTarget(lp, legacy.c, legacy.pin, legacy.s, f.Key(61), f.Key(14)); e == nil {
		_ = old.Close()
		t.Fatal("legacy root imported mandatory binding")
	}
}

func TestRequiredRuntimeClosedBindingAndAdvancedSourcesCannotGrant(t *testing.T) {
	x := newRequiredRuntimeFixture(t)
	target := x.createTarget(t)
	a := x.createAcceptor(t)
	serve := unclaimedServe(t, x.c)
	ar, e := a.ApplyServe(t.Context(), serve, x.c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	br, e := target.ApplyServe(t.Context(), serve, ar, x.c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	gid, _ := x.binding.Genesis.ID()
	s, e := NewAdmissionState(x.binding.Genesis, gid)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.Apply(x.binding.Chain[0]); e != nil {
		t.Fatal(e)
	}
	closeEntry := modelAdmissionEntry(t, x.binding.Genesis, s, x.c, AdmissionClose, &AdmissionClosure{Serve: serve, A: ar, B: br})
	closed := x.binding
	closed.Chain = append(append([]AdmissionCertificate{}, x.binding.Chain...), modelAdmissionCertificate(t, closeEntry))
	if e := closed.Verify(x.c); e == nil {
		t.Fatal("terminal accounting history became an active execution grant")
	}
	_ = target.Close()
	_ = a.Close()
	tp := filepath.Join(x.root, "closed-binding")
	if e := CreateRequiredTarget(tp, x.c, x.pin, x.s, closed); e == nil {
		t.Fatal("closed binding created executable root")
	}
	if _, e := os.Lstat(tp); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("closed binding wrote root")
	}
	// A historical active packet cannot reset an original source after its real
	// job has already appended a result, even through a fresh owner pathname.
	fresh := newRequiredRuntimeFixture(t)
	target = fresh.createTarget(t)
	a = fresh.createAcceptor(t)
	b := fresh.bundle(t, target)
	if _, e := a.Accept(t.Context(), b, fresh.c.Plan.Challenge.IssuedAt); e != nil {
		t.Fatal(e)
	}
	_ = target.Close()
	_ = a.Close()
	tp, ap := filepath.Join(fresh.root, "advanced-target"), filepath.Join(fresh.root, "advanced-acceptor")
	if e := CreateRequiredTarget(tp, fresh.c, fresh.pin, fresh.s, fresh.binding); e == nil {
		t.Fatal("historical admission reset B source")
	}
	if e := CreateRequiredAcceptor(ap, fresh.c, fresh.pin, fresh.ajournal, fresh.binding); e == nil {
		t.Fatal("historical admission reset A source")
	}
	for _, p := range []string{tp, ap} {
		if _, e := os.Lstat(p); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("advanced source rejection created root", e)
		}
	}
}

// The original job fence remains independent: a binding cannot substitute its
// accounting QC for a session Claim quorum.
func TestRequiredRuntimeAdmissionQCIsNotAnExecutionClaim(t *testing.T) {
	x := newRequiredRuntimeFixture(t)
	target := x.createTarget(t)
	if _, e := target.Prepare(); e != nil {
		t.Fatal(e)
	}
	q := custodyfence.Certificate{}
	if _, e := target.Execute(t.Context(), q, x.c.Plan.Challenge.IssuedAt); e == nil {
		t.Fatal("missing session claim executed mandatory admission")
	}
	if _, e := os.Lstat(filepath.Join(x.targetPath, "consumed")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("invalid Claim consumed admission", e)
	}
	state, e := target.r.decision.State()
	if e != nil || state.Sequence != 0 {
		t.Fatal("invalid Claim advanced source", state, e)
	}
}

func TestRequiredRuntimeDoesNotReadChunksBeforeAdmissionConsumption(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			x := newRequiredRuntimeFixture(t)
			chunk := filepath.Join(x.s.Objects, "chunk-"+x.c.Manifest.Chunks[0].ID.String()+".omwc")
			original, e := os.ReadFile(chunk)
			if e != nil {
				t.Fatal(e)
			}
			if kind == "missing" {
				e = os.Remove(chunk)
			} else {
				e = os.WriteFile(chunk, []byte("deliberately invalid chunk"), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			// Both owner open and session preparation must be metadata-only. If either
			// scans/hash-verifies the corrupted chunk, it crossed the effect boundary.
			target := x.createTarget(t)
			candidate, e := target.Prepare()
			if e != nil {
				t.Fatal("Prepare inspected chunk contents before consumption", e)
			}
			if _, e := os.Lstat(filepath.Join(x.targetPath, "consumed")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("Prepare consumed an admission", e)
			}
			claim := f.Certificate(candidate.Claim, 70, 71, 72)
			if _, e := target.Execute(t.Context(), claim, x.c.Plan.Challenge.IssuedAt); e == nil {
				t.Fatal("missing/corrupt current chunk answered custody")
			}
			requiredRuntimeConsumed(t, x)
			state, e := target.r.decision.State()
			if e != nil || state.Sequence != 0 {
				t.Fatal("failed chunk read advanced original source", state, e)
			}
			if _, e := target.ReadResult(); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("failed chunk read fabricated a result", e)
			}
			if s, e := target.ServeStatus(); e != nil || !s.Pending || !s.ArchiveHeld {
				t.Fatal("failed chunk read released obligation", s, e)
			}
			_ = target.Close()
			// Repairing the chunk is not a retry grant. The exact consumed unknown job
			// remains consumed after cold open, without another proof or source append.
			if e := os.WriteFile(chunk, original, 0600); e != nil {
				t.Fatal(e)
			}
			target = x.openTarget(t)
			if _, e := target.Prepare(); !errors.Is(e, ErrConsumed) {
				t.Fatal("chunk repair reissued session", e)
			}
			if _, e := target.Execute(t.Context(), claim, x.c.Plan.Challenge.IssuedAt); !errors.Is(e, ErrConsumed) {
				t.Fatal("chunk repair replayed consumed admission", e)
			}
		})
	}
}

func TestRequiredRuntimeAdmissionBoundPendingRequiresExplicitAResume(t *testing.T) {
	for _, stage := range []string{"pending-before-sync", "source-accepted-before-receipt"} {
		t.Run(stage, func(t *testing.T) {
			x := newRequiredRuntimeFixture(t)
			target := x.createTarget(t)
			a := x.createAcceptor(t)
			bundle := x.bundle(t, target)
			a.r.hook = func(at string) error {
				if at == stage {
					return errors.New("injected required acceptance failure")
				}
				return nil
			}
			if _, e := a.Accept(t.Context(), bundle, x.c.Plan.Challenge.IssuedAt); e == nil {
				t.Fatal("acceptance failure missing")
			}
			pending, e := os.ReadFile(filepath.Join(x.acceptorPath, "pending"))
			if e != nil {
				t.Fatal(e)
			}
			bid, _ := x.binding.ID()
			eid, _ := x.binding.Chain[0].Entry.ID()
			if len(pending) < 74 || string(pending[:8]) != "OMCVPEN3" || pending[8] != 0 || pending[9] != 3 || !bytes.Equal(pending[10:42], bid[:]) || !bytes.Equal(pending[42:74], eid[:]) {
				t.Fatal("A pending record omitted exact admission binding")
			}
			_ = a.Close()
			a = x.openAcceptor(t)
			state, e := a.r.decision.State()
			if e != nil {
				t.Fatal(e)
			}
			want := uint64(0)
			if stage == "source-accepted-before-receipt" {
				want = 1
			}
			if state.Sequence != want {
				t.Fatal("cold A open implicitly appended", state.Sequence)
			}
			if _, e := a.Resume(t.Context(), f.Hash("wrong-required-bundle"), x.c.Plan.Challenge.IssuedAt); !errors.Is(e, ErrPending) {
				t.Fatal("wrong exact resume accepted", e)
			}
			bundleID, _ := bundle.ID()
			now := x.c.Plan.Challenge.IssuedAt + 1
			if want == 1 {
				now = x.c.Plan.Challenge.ExpiresAt + 1000
			}
			receipt, e := a.Resume(t.Context(), bundleID, now)
			if e != nil {
				t.Fatal(e)
			}
			if receipt.AcceptedAt != x.c.Plan.Challenge.IssuedAt {
				t.Fatal("required A recovery refreshed proof time")
			}
			state, e = a.r.decision.State()
			if e != nil || state.Sequence != 1 {
				t.Fatal("required A resume did not publish one original append", state, e)
			}
		})
	}
}

func TestRequiredRuntimeCopiedAndMovedOwnersCannotImportAdmission(t *testing.T) {
	for _, kind := range []string{"copy", "move"} {
		t.Run(kind, func(t *testing.T) {
			x := newRequiredRuntimeFixture(t)
			target := x.createTarget(t)
			_ = target.Close()
			other := filepath.Join(x.root, "other-required-target")
			if kind == "copy" {
				copyAdmissionWitnessRoot(t, x.targetPath, other)
			} else if e := os.Rename(x.targetPath, other); e != nil {
				t.Fatal(e)
			}
			if moved, e := OpenRequiredTarget(other, x.c, x.pin, x.s, x.binding, f.Key(61), f.Key(14)); e == nil {
				_ = moved.Close()
				t.Fatal("admission opened a copied/moved original owner")
			}
			if kind == "move" {
				if e := os.Rename(other, x.targetPath); e != nil {
					t.Fatal(e)
				}
			}
			target = x.openTarget(t)
			candidate, e := target.Prepare()
			if e != nil || candidate.Verify(x.c) != nil {
				t.Fatal("rejected placement damaged original admission owner", e)
			}
			if _, e := os.Lstat(filepath.Join(x.targetPath, "consumed")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("placement review consumed admission", e)
			}
		})
	}
}

func TestRequiredRuntimeColdRecordsRejectAdmissionIdentitySubstitution(t *testing.T) {
	for _, kind := range []string{"consumed-binding", "consumed-entry", "pending-binding", "pending-entry"} {
		t.Run(kind, func(t *testing.T) {
			x := newRequiredRuntimeFixture(t)
			target := x.createTarget(t)
			a := x.createAcceptor(t)
			bundle := x.bundle(t, target)
			receipt, e := a.Accept(t.Context(), bundle, x.c.Plan.Challenge.IssuedAt)
			if e != nil {
				t.Fatal(e)
			}
			_ = target.Close()
			_ = a.Close()
			role := "consumed"
			owner := x.targetPath
			if kind == "pending-binding" || kind == "pending-entry" {
				role = "pending"
				owner = x.acceptorPath
			}
			p := filepath.Join(owner, role)
			original, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			corrupt := append([]byte{}, original...)
			offset := 10
			if kind == "consumed-entry" || kind == "pending-entry" {
				offset = 42
			}
			corrupt[offset] ^= 1
			if e := os.WriteFile(p, corrupt, 0600); e != nil {
				t.Fatal(e)
			}
			if role == "consumed" {
				if opened, e := OpenRequiredTarget(x.targetPath, x.c, x.pin, x.s, x.binding, f.Key(61), f.Key(14)); e == nil {
					_ = opened.Close()
					t.Fatal("changed consumed admission identity accepted")
				}
			} else {
				if opened, e := OpenRequiredAcceptor(x.acceptorPath, x.c, x.pin, x.ajournal, x.binding, f.Key(1)); e == nil {
					_ = opened.Close()
					t.Fatal("changed pending admission identity accepted")
				}
			}
			if e := os.WriteFile(p, original, 0600); e != nil {
				t.Fatal(e)
			}
			target = x.openTarget(t)
			a = x.openAcceptor(t)
			for _, r := range []*root{target.r, a.r} {
				s, e := r.decision.State()
				if e != nil || s.Sequence != 1 {
					t.Fatal("identity refusal changed original source", s, e)
				}
			}
			cached, e := a.ReadReceipt()
			if e != nil || cached != receipt {
				t.Fatal("identity refusal changed original accepted receipt", e)
			}
		})
	}
}
