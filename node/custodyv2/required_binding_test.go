package custodyv2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func bindingTestContext(t testing.TB) Context {
	t.Helper()
	c := requiredProfileContext(t)
	c.Assignment.Base.MaximumOperations = 4
	c.Assignment.Base.MaximumPending = 2
	aid, e := c.Assignment.ID()
	if e != nil {
		t.Fatal(e)
	}
	c.Plan.AssignmentID = aid
	c.Plan.Intent.AssignmentID = aid
	return modelAdmissionResign(t, c)
}
func bindingTestAdmission(t testing.TB, c Context) (AdmissionBinding, *AdmissionState) {
	t.Helper()
	g, e := NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	gid, _ := g.ID()
	state, e := NewAdmissionState(g, gid)
	if e != nil {
		t.Fatal(e)
	}
	q := modelAdmissionCertificate(t, modelAdmissionEntry(t, g, state, c, AdmissionAdmit, nil))
	if e := state.Apply(q); e != nil {
		t.Fatal(e)
	}
	b := AdmissionBinding{Version: Version2, Genesis: g, Chain: []AdmissionCertificate{q}}
	if e := b.Verify(c); e != nil {
		t.Fatal(e)
	}
	return b, state
}
func bindingTestOwners(t testing.TB, c Context, b AdmissionBinding) (fixture, *Target, *Acceptor) {
	t.Helper()
	x := fixtureWithContext(t, c)
	tp, ap := filepath.Join(x.root, "required-target"), filepath.Join(x.root, "required-acceptor")
	if e := CreateRequiredTarget(tp, c, x.pin, x.s, b); e != nil {
		t.Fatal(e)
	}
	target, e := OpenRequiredTarget(tp, c, x.pin, x.s, b, f.Key(61), f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = target.Close() })
	if e := CreateRequiredAcceptor(ap, c, x.pin, x.ajournal, b); e != nil {
		t.Fatal(e)
	}
	a, e := OpenRequiredAcceptor(ap, c, x.pin, x.ajournal, b, f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = a.Close() })
	return x, target, a
}
func bindingTestAppendClose(t testing.TB, b AdmissionBinding, state *AdmissionState, c Context, closure AdmissionClosure) AdmissionBinding {
	t.Helper()
	q := modelAdmissionCertificate(t, modelAdmissionEntry(t, b.Genesis, state, c, AdmissionClose, &closure))
	if e := state.Apply(q); e != nil {
		t.Fatal(e)
	}
	b.Chain = append(append([]AdmissionCertificate{}, b.Chain...), q)
	return b
}
func bindingTestFenceOwners(t testing.TB, c Context) (custodyfence.Scope, []*custodyfence.Witness) {
	t.Helper()
	scope, e := c.Scope()
	if e != nil {
		t.Fatal(e)
	}
	sid, _ := scope.ID()
	var owners []*custodyfence.Witness
	for seed := byte(70); seed < 74; seed++ {
		w, e := custodyfence.Create(filepath.Join(t.TempDir(), "execution-witness"), scope, sid, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = w.Close() })
		owners = append(owners, w)
	}
	return scope, owners
}
func bindingTestFenceVote(t testing.TB, scope custodyfence.Scope, owners []*custodyfence.Witness, cmd custodyfence.Command) custodyfence.Certificate {
	t.Helper()
	q := custodyfence.Certificate{Version: scope.Version, Command: cmd}
	for _, w := range owners[:3] {
		_, pin, e := w.Snapshot()
		if e != nil {
			t.Fatal(e)
		}
		v, e := w.VoteAt(pin, cmd)
		if e != nil {
			t.Fatal(e)
		}
		q.Votes = append(q.Votes, v)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	if e := q.Verify(scope); e != nil {
		t.Fatal(e)
	}
	return q
}
func bindingTestFenceCommit(t testing.TB, owners []*custodyfence.Witness, q custodyfence.Certificate) {
	t.Helper()
	for _, w := range owners {
		_, pin, e := w.Snapshot()
		if e != nil {
			t.Fatal(e)
		}
		if e := w.CommitAt(pin, q); e != nil {
			t.Fatal(e)
		}
	}
}
func bindingTestConflictingVotes(t testing.TB, scope custodyfence.Scope, owners []*custodyfence.Witness, cmd custodyfence.Command) {
	t.Helper()
	q := custodyfence.Certificate{Version: scope.Version, Command: cmd}
	sid, _ := scope.ID()
	before := custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: sid}}
	for _, w := range owners {
		if v, e := w.VoteAt(before, cmd); e == nil {
			q.Votes = append(q.Votes, v)
		}
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	if len(q.Votes) > 1 || q.Verify(scope) == nil {
		t.Fatal("original Claim and Unclaimed both obtained a quorum", len(q.Votes))
	}
}
func bindingTestCancelCommand(t testing.TB, c Context) custodyfence.Command {
	t.Helper()
	scope, e := c.Scope()
	if e != nil {
		t.Fatal(e)
	}
	sid, _ := scope.ID()
	cmd, e := (custodyfence.Command{Version: scope.Version, ScopeID: sid, ExpectedHead: sid, Kind: custodyfence.CloseUnclaimed, EvidenceID: f.Hash("required-binding-no-claim")}).Sign(f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	return cmd
}

func TestRequiredBindingCompletePrefixAndCanonicalPacket(t *testing.T) {
	c := bindingTestContext(t)
	first, state := bindingTestAdmission(t, c)
	raw, e := first.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	back, e := DecodeAdmissionBinding(raw)
	if e != nil || back.Verify(c) != nil {
		t.Fatal("valid binding round trip", e)
	}
	again, _ := back.CanonicalBytes()
	if !bytes.Equal(raw, again) {
		t.Fatal("binding bytes changed")
	}
	id, e := first.ID()
	if e != nil {
		t.Fatal(e)
	}
	const expected = "7a8b00412081f526f6ea278568eda0ad5d699f7fa7a5f99ae7afa3333fb5277d"
	if id.String() != expected {
		t.Fatal("binding canonical vector changed", id)
	}
	_, target, a := bindingTestOwners(t, c, first)
	serve := unclaimedServe(t, c)
	ar, e := a.ApplyServe(t.Context(), serve, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	br, e := target.ApplyServe(t.Context(), serve, ar, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	closed := bindingTestAppendClose(t, first, state, c, AdmissionClosure{Serve: serve, A: ar, B: br})
	if e := closed.Verify(c); e == nil {
		t.Fatal("closed prefix authorized a new execution")
	}
	next := c
	next.Plan.ClientTransportPublicKey = f.Public(47)
	next = modelAdmissionResign(t, next)
	q := modelAdmissionCertificate(t, modelAdmissionEntry(t, first.Genesis, state, next, AdmissionAdmit, nil))
	if e := state.Apply(q); e != nil {
		t.Fatal(e)
	}
	full := closed
	full.Chain = append(append([]AdmissionCertificate{}, closed.Chain...), q)
	if e := full.Verify(next); e != nil {
		t.Fatal("complete successor prefix", e)
	}
	if e := full.Verify(c); e == nil {
		t.Fatal("different active job authorized original context")
	}
	for name, b := range map[string]AdmissionBinding{
		"detached-successor": {Version: Version2, Genesis: first.Genesis, Chain: []AdmissionCertificate{q}},
		"gap":                {Version: Version2, Genesis: first.Genesis, Chain: []AdmissionCertificate{first.Chain[0], q}},
		"reordered":          {Version: Version2, Genesis: first.Genesis, Chain: []AdmissionCertificate{closed.Chain[1], first.Chain[0], q}},
		"duplicate-prefix":   {Version: Version2, Genesis: first.Genesis, Chain: []AdmissionCertificate{first.Chain[0], first.Chain[0], q}},
	} {
		t.Run(name, func(t *testing.T) {
			if e := b.Verify(next); e == nil {
				t.Fatal("incomplete/noncontiguous history verified")
			}
		})
	}
	for name, mutate := range map[string]func(*AdmissionBinding){
		"empty": func(b *AdmissionBinding) { b.Chain = nil }, "version": func(b *AdmissionBinding) { b.Version = 3 },
		"weak":            func(b *AdmissionBinding) { b.Chain[0].Votes = b.Chain[0].Votes[:2] },
		"duplicate-votes": func(b *AdmissionBinding) { v := b.Chain[0].Votes[0]; b.Chain[0].Votes = []AdmissionVote{v, v, v} },
		"descriptor":      func(b *AdmissionBinding) { b.Genesis.CustodyPolicy.MaximumProofAge++ },
		"wrong-genesis": func(b *AdmissionBinding) {
			other := bindingTestContext(t)
			other.Assignment.Base.MaximumOperations = 6
			aid, _ := other.Assignment.ID()
			other.Plan.AssignmentID = aid
			other.Plan.Intent.AssignmentID = aid
			other = modelAdmissionResign(t, other)
			b.Genesis, _ = NewAdmissionGenesis(other)
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, e := DecodeAdmissionBinding(raw)
			if e != nil {
				t.Fatal(e)
			}
			mutate(&b)
			if e := b.Verify(c); e == nil {
				t.Fatal("invalid binding verified")
			}
		})
	}
	wrong := c
	wrong.Plan.ClientTransportPublicKey = f.Public(48)
	wrong = modelAdmissionResign(t, wrong)
	if e := first.Verify(wrong); e == nil {
		t.Fatal("unadmitted Context authorized")
	}
	if e := first.Verify(fixtureContext(t)); e == nil {
		t.Fatal("required binding authorized legacy profile")
	}
	for _, bad := range [][]byte{raw[:len(raw)-1], append(append([]byte{}, raw...), 0), append([]byte("OMCVBND2\x00\x03"), raw[10:]...)} {
		if _, e := DecodeAdmissionBinding(bad); e == nil {
			t.Fatal("noncanonical or unknown-version binding accepted")
		}
	}
	for _, r := range []*root{target.r, a.r} {
		s, e := r.decision.State()
		if e != nil || s.Sequence != 0 {
			t.Fatal("accounting prefix changed original source", e)
		}
	}
}

func TestRequiredBindingStaleAdmissionCannotCrossUnclaimedQuorum(t *testing.T) {
	c := bindingTestContext(t)
	binding, state := bindingTestAdmission(t, c)
	x, target, a := bindingTestOwners(t, c, binding)
	scope, owners := bindingTestFenceOwners(t, c)
	candidate, e := target.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	noClaim := bindingTestFenceVote(t, scope, owners, bindingTestCancelCommand(t, c))
	bindingTestConflictingVotes(t, scope, owners, candidate.Claim)
	bindingTestFenceCommit(t, owners, noClaim)
	// The old active prefix remains valid historical evidence. Its exact original
	// execution slot, including a prepared live session, can no longer get Claim.
	if e := binding.Verify(c); e != nil {
		t.Fatal("historical prefix changed", e)
	}
	bindingTestConflictingVotes(t, scope, owners, candidate.Claim)
	p, e := NewServeUnclaimed(c, noClaim)
	if e != nil {
		t.Fatal(e)
	}
	serve := signedServe(t, c, p)
	ar, e := a.ApplyServe(t.Context(), serve, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	br, e := target.ApplyServe(t.Context(), serve, ar, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	closed := bindingTestAppendClose(t, binding, state, c, AdmissionClosure{Serve: serve, A: ar, B: br})
	if e := closed.Verify(c); e == nil {
		t.Fatal("closed proof authorized")
	}
	if _, e := target.Prepare(); !errors.Is(e, ErrServeClosed) {
		t.Fatal("original cancelled owner prepared", e)
	}
	if e := target.Close(); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(x.root, "fresh-stale-prefix-target")
	if e := CreateRequiredTarget(path, c, x.pin, x.s, binding); e != nil {
		t.Fatal(e)
	}
	fresh, e := OpenRequiredTarget(path, c, x.pin, x.s, binding, f.Key(61), f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	newCandidate, e := fresh.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	if newCandidate.SessionPublicKey == candidate.SessionPublicKey {
		t.Fatal("stale prefix imported a volatile session")
	}
	bindingTestConflictingVotes(t, scope, owners, newCandidate.Claim)
	source, e := fresh.r.decision.State()
	if e != nil || source.Sequence != 0 {
		t.Fatal("stale prefix executed", e)
	}
	if _, e := os.Lstat(filepath.Join(path, "consumed")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("stale prefix invented consumed record", e)
	}
}

func TestRequiredBindingClaimQuorumConsumptionAndSourceAdvance(t *testing.T) {
	c := bindingTestContext(t)
	binding, state := bindingTestAdmission(t, c)
	x, target, a := bindingTestOwners(t, c, binding)
	scope, owners := bindingTestFenceOwners(t, c)
	candidate, e := target.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	claim := bindingTestFenceVote(t, scope, owners, candidate.Claim)
	bindingTestConflictingVotes(t, scope, owners, bindingTestCancelCommand(t, c))
	bindingTestFenceCommit(t, owners, claim)
	result, e := target.Execute(t.Context(), claim, c.Plan.Challenge.IssuedAt)
	if e != nil {
		t.Fatal(e)
	}
	recovered, command, e := target.ResultCommand([]custodyfence.Certificate{claim})
	if e != nil {
		t.Fatal(e)
	}
	one, _ := result.ID()
	two, _ := recovered.ID()
	if one != two {
		t.Fatal("recovery changed result")
	}
	resultQC := bindingTestFenceVote(t, scope, owners, command)
	bindingTestFenceCommit(t, owners, resultQC)
	bundle := Bundle{Version: Version2, Result: result, Chain: []custodyfence.Certificate{claim, resultQC}}
	receipt, e := a.Accept(t.Context(), bundle, c.Plan.Challenge.IssuedAt)
	if e != nil {
		t.Fatal(e)
	}
	proposal, e := NewServeFulfilled(c, bundle, receipt)
	if e != nil {
		t.Fatal(e)
	}
	serve := signedServe(t, c, proposal)
	ar, e := a.ApplyServe(t.Context(), serve, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	br, e := target.ApplyServe(t.Context(), serve, ar, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	closed := bindingTestAppendClose(t, binding, state, c, AdmissionClosure{Serve: serve, A: ar, B: br})
	next := c
	next.Previous = result.Entry.Record.RenewedReceipt
	head, _ := result.Entry.ID()
	rid, _ := next.Previous.ID()
	challenge, e := workarchive.CreateCustodyChallenge(c.Manifest, next.Previous, f.Key(3), next.Previous.StoredAt+1, 60, 1, next.Previous.RetainUntil+3600)
	if e != nil {
		t.Fatal(e)
	}
	next.Plan.Challenge = challenge
	intent := &next.Plan.Intent
	intent.PriorSequence = result.Entry.Sequence
	intent.PriorHeadID = head
	intent.PriorReceiptID = rid
	intent.IssuedAt = challenge.IssuedAt
	intent.ExpiresAt = challenge.ExpiresAt
	intent.RenewUntil = challenge.RenewUntil
	intent.RequestedSamples = challenge.RequestedSamples
	intent.Nonce = challenge.Nonce
	next = modelAdmissionResign(t, next)
	q := modelAdmissionCertificate(t, modelAdmissionEntry(t, binding.Genesis, state, next, AdmissionAdmit, nil))
	if e := state.Apply(q); e != nil {
		t.Fatal(e)
	}
	successor := closed
	successor.Chain = append(append([]AdmissionCertificate{}, closed.Chain...), q)
	if e := successor.Verify(next); e != nil {
		t.Fatal("valid current-source successor rejected", e)
	}
	if e := successor.Verify(c); e == nil {
		t.Fatal("successor proof authorized old job")
	}
	if e := binding.Verify(c); e != nil {
		t.Fatal("old historical Admit changed", e)
	}
	if _, e := target.Execute(t.Context(), claim, c.Plan.Challenge.IssuedAt); e == nil {
		t.Fatal("stale Admit reexecuted after consumption")
	}
	for _, r := range []*root{target.r, a.r} {
		s, e := r.decision.State()
		if e != nil || s.Sequence != 1 || s.HeadEntryID != head {
			t.Fatal("required execution/source cursor changed unexpectedly", s, e)
		}
	}
	_ = target.Close()
	_ = a.Close()
	stalePath := filepath.Join(x.root, "old-job-new-root")
	if e := CreateRequiredTarget(stalePath, c, x.pin, x.s, binding); e == nil {
		t.Fatal("historical admission rewound the original source")
	}
	if _, e := os.Lstat(stalePath); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("stale source refusal created owner root", e)
	}
}

func requiredBindingForgedCount(t testing.TB) []byte {
	t.Helper()
	g, err := NewAdmissionGenesis(requiredProfileContext(t))
	if err != nil {
		t.Fatal(err)
	}
	// Genesis is a public descriptor, not a signed Plan. A remote malformed
	// packet can advertise the largest legal budget without signing any new
	// job, before the complete delivery's Context comparison takes place.
	g.Assignment.Base.MaximumOperations = custodyauthority.MaximumOperations
	raw, err := g.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	count := MaxAdmissionEntries(g)
	if count != 65_538 {
		t.Fatal("unexpected maximum admission entry count", count)
	}
	out := codec.NewEncoder(len(raw) + int(count) + 32)
	out.Fixed([]byte("OMCVBND2"))
	out.U16(Version2)
	out.BytesField(raw)
	out.U32(uint32(count))
	// One byte for every declared entry satisfies the outer remaining-byte
	// guard. Every zero advertises an empty, consequently invalid certificate.
	out.Fixed(make([]byte, int(count)))
	return out.Bytes()
}

func TestRequiredBindingForgedCountDoesNotAllocateDeclaredHistory(t *testing.T) {
	raw := requiredBindingForgedCount(t)
	if len(raw) >= 128<<10 {
		t.Fatal("small malicious-count regression fixture grew unexpectedly", len(raw))
	}
	// These package tests are sequential. The generous bound tolerates minor
	// background/runtime allocations while catching the former eager 65,538
	// Context-bearing slots (over 160 MiB) in one decode, without repeatedly
	// allocating that regression amount in a benchmark calibration loop.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := DecodeAdmissionBinding(raw)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("forged maximum certificate count decoded")
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated >= 16<<20 {
		t.Fatal("malformed binding allocated the advertised history", allocated)
	}
	t.Logf("%d-byte malformed binding allocated %d bytes before refusal", len(raw), allocated)
}

func FuzzRequiredBindingDecoder(fz *testing.F) {
	c := bindingTestContext(fz)
	b, _ := bindingTestAdmission(fz, c)
	raw, e := b.CanonicalBytes()
	if e != nil {
		fz.Fatal(e)
	}
	fz.Add(raw)
	fz.Add([]byte("OMCVBND2"))
	fz.Add(append(append([]byte{}, raw...), 0))
	fz.Add(append([]byte("OMCVBND2\x00\x03"), raw[10:]...))
	fz.Add(requiredBindingForgedCount(fz))
	fz.Fuzz(func(t *testing.T, raw []byte) {
		if b, e := DecodeAdmissionBinding(raw); e == nil {
			again, e := b.CanonicalBytes()
			if e != nil || !bytes.Equal(raw, again) {
				t.Fatal("required binding decoder round trip", e)
			}
			_ = b.Verify(c)
		}
	})
}
