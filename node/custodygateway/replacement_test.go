//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	fixture "github.com/outcomemesh/outcomemesh/internal/protectedtest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func (x *protectedFixture) replaceSigner(t testing.TB, old [32]byte, successor byte) guard.ReplacementReceipt {
	t.Helper()
	id := x.guardStore.Identity()
	revoke, e := (guard.Revocation{GuardID: id.ID(), Subject: old, Authority: f.Public(250), ReasonID: f.Hash("incident inventory")}).Sign(f.Key(250))
	fixture.Require(t, e)
	_, e = x.guardStore.Revoke(t.Context(), revoke)
	fixture.Require(t, e)
	rid, _ := revoke.ID()
	before, e := x.guardStore.Position()
	fixture.Require(t, e)
	q, e := (guard.Replacement{GuardID: id.ID(), Subject: old, Successor: f.Public(successor), Authority: f.Public(249), RevocationID: rid, EvidenceID: f.Hash("original roots and retained outstanding obligations"), Before: before}).Accept(f.Key(successor))
	fixture.Require(t, e)
	q, e = q.Authorize(f.Key(249))
	fixture.Require(t, e)
	r, e := x.guardStore.Replace(t.Context(), q)
	fixture.Require(t, e)
	return r
}
func (x *protectedFixture) activateService(t testing.TB, target bool, r guard.ReplacementReceipt, seed byte, attempt *wire.Request) {
	t.Helper()
	owner, root, d := x.a, x.aroot, x.ad
	if target {
		owner, root, d = x.b, x.broot, x.bd
	}
	pin, _ := owner.Position()
	id, _ := d.ID()
	identity := owner.identity
	config := owner.configHash
	fixture.Require(t, owner.Close())
	fixture.Require(t, ActivateReplacement(t.Context(), root, id, pin, attempt, r, f.Key(seed)))
	fixture.Require(t, ActivateReplacement(t.Context(), root, id, pin, attempt, r, f.Key(seed)))
	reopened, e := Open(root, id, pin, attempt)
	fixture.Require(t, e)
	reopened.SetGuard(x.guard)
	if reopened.identity != identity || reopened.configHash != config {
		t.Fatal("replacement changed source identity or configuration")
	}
	if target {
		x.b = reopened
	} else {
		x.a = reopened
	}
}
func (x *protectedFixture) replaceWitness(t testing.TB, r guard.ReplacementReceipt) {
	t.Helper()
	gid, _ := x.source.Genesis.ID()
	before, pin, e := x.admission[0].Snapshot()
	fixture.Require(t, e)
	fixture.Require(t, x.admission[0].Close())
	w, e := v2.OpenReplacementAdmissionWitness(filepath.Join(x.source.Root, "admission-70"), x.source.Genesis, gid, f.Key(232), pin, r, x.source.Enrollment)
	fixture.Require(t, e)
	w.SetGuard(x.guard)
	x.admission[0] = w
	t.Cleanup(func() { w.Close() })
	after, afterPin, e := w.Snapshot()
	fixture.Require(t, e)
	if !reflect.DeepEqual(before, after) || afterPin != pin {
		t.Fatal("admission replacement changed accounting")
	}
	x.replacements = map[byte]guard.ReplacementReceipt{70: r}
	if len(x.jobWitnesses) > 0 {
		_, pin, e := x.jobWitnesses[0].Snapshot()
		fixture.Require(t, e)
		fixture.Require(t, x.jobWitnesses[0].Close())
		scope, e := x.c.Scope()
		fixture.Require(t, e)
		sid, _ := scope.ID()
		job, e := custodyfence.Open(filepath.Join(x.source.Root, "slot-70"), scope, sid, f.Key(232), pin, r)
		fixture.Require(t, e)
		job.SetGuard(x.guard)
		x.jobWitnesses[0] = job
		t.Cleanup(func() { job.Close() })
	}
}
func (x *protectedFixture) replacementServeQuorum(t testing.TB, scope custodyfence.Scope, command custodyfence.Command) custodyfence.Certificate {
	t.Helper()
	sid, _ := scope.ID()
	cert := custodyfence.Certificate{Version: scope.Version, Command: command}
	for _, seed := range []byte{70, 71, 72} {
		key := f.Key(seed)
		var proof []guard.ReplacementReceipt
		if r, ok := x.replacements[seed]; ok {
			key = f.Key(232)
			proof = []guard.ReplacementReceipt{r}
		}
		w, e := custodyfence.Create(filepath.Join(x.source.Root, fmt.Sprint("replacement-serve-", seed)), scope, sid, key, proof...)
		fixture.Require(t, e)
		w.SetGuard(x.guard)
		vote, e := w.Vote(command)
		w.Close()
		fixture.Require(t, e)
		cert.Votes = append(cert.Votes, vote)
	}
	sort.Slice(cert.Votes, func(i, j int) bool { return bytes.Compare(cert.Votes[i].Witness[:], cert.Votes[j].Witness[:]) < 0 })
	fixture.Require(t, cert.Verify(scope))
	raw, e := cert.CanonicalBytes()
	fixture.Require(t, e)
	cert, e = custodyfence.DecodeCertificate(raw)
	fixture.Require(t, e)
	fixture.Require(t, cert.Verify(scope))
	return cert
}
func TestReplacementProfile5KeepsObligationsThroughExecuteServeAndClose(t *testing.T) {
	x := newProtectedFixture(t, true, true, true)
	before := x.state.Snapshot()
	deployment, _ := x.dep.CanonicalBytes()
	// Rotate before session creation, then again for the already committed witness journal.
	ar := x.replaceSigner(t, x.ad.Gateway, 230)
	x.activateService(t, false, ar, 230, nil)
	br := x.replaceSigner(t, x.bd.Gateway, 231)
	x.activateService(t, true, br, 231, nil)
	claim := x.claim(t)
	wr := x.replaceSigner(t, f.Public(70), 232)
	x.replaceWitness(t, wr)
	if !reflect.DeepEqual(before, x.state.Snapshot()) {
		t.Fatal("rotation reset admission")
	}
	fixture.Require(t, x.binding.Verify(x.c))
	fixture.Require(t, claim.Verify(mustScope(t, x.c)))
	raw, _ := claim.CanonicalBytes()
	data, q, payload, e := protectedCall(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.binding, Data: raw, Now: 1}, "replacement-execute")
	fixture.Require(t, e)
	result, e := v2.DecodeResult(data)
	fixture.Require(t, e)
	fixture.Require(t, result.Verify(x.c, claim))
	responseRaw, e := x.b.ExecuteRuntime(t.Context(), q, payload)
	fixture.Require(t, e)
	response, e := wire.DecodeResponse(responseRaw)
	fixture.Require(t, e)
	fixture.Require(t, response.Verify(x.bd, q))
	if response.Replacement == nil || response.GuardSeal == ([64]byte{}) || result.Protection.Replacement == nil {
		t.Fatal("successor evidence missing")
	}
	stripped := response
	stripped.Replacement = nil
	if stripped.Verify(x.bd, q) == nil {
		t.Fatal("stripped successor proof accepted")
	}
	stripped = response
	stripped.GuardSeal = [64]byte{}
	if stripped.Verify(x.bd, q) == nil {
		t.Fatal("unsealed outer response accepted")
	}
	bundle := x.recordBundle(t, claim, result)
	data, e = bundle.CanonicalBytes()
	fixture.Require(t, e)
	data = mustProtected(t, x.a, x.ad, v2.ProtectedCommand{Kind: v2.ProtectedAccept, Admission: x.binding, Data: data, Now: 1}, "replacement-accept")
	receipt, e := v2.DecodeReceipt(data)
	fixture.Require(t, e)
	fixture.Require(t, receipt.Verify(x.c, bundle))
	proposal, e := v2.NewServeFulfilled(x.c, bundle, receipt)
	fixture.Require(t, e)
	for _, r := range []struct {
		name string
		seed byte
	}{{"authority", 101}, {"consumer", 4}} {
		proposal, e = proposal.Sign(x.c, r.name, f.Key(r.seed))
		fixture.Require(t, e)
	}
	decision, e := proposal.Decision(x.c, f.Key(101))
	fixture.Require(t, e)
	scope, e := x.c.ServeScope()
	fixture.Require(t, e)
	cert := v2.ServeCertificate{Version: 2, Proposal: proposal, Decision: x.replacementServeQuorum(t, scope, decision)}
	fixture.Require(t, cert.Verify(x.c))
	data, e = EncodeExecutionServe(cert, nil)
	fixture.Require(t, e)
	data = mustProtected(t, x.a, x.ad, v2.ProtectedCommand{Kind: v2.ProtectedServe, Admission: x.binding, Data: data, Now: 1}, "replacement-serve-a")
	a, e := v2.DecodeServeReceipt(data)
	fixture.Require(t, e)
	data, e = EncodeExecutionServe(cert, &a)
	fixture.Require(t, e)
	data = mustProtected(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedServe, Admission: x.binding, Data: data, Now: 1}, "replacement-serve-b")
	b, e := v2.DecodeServeReceipt(data)
	fixture.Require(t, e)
	closure := v2.AdmissionClosure{Serve: cert, A: a, B: b}
	fixture.Require(t, closure.Verify(x.c))
	closing := x.account(t, v2.AdmissionClose, &closure)
	raw, e = closing.CanonicalBytes()
	fixture.Require(t, e)
	closing, e = v2.DecodeAdmissionCertificate(raw)
	fixture.Require(t, e)
	fixture.Require(t, closing.Verify(x.source.Genesis))
	after := x.state.Snapshot()
	if after.SpentOperations != 2 || after.PendingOperations != 0 || after.SourceSequence != 1 || after.RetainUntil < before.RetainUntil {
		t.Fatal("obligations lost", after)
	}
	for _, w := range x.admission {
		s, _, e := w.Snapshot()
		fixture.Require(t, e)
		if !reflect.DeepEqual(s, after) {
			t.Fatal("witness accounting diverged")
		}
	}
	again, _ := x.dep.CanonicalBytes()
	if !bytes.Equal(deployment, again) {
		t.Fatal("deployment identity changed")
	}
	// Cold-open both original roots with the successor file, then serve cached history.
	for _, target := range []bool{false, true} {
		o, root, d := x.a, x.aroot, x.ad
		if target {
			o, root, d = x.b, x.broot, x.bd
		}
		pin, _ := o.Position()
		id, _ := d.ID()
		o.Close()
		reopened, e := Open(root, id, pin, nil)
		fixture.Require(t, e)
		reopened.SetGuard(x.guard)
		if target {
			x.b = reopened
		} else {
			x.a = reopened
		}
	}
}
func mustScope(t testing.TB, c v2.Context) custodyfence.Scope {
	t.Helper()
	s, e := c.Scope()
	fixture.Require(t, e)
	return s
}

func TestReplacementProfile5UnknownOutcomeDoesNotRestoreSessionOrRefund(t *testing.T) {
	for _, stage := range []string{"consumed-before-read", "source-before-result"} {
		t.Run(stage, func(t *testing.T) {
			x := newProtectedFixture(t, true, true, true)
			claim := x.claim(t)
			raw, _ := claim.CanonicalBytes()
			x.b.executionHook = func(s string) error {
				if s == stage {
					return fmt.Errorf("interrupted %s", stage)
				}
				return nil
			}
			_, q, payload, e := protectedCall(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.binding, Data: raw, Now: 1}, "unknown-replacement")
			if e == nil {
				t.Fatal("fault ignored")
			}
			scope := mustScope(t, x.c)
			sid, _ := scope.ID()
			before, e := x.b.currentExecutionSource()
			fixture.Require(t, e)
			accounting := x.state.Snapshot()
			receipt := x.replaceSigner(t, x.bd.Gateway, 231)
			x.activateService(t, true, receipt, 231, &q)
			if _, e = x.b.ExecuteRuntime(t.Context(), q, payload); e == nil {
				t.Fatal("replacement replayed consumed work")
			}
			after, e := x.b.currentExecutionSource()
			fixture.Require(t, e)
			if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(accounting, x.state.Snapshot()) {
				t.Fatal("unknown outcome reset source or accounting")
			}
			if _, e = x.b.jobRead(sid, "result", v2.MaximumResultBytes); !os.IsNotExist(e) {
				t.Fatal("replacement manufactured result", e)
			}
			if stage == "source-before-result" {
				entry, e := x.b.jobRead(sid, "entry", workarchive.MaximumCustodyJournalEntryBytes)
				fixture.Require(t, e)
				decoded, e := workarchive.DecodeCustodyJournalEntry(entry)
				fixture.Require(t, e)
				if decoded.Sequence != 1 {
					t.Fatal("source advanced twice")
				}
			}
		})
	}
}

func TestReplacementServiceRefusesStalePinsWrongSeedsAndChangedInstallation(t *testing.T) {
	x := newProtectedFixture(t, true, true, true)
	r := x.replaceSigner(t, x.ad.Gateway, 230)
	pin, _ := x.a.Position()
	var e error
	did, _ := x.ad.ID()
	x.a.Close()
	if ActivateReplacement(t.Context(), x.aroot, did, wire.Position{}, nil, r, f.Key(230)) == nil {
		t.Fatal("stale owner pin")
	}
	if ActivateReplacement(t.Context(), x.aroot, did, pin, nil, r, f.Key(231)) == nil {
		t.Fatal("wrong successor seed")
	}
	if _, e = os.Lstat(filepath.Join(x.aroot, replacementFile)); !os.IsNotExist(e) {
		t.Fatal("invalid attempt wrote key")
	}
	fixture.Require(t, ActivateReplacement(t.Context(), x.aroot, did, pin, nil, r, f.Key(230)))
	path := filepath.Join(x.aroot, replacementFile)
	raw, e := os.ReadFile(path)
	fixture.Require(t, e)
	fixture.Require(t, os.WriteFile(path, raw[:len(raw)-1], 0600))
	if o, e := Open(x.aroot, did, pin, nil); e == nil {
		o.Close()
		t.Fatal("partial activation accepted")
	}
	if ActivateReplacement(t.Context(), x.aroot, did, pin, nil, r, f.Key(230)) == nil {
		t.Fatal("partial activation repaired implicitly")
	}
}

func TestReplacementAdmissionMemberCannotCountOldAndNewKeysTwice(t *testing.T) {
	x := newProtectedFixture(t, true, true, true)
	proof := x.replaceSigner(t, f.Public(70), 232)
	q := x.binding.Chain[0]
	entryID, _ := q.Entry.ID()
	v := v2.AdmissionVote{Version: 2, EntryID: entryID, Witness: f.Public(232), Replacement: &proof}
	enc := codec.NewEncoder(v2.AdmissionVoteBytes)
	enc.Fixed([]byte("OMCVAVT2"))
	enc.U16(2)
	enc.Fixed(v.EntryID[:])
	enc.Fixed(v.Witness[:])
	h := types.DomainHash("OMESH/custody/v2/admission/vote/signature", enc.Bytes())
	copy(v.Signature[:], ed25519.Sign(f.Key(232), h[:]))
	var e error
	v.GuardSeal, e = guard.Obtain(t.Context(), x.guard, x.dep.Guard, v2.AdmissionGuardRequest(q.Entry, v.Witness), f.Key(232))
	fixture.Require(t, e)
	var old, other v2.AdmissionVote
	for i, existing := range q.Votes {
		if existing.Witness == f.Public(70) {
			old = existing
			q.Votes[i] = v
		} else {
			other = existing
		}
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	fixture.Require(t, q.Verify(x.source.Genesis))
	q.Votes = []v2.AdmissionVote{v, old, other}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	if _, e = q.CanonicalBytes(); e != nil {
		t.Fatal("unique physical signers must be canonical", e)
	}
	if q.Verify(x.source.Genesis) == nil {
		t.Fatal("one logical member counted twice")
	}
}
