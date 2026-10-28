package custodyv2

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	ct "github.com/outcomemesh/outcomemesh/internal/carryovertest"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
	"github.com/outcomemesh/outcomemesh/node/transport"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func importedFixture(t testing.TB) (AdmissionGenesis, ImportPins) {
	t.Helper()
	p := ct.Proposal(t)
	rid, _ := p.Anchor.ID()
	did, _ := p.Anchor.DescriptorID()
	lid, _ := p.Evidence.Assignment.ID()
	pid, _ := p.ID()
	pins := ImportPins{RegistryID: rid, RegistryDescriptorID: did, LegacyID: lid, Retirement: p.Evidence.End, ProposalID: pid}
	g, e := NewImportedAdmissionGenesis(p, pins)
	if e != nil {
		t.Fatal(e)
	}
	return g, pins
}
func importedEnrollmentFixture(t testing.TB, g AdmissionGenesis) EnrollmentBinding {
	t.Helper()
	registry := g.Import.Anchor
	raw, e := g.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	s := wire.Selection{Version: wire.SelectionVersionImported, RegistryID: g.Assignment.Policy.RegistryID, DescriptorID: g.Assignment.Policy.RegistryDescriptorID, Candidate: raw}
	for _, r := range []struct {
		name string
		seed byte
	}{{"issuer", 110}, {"authority", 101}, {"control", 102}} {
		s, e = s.Sign(r.name, f.Key(r.seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	sid, _ := s.ID()
	q := wire.Certificate{Version: s.Version, Selection: s}
	for _, seed := range []byte{111, 112, 113} {
		v, e := (wire.Vote{Version: s.Version, RegistryID: s.RegistryID, DescriptorID: s.DescriptorID, SelectionID: sid}).Sign(registry, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
		q.Votes = append(q.Votes, v)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	raw, e = q.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	b := EnrollmentBinding{Version: PolicyVersionImported, Registry: registry, Certificate: raw}
	if e := b.VerifyImported(g); e != nil {
		t.Fatal(e)
	}
	return b
}
func importedContext(t testing.TB, g AdmissionGenesis, seq uint64, head types.Hash, previous workarchive.ReplicaReceipt) Context {
	t.Helper()
	template := g.Import.Evidence.Cycles[0].Terminal
	now := previous.StoredAt + 1
	ch, e := workarchive.CreateCustodyChallenge(g.Manifest, previous, f.Key(3), now, 10, 1, previous.RetainUntil+1)
	if e != nil {
		t.Fatal(e)
	}
	intent := template.Intent
	aid, _ := g.Assignment.ID()
	rid, _ := previous.ID()
	intent.AssignmentID = aid
	intent.PriorSequence = seq
	intent.PriorHeadID = head
	intent.PriorReceiptID = rid
	intent.Nonce = ch.Nonce
	intent.IssuedAt = ch.IssuedAt
	intent.ExpiresAt = ch.ExpiresAt
	intent.RenewUntil = ch.RenewUntil
	intent.RequestedSamples = ch.RequestedSamples
	intent.ReplicaPeerID, e = transport.PeerIDFromPublicKey(g.Assignment.Base.RemoteTransportPublicKey[:])
	if e != nil {
		t.Fatal(e)
	}
	p := Plan{Version: Version2, AssignmentID: aid, Intent: intent, Challenge: ch, ServeConsumer: f.Public(4), ClientTransportPublicKey: f.Public(46)}
	for _, r := range []struct {
		name string
		seed byte
	}{{"audit", 4}, {"serve", 4}, {"authority", 101}} {
		p, e = p.Sign(r.name, f.Key(r.seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	c := Context{Assignment: g.Assignment, Plan: p, Manifest: g.Manifest, Initial: g.Initial, Previous: previous, CustodyPolicy: g.CustodyPolicy}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	return c
}
func importedEntry(t testing.TB, g AdmissionGenesis, pos custodyfence.Position, c Context, closure *AdmissionClosure) AdmissionEntry {
	t.Helper()
	gid, _ := g.ID()
	kind := AdmissionAdmit
	if closure != nil {
		kind = AdmissionClose
	}
	e, err := (AdmissionEntry{Version: Version2, GenesisID: gid, ExpectedSequence: pos.Sequence, ExpectedHead: pos.HeadID, Kind: kind, Context: c, Closure: closure}).Sign(g, f.Key(101))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Synthetic signed receipts exercise the reference arithmetic only. Profile 5
// cannot create the original execution owners that would produce these receipts.
func importedReferenceClosure(t testing.TB, c Context) AdmissionClosure {
	t.Helper()
	scope, _ := c.Scope()
	sid, _ := scope.ID()
	cmd, e := (custodyfence.Command{Version: scope.Version, ScopeID: sid, ExpectedHead: sid, Kind: custodyfence.CloseUnclaimed, EvidenceID: f.Hash("import-reference-no-claim")}).Sign(f.Key(101))
	if e != nil {
		t.Fatal(e)
	}
	p, e := NewServeUnclaimed(c, f.Certificate(cmd, 70, 71, 72))
	if e != nil {
		t.Fatal(e)
	}
	p, e = p.Sign(c, "authority", f.Key(101))
	if e != nil {
		t.Fatal(e)
	}
	p, e = p.Sign(c, "consumer", f.Key(4))
	if e != nil {
		t.Fatal(e)
	}
	cmd, e = p.Decision(c, f.Key(101))
	if e != nil {
		t.Fatal(e)
	}
	cert := ServeCertificate{Version: Version2, Proposal: p, Decision: f.Certificate(cmd, 70, 71, 72)}
	cid, _ := cert.ID()
	retain, _ := p.Retention(c)
	receipt := func(role uint8, parent types.Hash, seed byte) ServeReceipt {
		r := ServeReceipt{Version: Version2, Role: role, ScopeID: sid, CertificateID: cid, SourceSequence: c.Plan.Intent.PriorSequence, SourceHeadID: c.Plan.Intent.PriorHeadID, MinimumRetainUntil: retain, AppliedAt: c.Plan.Challenge.IssuedAt, Signer: f.Public(seed), ParentID: parent}
		raw, e := r.unsignedBytes()
		if e != nil {
			t.Fatal(e)
		}
		h := types.DomainHash("OMESH/custody/v2/serve/applied/signature", raw)
		copy(r.Signature[:], ed25519.Sign(f.Key(seed), h[:]))
		return r
	}
	ar := receipt(ServeAuthority, types.Hash{}, 101)
	pid, _ := ar.ID()
	br := receipt(ServeTarget, pid, 102)
	closure := AdmissionClosure{Serve: cert, A: ar, B: br}
	if e := closure.Verify(c); e != nil {
		t.Fatal(e)
	}
	return closure
}
func TestRemoteImportedAccountingCarriesSpentSourceAndRetention(t *testing.T) {
	g, _ := importedFixture(t)
	gid, _ := g.ID()
	s, e := NewAdmissionState(g, gid)
	if e != nil {
		t.Fatal(e)
	}
	before := s.Snapshot()
	if before.SpentOperations != 2 || before.SourceSequence != 1 || before.PendingOperations != 0 || g.Assignment.Base.MaximumOperations != 4 {
		t.Fatal(before)
	}
	last := g.Import.Evidence.Cycles[0].Terminal.Entry
	head, _ := last.ID()
	rid, _ := last.Record.RenewedReceipt.ID()
	if before.SourceHeadID != head || before.SourceReceiptID != rid || before.CurrentReceipt != last.Record.RenewedReceipt || before.RetainUntil < last.Record.RenewedReceipt.RetainUntil {
		t.Fatal("lost source or retention")
	}
	c := importedContext(t, g, 1, head, before.CurrentReceipt)
	stale := importedContext(t, g, 0, types.Hash{}, g.Initial)
	if e := s.ValidateNext(importedEntry(t, g, before.Position, stale, nil)); e == nil {
		t.Fatal("zero source accepted")
	}
	admit := importedEntry(t, g, before.Position, c, nil)
	if e := s.Apply(modelAdmissionCertificate(t, admit)); e != nil {
		t.Fatal(e)
	}
	if s.Snapshot().SpentOperations != 4 || s.Snapshot().PendingOperations != 2 {
		t.Fatal(s.Snapshot())
	}
	closure := importedReferenceClosure(t, c)
	close := importedEntry(t, g, s.Snapshot().Position, c, &closure)
	if e := s.Apply(modelAdmissionCertificate(t, close)); e != nil {
		t.Fatal(e)
	}
	after := s.Snapshot()
	if after.SpentOperations != 4 || after.PendingOperations != 0 || after.SourceSequence != 1 || after.CurrentReceipt != before.CurrentReceipt || after.RetainUntil < before.RetainUntil {
		t.Fatal("close refunded or reset", after)
	}
	next := importedContext(t, g, 1, head, before.CurrentReceipt)
	if e := s.ValidateNext(importedEntry(t, g, after.Position, next, nil)); !errors.Is(e, ErrAdmissionBudget) {
		t.Fatal("spent allowance reused", e)
	}
}
func TestRemoteImportedGenesisRefusesResetsAndWrongEvidence(t *testing.T) {
	g, pins := importedFixture(t)
	for name, mutate := range map[string]func(*AdmissionGenesis){"native-version": func(g *AdmissionGenesis) { g.Version = Version2 }, "missing-proof": func(g *AdmissionGenesis) { g.Import = nil }, "cap": func(g *AdmissionGenesis) { g.Assignment.Base.MaximumOperations++ }, "pending": func(g *AdmissionGenesis) { g.Assignment.Base.MaximumPending++ }, "policy": func(g *AdmissionGenesis) { g.Assignment.Policy.Version = PolicyVersionEnrolled }, "receipt": func(g *AdmissionGenesis) { g.Initial.RetainUntil++ }, "witness": func(g *AdmissionGenesis) { g.Assignment.Policy.Threshold = 4 }, "origin": func(g *AdmissionGenesis) { g.Assignment.Policy.ImportID = f.Hash("other-proof") }} {
		t.Run(name, func(t *testing.T) {
			bad := g
			mutate(&bad)
			if _, e := bad.CanonicalBytes(); e == nil {
				t.Fatal("changed import accepted")
			}
		})
	}
	for _, change := range []func(*ImportPins){func(p *ImportPins) { p.ProposalID = f.Hash("other") }, func(p *ImportPins) { p.RegistryDescriptorID = f.Hash("other") }, func(p *ImportPins) { p.Retirement.Sequence-- }, func(p *ImportPins) { p.LegacyID = f.Hash("other") }} {
		bad := pins
		change(&bad)
		if _, e := NewImportedAdmissionGenesis(*g.Import, bad); e == nil {
			t.Fatal("wrong external pins accepted")
		}
	}
	altered := *g.Import
	altered.Allowance++
	if _, e := deriveImportedGenesis(altered); e == nil {
		t.Fatal("unsigned budget increase")
	}
}
func TestRemoteImportedWitnessRequiresSelectionAndSurvivesColdRestart(t *testing.T) {
	g, _ := importedFixture(t)
	gid, _ := g.ID()
	binding := importedEnrollmentFixture(t, g)
	path := filepath.Join(t.TempDir(), "imported")
	if _, e := CreateAdmissionWitness(path, g, gid, f.Key(70)); e == nil {
		t.Fatal("missing selection")
	}
	if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("created owner before proof")
	}
	w, e := CreateAdmissionWitness(path, g, gid, f.Key(70), binding)
	if e != nil {
		t.Fatal(e)
	}
	x, pin, e := w.Snapshot()
	if e != nil || x.SpentOperations != 2 || x.SourceSequence != 1 {
		t.Fatal(x, e)
	}
	if other, e := OpenAdmissionWitness(path, g, gid, f.Key(70), pin, binding); e == nil {
		other.Close()
		t.Fatal("concurrent owner")
	}
	c := importedContext(t, g, x.SourceSequence, x.SourceHeadID, x.CurrentReceipt)
	entry := importedEntry(t, g, x.Position, c, nil)
	vote, e := w.VoteAt(pin, entry)
	if e != nil {
		t.Fatal(e)
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	if stale, e := OpenAdmissionWitness(path, g, gid, f.Key(70), pin, binding); e == nil {
		stale.Close()
		t.Fatal("forgot retained vote")
	}
	w, e = RecoverAdmissionVote(path, g, gid, f.Key(70), pin, entry, binding)
	if e != nil {
		t.Fatal(e)
	}
	again, e := w.VoteAt(pin, entry)
	if e != nil || vote != again {
		t.Fatal("lost output changed vote", e)
	}
	_, pending, e := w.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	cert := modelAdmissionCertificate(t, entry)
	if e := w.CommitAt(pending, cert); e != nil {
		t.Fatal(e)
	}
	_, after, e := w.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	w.Close()
	if _, e := OpenAdmissionWitness(path, g, gid, f.Key(70), after); e == nil {
		t.Fatal("cold selection bypass")
	}
	w, e = OpenAdmissionWitness(path, g, gid, f.Key(70), after, binding)
	if e != nil {
		t.Fatal(e)
	}
	x, _, e = w.Snapshot()
	if e != nil || x.SpentOperations != 4 || x.PendingOperations != 2 || x.SourceSequence != 1 {
		t.Fatal(x, e)
	}
	w.Close()
	copyPath := filepath.Join(t.TempDir(), "copy")
	if e := os.CopyFS(copyPath, os.DirFS(path)); e != nil {
		t.Fatal(e)
	}
	privateAdmissionCopy(t, copyPath)
	if copy, e := OpenAdmissionWitness(copyPath, g, gid, f.Key(70), after, binding); e == nil {
		copy.Close()
		t.Fatal("copied witness accepted")
	}
	if e := os.Remove(filepath.Join(path, "enrollment")); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenAdmissionWitness(path, g, gid, f.Key(70), after, binding); e == nil {
		t.Fatal("missing retained selection")
	}
}
func privateAdmissionCopy(t testing.TB, root string) {
	t.Helper()
	if e := filepath.Walk(root, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		mode := os.FileMode(0600)
		if info.IsDir() {
			mode = 0700
		}
		return os.Chmod(path, mode)
	}); e != nil {
		t.Fatal(e)
	}
}
func TestRemoteImportedExecutionAndNativeGenesisStayBlocked(t *testing.T) {
	g, _ := importedFixture(t)
	gid, _ := g.ID()
	s, _ := NewAdmissionState(g, gid)
	x := s.Snapshot()
	c := importedContext(t, g, x.SourceSequence, x.SourceHeadID, x.CurrentReceipt)
	if _, e := NewAdmissionGenesis(c); e == nil {
		t.Fatal("native reset")
	}
	entry := importedEntry(t, g, x.Position, c, nil)
	binding := AdmissionBinding{Version: Version2, Genesis: g, Chain: []AdmissionCertificate{modelAdmissionCertificate(t, entry)}}
	if e := binding.Verify(c); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "forbidden-owner")
	scope, _ := c.Scope()
	pin, _ := scope.ID()
	if e := CreateRequiredTarget(path, c, pin, Sources{}, binding); !errors.Is(e, ErrAdmissionRequired) {
		t.Fatal("import activated", e)
	}
	if e := CreateTarget(path, c, pin, Sources{}); !errors.Is(e, ErrImportInactive) {
		t.Fatal("raw import activated", e)
	}
	if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("owner created")
	}
}
func FuzzImportedAdmissionCodecs(fuzz *testing.F) {
	g, _ := importedFixture(fuzz)
	raw, _ := g.CanonicalBytes()
	b := importedEnrollmentFixture(fuzz, g)
	binding, _ := b.CanonicalBytes()
	fuzz.Add(raw)
	fuzz.Add(binding)
	fuzz.Add([]byte("OMCVAGN5"))
	fuzz.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}
		if g, e := DecodeAdmissionGenesis(raw); e == nil {
			again, e := g.CanonicalBytes()
			if e != nil || !bytes.Equal(raw, again) {
				t.Fatal("genesis round trip")
			}
		}
		if b, e := DecodeEnrollmentBinding(raw); e == nil {
			again, e := b.CanonicalBytes()
			if e != nil || !bytes.Equal(raw, again) {
				t.Fatal("selection round trip")
			}
		}
	})
}

func TestRemoteImportedWitnessWriteFaultsNeverRefund(t *testing.T) {
	g, _ := importedFixture(t)
	gid, _ := g.ID()
	binding := importedEnrollmentFixture(t, g)
	for _, stage := range []string{"00000001.vote-before-sync", "00000001.vote-durable", "00000001.certificate-before-sync", "00000001.certificate-durable"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "witness")
			w, e := CreateAdmissionWitness(path, g, gid, f.Key(70), binding)
			if e != nil {
				t.Fatal(e)
			}
			x, before, e := w.Snapshot()
			if e != nil {
				t.Fatal(e)
			}
			c := importedContext(t, g, x.SourceSequence, x.SourceHeadID, x.CurrentReceipt)
			entry := importedEntry(t, g, x.Position, c, nil)
			q := modelAdmissionCertificate(t, entry)
			injected := errors.New("imported accounting persistence failure")
			w.hook = func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			}
			isVote := bytes.Contains([]byte(stage), []byte(".vote"))
			if isVote {
				_, e = w.VoteAt(before, entry)
			} else {
				e = w.CommitAt(before, q)
			}
			if !errors.Is(e, ErrUncertain) {
				t.Fatal(e)
			}
			if _, _, e = w.Snapshot(); e == nil {
				t.Fatal("uncertain owner remained usable")
			}
			w.Close()
			if old, e := OpenAdmissionWitness(path, g, gid, f.Key(70), before, binding); e == nil {
				old.Close()
				t.Fatal("uncertain write forgotten")
			}
			if isVote {
				w, e = RecoverAdmissionVote(path, g, gid, f.Key(70), before, entry, binding)
			} else {
				w, e = RecoverAdmissionCommit(path, g, gid, f.Key(70), before, q, binding)
			}
			if e != nil {
				t.Fatal(e)
			}
			defer w.Close()
			if isVote {
				if _, e = w.VoteAt(before, entry); e != nil {
					t.Fatal(e)
				}
				x, _, e = w.Snapshot()
				if e != nil || x.SpentOperations != 2 || x.PendingOperations != 0 {
					t.Fatal(x, e)
				}
			} else {
				if e = w.CommitAt(before, q); e != nil {
					t.Fatal(e)
				}
				x, _, e = w.Snapshot()
				if e != nil || x.SpentOperations != 4 || x.PendingOperations != 2 {
					t.Fatal(x, e)
				}
			}
		})
	}
}
func TestRemoteImportedWitnessLockReplacementAndDescriptorSwapRefused(t *testing.T) {
	g, _ := importedFixture(t)
	gid, _ := g.ID()
	binding := importedEnrollmentFixture(t, g)
	for _, kind := range []string{"lock", "genesis", "ready", "enrollment"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "original")
			w, e := CreateAdmissionWitness(path, g, gid, f.Key(70), binding)
			if e != nil {
				t.Fatal(e)
			}
			_, pin, e := w.Snapshot()
			if e != nil {
				t.Fatal(e)
			}
			w.Close()
			name := kind
			if kind == "lock" {
				name = "owner.lock"
			}
			file := filepath.Join(path, name)
			if kind == "lock" {
				if e := os.Remove(file); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(file, nil, 0600); e != nil {
					t.Fatal(e)
				}
			} else {
				raw, e := os.ReadFile(file)
				if e != nil {
					t.Fatal(e)
				}
				raw[len(raw)-1] ^= 1
				if e := os.WriteFile(file, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if copied, e := OpenAdmissionWitness(path, g, gid, f.Key(70), pin, binding); e == nil {
				copied.Close()
				t.Fatal("replaced owner reopened")
			}
		})
	}
}
func TestRemoteImportedCodecVectors(t *testing.T) {
	g, _ := importedFixture(t)
	enrollment := importedEnrollmentFixture(t, g)
	for name, value := range map[string]interface {
		CanonicalBytes() ([]byte, error)
		ID() (types.Hash, error)
	}{"genesis": g, "policy": g.Assignment.Policy, "enrollment": enrollment} {
		raw, e := value.CanonicalBytes()
		if e != nil {
			t.Fatal(e)
		}
		id, e := value.ID()
		if e != nil {
			t.Fatal(e)
		}
		want := map[string]struct {
			size int
			id   string
		}{
			"genesis":    {10512, "aba0ce0390dbc718258d66eefa9f93c41c058e7606c617fc71a1c3504825c136"},
			"policy":     {236, "050f3a54ed9386def663166484a4025cdb7b89627772c648f6512f33054a8c8e"},
			"enrollment": {11660, "b4a1157a8d46343197594560a67358c607e5a15497384fd3e08ab95fb040af41"},
		}[name]
		if len(raw) != want.size || id.String() != want.id {
			t.Fatal("canonical vector changed", name, len(raw), id)
		}
	}
}

func TestRemoteImportedSelectionProofRefusesWeakWrongAndOldRoles(t *testing.T) {
	g, _ := importedFixture(t)
	binding := importedEnrollmentFixture(t, g)
	raw, _ := binding.CanonicalBytes()
	for _, kind := range []string{"weak", "old-authority", "old-control", "candidate", "version", "anchor"} {
		t.Run(kind, func(t *testing.T) {
			b, e := DecodeEnrollmentBinding(raw)
			if e != nil {
				t.Fatal(e)
			}
			q, e := wire.DecodeCertificate(b.Certificate)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "weak":
				q.Votes = q.Votes[:2]
			case "old-authority":
				q.Selection, e = q.Selection.Sign("authority", f.Key(1))
			case "old-control":
				q.Selection, e = q.Selection.Sign("control", f.Key(14))
			case "candidate":
				q.Selection.Candidate[len(q.Selection.Candidate)-1] ^= 1
			case "version":
				b.Version = PolicyVersionEnrolled
			case "anchor":
				b.Registry.ResourceID = f.Hash("different-resource")
			}
			if e != nil {
				t.Fatal(e)
			}
			changed, e := q.CanonicalBytes()
			// Changed candidate/signatures invalidate retained vote IDs at framing already.
			if e == nil {
				b.Certificate = changed
				if e := b.VerifyImported(g); e == nil {
					t.Fatal("invalid selection accepted")
				}
			}
		})
	}
}
