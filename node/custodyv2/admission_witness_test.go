package custodyv2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type admissionWitnessGroup struct {
	g      AdmissionGenesis
	pin    types.Hash
	roots  []string
	owners []*AdmissionWitness
}

func admissionContextBudget(t testing.TB, operations uint32, pending uint16) Context {
	t.Helper()
	c := fixtureContext(t)
	c.Assignment.Base.MaximumOperations = operations
	c.Assignment.Base.MaximumPending = pending
	id, e := c.Assignment.ID()
	if e != nil {
		t.Fatal(e)
	}
	c.Plan.AssignmentID = id
	c.Plan.Intent.AssignmentID = id
	return admissionResignPlan(t, c)
}
func admissionResignPlan(t testing.TB, c Context) Context {
	t.Helper()
	c.Plan.AuditSignature = [64]byte{}
	c.Plan.ServeSignature = [64]byte{}
	c.Plan.AuthoritySignature = [64]byte{}
	for _, role := range []string{"audit", "serve", "authority"} {
		seed := byte(4)
		if role == "authority" {
			seed = 1
		}
		var e error
		c.Plan, e = c.Plan.Sign(role, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	return c
}
func admissionDistinctContext(t testing.TB, c Context, delta uint64) Context {
	t.Helper()
	old := c.Plan.Challenge
	ch, e := workarchive.CreateCustodyChallenge(c.Manifest, c.Previous, f.Key(3), old.IssuedAt+delta, old.ExpiresAt-old.IssuedAt, old.RequestedSamples, old.RenewUntil)
	if e != nil {
		t.Fatal(e)
	}
	c.Plan.Challenge = ch
	c.Plan.Intent.Nonce = ch.Nonce
	c.Plan.Intent.IssuedAt = ch.IssuedAt
	c.Plan.Intent.ExpiresAt = ch.ExpiresAt
	c.Plan.Intent.RenewUntil = ch.RenewUntil
	return admissionResignPlan(t, c)
}
func newAdmissionWitnessGroup(t testing.TB, c Context) *admissionWitnessGroup {
	t.Helper()
	g, e := NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	pin, e := g.ID()
	if e != nil {
		t.Fatal(e)
	}
	group := &admissionWitnessGroup{g: g, pin: pin}
	for i := byte(70); i < 74; i++ {
		root := filepath.Join(t.TempDir(), "witness")
		w, e := CreateAdmissionWitness(root, g, pin, f.Key(i))
		if e != nil {
			t.Fatal(e)
		}
		group.roots = append(group.roots, root)
		group.owners = append(group.owners, w)
		t.Cleanup(func() { _ = w.Close() })
	}
	return group
}
func admissionEntryAt(t testing.TB, g AdmissionGenesis, pos custodyfence.Position, c Context, closure *AdmissionClosure) AdmissionEntry {
	t.Helper()
	pin, _ := g.ID()
	kind := AdmissionAdmit
	if closure != nil {
		kind = AdmissionClose
	}
	e, err := (AdmissionEntry{Version: Version2, GenesisID: pin, ExpectedSequence: pos.Sequence, ExpectedHead: pos.HeadID, Kind: kind, Context: c, Closure: closure}).Sign(g, f.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func admissionUnclaimedClosure(t testing.TB, c Context) AdmissionClosure {
	t.Helper()
	x := fixtureWithContext(t, c)
	target := x.target(t, "target")
	a := x.acceptor(t)
	cert := unclaimedServe(t, c)
	ar, e := a.ApplyServe(t.Context(), cert, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	br, e := target.ApplyServe(t.Context(), cert, ar, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	out := AdmissionClosure{Serve: cert, A: ar, B: br}
	if e := out.Verify(c); e != nil {
		t.Fatal(e)
	}
	return out
}
func (g *admissionWitnessGroup) votes(t testing.TB, e AdmissionEntry, indices ...int) AdmissionCertificate {
	t.Helper()
	cert := AdmissionCertificate{Version: Version2, Entry: e}
	for _, i := range indices {
		_, before, err := g.owners[i].Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		v, err := g.owners[i].VoteAt(before, e)
		if err != nil {
			t.Fatal(err)
		}
		cert.Votes = append(cert.Votes, v)
	}
	sort.Slice(cert.Votes, func(i, j int) bool { return bytes.Compare(cert.Votes[i].Witness[:], cert.Votes[j].Witness[:]) < 0 })
	return cert
}
func (g *admissionWitnessGroup) commit(t testing.TB, cert AdmissionCertificate) {
	t.Helper()
	if e := cert.Verify(g.g); e != nil {
		t.Fatal(e)
	}
	for _, w := range g.owners {
		_, before, e := w.Snapshot()
		if e != nil {
			t.Fatal(e)
		}
		if e := w.CommitAt(before, cert); e != nil {
			t.Fatal(e)
		}
	}
}
func admissionSnapshot(t testing.TB, w *AdmissionWitness) (AdmissionSnapshot, custodyfence.WitnessPin) {
	t.Helper()
	s, p, e := w.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	return s, p
}

func TestAdmissionWitnessQuorumAndPermanentChoice(t *testing.T) {
	c := admissionContextBudget(t, 4, 2)
	group := newAdmissionWitnessGroup(t, c)
	w := group.owners[0]
	initial := custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: group.pin}}
	entry := admissionEntryAt(t, group.g, initial.Position, c, nil)
	first, e := w.VoteAt(initial, entry)
	if e != nil {
		t.Fatal(e)
	}
	competing := admissionEntryAt(t, group.g, initial.Position, admissionDistinctContext(t, c, 1), nil)
	if _, e := w.VoteAt(initial, competing); e == nil {
		t.Fatal("one witness endorsed competing assignment-global jobs")
	}
	state, locked := admissionSnapshot(t, w)
	id, _ := entry.ID()
	if state.Position.Sequence != 0 || state.SpentOperations != 0 || state.PendingOperations != 0 || locked.PendingID != id {
		t.Fatal("vote implicitly committed admission", state, locked)
	}
	_ = w.Close()
	if opened, e := OpenAdmissionWitness(group.roots[0], group.g, group.pin, f.Key(70), initial); e == nil {
		_ = opened.Close()
		t.Fatal("cold open silently adopted unknown pending vote")
	}
	if opened, e := RecoverAdmissionVote(group.roots[0], group.g, group.pin, f.Key(70), initial, competing); e == nil {
		_ = opened.Close()
		t.Fatal("cold recovery switched locked job")
	}
	w, e = RecoverAdmissionVote(group.roots[0], group.g, group.pin, f.Key(70), initial, entry)
	if e != nil {
		t.Fatal(e)
	}
	group.owners[0] = w
	defer w.Close()
	state, _ = admissionSnapshot(t, w)
	if state.Position.Sequence != 0 || state.SpentOperations != 0 {
		t.Fatal("open voted or committed", state)
	}
	retry, e := w.VoteAt(initial, entry)
	if e != nil || retry != first {
		t.Fatal("exact cold vote changed", e)
	}
	weak := group.votes(t, entry, 0, 1)
	if weak.Verify(group.g) == nil {
		t.Fatal("two of four formed admission quorum")
	}
	duplicate := AdmissionCertificate{Version: Version2, Entry: entry, Votes: []AdmissionVote{first, first, first}}
	if duplicate.Verify(group.g) == nil {
		t.Fatal("duplicate member formed admission quorum")
	}
	_, pendingBefore := admissionSnapshot(t, w)
	for _, invalid := range []AdmissionCertificate{weak, duplicate} {
		if e := w.CommitAt(pendingBefore, invalid); e == nil {
			t.Fatal("durable witness committed a weak or duplicate quorum")
		}
		unchanged, pin := admissionSnapshot(t, w)
		if unchanged != state || pin != pendingBefore {
			t.Fatal("refused quorum changed committed state or pending choice", unchanged, pin)
		}
	}
	cert := group.votes(t, entry, 0, 1, 2)
	group.commit(t, cert)
	want, after := admissionSnapshot(t, w)
	cid, _ := c.ID()
	if want.SpentOperations != 2 || want.PendingOperations != 2 || want.ActiveContextID != cid || want.Position.Sequence != 1 {
		t.Fatal("incorrect committed reservation", want)
	}
	for _, member := range group.owners {
		got, p := admissionSnapshot(t, member)
		if got != want || p != after {
			t.Fatal("assignment witnesses diverged", got, p)
		}
	}
	if _, e := w.VoteAt(initial, entry); e == nil {
		t.Fatal("committed grant was voted again from stale head")
	}
}

func TestAdmissionWitnessUnclaimedCloseDoesNotRefundBudget(t *testing.T) {
	c := admissionContextBudget(t, 4, 2)
	group := newAdmissionWitnessGroup(t, c)
	for cycle := 0; cycle < 2; cycle++ {
		if cycle > 0 {
			c = admissionDistinctContext(t, c, 1)
		}
		state, _ := admissionSnapshot(t, group.owners[0])
		entry := admissionEntryAt(t, group.g, state.Position, c, nil)
		group.commit(t, group.votes(t, entry, 0, 1, 2))
		active, p := admissionSnapshot(t, group.owners[0])
		other := admissionDistinctContext(t, c, 1)
		blocked := admissionEntryAt(t, group.g, active.Position, other, nil)
		if _, e := group.owners[0].VoteAt(p, blocked); !errors.Is(e, ErrAdmissionActive) {
			t.Fatal("active pending job admitted a competitor", e)
		}
		closure := admissionUnclaimedClosure(t, c)
		closeEntry := admissionEntryAt(t, group.g, active.Position, c, &closure)
		group.commit(t, group.votes(t, closeEntry, 0, 1, 2))
		state, _ = admissionSnapshot(t, group.owners[0])
		if state.SpentOperations != uint32(2*(cycle+1)) || state.PendingOperations != 0 || !state.ActiveContextID.IsZero() || state.SourceSequence != 0 || !state.SourceHeadID.IsZero() {
			t.Fatal("unclaimed closure refunded spent units or advanced source", state)
		}
		replay := admissionEntryAt(t, group.g, state.Position, c, nil)
		_, pin := admissionSnapshot(t, group.owners[0])
		if _, e := group.owners[0].VoteAt(pin, replay); e == nil {
			t.Fatal("closed context reused an operation budget")
		}
	}
	state, before := admissionSnapshot(t, group.owners[0])
	next := admissionEntryAt(t, group.g, state.Position, admissionDistinctContext(t, c, 1), nil)
	for i, w := range group.owners {
		if _, e := w.VoteAt(before, next); !errors.Is(e, ErrAdmissionBudget) {
			t.Fatal("spent budget admitted a fresh job", i, e)
		}
		_, pin := admissionSnapshot(t, w)
		if pin != before {
			t.Fatal("refused admission left a permanent vote", pin)
		}
	}
	_ = group.owners[0].Close()
	w, e := OpenAdmissionWitness(group.roots[0], group.g, group.pin, f.Key(70), before)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	cold, _ := admissionSnapshot(t, w)
	if cold != state {
		t.Fatal("restart reset spent budget", cold)
	}
	if _, e := w.VoteAt(before, next); !errors.Is(e, ErrAdmissionBudget) {
		t.Fatal("cold spent budget reset", e)
	}
}

func TestAdmissionWitnessUnknownStaysActiveAcrossRestart(t *testing.T) {
	c := admissionContextBudget(t, 4, 2)
	group := newAdmissionWitnessGroup(t, c)
	initial := custodyfence.Position{HeadID: group.pin}
	entry := admissionEntryAt(t, group.g, initial, c, nil)
	group.commit(t, group.votes(t, entry, 0, 1, 2))
	state, before := admissionSnapshot(t, group.owners[0])
	other := admissionDistinctContext(t, c, 1)
	next := admissionEntryAt(t, group.g, state.Position, other, nil)
	_ = group.owners[0].Close()
	w, e := OpenAdmissionWitness(group.roots[0], group.g, group.pin, f.Key(70), before)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	if _, e := w.VoteAt(before, next); !errors.Is(e, ErrAdmissionActive) {
		t.Fatal("missing result released active reservation", e)
	}
	bad := AdmissionEntry{Version: Version2, GenesisID: group.pin, ExpectedSequence: state.Position.Sequence, ExpectedHead: state.Position.HeadID, Kind: AdmissionClose, Context: c}
	if _, e := w.VoteAt(before, bad); e == nil {
		t.Fatal("missing closure proof completed active job")
	}
	after, pin := admissionSnapshot(t, w)
	if after != state || pin != before || after.PendingOperations != 2 {
		t.Fatal("invalid completion changed unknown reservation", after, pin)
	}
}

func TestAdmissionWitnessVotePersistenceFailuresKeepExactAttempt(t *testing.T) {
	for _, stage := range []string{"00000001.vote-before-sync", "00000001.vote-durable"} {
		t.Run(stage, func(t *testing.T) {
			c := admissionContextBudget(t, 4, 2)
			group := newAdmissionWitnessGroup(t, c)
			w := group.owners[0]
			initial := custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: group.pin}}
			entry := admissionEntryAt(t, group.g, initial.Position, c, nil)
			w.hook = func(at string) error {
				if at == stage {
					return errors.New("injected vote persistence failure")
				}
				return nil
			}
			if _, e := w.VoteAt(initial, entry); !errors.Is(e, ErrUncertain) {
				t.Fatal("failed sync released a vote", e)
			}
			if _, _, e := w.Snapshot(); !errors.Is(e, ErrUncertain) {
				t.Fatal("poisoned witness returned usable metadata", e)
			}
			_ = w.Close()
			recovered, e := RecoverAdmissionVote(group.roots[0], group.g, group.pin, f.Key(70), initial, entry)
			if e != nil {
				t.Fatal(e)
			}
			defer recovered.Close()
			s, pin := admissionSnapshot(t, recovered)
			id, _ := entry.ID()
			if s.Position.Sequence != 0 || s.SpentOperations != 0 || pin.PendingID != id {
				t.Fatal("cold recovery invented a committed grant", s, pin)
			}
			v, e := recovered.VoteAt(initial, entry)
			if e != nil {
				t.Fatal(e)
			}
			if v.EntryID != id {
				t.Fatal("recovered another vote")
			}
		})
	}
}

func TestAdmissionWitnessCommitPersistenceFailuresOnlyExactExtension(t *testing.T) {
	for _, stage := range []string{"00000001.certificate-before-sync", "00000001.certificate-durable"} {
		t.Run(stage, func(t *testing.T) {
			c := admissionContextBudget(t, 4, 2)
			group := newAdmissionWitnessGroup(t, c)
			entry := admissionEntryAt(t, group.g, custodyfence.Position{HeadID: group.pin}, c, nil)
			cert := group.votes(t, entry, 0, 1, 2)
			w := group.owners[0]
			_, before := admissionSnapshot(t, w)
			w.hook = func(at string) error {
				if at == stage {
					return errors.New("injected commit persistence failure")
				}
				return nil
			}
			if e := w.CommitAt(before, cert); !errors.Is(e, ErrUncertain) {
				t.Fatal("failed certificate sync reported success", e)
			}
			_ = w.Close()
			wrong := before
			wrong.PendingID = f.Hash("different external vote pin")
			if opened, e := RecoverAdmissionCommit(group.roots[0], group.g, group.pin, f.Key(70), wrong, cert); e == nil {
				_ = opened.Close()
				t.Fatal("lost commit recovery ignored external pending pin")
			}
			recovered, e := RecoverAdmissionCommit(group.roots[0], group.g, group.pin, f.Key(70), before, cert)
			if e != nil {
				t.Fatal(e)
			}
			defer recovered.Close()
			s, p := admissionSnapshot(t, recovered)
			id, _ := entry.ID()
			if s.Position.Sequence > 1 || (s.Position.Sequence == 1 && (s.Position.HeadID != id || s.SpentOperations != 2 || !p.PendingID.IsZero())) {
				t.Fatal("cold recovery selected another extension", s, p)
			}
			if e := recovered.CommitAt(before, cert); e != nil {
				t.Fatal("exact explicit commit recovery", e)
			}
			s, p = admissionSnapshot(t, recovered)
			if s.Position.Sequence != 1 || s.SpentOperations != 2 || s.PendingOperations != 2 || !p.PendingID.IsZero() {
				t.Fatal("commit recovery reset or doubled budget", s, p)
			}
			if e := recovered.CommitAt(before, cert); e != nil {
				t.Fatal("same one-transition recovery was not idempotent", e)
			}
		})
	}
}

func copyAdmissionWitnessRoot(t testing.TB, source, target string) {
	t.Helper()
	if e := os.Mkdir(target, 0700); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(source)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			t.Fatal("unexpected fixture layout", entry.Name())
		}
		b, e := os.ReadFile(filepath.Join(source, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(target, entry.Name()), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
func TestAdmissionWitnessOriginalRootAndKeyRemainRequired(t *testing.T) {
	c := admissionContextBudget(t, 4, 2)
	for _, kind := range []string{"copy", "move", "ready", "mode", "key", "busy"} {
		t.Run(kind, func(t *testing.T) {
			group := newAdmissionWitnessGroup(t, c)
			root := group.roots[0]
			_, pin := admissionSnapshot(t, group.owners[0])
			if kind == "busy" {
				if w, e := OpenAdmissionWitness(root, group.g, group.pin, f.Key(70), pin); e == nil {
					_ = w.Close()
					t.Fatal("two owners acquired one original root")
				}
				return
			}
			_ = group.owners[0].Close()
			key := f.Key(70)
			switch kind {
			case "copy":
				target := filepath.Join(t.TempDir(), "copy")
				copyAdmissionWitnessRoot(t, root, target)
				root = target
			case "move":
				target := filepath.Join(filepath.Dir(root), "moved")
				if e := os.Rename(root, target); e != nil {
					t.Fatal(e)
				}
				root = target
			case "ready":
				p := filepath.Join(root, "ready")
				b, e := os.ReadFile(p)
				if e != nil || len(b) == 0 {
					t.Fatal(e)
				}
				b[len(b)-1] ^= 1
				if e := os.WriteFile(p, b, 0600); e != nil {
					t.Fatal(e)
				}
			case "mode":
				if e := os.Chmod(filepath.Join(root, "owner.lock"), 0644); e != nil {
					t.Fatal(e)
				}
			case "key":
				key = f.Key(71)
			}
			if w, e := OpenAdmissionWitness(root, group.g, group.pin, key, pin); e == nil {
				_ = w.Close()
				t.Fatal("replaced original root/key accepted", kind)
			}
		})
	}
}

func TestAdmissionWitnessConcurrentJobsCannotBothReachQuorum(t *testing.T) {
	c := admissionContextBudget(t, 4, 2)
	group := newAdmissionWitnessGroup(t, c)
	before := custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: group.pin}}
	entries := []AdmissionEntry{admissionEntryAt(t, group.g, before.Position, c, nil), admissionEntryAt(t, group.g, before.Position, admissionDistinctContext(t, c, 1), nil)}
	type outcome struct {
		member, proposal int
		vote             AdmissionVote
		err              error
	}
	replies := make(chan outcome, 8)
	start := make(chan struct{})
	var running sync.WaitGroup
	for member, w := range group.owners {
		for choice, e := range entries {
			running.Add(1)
			go func() {
				defer running.Done()
				<-start
				vote, err := w.VoteAt(before, e)
				replies <- outcome{member: member, proposal: choice, vote: vote, err: err}
			}()
		}
	}
	close(start)
	running.Wait()
	close(replies)
	selected := map[int]int{}
	certs := []AdmissionCertificate{{Version: Version2, Entry: entries[0]}, {Version: Version2, Entry: entries[1]}}
	for result := range replies {
		if result.err != nil {
			continue
		}
		if _, ok := selected[result.member]; ok {
			t.Fatal("one durable witness signed both racing jobs", result.member)
		}
		selected[result.member] = result.proposal
		certs[result.proposal].Votes = append(certs[result.proposal].Votes, result.vote)
	}
	if len(selected) != 4 {
		t.Fatal("a valid racing proposal failed to acquire every available witness", selected)
	}
	complete := 0
	for _, cert := range certs {
		sort.Slice(cert.Votes, func(i, j int) bool { return bytes.Compare(cert.Votes[i].Witness[:], cert.Votes[j].Witness[:]) < 0 })
		if cert.Verify(group.g) == nil {
			complete++
			group.commit(t, cert)
		}
	}
	if complete > 1 {
		t.Fatal("competing jobs both obtained a quorum")
	}
	if complete == 0 {
		for _, w := range group.owners {
			s, pin := admissionSnapshot(t, w)
			if s.Position.Sequence != 0 || s.SpentOperations != 0 || pin.PendingID.IsZero() {
				t.Fatal("split votes invented admission or unlocked", s, pin)
			}
		}
	}
}

func TestAdmissionWitnessMinorityVoteFollowsOnlyExactQuorum(t *testing.T) {
	c := admissionContextBudget(t, 4, 2)
	group := newAdmissionWitnessGroup(t, c)
	before := custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: group.pin}}
	minority := admissionEntryAt(t, group.g, before.Position, c, nil)
	selectedContext := admissionDistinctContext(t, c, 1)
	selected := admissionEntryAt(t, group.g, before.Position, selectedContext, nil)
	w := group.owners[0]
	if _, e := w.VoteAt(before, minority); e != nil {
		t.Fatal(e)
	}
	_, locked := admissionSnapshot(t, w)
	cert := group.votes(t, selected, 1, 2, 3)
	if e := cert.Verify(group.g); e != nil {
		t.Fatal(e)
	}
	if e := w.CommitAt(locked, cert); e != nil {
		t.Fatal("valid quorum could not resolve a minority local choice", e)
	}
	state, after := admissionSnapshot(t, w)
	cid, _ := selectedContext.ID()
	if state.ActiveContextID != cid || state.Position.Sequence != 1 || state.SpentOperations != 2 || !after.PendingID.IsZero() {
		t.Fatal("wrong selected job after majority QC", state, after)
	}
	_ = w.Close()
	if opened, e := RecoverAdmissionVote(group.roots[0], group.g, group.pin, f.Key(70), before, minority); e == nil {
		_ = opened.Close()
		t.Fatal("old minority vote revived after selected quorum")
	}
	recovered, e := RecoverAdmissionCommit(group.roots[0], group.g, group.pin, f.Key(70), locked, cert)
	if e != nil {
		t.Fatal("cold replay rejected the retained minority-vote/majority-QC history", e)
	}
	defer recovered.Close()
	cold, pin := admissionSnapshot(t, recovered)
	if cold != state || pin != after {
		t.Fatal("cold replay changed selected history", cold, pin)
	}
	if e := recovered.CommitAt(locked, cert); e != nil {
		t.Fatal("exact majority commit retry", e)
	}
	wrongPin := locked
	wrongPin.PendingID = f.Hash("unretained minority choice")
	if e := recovered.CommitAt(wrongPin, cert); e == nil {
		t.Fatal("commit retry ignored independently retained old minority pin")
	}
}
