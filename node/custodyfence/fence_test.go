package custodyfence

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}
func testPublic(seed byte) (key [32]byte) {
	copy(key[:], testKey(seed).Public().(ed25519.PublicKey))
	return key
}
func testHash(seed byte) types.Hash {
	return types.DomainHash("OMESH/custody-fence/test/v0", []byte{seed})
}
func testScope() Scope {
	s := Scope{AssignmentID: testHash(1), IntentID: testHash(2), PlanID: testHash(3), BeginID: testHash(4), Owner: testPublic(1), Controller: testPublic(2), Threshold: 3}
	for seed := byte(3); seed <= 6; seed++ {
		s.Witnesses = append(s.Witnesses, testPublic(seed))
	}
	sort.Slice(s.Witnesses, func(i, j int) bool { return bytes.Compare(s.Witnesses[i][:], s.Witnesses[j][:]) < 0 })
	return s
}
func signed(t testing.TB, s Scope, position Position, kind Kind, claim, evidence types.Hash) Command {
	t.Helper()
	id, _ := s.ID()
	c := Command{ScopeID: id, ExpectedSequence: position.Sequence, ExpectedHead: position.HeadID, Kind: kind, ClaimID: claim, EvidenceID: evidence}
	key := testKey(1)
	if kind == MarkUnknown || kind == CloseUnclaimed {
		key = testKey(2)
	}
	c, err := c.Sign(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func certificate(t testing.TB, c Command, seeds ...byte) Certificate {
	t.Helper()
	cert := Certificate{Command: c}
	for _, seed := range seeds {
		v, err := signVote(c, testKey(seed))
		if err != nil {
			t.Fatal(err)
		}
		cert.Votes = append(cert.Votes, v)
	}
	sort.Slice(cert.Votes, func(i, j int) bool { return bytes.Compare(cert.Votes[i].Witness[:], cert.Votes[j].Witness[:]) < 0 })
	return cert
}
func initial(s Scope) WitnessPin { id, _ := s.ID(); return WitnessPin{Position: Position{HeadID: id}} }
func root(t testing.TB) string {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "witness")
}

func TestIndependentFenceUnknownNeverCancelsOrReissues(t *testing.T) {
	s := testScope()
	p := initial(s)
	state, err := NewState(s, p.Position.HeadID)
	if err != nil {
		t.Fatal(err)
	}
	claim := signed(t, s, p.Position, Claim, types.Hash{}, types.Hash{})
	claimID, _ := claim.ID()
	if err := state.Apply(certificate(t, claim, 3, 4, 5)); err != nil {
		t.Fatal(err)
	}
	unknown := signed(t, s, state.Snapshot().Position, MarkUnknown, claimID, testHash(20))
	if err := state.Apply(certificate(t, unknown, 3, 4, 6)); err != nil {
		t.Fatal(err)
	}
	held := state.Snapshot()
	if held.Phase != Unknown || !held.ObligationHeld || held.ClaimID != claimID {
		t.Fatal(held)
	}
	// The copied owner can still sign, but cannot select another attempt,
	// close an already claimed slot or rewrite the uncertainty observation.
	for _, c := range []Command{
		signed(t, s, held.Position, Claim, types.Hash{}, types.Hash{}),
		signed(t, s, held.Position, CloseUnclaimed, types.Hash{}, testHash(21)),
		signed(t, s, held.Position, MarkUnknown, claimID, testHash(22)),
		signed(t, s, held.Position, RecordResult, testHash(23), testHash(24)),
	} {
		if err := state.Apply(certificate(t, c, 3, 4, 5)); err == nil {
			t.Fatal("unknown outcome released or rebound")
		}
		if state.Snapshot() != held {
			t.Fatal("rejection mutated state")
		}
	}
	result := signed(t, s, held.Position, RecordResult, claimID, testHash(25))
	if err := state.Apply(certificate(t, result, 3, 5, 6)); err != nil {
		t.Fatal(err)
	}
	x := state.Snapshot()
	if x.Phase != ResultRecorded || !x.ObligationHeld || x.ClaimID != claimID || x.EvidenceID != testHash(25) {
		t.Fatal("result released administrative hold", x)
	}
}

func TestIndependentFenceCertificateSubsetsAndSignatureSeparation(t *testing.T) {
	s := testScope()
	p := initial(s)
	claim := signed(t, s, p.Position, Claim, types.Hash{}, types.Hash{})
	first, _ := NewState(s, p.Position.HeadID)
	second, _ := NewState(s, p.Position.HeadID)
	if err := first.Apply(certificate(t, claim, 3, 4, 5)); err != nil {
		t.Fatal(err)
	}
	if err := second.Apply(certificate(t, claim, 4, 5, 6)); err != nil {
		t.Fatal(err)
	}
	if first.Snapshot() != second.Snapshot() {
		t.Fatal("quorum subset changed transition head")
	}
	for _, bad := range []Certificate{certificate(t, claim, 3, 4), certificate(t, claim, 3, 4, 7), certificate(t, claim, 3, 3, 4)} {
		if err := bad.Verify(s); err == nil {
			t.Fatal("invalid quorum accepted")
		}
	}
	bad := claim
	bad.Signature = [64]byte{}
	bad, _ = bad.Sign(testKey(2))
	if err := bad.Verify(s); err == nil {
		t.Fatal("controller impersonated owner")
	}
	for _, change := range []func(*Scope){func(s *Scope) { s.Threshold = 2 }, func(s *Scope) { s.Witnesses[0] = s.Owner }, func(s *Scope) { s.Witnesses[1] = s.Witnesses[0] }, func(s *Scope) { s.Version = 2 }} {
		other := testScope()
		change(&other)
		if _, err := other.ID(); err == nil {
			t.Fatal("invalid scope accepted")
		}
	}
	other := testScope()
	other.IntentID = testHash(99)
	if err := certificate(t, claim, 3, 4, 5).Verify(other); err == nil {
		t.Fatal("signature transferred to another intent")
	}
}

func TestIndependentWitnessDurableLocksAndQuorumRecovery(t *testing.T) {
	s := testScope()
	pin := initial(s)
	paths := make([]string, 4)
	witnesses := make([]*Witness, 4)
	for i := range witnesses {
		paths[i] = root(t)
		w, err := Create(paths[i], s, pin.Position.HeadID, testKey(byte(i+3)))
		if err != nil {
			t.Fatal(err)
		}
		witnesses[i] = w
		t.Cleanup(func() { _ = w.Close() })
	}
	claim := signed(t, s, pin.Position, Claim, types.Hash{}, types.Hash{})
	cancel := signed(t, s, pin.Position, CloseUnclaimed, types.Hash{}, testHash(30))
	cert := Certificate{Command: claim}
	for _, w := range witnesses[:3] {
		v, err := w.Vote(claim)
		if err != nil {
			t.Fatal(err)
		}
		cert.Votes = append(cert.Votes, v)
	}
	if _, err := witnesses[3].Vote(cancel); err != nil {
		t.Fatal(err)
	}
	sort.Slice(cert.Votes, func(i, j int) bool { return bytes.Compare(cert.Votes[i].Witness[:], cert.Votes[j].Witness[:]) < 0 })
	if other, err := Open(paths[0], s, pin.Position.HeadID, testKey(3), pin); !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("second owner", err)
	}
	_, locked, err := witnesses[0].Snapshot()
	if err != nil || locked.PendingID.IsZero() {
		t.Fatal(err)
	}
	if err := witnesses[0].Close(); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(paths[0], s, pin.Position.HeadID, testKey(3), pin); err == nil {
		_ = other.Close()
		t.Fatal("stale pre-vote pin accepted")
	}
	w, err := Open(paths[0], s, pin.Position.HeadID, testKey(3), locked)
	if err != nil {
		t.Fatal(err)
	}
	witnesses[0] = w
	defer w.Close()
	if _, err := w.Vote(cancel); !errors.Is(err, ErrLocked) {
		t.Fatal("cold restart forgot vote lock", err)
	}
	if vote, err := w.Vote(claim); err != nil || vote.CommandID != locked.PendingID {
		t.Fatal("exact vote retry", err)
	}
	for i, w := range witnesses {
		if err := w.Commit(cert); err != nil {
			t.Fatal("valid quorum must override minority local proposal", err)
		}
		x, next, err := w.Snapshot()
		if err != nil || x.Phase != Claimed || !next.PendingID.IsZero() {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := Open(paths[i], s, pin.Position.HeadID, testKey(byte(i+3)), next)
		if err != nil {
			t.Fatal("full replay", err)
		}
		defer reopened.Close()
		if err := reopened.Commit(cert); err != nil {
			t.Fatal("exact commit retry", err)
		}
		if _, err := reopened.Vote(claim); err == nil {
			t.Fatal("historical claim returned a new vote")
		}
	}
}

func TestIndependentWitnessCopiedParticipantCannotCertifyConflict(t *testing.T) {
	s := testScope()
	pin := initial(s)
	claim := signed(t, s, pin.Position, Claim, types.Hash{}, types.Hash{})
	witnesses := make([]*Witness, 4)
	cert := Certificate{Command: claim}
	for i := range witnesses {
		w, err := Create(root(t), s, pin.Position.HeadID, testKey(byte(i+3)))
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		witnesses[i] = w
		v, err := w.Vote(claim)
		if err != nil {
			t.Fatal(err)
		}
		cert.Votes = append(cert.Votes, v)
	}
	sort.Slice(cert.Votes, func(i, j int) bool { return bytes.Compare(cert.Votes[i].Witness[:], cert.Votes[j].Witness[:]) < 0 })
	for _, w := range witnesses {
		if err := w.Commit(cert); err != nil {
			t.Fatal(err)
		}
	}
	position := Position{Sequence: 1}
	position.HeadID, _ = claim.ID()
	result := signed(t, s, position, RecordResult, position.HeadID, testHash(40))
	for _, w := range witnesses[:3] {
		if _, err := w.Vote(result); err != nil {
			t.Fatal(err)
		}
	}
	// The attacker copied the owner's seed AND its old journal. Its command
	// has a valid owner signature and exact position, but three independent
	// witness locks reject it. Even one compromised witness cannot form 3/4.
	conflict := signed(t, s, position, RecordResult, position.HeadID, testHash(41))
	forged := certificate(t, conflict, 3)
	for _, w := range witnesses[1:] {
		v, err := w.Vote(conflict)
		if err == nil {
			forged.Votes = append(forged.Votes, v)
		}
	}
	sort.Slice(forged.Votes, func(i, j int) bool { return bytes.Compare(forged.Votes[i].Witness[:], forged.Votes[j].Witness[:]) < 0 })
	if len(forged.Votes) >= int(s.Threshold) || forged.Verify(s) == nil {
		t.Fatal("copied participant and one compromised witness formed a quorum")
	}
}

func TestIndependentWitnessPersistenceErrorsNeverReleaseVotes(t *testing.T) {
	for _, stage := range []string{"before-file-sync", "before-directory-sync", "after-directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			s := testScope()
			before := initial(s)
			path := root(t)
			w, err := Create(path, s, before.Position.HeadID, testKey(3))
			if err != nil {
				t.Fatal(err)
			}
			command := signed(t, s, before.Position, Claim, types.Hash{}, types.Hash{})
			w.hook = func(at string) error {
				if at == stage {
					return errors.New("injected persistence uncertainty")
				}
				return nil
			}
			if vote, err := w.Vote(command); !errors.Is(err, ErrUncertain) || vote != (Vote{}) {
				t.Fatal("signature escaped uncertain persistence", vote, err)
			}
			if _, _, err := w.Snapshot(); !errors.Is(err, ErrUncertain) {
				t.Fatal("uncertain owner remained usable", err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			other := signed(t, s, before.Position, CloseUnclaimed, types.Hash{}, testHash(60))
			if recovered, err := RecoverVote(path, s, before.Position.HeadID, testKey(3), before, other); err == nil {
				_ = recovered.Close()
				t.Fatal("recovery selected a competing proposal")
			}
			w, err = RecoverVote(path, s, before.Position.HeadID, testKey(3), before, command)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if vote, err := w.Vote(command); err != nil || vote.CommandID.IsZero() {
				t.Fatal("explicit exact recovery", err)
			}
		})
	}
}

func TestIndependentWitnessCommitUncertaintyKeepsExactExtension(t *testing.T) {
	s := testScope()
	before := initial(s)
	path := root(t)
	w, err := Create(path, s, before.Position.HeadID, testKey(3))
	if err != nil {
		t.Fatal(err)
	}
	claim := signed(t, s, before.Position, Claim, types.Hash{}, types.Hash{})
	cert := certificate(t, claim, 3, 4, 5)
	w.hook = func(stage string) error {
		if stage == "after-directory-sync" {
			return errors.New("lost durable commit acknowledgement")
		}
		return nil
	}
	if err := w.Commit(cert); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	_ = w.Close()
	if stale, err := Open(path, s, before.Position.HeadID, testKey(3), before); err == nil {
		_ = stale.Close()
		t.Fatal("accepted stale pin after commit")
	}
	w, err = RecoverCommit(path, s, before.Position.HeadID, testKey(3), before, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Commit(cert); err != nil {
		t.Fatal(err)
	}
	x, _, err := w.Snapshot()
	if err != nil || x.Position.Sequence != 1 || x.Phase != Claimed {
		t.Fatal(x, err)
	}
}

func TestIndependentWitnessConcurrentConflictsAndTampering(t *testing.T) {
	s := testScope()
	pin := initial(s)
	path := root(t)
	w, err := Create(path, s, pin.Position.HeadID, testKey(3))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	claim := signed(t, s, pin.Position, Claim, types.Hash{}, types.Hash{})
	cancel := signed(t, s, pin.Position, CloseUnclaimed, types.Hash{}, testHash(70))
	var wg sync.WaitGroup
	results := make(chan Vote, 2)
	for _, c := range []Command{claim, cancel} {
		wg.Add(1)
		go func() { defer wg.Done(); v, _ := w.Vote(c); results <- v }()
	}
	wg.Wait()
	close(results)
	count := 0
	for v := range results {
		if v != (Vote{}) {
			count++
		}
	}
	if count != 1 {
		t.Fatal("conflicting concurrent signatures", count)
	}
	_, before, _ := w.Snapshot()
	if err := os.WriteFile(filepath.Join(path, "unexpected"), []byte("copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.Snapshot(); err == nil {
		t.Fatal("unexpected file ignored")
	}
	if err := os.Remove(filepath.Join(path, "unexpected")); err != nil {
		t.Fatal(err)
	}
	_, after, err := w.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed check mutated state", err)
	}
}

func TestIndependentFenceCodecRoundTripsAndGoldens(t *testing.T) {
	s := testScope()
	pin := initial(s)
	c := signed(t, s, pin.Position, Claim, types.Hash{}, types.Hash{})
	cert := certificate(t, c, 3, 4, 5)
	v := cert.Votes[0]
	for _, tc := range []struct {
		name   string
		encode func() ([]byte, error)
		decode func([]byte) ([]byte, error)
	}{
		{"scope", s.CanonicalBytes, func(b []byte) ([]byte, error) {
			x, e := DecodeScope(b)
			if e != nil {
				return nil, e
			}
			return x.CanonicalBytes()
		}},
		{"command", c.CanonicalBytes, func(b []byte) ([]byte, error) {
			x, e := DecodeCommand(b)
			if e != nil {
				return nil, e
			}
			return x.CanonicalBytes()
		}},
		{"vote", v.CanonicalBytes, func(b []byte) ([]byte, error) {
			x, e := DecodeVote(b)
			if e != nil {
				return nil, e
			}
			return x.CanonicalBytes()
		}},
		{"certificate", cert.CanonicalBytes, func(b []byte) ([]byte, error) {
			x, e := DecodeCertificate(b)
			if e != nil {
				return nil, e
			}
			return x.CanonicalBytes()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.encode()
			if err != nil {
				t.Fatal(err)
			}
			got, err := tc.decode(b)
			if err != nil || !bytes.Equal(b, got) {
				t.Fatal(err)
			}
			for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte(nil), b...), 0), append([]byte{0}, b...)} {
				if _, err := tc.decode(bad); err == nil {
					t.Fatal("noncanonical encoding accepted")
				}
			}
		})
	}
	id, _ := c.ID()
	if pin.Position.HeadID.String() != "d4e3af76f965480b597aff058092e5cf40d34d7612378febd6a464dfde49571b" ||
		id.String() != "43779ea010f7d43645d85f69647c6588e602f825ce44330db32bb431ff1313e7" || CommandBytes != 211 || VoteBytes != 138 {
		t.Fatal("independent fence V0 vector changed", pin.Position.HeadID, id)
	}
}

func FuzzIndependentFenceCodecs(f *testing.F) {
	s := testScope()
	scope, _ := s.CanonicalBytes()
	id, _ := s.ID()
	command, _ := (Command{ScopeID: id, ExpectedHead: id, Kind: Claim}).Sign(testKey(1))
	cb, _ := command.CanonicalBytes()
	vote, _ := signVote(command, testKey(3))
	vb, _ := vote.CanonicalBytes()
	cert := (Certificate{Command: command, Votes: []Vote{vote}})
	qb, _ := cert.CanonicalBytes()
	for _, b := range [][]byte{scope, cb, vb, qb, nil} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if x, err := DecodeScope(b); err == nil {
			out, err := x.CanonicalBytes()
			if err != nil || !bytes.Equal(b, out) {
				t.Fatal("scope did not round trip")
			}
		}
		if x, err := DecodeCommand(b); err == nil {
			out, err := x.CanonicalBytes()
			if err != nil || !bytes.Equal(b, out) {
				t.Fatal("command did not round trip")
			}
		}
		if x, err := DecodeVote(b); err == nil {
			out, err := x.CanonicalBytes()
			if err != nil || !bytes.Equal(b, out) {
				t.Fatal("vote did not round trip")
			}
		}
		if x, err := DecodeCertificate(b); err == nil {
			out, err := x.CanonicalBytes()
			if err != nil || !bytes.Equal(b, out) {
				t.Fatal("certificate did not round trip")
			}
		}
	})
}
