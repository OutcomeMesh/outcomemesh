//go:build linux || darwin

package custodyguard

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

func testKey(n byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)) }
func subject(n byte) (p [32]byte)       { copy(p[:], testKey(n)[32:]); return }
func hash(s string) types.Hash          { return types.DomainHash("guard/test", []byte(s)) }
func request(t testing.TB, choice string) wire.Request {
	t.Helper()
	q, e := (wire.Request{Kind: wire.Fence, Subject: subject(1), Namespace: hash("scope"), Slot: 0, Choice: hash(choice)}).Sign(testKey(1))
	if e != nil {
		t.Fatal(e)
	}
	return q
}
func newStore(t testing.TB, limit uint32) *Store {
	t.Helper()
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	s, e := Create(filepath.Join(parent, "guard"), Config{Subjects: [][32]byte{subject(1)}, Limit: limit})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func TestGuardCopiedKeysCannotSelectAnotherChoice(t *testing.T) {
	s := newStore(t, 2)
	q := request(t, "first")
	seal, e := s.Choose(t.Context(), q)
	if e != nil || q.VerifySeal(s.Identity().PublicKey, seal) != nil {
		t.Fatal(e)
	}
	// A clone knows exactly the same subject private key but cannot change choice.
	other := request(t, "fork")
	if _, e = s.Choose(t.Context(), other); e == nil {
		t.Fatal("cloned signer equivocated")
	}
	p, _ := s.Position()
	id := s.Identity()
	root := s.root
	s.Close()
	if _, e = Open(root, id, Position{}, nil); e == nil {
		t.Fatal("stale external cursor adopted")
	}
	restored, e := Open(root, id, Position{}, &q)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	again, e := restored.Choose(t.Context(), q)
	if e != nil || again != seal {
		t.Fatal("exact replay", e)
	}
	if got, e := restored.Position(); e != nil || got != p {
		t.Fatal("retry advanced", got, e)
	}
	if _, e = restored.Choose(t.Context(), other); e == nil {
		t.Fatal("cold clone bypass")
	}
	for _, kind := range []uint8{wire.Effect, wire.Admission} {
		bad := q
		bad.Kind = kind
		if bad.VerifySeal(id.PublicKey, seal) == nil {
			t.Fatal("cross-role seal")
		}
	}
	bad := q
	bad.Slot++
	if bad.VerifySeal(id.PublicKey, seal) == nil {
		t.Fatal("cross-slot seal")
	}
}
func TestGuardConcurrentCopiesOneWinner(t *testing.T) {
	s := newStore(t, 2)
	qs := []wire.Request{request(t, "a"), request(t, "b")}
	var wg sync.WaitGroup
	won := make(chan wire.Request, 32)
	for i := 0; i < 32; i++ {
		q := qs[i%2]
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := s.Choose(t.Context(), q); e == nil {
				won <- q
			}
		}()
	}
	wg.Wait()
	close(won)
	var choice types.Hash
	for q := range won {
		if !choice.IsZero() && choice != q.Choice {
			t.Fatal("two choices")
		}
		choice = q.Choice
	}
	if choice.IsZero() {
		t.Fatal("no winner")
	}
	p, e := s.Position()
	if e != nil || p.Sequence != 1 {
		t.Fatal(p, e)
	}
}
func TestGuardCrashBeforeReplyAndPartialEvidence(t *testing.T) {
	s := newStore(t, 2)
	q := request(t, "a")
	id := s.Identity()
	root := s.root
	s.hook = func(stage string) error {
		if stage == "after-persist" {
			return errors.New("power loss")
		}
		return nil
	}
	if _, e := s.Choose(t.Context(), q); e == nil {
		t.Fatal("fault ignored")
	}
	s.Close()
	if _, e := Open(root, id, Position{}, func() *wire.Request { x := request(t, "b"); return &x }()); e == nil {
		t.Fatal("different recovery")
	}
	live, e := Open(root, id, Position{}, &q)
	if e != nil {
		t.Fatal(e)
	}
	seal, e := live.Choose(t.Context(), q)
	if e != nil || q.VerifySeal(id.PublicKey, seal) != nil {
		t.Fatal(e)
	}
	p, _ := live.Position()
	live.Close()
	if e = os.WriteFile(filepath.Join(root, "events", eventName(2)), []byte{1}, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Open(root, id, p, nil); e == nil {
		t.Fatal("partial evidence repaired")
	}
}
func TestGuardCapacityForeignKeyAndLiveRollback(t *testing.T) {
	s := newStore(t, 1)
	q := request(t, "a")
	foreign := q
	foreign.Subject = subject(2)
	foreign, _ = foreign.Sign(testKey(2))
	if _, e := s.Choose(t.Context(), foreign); e == nil {
		t.Fatal("foreign signer")
	}
	seal, e := s.Choose(t.Context(), q)
	if e != nil {
		t.Fatal(e)
	}
	other := q
	other.Slot++
	other, _ = other.Sign(testKey(1))
	if _, e = s.Choose(t.Context(), other); e == nil {
		t.Fatal("unbounded journal")
	}
	if a, e := s.Choose(t.Context(), q); e != nil || a != seal {
		t.Fatal("full store lost exact recovery")
	}
	if e = os.Remove(filepath.Join(s.root, "events", eventName(1))); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Choose(t.Context(), other); e == nil {
		t.Fatal("live rollback adopted")
	}
}
func TestGuardHTTPAuthenticationEOFAndLostReply(t *testing.T) {
	s := newStore(t, 3)
	q := request(t, "a")
	base := Handler(s)
	lost := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lost {
			lost = false
			rec := httptest.NewRecorder()
			base.ServeHTTP(rec, r)
			w.WriteHeader(503)
			return
		}
		base.ServeHTTP(w, r)
	}))
	defer srv.Close()
	c := Client{URL: srv.URL}
	if _, e := wire.Obtain(t.Context(), c, s.Identity().PublicKey, q, testKey(1)); e == nil {
		t.Fatal("lost reply accepted")
	}
	seal, e := wire.Obtain(t.Context(), c, s.Identity().PublicKey, q, testKey(1))
	if e != nil || q.VerifySeal(s.Identity().PublicKey, seal) != nil {
		t.Fatal(e)
	}
	p, _ := s.Position()
	raw, _ := q.CanonicalBytes()
	r, e := http.Post(srv.URL+Route, "application/octet-stream", bytes.NewReader(append(raw, 1)))
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r.StatusCode == 200 {
		t.Fatal("trailing payload")
	}
	if now, _ := s.Position(); now != p {
		t.Fatal("malformed request consumed")
	}
	srv.Close()
	if _, e = wire.Obtain(t.Context(), c, s.Identity().PublicKey, q, testKey(1)); e == nil {
		t.Fatal("network failure passed")
	}
}
func FuzzGuardRequest(f *testing.F) {
	q := request(f, "seed")
	b, _ := q.CanonicalBytes()
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		q, e := wire.DecodeRequest(b)
		if e != nil {
			return
		}
		a, e := q.CanonicalBytes()
		if e != nil || !bytes.Equal(a, b) {
			t.Fatal("noncanonical")
		}
	})
}

func TestGuardFullRosterAndObserverFailure(t *testing.T) {
	// A bounded roster can exceed 4 KiB in JSON. Creation and reopening must agree.
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	c := Config{Limit: 1}
	for i := 0; i < MaximumSubjects; i++ {
		var k [32]byte
		for j := range k {
			k[j] = 255
		}
		k[0] = byte(200 + i)
		c.Subjects = append(c.Subjects, k)
	}
	s, e := Create(filepath.Join(parent, "maximum-config"), c)
	if e != nil {
		t.Fatal(e)
	}
	if len(s.configBytes) <= 4096 {
		t.Fatal("fixture not exercising bound")
	}
	id := s.Identity()
	path := s.root
	s.Close()
	s, e = Open(path, id, Position{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	live := newStore(t, 2)
	q := request(t, "selected")
	live.SetObserver(func(Position, wire.Request) error { return errors.New("external log unavailable") })
	if _, e = live.Choose(t.Context(), q); e == nil {
		t.Fatal("observer failure ignored")
	}
	if _, e = live.Choose(t.Context(), request(t, "fork")); e == nil {
		t.Fatal("observer failure rolled back durable choice")
	}
	live.SetObserver(nil)
	seal, e := live.Choose(t.Context(), q)
	if e != nil || q.VerifySeal(live.Identity().PublicKey, seal) != nil {
		t.Fatal(e)
	}
}

func TestGuardRequestCanonicalVector(t *testing.T) {
	q := request(t, "vector")
	raw, e := q.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	got := types.DomainHash("OMESH/test/guard-request/vector", raw).String()
	const want = "95921e85545bdf9d43507d06e36ac511b38bedc99c4c4f7b53459af5049886e7"
	if got != want {
		t.Fatal(got)
	}
}
