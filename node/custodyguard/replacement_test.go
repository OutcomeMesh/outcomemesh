//go:build linux || darwin

package custodyguard

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

func replaceableStore(t testing.TB, limit uint32) *Store {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	subs := [][32]byte{subject(1), subject(2)}
	sort.Slice(subs, func(i, j int) bool { return bytes.Compare(subs[i][:], subs[j][:]) < 0 })
	s, err := Create(filepath.Join(parent, "guard"), Config{Subjects: subs, Limit: limit, Revoker: subject(9), Replacer: subject(10)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func replacementRequest(t testing.TB, s *Store, old, new byte) wire.Replacement {
	t.Helper()
	rev := revokeRequest(t, s, old)
	if _, err := s.Revoke(t.Context(), rev); err != nil {
		t.Fatal(err)
	}
	p, err := s.Position()
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := rev.ID()
	q := wire.Replacement{GuardID: s.Identity().ID(), Subject: subject(old), Successor: subject(new), Authority: subject(10), RevocationID: rid, EvidenceID: hash("retained obligations inventory"), Before: p}
	q, err = q.Accept(testKey(new))
	if err != nil {
		t.Fatal(err)
	}
	q, err = q.Authorize(testKey(10))
	if err != nil {
		t.Fatal(err)
	}
	return q
}
func resignReplacement(t testing.TB, q wire.Replacement, new byte) wire.Replacement {
	t.Helper()
	q.SuccessorSignature = [64]byte{}
	q.Signature = [64]byte{}
	var err error
	q, err = q.Accept(testKey(new))
	if err != nil {
		t.Fatal(err)
	}
	q, err = q.Authorize(testKey(10))
	if err != nil {
		t.Fatal(err)
	}
	return q
}
func TestGuardReplacementKeepsSlotsBudgetAndPermanentRevocations(t *testing.T) {
	s := replaceableStore(t, 2)
	old := request(t, "selected before incident")
	if _, err := s.Choose(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	q := replacementRequest(t, s, 1, 80)
	r, err := s.Replace(t.Context(), q)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verify(s.Identity().PublicKey, s.Identity().ID(), q) != nil {
		t.Fatal("receipt")
	}
	fresh := old
	fresh.Subject = subject(80)
	fresh, _ = fresh.Sign(testKey(80))
	seal, err := s.Choose(t.Context(), fresh)
	if err != nil || fresh.VerifySeal(s.Identity().PublicKey, seal) != nil {
		t.Fatal("inherited exact choice", err)
	}
	conflict := fresh
	conflict.Choice = hash("different outcome")
	conflict, _ = conflict.Sign(testKey(80))
	if _, err = s.Choose(t.Context(), conflict); err == nil {
		t.Fatal("replacement reset old slot")
	}
	for kind := wire.Fence; kind <= wire.Gateway; kind++ {
		copyQ := old
		copyQ.Kind = kind
		copyQ.Namespace = hash("fresh copied root")
		copyQ, _ = copyQ.Sign(testKey(1))
		if _, err = s.Choose(t.Context(), copyQ); err == nil {
			t.Fatal("old key revived", kind)
		}
	}
	fresh.Slot++
	fresh, _ = fresh.Sign(testKey(80))
	if _, err = s.Choose(t.Context(), fresh); err != nil {
		t.Fatal(err)
	}
	fresh.Slot++
	fresh, _ = fresh.Sign(testKey(80))
	if _, err = s.Choose(t.Context(), fresh); err == nil {
		t.Fatal("replacement refunded budget")
	}
	if len(s.choices) != 2 {
		t.Fatal("lost choices")
	}
	rev := wire.Revocation{GuardID: s.Identity().ID(), Subject: subject(80), Authority: subject(9), ReasonID: hash("successor incident")}
	rev, err = rev.Sign(testKey(9))
	if err != nil {
		t.Fatal(err)
	}
	if ValidateSuccessorRevocation(s.config, s.Identity(), rev, r) != nil {
		t.Fatal("public successor revocation")
	}
	if _, err = s.Revoke(t.Context(), rev); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Choose(t.Context(), fresh); err == nil {
		t.Fatal("revoked successor")
	}
	again, err := s.Replace(t.Context(), q)
	if err != nil || again != r {
		t.Fatal("historical receipt", err)
	}
	third := q
	third.Subject = subject(80)
	third.Successor = subject(81)
	third.RevocationID, _ = rev.ID()
	third.Before, _ = s.Position()
	third = resignReplacement(t, third, 81)
	if _, err = s.Replace(t.Context(), third); err == nil {
		t.Fatal("unbounded replacement chain")
	}
	id, root := s.Identity(), s.root
	p, _ := s.Position()
	s.Close()
	cold, err := Open(root, id, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	if len(cold.choices) != 2 || len(cold.revoked) != 2 || len(cold.replacements) != 1 {
		t.Fatal("cold continuity")
	}
	if _, err = cold.Choose(t.Context(), fresh); err == nil {
		t.Fatal("cold successor revocation lost")
	}
	again, err = cold.Replace(t.Context(), q)
	if err != nil || again != r {
		t.Fatal("cold exact receipt", err)
	}
}
func TestGuardReplacementRejectsUnauthorizedStaleAndReusedKeys(t *testing.T) {
	s := replaceableStore(t, 8)
	q := replacementRequest(t, s, 1, 80)
	before, _ := s.Position()
	for _, mutate := range []func(*wire.Replacement){
		func(q *wire.Replacement) { q.GuardID = hash("other") }, func(q *wire.Replacement) { q.Subject = subject(2) },
		func(q *wire.Replacement) { q.RevocationID = hash("other revocation") }, func(q *wire.Replacement) { q.Before.Head = hash("stale") },
	} {
		bad := q
		mutate(&bad)
		bad = resignReplacement(t, bad, 80)
		if _, err := s.Replace(t.Context(), bad); err == nil {
			t.Fatal("bad replacement accepted")
		}
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.Replace(canceled, q); err == nil {
		t.Fatal("canceled")
	}
	if _, err := s.Replace(nil, q); err == nil {
		t.Fatal("nil context")
	}
	if after, _ := s.Position(); after != before {
		t.Fatal("invalid requests mutated history")
	}
	if _, err := s.Replace(t.Context(), q); err != nil {
		t.Fatal(err)
	}
	other := replacementRequest(t, s, 2, 80)
	if _, err := s.Replace(t.Context(), other); err == nil {
		t.Fatal("same signer counted as two subjects")
	}
	legacy := revocableStore(t, 2)
	q = replacementRequest(t, legacy, 1, 80)
	if _, err := legacy.Replace(t.Context(), q); err == nil {
		t.Fatal("legacy config gained replacement authority")
	}
}
func TestGuardReplacementRaceRetainsOneSuccessor(t *testing.T) {
	s := replaceableStore(t, 4)
	q := replacementRequest(t, s, 1, 80)
	other := q
	other.Successor = subject(81)
	other = resignReplacement(t, other, 81)
	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, q := range []wire.Replacement{q, other} {
		go func() { defer wg.Done(); <-start; _, err := s.Replace(t.Context(), q); results <- err }()
	}
	close(start)
	wg.Wait()
	close(results)
	good := 0
	for err := range results {
		if err == nil {
			good++
		}
	}
	if good != 1 || len(s.replacements) != 1 {
		t.Fatal("competing successors", good)
	}
}
func TestGuardReplacementCrashRecoveryAndTampering(t *testing.T) {
	for _, stage := range []string{"before-persist", "after-persist", "observer"} {
		t.Run(stage, func(t *testing.T) {
			s := replaceableStore(t, 4)
			q := replacementRequest(t, s, 1, 80)
			id, root := s.Identity(), s.root
			failure := errors.New("cut")
			if stage == "observer" {
				s.SetReplacementObserver(func(Position, wire.Replacement) error { return failure })
			} else {
				s.hook = func(at string) error {
					if at == stage {
						return failure
					}
					return nil
				}
			}
			if _, err := s.Replace(t.Context(), q); !errors.Is(err, failure) {
				t.Fatal(err)
			}
			s.Close()
			if stage != "before-persist" {
				if stale, err := Open(root, id, q.Before, nil); err == nil {
					stale.Close()
					t.Fatal("adopted unknown tip")
				}
			}
			cold, err := RecoverReplacement(root, id, q.Before, q)
			if err != nil {
				t.Fatal(err)
			}
			defer cold.Close()
			r, err := cold.Replace(t.Context(), q)
			if err != nil {
				t.Fatal(err)
			}
			after, _ := r.After()
			actual, _ := cold.Position()
			if after != actual {
				t.Fatal("recovery appended twice")
			}
			if err = os.WriteFile(filepath.Join(root, "events", eventName(int(actual.Sequence)+1)), []byte("partial"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = cold.Replace(t.Context(), q); err == nil {
				t.Fatal("live tampering")
			}
			cold.Close()
			if broken, err := Open(root, id, actual, nil); err == nil {
				broken.Close()
				t.Fatal("partial record accepted")
			}
		})
	}
}
func TestGuardReplacementHTTPCompleteRequestAndLostReply(t *testing.T) {
	s := replaceableStore(t, 4)
	q := replacementRequest(t, s, 1, 80)
	raw, _ := q.CanonicalBytes()
	handler := Handler(s)
	for _, body := range []io.ReadCloser{io.NopCloser(bytes.NewReader(append(bytes.Clone(raw), 0))), lateBodyError{bytes.NewReader(raw)}} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, ReplacementRoute, body))
		if w.Code == 200 {
			t.Fatal("framing")
		}
	}
	if p, _ := s.Position(); p != q.Before {
		t.Fatal("mutation before EOF")
	}
	var mu sync.Mutex
	first := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		mu.Lock()
		drop := first
		first = false
		mu.Unlock()
		if drop {
			http.Error(w, "lost", 503)
			return
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	defer server.Close()
	client := Client{URL: server.URL}
	id := s.Identity()
	if _, err := wire.ObtainReplacement(t.Context(), client, id.PublicKey, id.ID(), q); err == nil {
		t.Fatal("lost reply reported success")
	}
	r, err := wire.ObtainReplacement(t.Context(), client, id.PublicKey, id.ID(), q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wire.ObtainReplacement(t.Context(), client, subject(99), id.ID(), q); err == nil {
		t.Fatal("foreign guard")
	}
	after, _ := r.After()
	if p, _ := s.Position(); p != after {
		t.Fatal("duplicate event")
	}
}

func TestGuardReplacementReservedCapacityForEveryConfiguredSubject(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	subjects := make([][32]byte, MaximumSubjects)
	for i := range subjects {
		subjects[i] = subject(byte(i + 20))
	}
	sort.Slice(subjects, func(i, j int) bool { return bytes.Compare(subjects[i][:], subjects[j][:]) < 0 })
	s, err := Create(filepath.Join(parent, "guard"), Config{Subjects: subjects, Limit: 1, Revoker: subject(9), Replacer: subject(10)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q := wire.Request{Kind: wire.Gateway, Subject: subject(20), Namespace: hash("exhausted budget"), Choice: hash("one choice")}
	q, err = q.Sign(testKey(20))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Choose(t.Context(), q); err != nil {
		t.Fatal(err)
	}
	for old := byte(20); old < 20+MaximumSubjects; old++ {
		r := replacementRequest(t, s, old, old+100)
		if _, err = s.Replace(t.Context(), r); err != nil {
			t.Fatal("replacement reserved slot", old, err)
		}
		revoke := revokeRequest(t, s, old+100)
		if _, err = s.Revoke(t.Context(), revoke); err != nil {
			t.Fatal("successor revocation reserved slot", old, err)
		}
	}
	p, err := s.Position()
	if err != nil || p.Sequence != 1+3*MaximumSubjects {
		t.Fatal(p, err)
	}
	id, root := s.Identity(), s.root
	s.Close()
	s, err = Open(root, id, p, nil)
	if err != nil {
		t.Fatal("cold maximum roster", err)
	}
	defer s.Close()
	if len(s.choices) != 1 || len(s.replacements) != MaximumSubjects || len(s.revoked) != 2*MaximumSubjects {
		t.Fatal("history accounting")
	}
}
