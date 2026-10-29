//go:build linux || darwin

package custodyguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

func revocableStore(t testing.TB, limit uint32) *Store {
	t.Helper()
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	subjects := [][32]byte{subject(1), subject(2)}
	sort.Slice(subjects, func(i, j int) bool { return bytes.Compare(subjects[i][:], subjects[j][:]) < 0 })
	s, e := Create(filepath.Join(parent, "guard"), Config{Subjects: subjects, Limit: limit, Revoker: subject(9)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func revokeRequest(t testing.TB, s *Store, n byte) wire.Revocation {
	t.Helper()
	q, e := (wire.Revocation{GuardID: s.Identity().ID(), Subject: subject(n), Authority: subject(9), ReasonID: hash("incident")}).Sign(testKey(9))
	if e != nil {
		t.Fatal(e)
	}
	return q
}
func TestGuardRevocationPermanentReservedCapacityAndLegacyConfig(t *testing.T) {
	legacy := Config{Subjects: [][32]byte{subject(1)}, Limit: 2}
	raw, _ := json.Marshal(legacy)
	old, _ := json.Marshal(struct {
		Subjects [][32]byte
		Limit    uint32
	}{legacy.Subjects, legacy.Limit})
	if !bytes.Equal(raw, old) {
		t.Fatal("legacy config bytes changed")
	}
	s := revocableStore(t, 1)
	q := request(t, "first")
	seal, e := s.Choose(t.Context(), q)
	if e != nil {
		t.Fatal(e)
	}
	rev := revokeRequest(t, s, 1)
	r, e := s.Revoke(t.Context(), rev)
	if e != nil || r.Verify(s.Identity().PublicKey, s.Identity().ID(), rev) != nil {
		t.Fatal("reserved slot", e)
	}
	for kind := wire.Fence; kind <= wire.Admission; kind++ {
		for slot := uint64(0); slot < 3; slot++ {
			copyQ := q
			copyQ.Kind = kind
			copyQ.Slot = slot
			if slot > 0 {
				copyQ.Namespace = hash("new namespace")
			}
			copyQ, _ = copyQ.Sign(testKey(1))
			if _, e = s.Choose(t.Context(), copyQ); e == nil {
				t.Fatal("revoked key obtained seal", kind, slot)
			}
		}
	}
	if q.VerifySeal(s.Identity().PublicKey, seal) != nil {
		t.Fatal("historical seal invalidated")
	}
	r2, e := s.Revoke(t.Context(), revokeRequest(t, s, 2))
	if e != nil {
		t.Fatal("every subject has reserve", e)
	}
	after, _ := r2.After()
	p, _ := s.Position()
	if p != after || p.Sequence != 3 || len(s.choices) != 1 {
		t.Fatal("accounting", p)
	}
	again, e := s.Revoke(t.Context(), rev)
	if e != nil || again != r {
		t.Fatal("stable receipt after later event", e)
	}
	changed := rev
	changed.ReasonID = hash("changed reason")
	changed, _ = changed.Sign(testKey(9))
	if _, e = s.Revoke(t.Context(), changed); e == nil {
		t.Fatal("replaced tombstone")
	}
	id, root := s.Identity(), s.root
	s.Close()
	cold, e := Open(root, id, p, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer cold.Close()
	again, e = cold.Revoke(t.Context(), rev)
	if e != nil || again != r {
		t.Fatal("cold receipt", e)
	}
	if _, e = cold.Choose(t.Context(), q); e == nil {
		t.Fatal("cold revoked key")
	}
	l := newStore(t, 1)
	if _, e = l.Revoke(t.Context(), revokeRequest(t, l, 1)); e == nil {
		t.Fatal("legacy root gained authority")
	}
}
func TestGuardRevocationAuthorizationNoMutationAndUnaffectedSubject(t *testing.T) {
	s := revocableStore(t, 8)
	q := revokeRequest(t, s, 1)
	for _, mutate := range []func(*wire.Revocation){
		func(q *wire.Revocation) { q.Authority = subject(8) }, func(q *wire.Revocation) { q.GuardID = hash("other guard") },
		func(q *wire.Revocation) { q.Subject = subject(7) }, func(q *wire.Revocation) { q.ReasonID = types.Hash{} },
		func(q *wire.Revocation) { q.Subject = q.Authority },
	} {
		bad := q
		mutate(&bad)
		key := testKey(9)
		if bad.Authority == subject(8) {
			key = testKey(8)
		}
		signed, e := bad.Sign(key)
		if e == nil {
			bad = signed
		}
		if _, e = s.Revoke(t.Context(), bad); e == nil {
			t.Fatal("bad authorization")
		}
	}
	bad := q
	bad.Signature[0] ^= 1
	if _, e := s.Revoke(t.Context(), bad); e == nil {
		t.Fatal("forged signature")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := s.Revoke(canceled, q); e == nil {
		t.Fatal("canceled revoke")
	}
	if _, e := s.Revoke(nil, q); e == nil {
		t.Fatal("nil context")
	}
	p, _ := s.Position()
	if p != (Position{}) {
		t.Fatal("invalid command mutated state")
	}
	if _, e := s.Revoke(t.Context(), q); e != nil {
		t.Fatal(e)
	}
	other := request(t, "other")
	other.Subject = subject(2)
	other, _ = other.Sign(testKey(2))
	if _, e := s.Choose(t.Context(), other); e != nil {
		t.Fatal("unaffected subject", e)
	}
	pos, _ := s.Position()
	if pos.Sequence != 2 {
		t.Fatal(pos)
	}
}
func TestGuardRevocationFaultRecoveryAndObserver(t *testing.T) {
	for _, stage := range []string{"before-persist", "after-persist", "observer"} {
		t.Run(stage, func(t *testing.T) {
			s := revocableStore(t, 2)
			q := revokeRequest(t, s, 1)
			id, root := s.Identity(), s.root
			failure := errors.New("injected")
			if stage == "observer" {
				s.SetRevocationObserver(func(Position, wire.Revocation) error { return failure })
			} else {
				s.hook = func(at string) error {
					if at == stage {
						return failure
					}
					return nil
				}
			}
			if _, e := s.Revoke(t.Context(), q); !errors.Is(e, failure) {
				t.Fatal(e)
			}
			if _, e := s.Choose(t.Context(), request(t, "copy")); e == nil {
				t.Fatal("failed revocation allowed choice")
			}
			s.Close()
			if stage != "before-persist" {
				if bad, e := Open(root, id, Position{}, nil); e == nil {
					bad.Close()
					t.Fatal("adopted unknown tip")
				}
			}
			wrong := q
			wrong.ReasonID = hash("other")
			wrong, _ = wrong.Sign(testKey(9))
			if stage != "before-persist" {
				if bad, e := RecoverRevocation(root, id, Position{}, wrong); e == nil {
					bad.Close()
					t.Fatal("wrong recovery attempt")
				}
			}
			cold, e := RecoverRevocation(root, id, Position{}, q)
			if e != nil {
				t.Fatal(e)
			}
			defer cold.Close()
			r, e := cold.Revoke(t.Context(), q)
			if e != nil {
				t.Fatal(e)
			}
			after, _ := r.After()
			p, _ := cold.Position()
			if after != p || p.Sequence != 1 {
				t.Fatal("duplicate append")
			}
			if _, e = cold.Choose(t.Context(), request(t, "copy")); e == nil {
				t.Fatal("cold revoked copy")
			}
		})
	}
}
func TestGuardRevocationTamperPartialAndChoiceAfterTombstone(t *testing.T) {
	for _, mode := range []string{"partial", "duplicate", "choice-after", "remove"} {
		t.Run(mode, func(t *testing.T) {
			s := revocableStore(t, 4)
			q := revokeRequest(t, s, 1)
			r, e := s.Revoke(t.Context(), q)
			if e != nil {
				t.Fatal(e)
			}
			p, _ := r.After()
			id, root := s.Identity(), s.root
			raw, _ := q.CanonicalBytes()
			switch mode {
			case "partial":
				raw = raw[:17]
			case "choice-after":
				raw, _ = request(t, "forged later choice").CanonicalBytes()
			}
			if mode == "remove" {
				e = os.Remove(filepath.Join(root, "events", eventName(1)))
			} else {
				e = os.WriteFile(filepath.Join(root, "events", eventName(2)), raw, 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.Revoke(t.Context(), q); e == nil {
				t.Fatal("live tampering ignored")
			}
			s.Close()
			if cold, e := Open(root, id, p, nil); e == nil {
				cold.Close()
				t.Fatal("corrupt history opened")
			}
		})
	}
}
func TestGuardRevocationConcurrentChoiceLinearization(t *testing.T) {
	for i := 0; i < 12; i++ {
		s := revocableStore(t, 8)
		q := request(t, "racing choice")
		rev := revokeRequest(t, s, 1)
		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})
		var choiceErr, revokeErr error
		var seal [64]byte
		var r wire.RevocationReceipt
		go func() { defer wg.Done(); <-start; seal, choiceErr = s.Choose(t.Context(), q) }()
		go func() { defer wg.Done(); <-start; r, revokeErr = s.Revoke(t.Context(), rev) }()
		close(start)
		wg.Wait()
		if revokeErr != nil {
			t.Fatal(revokeErr)
		}
		if choiceErr == nil {
			if r.Before.Sequence != 1 || q.VerifySeal(s.Identity().PublicKey, seal) != nil {
				t.Fatal("choice not before revocation")
			}
		} else if r.Before.Sequence != 0 {
			t.Fatal("unexpected history")
		}
		if _, e := s.Choose(t.Context(), q); e == nil {
			t.Fatal("choice after completed revoke")
		}
	}
}

type lateBodyError struct{ *bytes.Reader }

func (b lateBodyError) Read(p []byte) (int, error) {
	n, e := b.Reader.Read(p)
	if e == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	return n, e
}
func (b lateBodyError) Close() error { return nil }
func TestGuardRevocationHTTPFramingLostReplyAndPinnedReceipt(t *testing.T) {
	s := revocableStore(t, 4)
	q := revokeRequest(t, s, 1)
	raw, _ := q.CanonicalBytes()
	h := Handler(s)
	for _, body := range []io.ReadCloser{io.NopCloser(bytes.NewReader(append(bytes.Clone(raw), 0))), lateBodyError{bytes.NewReader(raw)}} {
		req := httptest.NewRequest(http.MethodPost, RevocationRoute, body)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == 200 {
			t.Fatal("bad framing")
		}
	}
	p, _ := s.Position()
	if p.Sequence != 0 {
		t.Fatal("mutated before EOF")
	}
	var mu sync.Mutex
	first := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		mu.Lock()
		drop := first
		first = false
		mu.Unlock()
		if drop {
			http.Error(w, "lost", 503)
			return
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	defer server.Close()
	client := Client{URL: server.URL}
	id := s.Identity()
	if _, e := wire.ObtainRevocation(t.Context(), client, id.PublicKey, id.ID(), q); e == nil {
		t.Fatal("lost reply reported success")
	}
	r, e := wire.ObtainRevocation(t.Context(), client, id.PublicKey, id.ID(), q)
	if e != nil {
		t.Fatal(e)
	}
	after, _ := r.After()
	p, _ = s.Position()
	if p != after || p.Sequence != 1 {
		t.Fatal("retry added event")
	}
	if _, e = wire.ObtainRevocation(t.Context(), client, subject(7), id.ID(), q); e == nil {
		t.Fatal("wrong pinned signer")
	}
	if _, e = client.Choose(t.Context(), request(t, "copy")); e == nil {
		t.Fatal("network clone")
	}
}

func TestGuardRevocationMixedHistoryBoundedRecovery(t *testing.T) {
	s := revocableStore(t, 2)
	first := request(t, "before revoke")
	if _, e := s.Choose(t.Context(), first); e != nil {
		t.Fatal(e)
	}
	before, _ := s.Position()
	q := revokeRequest(t, s, 1)
	r, e := s.Revoke(t.Context(), q)
	if e != nil {
		t.Fatal(e)
	}
	id, root := s.Identity(), s.root
	s.Close()
	if bad, e := Open(root, id, before, &first); e == nil {
		bad.Close()
		t.Fatal("choice recovery skipped revocation")
	}
	s, e = RecoverRevocation(root, id, before, q)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	second := request(t, "unaffected after revoke")
	second.Subject = subject(2)
	second, _ = second.Sign(testKey(2))
	if _, e = s.Choose(t.Context(), second); e != nil {
		t.Fatal("revocation consumed ordinary capacity", e)
	}
	tip, _ := s.Position()
	s.Close()
	if bad, e := RecoverRevocation(root, id, before, q); e == nil {
		bad.Close()
		t.Fatal("revocation recovery skipped later choice")
	}
	s, e = Open(root, id, tip, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	again, e := s.Revoke(t.Context(), q)
	if e != nil || again != r {
		t.Fatal("historical receipt changed", e)
	}
	extra := second
	extra.Slot++
	extra, _ = extra.Sign(testKey(2))
	if _, e = s.Choose(t.Context(), extra); e == nil {
		t.Fatal("revocation refunded ordinary capacity")
	}
}

func TestGuardRevocationMaximumRosterHasReservedSlots(t *testing.T) {
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	cfg := Config{Limit: 1, Revoker: subject(99)}
	for n := byte(1); n <= MaximumSubjects; n++ {
		cfg.Subjects = append(cfg.Subjects, subject(n))
	}
	sort.Slice(cfg.Subjects, func(i, j int) bool { return bytes.Compare(cfg.Subjects[i][:], cfg.Subjects[j][:]) < 0 })
	raw, _ := json.Marshal(cfg)
	if len(raw) > MaximumConfigBytes {
		t.Fatal("config exceeds read bound")
	}
	s, e := Create(filepath.Join(parent, "guard"), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Choose(t.Context(), request(t, "fill normal budget")); e != nil {
		t.Fatal(e)
	}
	for _, sub := range cfg.Subjects {
		q, e := (wire.Revocation{GuardID: s.Identity().ID(), Subject: sub, Authority: cfg.Revoker, ReasonID: hash("incident")}).Sign(testKey(99))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Revoke(t.Context(), q); e != nil {
			t.Fatal("reserved slot missing", e)
		}
	}
	tip, _ := s.Position()
	if tip.Sequence != MaximumSubjects+1 {
		t.Fatal(tip)
	}
	id, root := s.Identity(), s.root
	s.Close()
	s, e = Open(root, id, tip, nil)
	if e != nil {
		t.Fatal("max roster reopen", e)
	}
	defer s.Close()
	bad := cfg
	bad.Revoker = bad.Subjects[0]
	if ValidateConfig(bad) == nil {
		t.Fatal("subject is authority")
	}
}
