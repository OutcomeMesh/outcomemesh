package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard"
	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

func TestCustodyGuardRevokeCLIReviewSignSendInspectAndStaleInputs(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	cfg := guard.Config{Subjects: [][32]byte{f.Public(70)}, Limit: 1, Revoker: f.Public(90)}
	s, e := guard.Create(filepath.Join(dir, "private"), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	id := s.Identity()
	writeJSON := func(name string, v any) string {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		p := filepath.Join(dir, name)
		if e = os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	identity := writeJSON("identity.json", id)
	config := writeJSON("config.json", cfg)
	key := filepath.Join(dir, "offline.seed")
	request := filepath.Join(dir, "revoke.bin")
	receipt := filepath.Join(dir, "receipt.bin")
	report := filepath.Join(dir, "report.json")
	review := func(args []string) string {
		t.Helper()
		var out bytes.Buffer
		if e := runCustodyGuardRevoke(t.Context(), args, &out); e != nil {
			t.Fatal(e)
		}
		fields := pruneCLIFields(strings.SplitN(out.String(), "\n", 2)[0])
		if fields["keys_loaded"] != "false" || fields["network_called"] != "false" || fields["review_id"] == "" {
			t.Fatal(out.String())
		}
		return fields["review_id"]
	}
	run := func(args []string, pin string) error {
		var out bytes.Buffer
		return runCustodyGuardRevoke(t.Context(), append(append([]string{}, args...), "--mode", "run", "--expected-review-id", pin), &out)
	}
	common := []string{custodyGuardRevokeCommand, "--identity", identity, "--config", config}
	sign := append(append([]string{}, common...), "--action", "sign", "--subject", fmt.Sprintf("%x", f.Public(70)), "--reason-id", f.Hash("incident").String(), "--key", key, "--out", request)
	pin := review(sign) // Offline key does not exist yet.
	if _, e = os.Lstat(request); !os.IsNotExist(e) {
		t.Fatal("review wrote request")
	}
	changed := append([]string{}, sign...)
	for i := range changed {
		if changed[i] == f.Hash("incident").String() {
			changed[i] = f.Hash("another incident").String()
		}
	}
	if run(changed, pin) == nil {
		t.Fatal("stale reason accepted")
	}
	if e = os.WriteFile(key, f.Key(91).Seed(), 0600); e != nil {
		t.Fatal(e)
	}
	if run(sign, pin) == nil {
		t.Fatal("wrong authority key")
	}
	if e = os.WriteFile(key, f.Key(90).Seed(), 0600); e != nil {
		t.Fatal(e)
	}
	if e = run(sign, pin); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(request)
	if e != nil {
		t.Fatal(e)
	}
	q, e := wire.DecodeRevocation(raw)
	if e != nil || guard.ValidateRevocation(cfg, id, q) != nil {
		t.Fatal("signed request", e)
	}
	var calls atomic.Int32
	h := guard.Handler(s)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); h.ServeHTTP(w, r) }))
	defer server.Close()
	send := append(append([]string{}, common...), "--action", "send", "--request", request, "--guard-url", server.URL, "--out", receipt)
	pin = review(send)
	if calls.Load() != 0 {
		t.Fatal("review contacted server")
	}
	changed = append([]string{}, send...)
	for i := range changed {
		if changed[i] == server.URL {
			changed[i] = "http://127.0.0.1:1"
		}
	}
	if run(changed, pin) == nil || calls.Load() != 0 {
		t.Fatal("stale endpoint contacted server")
	}
	changedCfg := cfg
	changedCfg.Revoker = f.Public(91)
	writeJSON("config.json", changedCfg)
	if run(send, pin) == nil || calls.Load() != 0 {
		t.Fatal("changed authority adopted")
	}
	writeJSON("config.json", cfg)
	if e = run(send, pin); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 1 {
		t.Fatal("expected one send")
	}
	raw, e = os.ReadFile(receipt)
	if e != nil {
		t.Fatal(e)
	}
	r, e := wire.DecodeRevocationReceipt(raw)
	if e != nil || r.Verify(id.PublicKey, id.ID(), q) != nil {
		t.Fatal("receipt", e)
	}
	inspect := append(append([]string{}, common...), "--action", "inspect", "--request", request, "--receipt", receipt, "--out", report)
	if e = run(inspect, review(inspect)); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 1 {
		t.Fatal("inspection contacted server")
	}
	raw, e = os.ReadFile(report)
	if e != nil || !bytes.Contains(raw, []byte(`"HistoricalOnly":true`)) {
		t.Fatal("historical report", e)
	}
	if e = run(send, pin); e == nil || calls.Load() != 1 {
		t.Fatal("existing output caused side effect")
	}
	// Exact retransmission has its own fresh output review and never adds an event.
	retry := append([]string{}, send...)
	retry[len(retry)-1] = filepath.Join(dir, "receipt-retry.bin")
	if e = run(retry, review(retry)); e != nil {
		t.Fatal(e)
	}
	p, e := s.Position()
	if e != nil || p.Sequence != 1 {
		t.Fatal("duplicate revocation", e)
	}
	before := writeJSON("position.json", guard.Position{})
	serve := []string{custodyGuardCommand, "--action", "serve", "--root", filepath.Join(dir, "absent-root"), "--identity", identity, "--position", before, "--listen", "127.0.0.1:0", "--revoke-attempt", request}
	var out bytes.Buffer
	if e = runCustodyGuard(t.Context(), serve, &out); e != nil {
		t.Fatal("public recovery review opened private root", e)
	}
	if e = runCustodyGuard(t.Context(), append(serve, "--attempt", request), &out); e == nil {
		t.Fatal("mixed recovery selectors")
	}
	// A legacy config is never silently given a revocation authority.
	legacy := cfg
	legacy.Revoker = [32]byte{}
	writeJSON("config.json", legacy)
	if e = runCustodyGuardRevoke(t.Context(), sign, &out); e == nil {
		t.Fatal("legacy authority inferred")
	}
}
