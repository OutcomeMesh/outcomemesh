package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

func TestCustodyGuardReplaceCLIConsentAuthorizationRetryAndSuccessorRevocation(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	cfg := guard.Config{Subjects: [][32]byte{f.Public(70)}, Limit: 2, Revoker: f.Public(90), Replacer: f.Public(91)}
	s, e := guard.Create(filepath.Join(dir, "private"), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	save := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	js := func(name string, v any) string {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return save(name, b)
	}
	identity, config := js("identity.json", s.Identity()), js("config.json", cfg)
	rev, e := (wire.Revocation{GuardID: s.Identity().ID(), Subject: f.Public(70), Authority: f.Public(90), ReasonID: f.Hash("incident")}).Sign(f.Key(90))
	if e != nil {
		t.Fatal(e)
	}
	revoked, e := s.Revoke(t.Context(), rev)
	if e != nil {
		t.Fatal(e)
	}
	b, e := revoked.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	revPath := save("revoked.bin", b)
	pos, e := s.Position()
	if e != nil {
		t.Fatal(e)
	}
	position := js("position.json", pos)
	var calls atomic.Int32
	handler := guard.Handler(s)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); handler.ServeHTTP(w, r) }))
	defer server.Close()
	review := func(run func([]string, io.Writer) error, args []string) string {
		t.Helper()
		var out bytes.Buffer
		if e := run(args, &out); e != nil {
			t.Fatal(e)
		}
		fields := pruneCLIFields(strings.SplitN(out.String(), "\n", 2)[0])
		if fields["keys_loaded"] != "false" || fields["network_called"] != "false" || fields["review_id"] == "" {
			t.Fatal(out.String())
		}
		return fields["review_id"]
	}
	replace := func(args []string, out io.Writer) error { return runCustodyGuardReplace(t.Context(), args, out) }
	revoke := func(args []string, out io.Writer) error { return runCustodyGuardRevoke(t.Context(), args, out) }
	run := func(command func([]string, io.Writer) error, args []string, pin string) error {
		return command(append(append([]string{}, args...), "--mode", "run", "--expected-review-id", pin), io.Discard)
	}
	common := []string{custodyGuardReplaceCommand, "--identity", identity, "--config", config}
	seed, authority := filepath.Join(dir, "successor.seed"), filepath.Join(dir, "authority.seed")
	proposal, request, receipt := filepath.Join(dir, "proposal.bin"), filepath.Join(dir, "request.bin"), filepath.Join(dir, "receipt.bin")
	propose := append(append([]string{}, common...), "--action", "propose", "--revocation", revPath, "--position", position, "--successor", fmt.Sprintf("%x", f.Public(92)), "--evidence-id", f.Hash("obligation inventory").String(), "--key", seed, "--out", proposal)
	pin := review(replace, propose)
	if _, e = os.Lstat(proposal); !os.IsNotExist(e) {
		t.Fatal("review wrote proposal")
	}
	save("successor.seed", f.Key(93).Seed())
	if run(replace, propose, pin) == nil {
		t.Fatal("wrong successor accepted")
	}
	save("successor.seed", f.Key(92).Seed())
	if e = run(replace, propose, pin); e != nil {
		t.Fatal(e)
	}
	authorize := append(append([]string{}, common...), "--action", "authorize", "--proposal", proposal, "--key", authority, "--out", request)
	pin = review(replace, authorize)
	save("authority.seed", f.Key(92).Seed())
	if run(replace, authorize, pin) == nil {
		t.Fatal("successor self authorized")
	}
	save("authority.seed", f.Key(91).Seed())
	if e = run(replace, authorize, pin); e != nil {
		t.Fatal(e)
	}
	send := append(append([]string{}, common...), "--action", "send", "--request", request, "--guard-url", server.URL, "--out", receipt)
	pin = review(replace, send)
	if calls.Load() != 0 {
		t.Fatal("review contacted guard")
	}
	altered := append([]string{}, send...)
	altered[len(altered)-1] = filepath.Join(dir, "different.bin")
	if run(replace, altered, pin) == nil || calls.Load() != 0 {
		t.Fatal("stale output review")
	}
	if e = run(replace, send, pin); e != nil {
		t.Fatal(e)
	}
	inspect := append(append([]string{}, common...), "--action", "inspect", "--request", request, "--receipt", receipt, "--out", filepath.Join(dir, "inspection.json"))
	if e = run(replace, inspect, review(replace, inspect)); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 1 {
		t.Fatal("inspection contacted guard")
	}
	if run(replace, send, pin) == nil || calls.Load() != 1 {
		t.Fatal("existing output submitted twice")
	}
	retry := append([]string{}, send...)
	retry[len(retry)-1] = filepath.Join(dir, "retry.bin")
	if e = run(replace, retry, review(replace, retry)); e != nil {
		t.Fatal(e)
	}
	before, e := s.Position()
	if e != nil || before.Sequence != 2 {
		t.Fatal("retry consumed replacement slot", e)
	}
	b, e = os.ReadFile(receipt)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := wire.DecodeReplacementReceipt(b)
	if e != nil {
		t.Fatal(e)
	}
	sign := []string{custodyGuardRevokeCommand, "--action", "sign", "--identity", identity, "--config", config, "--replacement", receipt, "--subject", fmt.Sprintf("%x", f.Public(92)), "--reason-id", f.Hash("successor incident").String(), "--key", filepath.Join(dir, "revoker.seed"), "--out", filepath.Join(dir, "successor-revoke.bin")}
	pin = review(revoke, sign)
	save("revoker.seed", f.Key(90).Seed())
	if e = run(revoke, sign, pin); e != nil {
		t.Fatal(e)
	}
	b, e = os.ReadFile(sign[len(sign)-1])
	if e != nil {
		t.Fatal(e)
	}
	r, e := wire.DecodeRevocation(b)
	if e != nil || guard.ValidateSuccessorRevocation(cfg, s.Identity(), r, proof) != nil {
		t.Fatal("successor revoke proof", e)
	}
	sendRevoke := []string{custodyGuardRevokeCommand, "--action", "send", "--identity", identity, "--config", config, "--replacement", receipt, "--request", sign[len(sign)-1], "--guard-url", server.URL, "--out", filepath.Join(dir, "successor-revoked.bin")}
	if e = run(revoke, sendRevoke, review(revoke, sendRevoke)); e != nil {
		t.Fatal(e)
	}
	q, e := (wire.Request{Kind: wire.Fence, Subject: f.Public(92), Namespace: f.Hash("fresh scope"), Choice: f.Hash("fresh choice")}).Sign(f.Key(92))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Choose(t.Context(), q); e == nil {
		t.Fatal("revoked successor still signs")
	}
}
