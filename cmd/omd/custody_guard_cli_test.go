//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard"
)

func TestCustodyGuardCLIReviewCreatePinsAndStaleApproval(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(dir, "private")
	config := filepath.Join(dir, "config.json")
	identity := filepath.Join(dir, "identity.json")
	raw, _ := json.Marshal(guard.Config{Subjects: [][32]byte{f.Public(70)}, Limit: 8})
	if e = os.WriteFile(config, raw, 0600); e != nil {
		t.Fatal(e)
	}
	args := []string{custodyGuardCommand, "--action", "create", "--root", root, "--config", config, "--out", identity}
	var out bytes.Buffer
	if e = runCustodyGuard(t.Context(), args, &out); e != nil {
		t.Fatal(e)
	}
	fields := pruneCLIFields(strings.SplitN(out.String(), "\n", 2)[0])
	if fields["roots_opened"] != "false" || fields["keys_loaded"] != "false" || fields["review_id"] == "" {
		t.Fatal(out.String())
	}
	if _, e = os.Lstat(root); !os.IsNotExist(e) {
		t.Fatal("review created owner")
	}
	run := append(append([]string(nil), args...), "--mode", "run", "--expected-review-id", fields["review_id"])
	changed, _ := json.Marshal(guard.Config{Subjects: [][32]byte{f.Public(70)}, Limit: 9})
	if e = os.WriteFile(config, changed, 0600); e != nil {
		t.Fatal(e)
	}
	if e = runCustodyGuard(t.Context(), run, &out); e == nil {
		t.Fatal("changed config reused review")
	}
	if _, e = os.Lstat(root); !os.IsNotExist(e) {
		t.Fatal("stale review opened root")
	}
	if e = os.WriteFile(config, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = runCustodyGuard(t.Context(), run, &out); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(identity)
	if e != nil {
		t.Fatal(e)
	}
	var id guard.Identity
	if e = json.Unmarshal(data, &id); e != nil {
		t.Fatal(e)
	}
	s, e := guard.Open(root, id, guard.Position{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	if e = runCustodyGuard(t.Context(), run, &out); e == nil {
		t.Fatal("recreated existing guard")
	}
	pos := filepath.Join(dir, "position.json")
	raw, _ = json.Marshal(guard.Position{})
	if e = os.WriteFile(pos, raw, 0600); e != nil {
		t.Fatal(e)
	}
	serve := []string{custodyGuardCommand, "--action", "serve", "--root", filepath.Join(dir, "absent-original"), "--identity", identity, "--position", pos, "--listen", "127.0.0.1:0"}
	out.Reset()
	if e = runCustodyGuard(t.Context(), serve, &out); e != nil {
		t.Fatal("serve review opened missing original", e)
	}
	if !strings.Contains(out.String(), "roots_opened=false") {
		t.Fatal(out.String())
	}
}
