//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

func TestCustodyGatewayReplaceCLIReviewBindsOriginalIdentityWithoutOpeningRoot(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	save := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	d, e := (wire.Descriptor{Guard: f.Public(240), RootID: f.Hash("root"), SourceID: f.Hash("source"), GenesisID: f.Hash("genesis"), GenesisDescriptorID: f.Hash("descriptor"), EnrollmentID: f.Hash("enrollment"), Gateway: f.Public(201), Issuer: f.Public(110), Clients: [][32]byte{f.Public(14)}, OwnerUID: 1000, ParticipantUID: 1001, EventLimit: 32}).Sign(f.Key(110))
	if e != nil {
		t.Fatal(e)
	}
	b, e := d.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	descriptor := save("descriptor.bin", b)
	did, _ := d.ID()
	r, e := (guard.Replacement{GuardID: f.Hash("guard identity"), Subject: d.Gateway, Successor: f.Public(230), Authority: f.Public(249), RevocationID: f.Hash("revocation"), EvidenceID: f.Hash("inventory"), Before: guard.Position{Sequence: 1, Head: f.Hash("head")}}).Accept(f.Key(230))
	if e != nil {
		t.Fatal(e)
	}
	r, e = r.Authorize(f.Key(249))
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := (guard.ReplacementReceipt{Request: r, Guard: d.Guard}).Sign(f.Key(240))
	if e != nil {
		t.Fatal(e)
	}
	b, e = receipt.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	proof := save("receipt.bin", b)
	b, _ = json.Marshal(wire.Position{Sequence: 2, Head: f.Hash("retained service head")})
	position := save("position.json", b)
	root := filepath.Join(dir, "absent-original-root")
	seed := filepath.Join(dir, "absent-successor.seed")
	output := filepath.Join(dir, "report.json")
	args := []string{custodyGatewayReplaceCommand, "--root", root, "--descriptor", descriptor, "--descriptor-id", did.String(), "--position", position, "--replacement", proof, "--key", seed, "--out", output}
	var out bytes.Buffer
	if e = runCustodyGatewayReplace(t.Context(), args, &out); e != nil {
		t.Fatal(e)
	}
	fields := pruneCLIFields(strings.SplitN(out.String(), "\n", 2)[0])
	if fields["roots_opened"] != "false" || fields["keys_loaded"] != "false" || fields["network_called"] != "false" || fields["review_id"] == "" {
		t.Fatal(out.String())
	}
	for _, path := range []string{root, seed, output} {
		if _, e = os.Lstat(path); !os.IsNotExist(e) {
			t.Fatal("review touched private state or output", path)
		}
	}
	changedPosition, err := json.Marshal(wire.Position{Sequence: 3, Head: f.Hash("another head")})
	if err != nil {
		t.Fatal(err)
	}
	changed := replaceRemoteCLIFlag(args, "--position", save("different-position.json", changedPosition))
	if e = runCustodyGatewayReplace(t.Context(), append(changed, "--mode", "run", "--expected-review-id", fields["review_id"]), io.Discard); e == nil || !strings.Contains(e.Error(), "exact public review") {
		t.Fatal("changed cursor not bound", e)
	}
	alias := replaceRemoteCLIFlag(args, "--out", proof)
	if runCustodyGatewayReplace(t.Context(), alias, io.Discard) == nil {
		t.Fatal("proof/output alias")
	}
	missing := replaceRemoteCLIFlag(args, "--replacement", filepath.Join(dir, "missing-receipt"))
	if runCustodyGatewayReplace(t.Context(), missing, io.Discard) == nil {
		t.Fatal("missing proof")
	}
}
