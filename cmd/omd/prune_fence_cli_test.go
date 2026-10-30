package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnessnet"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func preparePruneFenceCLIPolicy(t testing.TB) (string, types.Hash) {
	t.Helper()
	hexKey := func(k [32]byte) string { return hex.EncodeToString(k[:]) }
	p := pruneFencePolicyJSON{Owner: hexKey(pruneCLIPublic(4)), Controller: hexKey(pruneCLIPublic(1)), Threshold: 3}
	for i := byte(70); i < 74; i++ {
		p.Witnesses = append(p.Witnesses, hexKey(f.Public(i)))
	}
	raw, _ := json.Marshal(p)
	in, out := filepath.Join(t.TempDir(), "policy.json"), filepath.Join(t.TempDir(), "policy")
	writePruneCLIFile(t, in, raw)
	var report struct {
		ArtifactID          string `json:"artifact_id"`
		ExecutionAuthorized bool   `json:"execution_authorized"`
	}
	args := []string{pruneFencePolicyCommand, "--input", in}
	scheduledCLIRun(t, args, &report)
	if report.ExecutionAuthorized {
		t.Fatal("review granted execution")
	}
	scheduledCLIRun(t, append(args, "--mode", "publish", "--expected-id", report.ArtifactID, "--out", out), &report)
	before, _ := os.ReadFile(out)
	scheduledCLIRun(t, append(args, "--mode", "publish", "--expected-id", report.ArtifactID, "--out", out), nil)
	after, _ := os.ReadFile(out)
	if !bytes.Equal(before, after) {
		t.Fatal("retry changed policy")
	}
	for _, extra := range [][]string{
		{"--out", out},
		{"--mode", "publish", "--expected-id", f.Hash("wrong").String(), "--out", out},
		{"--mode", "publish", "--expected-id", report.ArtifactID, "--out", in},
	} {
		if err := runPruneFenceArtifactCLI(t.Context(), append(append([]string(nil), args...), extra...), io.Discard); err == nil {
			t.Fatal("accepted invalid publication", extra)
		}
	}
	id, err := pruneExternalID("artifact_id", report.ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	return out, id
}

func preparePruneFenceCLINetwork(t testing.TB, plan string, planID types.Hash) []string {
	t.Helper()
	var report struct {
		ArtifactID string `json:"artifact_id"`
	}
	args := []string{pruneFenceScopeCommand, "--input", plan, "--plan-id", planID.String()}
	scheduledCLIRun(t, args, &report)
	path := filepath.Join(t.TempDir(), "scope")
	scheduledCLIRun(t, append(args, "--mode", "publish", "--expected-id", report.ArtifactID, "--out", path), nil)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := custodyfence.DecodeScope(raw)
	if err != nil {
		t.Fatal(err)
	}
	scopeID, err := pruneExternalID("artifact_id", report.ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	config := pruneFenceNetworkJSON{}
	pub := f.Public(99)
	config.ClientTransport = hex.EncodeToString(pub[:])
	for i := byte(0); i < 4; i++ {
		w, err := custodyfence.Create(filepath.Join(t.TempDir(), "witness"), scope, scopeID, f.Key(70+i))
		if err != nil {
			t.Fatal(err)
		}
		server, err := witnessnet.Start(t.Context(), w, scope, scopeID, f.Key(90+i), libp2ptransport.DefaultConfig(), []types.Hash{types.DomainHash("OMESH/p2p/ed25519/v0", pub[:])}, time.Second)
		if err != nil {
			w.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { server.Close() })
		wpub, transport := f.Public(70+i), f.Public(90+i)
		config.Witnesses = append(config.Witnesses, struct {
			Witness   string `json:"witness"`
			Transport string `json:"transport"`
			Address   string `json:"address"`
		}{hex.EncodeToString(wpub[:]), hex.EncodeToString(transport[:]), server.Addresses()[0]})
	}
	network, owner, transport := filepath.Join(t.TempDir(), "network.json"), filepath.Join(t.TempDir(), "owner.seed"), filepath.Join(t.TempDir(), "transport.seed")
	raw, _ = json.Marshal(config)
	writePruneCLIFile(t, network, raw)
	writePruneCLIFile(t, owner, pruneCLIKey(4).Seed())
	writePruneCLIFile(t, transport, f.Key(99).Seed())
	return []string{"--fence-network", network, "--fence-owner-key", owner, "--fence-transport-key", transport, "--fence-timeout", "1s"}
}

func TestPruneFencePolicyRejectsAmbiguousJSONAndRoleReuse(t *testing.T) {
	for _, raw := range []string{`{}`, `{"threshold":3,"threshold":4}`, `{"unknown":1}`, `[]`, "null", `{} {}`} {
		if _, err := parsePruneFencePolicy([]byte(raw)); err == nil {
			t.Fatal("invalid policy", raw)
		}
	}
	policy := pruneFencePolicyJSON{Owner: hex.EncodeToString(f.Key(1)[32:]), Controller: hex.EncodeToString(f.Key(2)[32:]), Threshold: 3}
	for i := byte(70); i < 74; i++ {
		policy.Witnesses = append(policy.Witnesses, hex.EncodeToString(f.Key(i)[32:]))
	}
	for _, duplicate := range []string{policy.Owner, policy.Controller, policy.Witnesses[1]} {
		bad := policy
		bad.Witnesses = append([]string(nil), policy.Witnesses...)
		bad.Witnesses[0] = duplicate
		raw, _ := json.Marshal(bad)
		if _, err := parsePruneFencePolicy(raw); err == nil {
			t.Fatal("reused role accepted")
		}
	}
}
