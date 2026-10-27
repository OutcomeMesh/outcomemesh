package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	fencefixture "github.com/outcomemesh/outcomemesh/internal/fencetest"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/custodyproof"
)

func witnessCustodyResultFixture(t testing.TB) (*remoteCLIFixture, custodyfence.Scope, custodyproof.Bundle) {
	t.Helper()
	f := newRemoteCLIFixture(t)
	b := startRemoteCLIControl(t, f.args("serve", "control"))
	b.send(t, "serve "+b.review(t))
	ready := b.next(t, "remote_custody_serving")
	a := startRemoteCLIControl(t, append(f.args("audit", "control"), "--peer", ready["listen"]))
	for _, step := range []struct{ action, prefix string }{{"prepare", "remote_custody_prepared"}, {"begin", "remote_custody_begun"}, {"execute", "remote_custody_executed"}, {"seal", "remote_custody_metadata"}, {"capture", "remote_custody_captured"}} {
		a.send(t, step.action+" "+a.review(t))
		a.next(t, step.prefix)
	}
	a.close(t)
	b.close(t)
	raw, err := os.ReadFile(f.terminal)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := store.DecodeRemoteCustodyTerminal(raw)
	if err != nil {
		t.Fatal(err)
	}
	s := fencefixture.Scope()
	s.AssignmentID = f.scope.Worker.Plan.AssignmentID
	s.IntentID, _ = f.intent.ID()
	s.PlanID = f.scope.Worker.PlanID
	s.BeginID = f.scope.Worker.BeginID
	s.Owner = f.scope.Worker.Assignment.RemoteControlPublicKey
	s.Controller = f.scope.Worker.Assignment.AuthorityPublicKey
	id, _ := s.ID()
	claim := custodyfence.Command{ScopeID: id, ExpectedHead: id, Kind: custodyfence.Claim}
	claim, err = claim.Sign(pruneCLIKey(14))
	if err != nil {
		t.Fatal(err)
	}
	cid, _ := claim.ID()
	unknown := custodyfence.Command{ScopeID: id, ExpectedSequence: 1, ExpectedHead: cid, Kind: custodyfence.MarkUnknown, ClaimID: cid, EvidenceID: fencefixture.Hash("historical-unknown")}
	unknown, err = unknown.Sign(pruneCLIKey(1))
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := unknown.ID()
	eid, _ := terminal.Entry.ID()
	result := custodyfence.Command{ScopeID: id, ExpectedSequence: 2, ExpectedHead: uid, Kind: custodyfence.RecordResult, ClaimID: cid, EvidenceID: eid}
	result, err = result.Sign(pruneCLIKey(14))
	if err != nil {
		t.Fatal(err)
	}
	return f, s, custodyproof.Bundle{ScopeID: id, Terminal: terminal, Chain: []custodyfence.Certificate{fencefixture.Certificate(claim, 70, 71, 72), fencefixture.Certificate(unknown, 70, 71, 73), fencefixture.Certificate(result, 70, 72, 73)}}
}

func TestWitnessResultRejectsOpaqueDigestDowngradeAndRoleReuse(t *testing.T) {
	f, s, bundle := witnessCustodyResultFixture(t)
	id, _ := s.ID()
	if err := bundle.Verify(s, id, f.scope, f.intent, f.audit); err != nil {
		t.Fatal(err)
	}
	raw, _ := bundle.CanonicalBytes()
	decoded, err := custodyproof.DecodeBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := decoded.CanonicalBytes()
	if !bytes.Equal(raw, again) {
		t.Fatal("bundle round trip")
	}
	terminalBytes, _ := bundle.Terminal.CanonicalBytes()
	if _, err := custodyproof.DecodeBundle(terminalBytes); err == nil {
		t.Fatal("legacy terminal bypassed mandatory certificate bundle")
	}
	for _, mutation := range []func(*custodyproof.Bundle){func(b *custodyproof.Bundle) { b.Chain = b.Chain[:1] }, func(b *custodyproof.Bundle) { b.Chain[2].Votes = b.Chain[2].Votes[:2] }, func(b *custodyproof.Bundle) {
		c := b.Chain[2].Command
		c.EvidenceID = fencefixture.Hash("opaque-unrelated-digest")
		c, _ = c.Sign(pruneCLIKey(14))
		b.Chain[2] = fencefixture.Certificate(c, 70, 71, 72)
	}, func(b *custodyproof.Bundle) { b.ScopeID = fencefixture.Hash("copied-scope") }} {
		copy, err := custodyproof.DecodeBundle(raw)
		if err != nil {
			t.Fatal(err)
		}
		mutation(&copy)
		if err := copy.Verify(s, id, f.scope, f.intent, f.audit); err == nil {
			t.Fatal("invalid witness result accepted")
		}
	}
	for _, key := range [][32]byte{f.scope.Worker.Assignment.ReplicaPublicKey, f.scope.Worker.Plan.AuditorTransportPublicKey, f.audit.Command.ActorPublicKey} {
		other := s
		other.Witnesses = append([][32]byte(nil), s.Witnesses...)
		other.Witnesses[0] = key
		sort.Slice(other.Witnesses, func(i, j int) bool { return bytes.Compare(other.Witnesses[i][:], other.Witnesses[j][:]) < 0 })
		otherID, err := other.ID()
		if err != nil {
			t.Fatal(err)
		}
		if err := custodyproof.ValidateBinding(other, otherID, f.scope, f.intent, f.audit); err == nil {
			t.Fatal("participant role counted as independent witness")
		}
	}
	if got, _ := bundle.Terminal.CanonicalBytes(); !bytes.Equal(got, terminalBytes) {
		t.Fatal("verification refreshed historical proof")
	}
}

func FuzzWitnessResultBundleCodec(f *testing.F) {
	_, _, bundle := witnessCustodyResultFixture(f)
	raw, _ := bundle.CanonicalBytes()
	f.Add(raw)
	f.Add([]byte("OMCFRS00"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if decoded, err := custodyproof.DecodeBundle(b); err == nil {
			out, err := decoded.CanonicalBytes()
			if err != nil || !bytes.Equal(b, out) {
				t.Fatal("bundle did not round trip")
			}
		}
	})
}

func TestWitnessResultCLIPublishAndPinnedReadOnlyVerification(t *testing.T) {
	f, s, bundle := witnessCustodyResultFixture(t)
	sid, _ := s.ID()
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope")
	raw, _ := s.CanonicalBytes()
	writePruneCLIFile(t, scopeFile, raw)
	var chain []map[string]string
	for i, cert := range bundle.Chain {
		path := filepath.Join(dir, string(rune('a'+i)))
		raw, _ := cert.CanonicalBytes()
		writePruneCLIFile(t, path, raw)
		chain = append(chain, map[string]string{"file": path, "id": witnessArtifactID("certificate", raw).String()})
	}
	chainFile := filepath.Join(dir, "chain.json")
	raw, _ = json.Marshal(chain)
	writePruneCLIFile(t, chainFile, raw)
	tid, _ := bundle.Terminal.ID()
	auditID, _ := f.audit.ID()
	base := append([]string{witnessResultCommand}, remoteOfflineCommonArgs(f)...)
	base = append(base, remoteOfflinePlanArgs(f)...)
	base = append(base, remoteOfflineChallengeArgs(f)...)
	base = append(base, "--begin", filepath.Join(f.public, "begin"), "--begin-id", f.scope.Worker.BeginID.String(), "--audit-admission", filepath.Join(f.public, "audit"), "--audit-ticket-id", auditID.String(), "--witness-scope", scopeFile, "--witness-scope-id", sid.String())
	build := append(append([]string{}, base...), "--terminal", f.terminal, "--terminal-id", tid.String(), "--chain", chainFile)
	view := witnessRun(t, build)
	path := filepath.Join(dir, "bundle")
	witnessRun(t, append(build, "--mode", "publish", "--expected-review-id", view["bundle_id"], "--out", path))
	verify := append(base, "--bundle", path, "--bundle-id", view["bundle_id"], "--mode", "verify")
	result := witnessRun(t, verify)
	if result["historical_result_verified"] != "true" || result["current_source_acceptance_checked"] != "false" || result["completion_submitted"] != "false" {
		t.Fatal(result)
	}
	if err := runWitness(t.Context(), replaceRemoteCLIFlag(verify, "--bundle-id", types.Hash{1}.String()), nil, &bytes.Buffer{}); err == nil {
		t.Fatal("wrong bundle pin accepted")
	}
}
