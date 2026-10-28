package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

func admissionInProcess(t testing.TB, args []string) string {
	t.Helper()
	var out bytes.Buffer
	if e := runCustodyV2Admission(t.Context(), args, &out); e != nil {
		t.Fatal(args, e)
	}
	return out.String()
}

func runAdmissionCLICampaign(t *testing.T, driver v2CLIDriver) {
	t.Helper()
	z := newServeCLIFixture(t)
	c := z.x.context
	g, e := v2.NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	gid, _ := g.ID()
	did, _ := g.DescriptorID()
	cid, _ := c.ID()
	genesis := filepath.Join(z.dir, "admission-genesis")
	base := []string{"--genesis-id", gid.String(), "--genesis-descriptor-id", did.String()}
	contextArgs := []string{"--context", filepath.Join(z.dir, "context"), "--context-id", cid.String()}
	args := func(action string, extra ...string) []string {
		a := append([]string{custodyV2AdmissionCommand, "--action", action}, base...)
		if action != "genesis" {
			a = append(a, "--genesis", genesis)
		}
		return append(a, extra...)
	}
	run := func(a []string) {
		t.Helper()
		review := pruneCLIFields(strings.SplitN(driver(t, a), "\n", 2)[0])
		if review["keys_loaded"] != "false" || review["owners_opened"] != "false" || review["coordinator_only"] != "true" || review["execution_granted"] != "false" {
			t.Fatal(review)
		}
		driver(t, append(a, "--mode", "run", "--expected-review-id", review["review_id"]))
	}
	pin := func(path string) string {
		t.Helper()
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		return custodyV2ArtifactID(b).String()
	}
	run(args("genesis", append(append([]string{}, contextArgs...), "--out", genesis)...))
	admitPath := filepath.Join(z.dir, "admit-entry")
	run(args("admit-entry", append(append([]string{}, contextArgs...), "--sequence", "0", "--head-id", gid.String(), "--sign-key", z.keys[1], "--out", admitPath)...))
	raw, e := os.ReadFile(admitPath)
	if e != nil {
		t.Fatal(e)
	}
	admit, e := v2.DecodeAdmissionEntry(raw)
	if e != nil || admit.Verify(g) != nil {
		t.Fatal("admit entry", e)
	}
	admitID, _ := admit.ID()
	roots := []string{}
	for i := 0; i < 3; i++ {
		root := filepath.Join(z.dir, "admission-witness-"+strconv.Itoa(i))
		roots = append(roots, root)
		run(args("witness-create", "--root", root, "--witness", types.Hash(f.Public(byte(70+i))).String(), "--sign-key", z.keys[byte(70+i)], "--sequence", "0", "--head-id", gid.String(), "--pending-id", types.Hash{}.String(), "--out", root+"-created"))
	}
	certify := func(entryPath, label string, sequence uint64, head types.Hash) string {
		t.Helper()
		var paths, pins []string
		raw, e := os.ReadFile(entryPath)
		if e != nil {
			t.Fatal(e)
		}
		entry, e := v2.DecodeAdmissionEntry(raw)
		if e != nil {
			t.Fatal(e)
		}
		eid, _ := entry.ID()
		for i, root := range roots {
			vp := filepath.Join(z.dir, label+"-vote-"+strconv.Itoa(i))
			extra := []string{"--root", root, "--witness", types.Hash(f.Public(byte(70 + i))).String(), "--sign-key", z.keys[byte(70+i)], "--sequence", strconv.FormatUint(sequence, 10), "--head-id", head.String(), "--pending-id", types.Hash{}.String(), "--in", entryPath, "--in-id", pin(entryPath), "--out", vp}
			run(args("witness-vote", extra...))
			extra[len(extra)-1] = vp + "-recovered"
			run(args("witness-vote", extra...))
			a, _ := os.ReadFile(vp)
			b, _ := os.ReadFile(vp + "-recovered")
			if !bytes.Equal(a, b) {
				t.Fatal("cold vote retry changed signature")
			}
			paths = append(paths, vp)
			pins = append(pins, pin(vp))
		}
		certPath := filepath.Join(z.dir, label+"-certificate")
		extra := []string{"--in", entryPath, "--in-id", pin(entryPath), "--votes", strings.Join(paths, ","), "--vote-ids", strings.Join(pins, ","), "--out", certPath}
		run(args("certificate", extra...))
		for i, root := range roots {
			extra := []string{"--root", root, "--witness", types.Hash(f.Public(byte(70 + i))).String(), "--sign-key", z.keys[byte(70+i)], "--sequence", strconv.FormatUint(sequence, 10), "--head-id", head.String(), "--pending-id", eid.String(), "--in", certPath, "--in-id", pin(certPath), "--out", root + "-" + label + "-committed"}
			run(args("witness-commit", extra...))
			extra[len(extra)-1] += "-recovered"
			run(args("witness-commit", extra...))
		}
		return certPath
	}
	certify(admitPath, "admit", 0, gid)
	status := func(i int, seq uint64, head types.Hash, label string) v2.AdmissionSnapshot {
		t.Helper()
		root := roots[i]
		sp := filepath.Join(z.dir, label+"-status-"+strconv.Itoa(i))
		run(args("witness-status", "--root", root, "--witness", types.Hash(f.Public(byte(70+i))).String(), "--sign-key", z.keys[byte(70+i)], "--sequence", strconv.FormatUint(seq, 10), "--head-id", head.String(), "--pending-id", types.Hash{}.String(), "--out", sp))
		raw, e := os.ReadFile(sp)
		if e != nil {
			t.Fatal(e)
		}
		var result struct {
			Snapshot                          v2.AdmissionSnapshot
			Pin                               custodyfence.WitnessPin
			CoordinatorOnly, ExecutionGranted bool
		}
		if e := json.Unmarshal(raw, &result); e != nil || !result.CoordinatorOnly || result.ExecutionGranted {
			t.Fatal("invalid status", e)
		}
		return result.Snapshot
	}
	for i := range roots {
		s := status(i, 1, admitID, "active")
		if s.SpentOperations != 2 || s.PendingOperations != 2 || s.ActiveContextID != cid {
			t.Fatal("admission not reserved", s)
		}
	}
	scope, _ := c.Scope()
	sid, _ := scope.ID()
	cancel, e := (custodyfence.Command{Version: scope.Version, ScopeID: sid, ExpectedHead: sid, Kind: custodyfence.CloseUnclaimed, EvidenceID: f.Hash("admission-cli-cancel")}).Sign(f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	proposal, e := v2.NewServeUnclaimed(c, f.Certificate(cancel, 70, 71, 72))
	if e != nil {
		t.Fatal(e)
	}
	proposal, e = proposal.Sign(c, "authority", f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	proposal, e = proposal.Sign(c, "consumer", f.Key(4))
	if e != nil {
		t.Fatal(e)
	}
	decision, e := proposal.Decision(c, f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	serve := v2.ServeCertificate{Version: v2.Version2, Proposal: proposal, Decision: f.Certificate(decision, 70, 71, 72)}
	a, e := v2.OpenAcceptor(z.x.acceptor, c, z.x.pin, z.x.legacy.base.config.Audit.JournalPath, f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	ar, e := a.ApplyServe(t.Context(), serve, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	if e := a.Close(); e != nil {
		t.Fatal(e)
	}
	target := z.x.open(t)
	br, e := target.ApplyServe(t.Context(), serve, ar, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	if e := target.Close(); e != nil {
		t.Fatal(e)
	}
	proof, ap, bp := filepath.Join(z.dir, "serve-certificate"), filepath.Join(z.dir, "serve-a-receipt"), filepath.Join(z.dir, "serve-b-receipt")
	raw, _ = serve.CanonicalBytes()
	writePruneCLIFile(t, proof, raw)
	raw, _ = ar.CanonicalBytes()
	writePruneCLIFile(t, ap, raw)
	raw, _ = br.CanonicalBytes()
	writePruneCLIFile(t, bp, raw)
	closePath := filepath.Join(z.dir, "close-entry")
	run(args("close-entry", append(append([]string{}, contextArgs...), "--sequence", "1", "--head-id", admitID.String(), "--sign-key", z.keys[1], "--in", proof, "--in-id", pin(proof), "--a-receipt", ap, "--a-receipt-id", pin(ap), "--b-receipt", bp, "--b-receipt-id", pin(bp), "--out", closePath)...))
	raw, _ = os.ReadFile(closePath)
	closed, e := v2.DecodeAdmissionEntry(raw)
	if e != nil {
		t.Fatal(e)
	}
	closedID, _ := closed.ID()
	certify(closePath, "close", 1, admitID)
	for i := range roots {
		s := status(i, 2, closedID, "closed")
		if s.SpentOperations != 2 || s.PendingOperations != 0 || !s.ActiveContextID.IsZero() || s.SourceSequence != 0 || s.RetainUntil != c.Previous.RetainUntil {
			t.Fatal("closure refunded allowance or lost retention", s)
		}
	}
}
func TestCustodyV2AdmissionCLICompleteLifecycle(t *testing.T) {
	runAdmissionCLICampaign(t, admissionInProcess)
}

func TestCustodyV2AdmissionReviewSelectorsAndNoKeyRead(t *testing.T) {
	z := newServeCLIFixture(t)
	c := z.x.context
	g, e := v2.NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	gid, _ := g.ID()
	did, _ := g.DescriptorID()
	cid, _ := c.ID()
	gp := filepath.Join(z.dir, "genesis")
	raw, _ := g.CanonicalBytes()
	writePruneCLIFile(t, gp, raw)
	key := z.keys[1]
	if e := os.WriteFile(key, []byte("not a seed"), 0600); e != nil {
		t.Fatal(e)
	}
	args := []string{custodyV2AdmissionCommand, "--action", "admit-entry", "--genesis", gp, "--genesis-id", gid.String(), "--genesis-descriptor-id", did.String(), "--context", filepath.Join(z.dir, "context"), "--context-id", cid.String(), "--sequence", "0", "--head-id", gid.String(), "--sign-key", key, "--out", filepath.Join(z.dir, "entry")}
	var out bytes.Buffer
	if e := runCustodyV2Admission(t.Context(), args, &out); e != nil {
		t.Fatal("review read role seed", e)
	}
	review := pruneCLIFields(strings.SplitN(out.String(), "\n", 2)[0])["review_id"]
	altered := append([]string{}, args...)
	for i := range altered {
		if altered[i] == "--sequence" {
			altered[i+1] = "1"
		}
	}
	if e := runCustodyV2Admission(t.Context(), append(altered, "--mode", "run", "--expected-review-id", review), io.Discard); e == nil {
		t.Fatal("stale review accepted")
	}
	for _, bad := range [][]string{append(args, "--now", "1"), append(args, "--pending-id", types.Hash{}.String()), append(args, "--action", "genesis")} {
		if e := runCustodyV2Admission(t.Context(), bad, io.Discard); e == nil {
			t.Fatal("irrelevant or duplicate selector accepted")
		}
	}
	// The full descriptor pin is required independently of the assignment-only ID.
	altered = append([]string{}, args...)
	for i := range altered {
		if altered[i] == "--genesis-descriptor-id" {
			altered[i+1] = f.Hash("other descriptor").String()
		}
	}
	if e := runCustodyV2Admission(t.Context(), altered, io.Discard); e == nil {
		t.Fatal("descriptor substitution accepted")
	}
}
func TestCustodyV2AdmissionLostOutputPublishesBeforeReply(t *testing.T) {
	z := newServeCLIFixture(t)
	g, e := v2.NewAdmissionGenesis(z.x.context)
	if e != nil {
		t.Fatal(e)
	}
	gid, _ := g.ID()
	did, _ := g.DescriptorID()
	cid, _ := z.x.context.ID()
	output := filepath.Join(z.dir, "genesis-output")
	args := []string{custodyV2AdmissionCommand, "--action", "genesis", "--context", filepath.Join(z.dir, "context"), "--context-id", cid.String(), "--genesis-id", gid.String(), "--genesis-descriptor-id", did.String(), "--out", output}
	var out bytes.Buffer
	if e := runCustodyV2Admission(t.Context(), args, &out); e != nil {
		t.Fatal(e)
	}
	review := pruneCLIFields(strings.SplitN(out.String(), "\n", 2)[0])["review_id"]
	if e := runCustodyV2Admission(t.Context(), append(args, "--mode", "run", "--expected-review-id", review), serveBrokenWriter{}); !errors.Is(e, io.ErrClosedPipe) {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(output)
	if e != nil {
		t.Fatal("artifact lost before reply", e)
	}
	if _, e := v2.DecodeAdmissionGenesis(raw); e != nil {
		t.Fatal(e)
	}
}
