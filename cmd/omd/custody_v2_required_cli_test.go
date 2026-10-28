package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

type requiredCLIFixture struct {
	x                                                                             *custodyV2Fixture
	c                                                                             v2.Context
	sid                                                                           types.Hash
	binding                                                                       v2.AdmissionBinding
	enrollmentPath                                                                string
	enrollment                                                                    v2.EnrollmentBinding
	dir, contextPath, genesisPath, certificatePath, bindingPath, target, acceptor string
	keys                                                                          map[byte]string
}

func newRequiredCLIFixture(t testing.TB, drivers ...v2CLIDriver) requiredCLIFixture {
	t.Helper()
	return newRequiredCLIFixtureProfile(t, nil, drivers...)
}
func newRequiredCLIFixtureProfile(t testing.TB, configure func(v2.Context) v2.Policy, drivers ...v2CLIDriver) requiredCLIFixture {
	t.Helper()
	x := newCustodyV2Fixture(t)
	c := x.context
	c.Assignment.Policy.Version = v2.PolicyVersionAdmission
	if configure != nil {
		c.Assignment.Policy = configure(c)
	}
	aid, e := c.Assignment.ID()
	if e != nil {
		t.Fatal(e)
	}
	c.Plan.AssignmentID = aid
	c.Plan.Intent.AssignmentID = aid
	c.Plan.AuditSignature = [64]byte{}
	c.Plan.ServeSignature = [64]byte{}
	c.Plan.AuthoritySignature = [64]byte{}
	for _, role := range []string{"audit", "serve", "authority"} {
		seed := byte(4)
		if role == "authority" {
			seed = 1
		}
		c.Plan, e = c.Plan.Sign(role, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	scope, e := c.Scope()
	if e != nil {
		t.Fatal(e)
	}
	sid, _ := scope.ID()
	g, e := v2.NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	gid, _ := g.ID()
	did, _ := g.DescriptorID()
	dir := t.TempDir()
	z := requiredCLIFixture{x: x, c: c, sid: sid, dir: dir, contextPath: filepath.Join(dir, "context"), genesisPath: filepath.Join(dir, "genesis"), certificatePath: filepath.Join(dir, "admission-qc"), bindingPath: filepath.Join(dir, "binding"), target: filepath.Join(dir, "target"), acceptor: filepath.Join(dir, "acceptor"), keys: map[byte]string{}}
	raw, _ := c.CanonicalBytes()
	writePruneCLIFile(t, z.contextPath, raw)
	for _, seed := range []byte{1, 4, 14, 15, 46, 61, 70, 71, 72} {
		path := filepath.Join(dir, "key-"+strconv.Itoa(int(seed)))
		writePruneCLIFile(t, path, f.Key(seed).Seed())
		z.keys[seed] = path
	}
	driver := v2CLIDriver(requiredInProcess)
	if len(drivers) > 0 {
		driver = drivers[0]
	}
	base := []string{"--genesis-id", gid.String(), "--genesis-descriptor-id", did.String()}
	args := func(action string, extra ...string) []string {
		a := append([]string{custodyV2AdmissionCommand, "--action", action}, base...)
		if action != "genesis" {
			a = append(a, "--genesis", z.genesisPath)
		}
		return append(a, extra...)
	}
	run := func(a []string) {
		t.Helper()
		review := pruneCLIFields(strings.SplitN(driver(t, a), "\n", 2)[0])
		if review["keys_loaded"] != "false" || review["owners_opened"] != "false" || review["execution_granted"] != "false" {
			t.Fatal(review)
		}
		driver(t, append(a, "--mode", "run", "--expected-review-id", review["review_id"]))
	}
	cid, _ := c.ID()
	contextArgs := []string{"--context", z.contextPath, "--context-id", cid.String()}
	run(args("genesis", append(append([]string{}, contextArgs...), "--out", z.genesisPath)...))
	entryPath := filepath.Join(dir, "admission-entry")
	run(args("admit-entry", append(append([]string{}, contextArgs...), "--sequence", "0", "--head-id", gid.String(), "--sign-key", z.keys[1], "--out", entryPath)...))
	raw, _ = os.ReadFile(entryPath)
	entry, e := v2.DecodeAdmissionEntry(raw)
	if e != nil {
		t.Fatal(e)
	}
	eid, _ := entry.ID()
	var votePaths, votePins []string
	for i := 0; i < 3; i++ {
		root := filepath.Join(dir, "admission-witness-"+strconv.Itoa(i))
		seed := byte(70 + i)
		common := []string{"--root", root, "--witness", types.Hash(f.Public(seed)).String(), "--sign-key", z.keys[seed], "--sequence", "0", "--head-id", gid.String(), "--pending-id", types.Hash{}.String()}
		run(args("witness-create", append(append([]string{}, common...), "--out", root+"-created")...))
		vp := root + "-vote"
		run(args("witness-vote", append(append([]string{}, common...), "--in", entryPath, "--in-id", z.pin(t, entryPath), "--out", vp)...))
		votePaths = append(votePaths, vp)
		votePins = append(votePins, z.pin(t, vp))
	}
	run(args("certificate", "--in", entryPath, "--in-id", z.pin(t, entryPath), "--votes", strings.Join(votePaths, ","), "--vote-ids", strings.Join(votePins, ","), "--out", z.certificatePath))
	for i := 0; i < 3; i++ {
		root := filepath.Join(dir, "admission-witness-"+strconv.Itoa(i))
		seed := byte(70 + i)
		run(args("witness-commit", "--root", root, "--witness", types.Hash(f.Public(seed)).String(), "--sign-key", z.keys[seed], "--sequence", "0", "--head-id", gid.String(), "--pending-id", eid.String(), "--in", z.certificatePath, "--in-id", z.pin(t, z.certificatePath), "--out", root+"-committed"))
	}
	raw, _ = os.ReadFile(z.certificatePath)
	cert, e := v2.DecodeAdmissionCertificate(raw)
	if e != nil {
		t.Fatal(e)
	}
	z.binding = v2.AdmissionBinding{Version: 2, Genesis: g, Chain: []v2.AdmissionCertificate{cert}}
	if e := z.binding.Verify(c); e != nil {
		t.Fatal(e)
	}
	return z
}
func (z requiredCLIFixture) args(action string, extra ...string) []string {
	cid, _ := z.c.ID()
	command := custodyV2RequiredCommand
	if z.c.Assignment.Policy.Version == v2.PolicyVersionEnrolled {
		command = custodyV2EnrolledCommand
	}
	args := []string{command, "--action", action, "--context", z.contextPath, "--context-id", cid.String(), "--scope-id", z.sid.String()}
	if action != "binding" {
		id, _ := z.binding.ID()
		args = append(args, "--binding", z.bindingPath, "--binding-id", id.String())
	}
	if z.c.Assignment.Policy.Version == v2.PolicyVersionEnrolled && action != "binding" && action != "enrollment" {
		id, _ := z.enrollment.ID()
		args = append(args, "--enrollment", z.enrollmentPath, "--enrollment-id", id.String())
	}
	return append(args, extra...)
}
func (z requiredCLIFixture) pin(t testing.TB, path string) string {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return custodyV2ArtifactID(b).String()
}
func (z requiredCLIFixture) bindingArgs(t testing.TB) []string {
	t.Helper()
	g := z.binding.Genesis
	gid, _ := g.ID()
	did, _ := g.DescriptorID()
	return z.args("binding", "--genesis", z.genesisPath, "--genesis-id", gid.String(), "--genesis-descriptor-id", did.String(), "--certificates", z.certificatePath, "--certificate-ids", z.pin(t, z.certificatePath), "--out", z.bindingPath)
}
func requiredInProcess(t testing.TB, args []string) string {
	t.Helper()
	var out bytes.Buffer
	var err error
	switch args[0] {
	case custodyV2RequiredCommand, custodyV2EnrolledCommand:
		err = runCustodyV2Required(t.Context(), args, nil, &out)
	case custodyRegistryCommand:
		err = runCustodyRegistry(t.Context(), args, &out)
	case custodyV2AdmissionCommand:
		err = runCustodyV2Admission(t.Context(), args, &out)
	case custodyV2Command:
		err = runCustodyV2(t.Context(), args, nil, &out)
	default:
		t.Fatal("unsupported test CLI", args[0])
	}
	if err != nil {
		t.Fatal(args, err)
	}
	return out.String()
}
func requiredReviewed(t testing.TB, driver v2CLIDriver, args []string) []string {
	t.Helper()
	r := pruneCLIFields(strings.SplitN(driver(t, args), "\n", 2)[0])
	if r["keys_loaded"] != "false" || r["owners_opened"] != "false" || r["admission_required"] != "true" {
		t.Fatal(r)
	}
	return append(args, "--mode", "run", "--expected-review-id", r["review_id"])
}
func (z requiredCLIFixture) aArgs() []string {
	return []string{"--root", z.acceptor, "--journal", z.x.legacy.base.config.Audit.JournalPath, "--sign-key", z.keys[1]}
}
func (z requiredCLIFixture) bArgs() []string {
	return []string{"--root", z.target, "--journal", z.x.sources.Journal, "--objects", z.x.sources.Objects, "--sign-key", z.keys[14], "--replica-key", z.keys[61]}
}
func (z requiredCLIFixture) execute(t testing.TB) v2.Bundle {
	t.Helper()
	target, e := z.openTarget()
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	candidate, e := target.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	claim := f.Certificate(candidate.Claim, 70, 71, 72)
	if _, e := target.Execute(t.Context(), claim, z.c.Plan.Challenge.IssuedAt); e != nil {
		t.Fatal(e)
	}
	result, cmd, e := target.ResultCommand([]custodyfence.Certificate{claim})
	if e != nil {
		t.Fatal(e)
	}
	bundle := v2.Bundle{Version: 2, Result: result, Chain: []custodyfence.Certificate{claim, f.Certificate(cmd, 70, 71, 72)}}
	if e := bundle.Verify(z.c); e != nil {
		t.Fatal(e)
	}
	return bundle
}
func initializeRequiredCLI(t testing.TB, z requiredCLIFixture, driver v2CLIDriver) {
	t.Helper()
	run := func(args []string) { driver(t, requiredReviewed(t, driver, args)) }
	if z.c.Assignment.Policy.Version != v2.PolicyVersionEnrolled {
		run(z.bindingArgs(t))
	}
	run(z.args("create-target", "--root", z.target, "--journal", z.x.sources.Journal, "--objects", z.x.sources.Objects))
	run(z.args("create-acceptor", "--root", z.acceptor, "--journal", z.x.legacy.base.config.Audit.JournalPath))
}

// Admission, binding and owner operations use normal reviewed CLI. With a
// service starter the actual effect/recovery uses the signed V2 network path;
// per-job execution/Serve quorums use public deterministic fixture endorsements.
func runRequiredCLICampaign(t *testing.T, driver v2CLIDriver, starts ...v2CLIStart) {
	t.Helper()
	z := newRequiredCLIFixture(t, driver)
	runRequiredCLIFixtureCampaign(t, z, driver, starts...)
}
func runRequiredCLIFixtureCampaign(t *testing.T, z requiredCLIFixture, driver v2CLIDriver, starts ...v2CLIStart) {
	t.Helper()
	initializeRequiredCLI(t, z, driver)
	run := func(a []string) { driver(t, requiredReviewed(t, driver, a)) }
	raw, e := os.ReadFile(z.bindingPath)
	if e != nil {
		t.Fatal(e)
	}
	expected, _ := z.binding.CanonicalBytes()
	if !bytes.Equal(raw, expected) {
		t.Fatal("binding changed during CLI construction")
	}
	if old, e := v2.OpenTarget(z.target, z.c, z.sid, z.x.sources, f.Key(61), f.Key(14)); e == nil {
		_ = old.Close()
		t.Fatal("raw target opened required root")
	}
	if old, e := v2.OpenAcceptor(z.acceptor, z.c, z.sid, z.x.legacy.base.config.Audit.JournalPath, f.Key(1)); e == nil {
		_ = old.Close()
		t.Fatal("raw acceptor opened required root")
	}
	var bundle v2.Bundle
	if len(starts) > 0 {
		bundle = z.networkBundle(t, driver, starts[0])
	} else {
		bundle = z.execute(t)
	}
	bundlePath := filepath.Join(z.dir, "bundle")
	raw, _ = bundle.CanonicalBytes()
	writePruneCLIFile(t, bundlePath, raw)
	accepted := filepath.Join(z.dir, "accepted")
	run(z.args("accept", append(z.aArgs(), "--in", bundlePath, "--in-id", z.pin(t, bundlePath), "--out", accepted)...))
	receiptPath := filepath.Join(z.dir, "receipt")
	run(z.args("receipt", append(z.aArgs(), "--out", receiptPath)...))
	original, _ := os.ReadFile(accepted)
	recovered, _ := os.ReadFile(receiptPath)
	if !bytes.Equal(original, recovered) {
		t.Fatal("cached accepted receipt changed")
	}
	bid, _ := bundle.ID()
	run(z.args("resume", append(z.aArgs(), "--bundle-id", bid.String(), "--out", filepath.Join(z.dir, "accepted-resumed"))...))
	receipt, e := v2.DecodeReceipt(original)
	if e != nil {
		t.Fatal(e)
	}
	proposal, e := v2.NewServeFulfilled(z.c, bundle, receipt)
	if e != nil {
		t.Fatal(e)
	}
	for _, role := range []string{"authority", "consumer"} {
		seed := byte(1)
		if role == "consumer" {
			seed = 4
		}
		proposal, e = proposal.Sign(z.c, role, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	decision, e := proposal.Decision(z.c, f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	serve := v2.ServeCertificate{Version: 2, Proposal: proposal, Decision: f.Certificate(decision, 70, 71, 72)}
	if e := serve.Verify(z.c); e != nil {
		t.Fatal(e)
	}
	servePath := filepath.Join(z.dir, "serve-certificate")
	raw, _ = serve.CanonicalBytes()
	writePruneCLIFile(t, servePath, raw)
	ar, br := filepath.Join(z.dir, "a-serve"), filepath.Join(z.dir, "b-serve")
	run(z.args("serve-apply-a", append(z.aArgs(), "--in", servePath, "--in-id", z.pin(t, servePath), "--out", ar)...))
	run(z.args("serve-apply-b", append(z.bArgs(), "--in", servePath, "--in-id", z.pin(t, servePath), "--proof", ar, "--proof-id", z.pin(t, ar), "--out", br)...))
	run(z.args("serve-resume-a", append(z.aArgs(), "--in", servePath, "--in-id", z.pin(t, servePath), "--out", ar+"-recovered")...))
	run(z.args("serve-resume-b", append(z.bArgs(), "--in", servePath, "--in-id", z.pin(t, servePath), "--proof", ar, "--proof-id", z.pin(t, ar), "--out", br+"-recovered")...))
	for _, p := range []string{ar, br} {
		a, _ := os.ReadFile(p)
		b, _ := os.ReadFile(p + "-recovered")
		if !bytes.Equal(a, b) {
			t.Fatal("Serve cold receipt changed")
		}
	}
	z.closeAccounting(t, driver, bundle, servePath, ar, br)
	for _, role := range []string{"a", "b"} {
		args := z.aArgs()
		if role == "b" {
			args = z.bArgs()
		}
		sp := filepath.Join(z.dir, "status-"+role)
		run(z.args("serve-status-"+role, append(args, "--out", sp)...))
		raw, e := os.ReadFile(sp)
		if e != nil {
			t.Fatal(e)
		}
		var s v2.ServeStatus
		if e := json.Unmarshal(raw, &s); e != nil || s.Pending || !s.ArchiveHeld {
			t.Fatal("required Serve state", s, e)
		}
	}
}
func TestCustodyV2RequiredCLICompleteLifecycle(t *testing.T) {
	runRequiredCLICampaign(t, requiredInProcess, requiredInProcessStart)
}
func TestCustodyV2RequiredReviewBindsProofAndDoesNotReadSeed(t *testing.T) {
	z := newRequiredCLIFixture(t)
	initializeRequiredCLI(t, z, requiredInProcess)
	if e := os.WriteFile(z.keys[1], []byte("not a seed"), 0600); e != nil {
		t.Fatal(e)
	}
	args := z.args("receipt", append(z.aArgs(), "--out", filepath.Join(z.dir, "unused-receipt"))...)
	var out bytes.Buffer
	if e := runCustodyV2Required(t.Context(), args, nil, &out); e != nil {
		t.Fatal("review loaded private seed", e)
	}
	r := pruneCLIFields(strings.SplitN(out.String(), "\n", 2)[0])
	changedOutput := append([]string{}, args...)
	for i := range changedOutput {
		if changedOutput[i] == "--out" {
			changedOutput[i+1] = filepath.Join(z.dir, "changed-output")
		}
	}
	if e := runCustodyV2Required(t.Context(), append(changedOutput, "--mode", "run", "--expected-review-id", r["review_id"]), nil, io.Discard); e == nil || !strings.Contains(e.Error(), "exact public review") {
		t.Fatal("changed output reused action review", e)
	}
	stale := append([]string{}, args...)
	for i := range stale {
		if stale[i] == "--binding-id" {
			stale[i+1] = f.Hash("other-binding").String()
		}
	}
	if e := runCustodyV2Required(t.Context(), append(stale, "--mode", "run", "--expected-review-id", r["review_id"]), nil, io.Discard); e == nil {
		t.Fatal("another binding retained stale review")
	}
	for _, extra := range [][]string{{"--now", "1"}, {"--replica-key", z.keys[61]}, {"--action", "binding"}} {
		if e := runCustodyV2Required(t.Context(), append(append([]string{}, args...), extra...), nil, io.Discard); e == nil {
			t.Fatal("irrelevant/duplicate selector accepted")
		}
	}
	alias := z.args("receipt", append(z.aArgs(), "--out", filepath.Join(z.acceptor, "misplaced"))...)
	if e := runCustodyV2Required(t.Context(), alias, nil, io.Discard); e == nil {
		t.Fatal("output inside owner accepted")
	}
}
func TestCustodyV2RequiredLostAcceptanceOutputRecoversExactReceipt(t *testing.T) {
	z := newRequiredCLIFixture(t)
	initializeRequiredCLI(t, z, requiredInProcess)
	bundle := z.execute(t)
	path := filepath.Join(z.dir, "bundle")
	raw, _ := bundle.CanonicalBytes()
	writePruneCLIFile(t, path, raw)
	accepted := filepath.Join(z.dir, "lost-accepted")
	args := z.args("accept", append(z.aArgs(), "--in", path, "--in-id", z.pin(t, path), "--out", accepted)...)
	run := requiredReviewed(t, requiredInProcess, args)
	if e := runCustodyV2Required(t.Context(), run, nil, serveBrokenWriter{}); !errors.Is(e, io.ErrClosedPipe) {
		t.Fatal("lost output did not propagate", e)
	}
	before, e := os.ReadFile(accepted)
	if e != nil {
		t.Fatal("accepted artifact missing after lost output", e)
	}
	receiptPath := filepath.Join(z.dir, "recovered-receipt")
	requiredInProcess(t, requiredReviewed(t, requiredInProcess, z.args("receipt", append(z.aArgs(), "--out", receiptPath)...)))
	after, e := os.ReadFile(receiptPath)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("lost acceptance recovery changed proof/time", e)
	}
}

func requiredInProcessStart(t testing.TB, args []string, prefix string) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	in, input := io.Pipe()
	out, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- runCustodyV2Required(ctx, args, in, writer); _ = writer.Close() }()
	ready := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(out)
		if scan.Scan() {
			ready <- scan.Text()
		} else {
			ready <- ""
		}
	}()
	t.Cleanup(func() { cancel(); _ = input.Close(); _ = out.Close() })
	select {
	case line := <-ready:
		record := pruneCLIFields(line)
		if !strings.HasPrefix(line, prefix+" ") || record["address"] == "" {
			t.Fatal("required service readiness", line)
		}
		return record["address"], func() {
			_, _ = io.WriteString(input, "close\n")
			select {
			case e := <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("required service did not drain")
			}
			cancel()
			_ = out.Close()
		}
	case <-time.After(10 * time.Second):
		t.Fatal("required service readiness timeout")
	}
	return "", func() {}
}

func (z requiredCLIFixture) networkBundle(t testing.TB, driver v2CLIDriver, start v2CLIStart) v2.Bundle {
	t.Helper()
	serve := z.args("serve-target", append(z.bArgs(), "--transport-key", z.keys[15])...)
	prefix := "custody_v2_required_serving"
	if z.c.Assignment.Policy.Version == v2.PolicyVersionEnrolled {
		prefix = "custody_v2_enrolled_serving"
	}
	address, closeTarget := start(t, requiredReviewed(t, driver, serve), prefix)
	defer closeTarget()
	cid, _ := z.c.ID()
	common := []string{"--context", z.contextPath, "--context-id", cid.String(), "--scope-id", z.sid.String()}
	args := func(action string, extra ...string) []string {
		return append(append([]string{custodyV2Command, "--action", action}, common...), extra...)
	}
	run := func(a []string) {
		t.Helper()
		review := pruneCLIFields(strings.SplitN(driver(t, a), "\n", 2)[0])
		if review["keys_loaded"] != "false" {
			t.Fatal(review)
		}
		driver(t, append(a, "--mode", "run", "--expected-review-id", review["review_id"]))
	}
	call := func(request, output string) {
		t.Helper()
		run(args("call", "--in", request, "--in-id", z.pin(t, request), "--transport-key", z.keys[46], "--peer", address, "--out", output))
	}
	prepare := filepath.Join(z.dir, "prepare-request")
	prepared := filepath.Join(z.dir, "prepare-response")
	run(args("request", "--operation", "prepare", "--nonce", f.Hash("required-prepare").String(), "--out", prepare))
	call(prepare, prepared)
	raw, e := os.ReadFile(prepared)
	if e != nil {
		t.Fatal(e)
	}
	response, e := v2.DecodeResponse(raw)
	if e != nil {
		t.Fatal(e)
	}
	if e := response.Candidate.Verify(z.c); e != nil {
		t.Fatal(e)
	}
	// These per-job endorsements are fixture evidence, while assignment admission
	// was selected and committed by the actual normal witness CLI above.
	claim := f.Certificate(response.Candidate.Claim, 70, 71, 72)
	claimPath := filepath.Join(z.dir, "claim-qc")
	raw, _ = claim.CanonicalBytes()
	writePruneCLIFile(t, claimPath, raw)
	execute := filepath.Join(z.dir, "execute-request")
	executed := filepath.Join(z.dir, "execute-response")
	run(args("request", "--operation", "execute", "--nonce", f.Hash("required-execute").String(), "--claim", claimPath, "--claim-id", z.pin(t, claimPath), "--out", execute))
	call(execute, executed)
	raw, e = os.ReadFile(executed)
	if e != nil {
		t.Fatal(e)
	}
	response, e = v2.DecodeResponse(raw)
	if e != nil {
		t.Fatal(e)
	}
	bundle := v2.Bundle{Version: 2, Result: response.Result, Chain: []custodyfence.Certificate{claim, f.Certificate(response.Command, 70, 71, 72)}}
	if e := bundle.Verify(z.c); e != nil {
		t.Fatal(e)
	}
	// Exact cached recovery runs over the same authenticated protocol without
	// preparing another session or signing a new chunk proof.
	recoverPath, recovered := filepath.Join(z.dir, "recover-request"), filepath.Join(z.dir, "recover-response")
	run(args("request", "--operation", "recover", "--nonce", f.Hash("required-recover").String(), "--claim", claimPath, "--claim-id", z.pin(t, claimPath), "--out", recoverPath))
	call(recoverPath, recovered)
	raw, e = os.ReadFile(recovered)
	if e != nil {
		t.Fatal(e)
	}
	cached, e := v2.DecodeResponse(raw)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := response.Result.CanonicalBytes()
	after, _ := cached.Result.CanonicalBytes()
	if !bytes.Equal(before, after) {
		t.Fatal("network recovery refreshed required result")
	}
	return bundle
}

func (z requiredCLIFixture) closeAccounting(t testing.TB, driver v2CLIDriver, bundle v2.Bundle, servePath, ar, br string) {
	t.Helper()
	g := z.binding.Genesis
	gid, _ := g.ID()
	did, _ := g.DescriptorID()
	admitID, _ := z.binding.Chain[len(z.binding.Chain)-1].Entry.ID()
	cid, _ := z.c.ID()
	args := func(action string, extra ...string) []string {
		return append([]string{custodyV2AdmissionCommand, "--action", action, "--genesis", z.genesisPath, "--genesis-id", gid.String(), "--genesis-descriptor-id", did.String()}, extra...)
	}
	run := func(a []string) {
		t.Helper()
		review := pruneCLIFields(strings.SplitN(driver(t, a), "\n", 2)[0])
		if review["keys_loaded"] != "false" || review["execution_granted"] != "false" {
			t.Fatal(review)
		}
		driver(t, append(a, "--mode", "run", "--expected-review-id", review["review_id"]))
	}
	ep := filepath.Join(z.dir, "admission-close-entry")
	run(args("close-entry", "--context", z.contextPath, "--context-id", cid.String(), "--sequence", "1", "--head-id", admitID.String(), "--sign-key", z.keys[1], "--in", servePath, "--in-id", z.pin(t, servePath), "--a-receipt", ar, "--a-receipt-id", z.pin(t, ar), "--b-receipt", br, "--b-receipt-id", z.pin(t, br), "--out", ep))
	raw, e := os.ReadFile(ep)
	if e != nil {
		t.Fatal(e)
	}
	entry, e := v2.DecodeAdmissionEntry(raw)
	if e != nil {
		t.Fatal(e)
	}
	eid, _ := entry.ID()
	var votes, pins []string
	for i := 0; i < 3; i++ {
		root := filepath.Join(z.dir, "admission-witness-"+strconv.Itoa(i))
		seed := byte(70 + i)
		vp := root + "-close-vote"
		run(args("witness-vote", "--root", root, "--witness", types.Hash(f.Public(seed)).String(), "--sign-key", z.keys[seed], "--sequence", "1", "--head-id", admitID.String(), "--pending-id", types.Hash{}.String(), "--in", ep, "--in-id", z.pin(t, ep), "--out", vp))
		votes = append(votes, vp)
		pins = append(pins, z.pin(t, vp))
	}
	qp := filepath.Join(z.dir, "admission-close-qc")
	run(args("certificate", "--in", ep, "--in-id", z.pin(t, ep), "--votes", strings.Join(votes, ","), "--vote-ids", strings.Join(pins, ","), "--out", qp))
	for i := 0; i < 3; i++ {
		root := filepath.Join(z.dir, "admission-witness-"+strconv.Itoa(i))
		seed := byte(70 + i)
		out := root + "-close-committed"
		run(args("witness-commit", "--root", root, "--witness", types.Hash(f.Public(seed)).String(), "--sign-key", z.keys[seed], "--sequence", "1", "--head-id", admitID.String(), "--pending-id", eid.String(), "--in", qp, "--in-id", z.pin(t, qp), "--out", out))
		raw, e := os.ReadFile(out)
		if e != nil {
			t.Fatal(e)
		}
		var observed struct {
			Snapshot v2.AdmissionSnapshot
			Pin      custodyfence.WitnessPin
		}
		if e := json.Unmarshal(raw, &observed); e != nil {
			t.Fatal(e)
		}
		head, _ := bundle.Result.Entry.ID()
		receipt, _ := bundle.Result.Entry.Record.RenewedReceipt.ID()
		s := observed.Snapshot
		if s.Position.Sequence != 2 || s.Position.HeadID != eid || s.SpentOperations != 2 || s.PendingOperations != 0 || !s.ActiveContextID.IsZero() || s.SourceSequence != 1 || s.SourceHeadID != head || s.SourceReceiptID != receipt || s.RetainUntil < bundle.Result.Entry.Record.RenewedReceipt.RetainUntil || !observed.Pin.PendingID.IsZero() {
			t.Fatal("required accounting close", s, observed.Pin)
		}
	}
	// Historical Admit proof remains structurally valid. Current original owner
	// state and the execution fence prevent reviving the completed effect.
	target, e := z.openTarget()
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	if _, e := target.Prepare(); !errors.Is(e, v2.ErrServeClosed) {
		t.Fatal("historical binding revived closed required owner", e)
	}
}

func (z requiredCLIFixture) openTarget() (*v2.Target, error) {
	if z.c.Assignment.Policy.Version == v2.PolicyVersionEnrolled {
		return v2.OpenEnrolledTarget(z.target, z.c, z.sid, z.x.sources, z.binding, z.enrollment, f.Key(61), f.Key(14))
	}
	return v2.OpenRequiredTarget(z.target, z.c, z.sid, z.x.sources, z.binding, f.Key(61), f.Key(14))
}
