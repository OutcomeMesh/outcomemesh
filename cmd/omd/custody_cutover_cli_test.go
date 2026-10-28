package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	fencetest "github.com/outcomemesh/outcomemesh/internal/fencetest"
	a "github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
)

func cutoverInProcess(t testing.TB, args []string) string {
	t.Helper()
	var out bytes.Buffer
	if err := runCustodyCutover(t.Context(), args, &out); err != nil {
		t.Fatal(args, err)
	}
	return out.String()
}
func cutoverReviewed(t testing.TB, driver v2CLIDriver, args []string) []string {
	t.Helper()
	r := pruneCLIFields(strings.SplitN(driver(t, args), "\n", 2)[0])
	if r["keys_loaded"] != "false" || r["stores_opened"] != "false" || r["execution_granted"] != "false" || r["activation_allowed"] != "false" || r["review_id"] == "" {
		t.Fatal(r)
	}
	return append(append([]string{}, args...), "--mode", "run", "--expected-review-id", r["review_id"])
}
func cutoverWrite(t testing.TB, path string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	writePruneCLIFile(t, path, raw)
}

// Setup uses the existing real managed V1 exchange. All new review, capture,
// signing and durable preparation actions below pass through the public CLI.
func cutoverAcceptedLegacy(t testing.TB) (*remoteCLIFixture, cut.Evidence) {
	t.Helper()
	f := newRemoteCLIFixture(t, 600)
	b := startRemoteCLIControl(t, f.args("serve", "control"))
	b.send(t, "serve "+b.review(t))
	ready := b.next(t, "remote_custody_serving")
	runtime := startRemoteCLIControl(t, append(f.args("audit", "control"), "--peer", ready["listen"]))
	for _, step := range []struct{ action, prefix string }{{"prepare", "remote_custody_prepared"}, {"begin", "remote_custody_begun"}, {"execute", "remote_custody_executed"}, {"seal", "remote_custody_metadata"}, {"capture", "remote_custody_captured"}} {
		runtime.send(t, step.action+" "+runtime.review(t))
		runtime.next(t, step.prefix)
	}
	runtime.close(t)
	b.close(t)
	raw, err := os.ReadFile(f.terminal)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := store.DecodeRemoteCustodyTerminal(raw)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := store.OpenCoordinator(f.authority, f.pins, f.scope.Worker.Assignment, f.scope.Worker.Plan.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	appendCommand := func(command a.Command, seed byte) {
		state, err := owner.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		command.Version = a.Version1
		command.AssignmentID = f.scope.Worker.Plan.AssignmentID
		command.ExpectedSequence = state.Confirmed.Sequence
		command.ExpectedHead = state.Confirmed.HeadID
		entry := signRemoteCLI(t, command, seed)
		if _, err = owner.Append(t.Context(), entry); err != nil {
			t.Fatal(err)
		}
	}
	for _, ticket := range []a.Entry{f.audit, f.scope.Worker.Plan.Admission} {
		id, _ := ticket.ID()
		state, err := owner.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		draft, err := store.BuildRemoteCustodyCompleteCommand(f.scope, terminal, id, state.Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		appendCommand(draft, 4)
	}
	appendCommand(a.Command{Kind: a.Stop, EvidenceID: pruneCLIHash(199)}, 1)
	state, err := owner.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	appendCommand(a.Command{Kind: a.Retire, EvidenceID: state.Confirmed.HeadID}, 1)
	return f, cut.Evidence{Version: cut.Version1, Assignment: f.scope.Worker.Assignment, Manifest: f.scope.Manifest, Initial: f.scope.InitialReceipt, Policy: f.scope.CustodyPolicy, Cycles: []cut.Cycle{{Plan: f.scope.Worker.Plan, Begin: f.scope.Worker.Begin, Terminal: terminal}}}
}
func runCutoverCLICampaign(t testing.TB, driver v2CLIDriver) {
	t.Helper()
	f, template := cutoverAcceptedLegacy(t)
	lid, _ := template.Assignment.ID()
	owner, err := store.OpenCoordinator(f.authority, f.pins, template.Assignment, lid)
	if err != nil {
		t.Fatal(err)
	}
	state, err := owner.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	templatePath := filepath.Join(dir, "template.json")
	cutoverWrite(t, templatePath, template)
	common := []string{"--legacy-id", lid.String(), "--retired-sequence", strconv.FormatUint(state.Confirmed.Sequence, 10), "--retired-head", state.Confirmed.HeadID.String()}
	args := func(action string, extra ...string) []string {
		base := []string{custodyCutoverCommand, "--action", action}
		if action != "source-location" {
			base = append(base, common...)
		}
		return append(base, extra...)
	}
	run := func(action string, extra ...string) { driver(t, cutoverReviewed(t, driver, args(action, extra...))) }
	roots := []string{f.authority, f.pins, f.worker, f.base.config.Audit.JournalPath, f.base.serve.config.Session.JournalPath}
	before := remoteCLITrees(t, roots)
	evidencePath := filepath.Join(dir, "evidence")
	historyArgs := args("history-export", "--template", templatePath, "--authority", f.authority, "--authority-pins", f.pins, "--out", evidencePath)
	reviewed := cutoverReviewed(t, driver, historyArgs)
	// Stale review and duplicate/unused arguments fail before opening any source.
	if err = runCustodyCutover(t.Context(), replaceRemoteCLIFlag(reviewed, "--retired-head", pruneCLIHash(188).String()), &bytes.Buffer{}); err == nil {
		t.Fatal("stale review ran")
	}
	driver(t, reviewed)
	raw, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := cut.DecodeEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := evidence.Verify(lid, state.Confirmed)
	if err != nil || assessment.SpentOperations != 2 || assessment.SourceSequence != 1 {
		t.Fatal(assessment, err)
	}
	run("assess", "--evidence", evidencePath, "--out", filepath.Join(dir, "assessment.json"))
	g := wire.Genesis{Version: 2, NetworkID: template.Assignment.NetworkID, ChainGenesisID: template.Assignment.GenesisID, ResourceID: pruneCLIHash(200), Issuer: pruneCLIPublic(110), Threshold: 3, MaximumOperations: 4, MaximumPending: 2}
	for i := byte(111); i < 115; i++ {
		g.Witnesses = append(g.Witnesses, pruneCLIPublic(i))
	}
	sort.Slice(g.Witnesses, func(i, j int) bool { return bytes.Compare(g.Witnesses[i][:], g.Witnesses[j][:]) < 0 })
	anchorID, _ := g.ID()
	descriptorID, _ := g.DescriptorID()
	anchorPins := []string{"--anchor-id", anchorID.String(), "--descriptor-id", descriptorID.String()}
	anchorPath := filepath.Join(dir, "anchor")
	raw, _ = g.CanonicalBytes()
	writePruneCLIFile(t, anchorPath, raw)
	var observations []string
	for _, role := range []cut.Role{cut.Authority, cut.Target} {
		l := cut.SourceLocation{Role: role, Journal: f.base.config.Audit.JournalPath, Authority: f.authority, AuthorityPins: f.pins}
		seed := byte(1)
		if role == cut.Target {
			l = cut.SourceLocation{Role: role, Journal: f.base.serve.config.Session.JournalPath, Workers: []string{f.worker}}
			seed = 14
		}
		for _, path := range []*string{&l.Journal, &l.Authority, &l.AuthorityPins} {
			if *path != "" {
				*path, err = canonicalPruneLineageDirectory(*path)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		for i := range l.Workers {
			l.Workers[i], err = canonicalPruneLineageDirectory(l.Workers[i])
			if err != nil {
				t.Fatal(err)
			}
		}
		label := strconv.Itoa(int(role))
		sourcePath := filepath.Join(dir, "source-"+label+".json")
		cutoverWrite(t, sourcePath, l)
		locationID, err := l.LocationID()
		if err != nil {
			t.Fatal(err)
		}
		run("source-location", "--source", sourcePath, "--out", filepath.Join(dir, "location-"+label+".json"))
		observationPath := filepath.Join(dir, "observation-"+label)
		observeArgs := args("observe", "--evidence", evidencePath, "--source", sourcePath, "--anchor-id", anchorID.String(), "--placement-id", locationID.String(), "--nonce", pruneCLIHash(202+byte(role)).String(), "--sign-key", f.keyPaths[seed], "--out", observationPath)
		// Public review succeeds even if the existing seed is temporarily absent.
		missing := filepath.Join(dir, "missing.seed")
		cutoverReviewed(t, driver, replaceRemoteCLIFlag(observeArgs, "--sign-key", missing))
		driver(t, cutoverReviewed(t, driver, observeArgs))
		observations = append(observations, observationPath)
	}
	blueprint := cut.Blueprint{Version: cut.Version1, IncarnationID: pruneCLIHash(204), Authority: pruneCLIPublic(101), Control: pruneCLIPublic(102), Transport: pruneCLIPublic(103), Threshold: 3, Witnesses: fencetest.Scope().Witnesses, MaximumPending: 2}
	blueprintPath := filepath.Join(dir, "blueprint.json")
	cutoverWrite(t, blueprintPath, blueprint)
	proposalPath := filepath.Join(dir, "proposal-unsigned")
	extra := append([]string{"--evidence", evidencePath, "--anchor", anchorPath, "--a-observation", observations[0], "--b-observation", observations[1], "--blueprint", blueprintPath, "--allowance", "2", "--out", proposalPath}, anchorPins...)
	run("proposal", extra...)
	key110 := filepath.Join(dir, "issuer.seed")
	writePruneCLIFile(t, key110, pruneCLIKey(110).Seed())
	for _, r := range []struct{ role, key string }{{"issuer", key110}, {"authority", f.keyPaths[1]}, {"control", f.keyPaths[14]}} {
		signed := filepath.Join(dir, "proposal-"+r.role)
		extra := append([]string{"--proposal", proposalPath, "--role", r.role, "--sign-key", r.key, "--out", signed}, anchorPins...)
		run("sign-proposal", extra...)
		proposalPath = signed
	}
	raw, err = os.ReadFile(proposalPath)
	if err != nil {
		t.Fatal(err)
	}
	p, err := cut.DecodeProposal(raw)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := p.ID()
	bridge, err := p.Verify(anchorID, descriptorID, lid, state.Confirmed)
	if err != nil || bridge.Spent != 2 || bridge.Authorized != 2 || bridge.WholeJobs != 1 || bridge.ActivationAllowed {
		t.Fatal(bridge, err)
	}
	run("verify-proposal", append([]string{"--proposal", proposalPath, "--out", filepath.Join(dir, "bridge.json")}, anchorPins...)...)
	prepRoot := filepath.Join(dir, "preparation")
	prepArgs := append([]string{"--proposal", proposalPath, "--proposal-id", pid.String(), "--root", prepRoot}, anchorPins...)
	run("prepare", prepArgs...)
	for _, action := range []string{"read-preparation", "recover-preparation"} {
		output := filepath.Join(dir, action)
		extra := append([]string{"--proposal-id", pid.String(), "--root", prepRoot, "--out", output}, anchorPins...)
		run(action, extra...)
		got, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatal("cold read changed proposal", err)
		}
	}
	after := remoteCLITrees(t, roots)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("cutover review changed legacy owners, sources or worker")
	}
	// Optional retained campaign output is private; no deployment seeds enter docs.
	if destination := os.Getenv("OMESH_CUTOVER_PUBLIC_EXPORT"); destination != "" {
		if err = os.Mkdir(destination, 0700); err != nil {
			t.Fatal(err)
		}
		for _, item := range []struct{ name, path string }{{"evidence", evidencePath}, {"anchor", anchorPath}, {"a-observation", observations[0]}, {"b-observation", observations[1]}, {"proposal", proposalPath}, {"assessment.json", filepath.Join(dir, "assessment.json")}, {"bridge.json", filepath.Join(dir, "bridge.json")}} {
			b, err := os.ReadFile(item.path)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(destination, item.name), b, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
func TestRemoteCutoverCLIOriginalCompletedCycleAndColdPreparation(t *testing.T) {
	runCutoverCLICampaign(t, cutoverInProcess)
}
func TestRemoteCutoverStrictJSONAndArgumentRefusals(t *testing.T) {
	good := cut.Blueprint{Version: 1, IncarnationID: pruneCLIHash(211), Authority: pruneCLIPublic(101), Control: pruneCLIPublic(102), Transport: pruneCLIPublic(103), Threshold: 3, Witnesses: fencetest.Scope().Witnesses, MaximumPending: 2}
	raw, _ := json.Marshal(good)
	for _, body := range [][]byte{[]byte(`{"Version":1,"Version":1}`), append(append([]byte{}, raw...), []byte(` {}`)...), bytes.Replace(raw, []byte(`"Authority":[`), []byte(`"Authority":[0,`), 1), bytes.Replace(raw, []byte(`"Version":1`), []byte(`"version":1`), 1), []byte(`null`)} {
		var decoded cut.Blueprint
		if err := cutoverJSON(body, &decoded); err == nil {
			t.Fatal("ambiguous JSON accepted", string(body))
		}
	}
	var decoded cut.Blueprint
	if err := cutoverJSON(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{custodyCutoverCommand, "--action", "activate"}, {custodyCutoverCommand, "--action", "assess", "--action", "assess"}, {custodyCutoverCommand, "--action", "source-location", "--root", "unused"}} {
		if err := runCustodyCutover(t.Context(), args, io.Discard); err == nil {
			t.Fatal("unused/duplicate/activation action accepted")
		}
	}
	if err := runCustodyCutover(nil, []string{custodyCutoverCommand}, io.Discard); err == nil {
		t.Fatal("nil context")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runCustodyCutover(canceled, []string{custodyCutoverCommand}, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestRemoteCutoverCLIBlockedOutputCancellationReleasesOriginalGuards(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native pipe ownership")
	}
	intercepted := false
	driver := func(t testing.TB, args []string) string {
		t.Helper()
		if admissionFlagValue(args, "--action") != "observe" || admissionFlagValue(args, "--mode") != "run" || intercepted {
			return cutoverInProcess(t, args)
		}
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		defer writer.Close()
		if err = writer.SetWriteDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err = writer.Write(bytes.Repeat([]byte("x"), 1<<20)); !os.IsTimeout(err) {
			t.Fatal("pipe did not fill", err)
		}
		if err = writer.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- runCustodyCutover(ctx, args, writer) }()
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			if _, err = os.Stat(admissionFlagValue(args, "--out")); err == nil {
				break
			}
			select {
			case err := <-done:
				t.Fatal("ended before retained output", err)
			case <-deadline.C:
				t.Fatal("observation did not retain output")
			case <-tick.C:
			}
		}
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("unobserved output reported success")
			}
		case <-time.After(time.Second):
			t.Fatal("cancellation retained original guards")
		}
		intercepted = true
		return ""
	}
	runCutoverCLICampaign(t, driver)
	if !intercepted {
		t.Fatal("source observation output was not interrupted")
	}
}
func admissionFlagValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}
