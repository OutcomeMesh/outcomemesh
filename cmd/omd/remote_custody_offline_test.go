package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
)

func remoteOfflineCommonArgs(f *remoteCLIFixture) []string {
	a := custodyCommandCLICommonArgs(f.base)
	iid, _ := f.intent.ID()
	values := map[string]string{"--assignment": filepath.Join(f.public, "assignment"), "--assignment-id": f.scope.Worker.Plan.AssignmentID.String(), "--intent": f.intentPath, "--intent-id": iid.String()}
	for i := 0; i < len(a)-1; i += 2 {
		if value, ok := values[a[i]]; ok {
			a[i+1] = value
		}
	}
	return a
}

func remoteOfflineChallengeArgs(f *remoteCLIFixture) []string {
	id, _ := f.scope.Challenge.ID()
	return []string{"--challenge", filepath.Join(f.public, "challenge"), "--challenge-id", id.String()}
}

func remoteOfflinePlanArgs(f *remoteCLIFixture) []string {
	return []string{"--plan", filepath.Join(f.public, "plan"), "--plan-id", f.scope.Worker.PlanID.String()}
}

func remoteOfflineRun(t testing.TB, args []string) map[string]string {
	t.Helper()
	var output bytes.Buffer
	if err := runCustodyCommand(t.Context(), args, nil, &output); err != nil {
		t.Fatal(args[0], err)
	}
	return pruneCLIFields(strings.SplitN(output.String(), "\n", 2)[0])
}

func remoteOfflineSignEntry(t testing.TB, f *remoteCLIFixture, args []string, actor byte) (custodyauthority.Entry, string) {
	t.Helper()
	args = append(append([]string{remoteCustodySignCommand}, remoteOfflineCommonArgs(f)...), args...)
	commandPath, entryPath := filepath.Join(t.TempDir(), "command"), filepath.Join(t.TempDir(), "entry")
	key := filepath.Join(t.TempDir(), "actor.seed")
	writePruneCLIFile(t, key, pruneCLIKey(actor).Seed())
	review := remoteOfflineRun(t, args)["review_id"]
	signing := append(append([]string{}, args...), "--mode", "sign", "--expected-review-id", review, "--actor-key", key, "--out", commandPath)
	remoteOfflineRun(t, signing)
	cosigning := append([]string{}, args...)
	cosigning[0] = remoteCustodyCosignCommand
	cosigning = append(cosigning, "--command", commandPath)
	entryReview := remoteOfflineRun(t, cosigning)["review_id"]
	cosigning = append(cosigning, "--mode", "sign", "--expected-review-id", entryReview, "--authority-key", f.keyPaths[1], "--out", entryPath)
	remoteOfflineRun(t, cosigning)
	b, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	e, err := custodyauthority.DecodeEntry(b)
	if err != nil {
		t.Fatal(err)
	}
	return e, entryPath
}

func TestRemoteCustodyOfflinePreparationAndSigning(t *testing.T) {
	f := newRemoteCLIFixture(t)
	w := f.scope.Worker
	before := remoteCLITrees(t, []string{f.authority, f.pins, f.worker, f.base.config.Audit.JournalPath, f.base.serve.config.Session.JournalPath})
	a := w.Assignment
	var auditors, consumers []string
	for _, key := range a.Auditors {
		auditors = append(auditors, fmt.Sprintf("%x", key))
	}
	for _, c := range a.Consumers {
		var purposes []string
		for _, p := range []struct {
			value custodyauthority.Purpose
			name  string
		}{{custodyauthority.Audit, "audit"}, {custodyauthority.Serve, "serve"}, {custodyauthority.Prune, "prune"}} {
			if c.Purposes&p.value != 0 {
				purposes = append(purposes, p.name)
			}
		}
		consumers = append(consumers, fmt.Sprintf("%x:%s", c.PublicKey, strings.Join(purposes, "+")))
	}
	policy := f.scope.CustodyPolicy
	assignmentArgs := []string{remoteCustodyAssignmentCommand, "--manifest", f.base.serve.manifestPath, "--receipt", f.base.serve.receiptPath,
		"--incarnation-id", a.IncarnationID.String(), "--authority-public-key", fmt.Sprintf("%x", a.AuthorityPublicKey), "--auditor-public-keys", strings.Join(auditors, ","), "--consumers", strings.Join(consumers, ","),
		"--remote-control-public-key", fmt.Sprintf("%x", a.RemoteControlPublicKey), "--remote-transport-public-key", fmt.Sprintf("%x", a.RemoteTransportPublicKey), "--max-operations", strconv.FormatUint(uint64(a.MaximumOperations), 10), "--max-pending", strconv.FormatUint(uint64(a.MaximumPending), 10),
		"--max-challenge-lifetime-seconds", strconv.FormatUint(policy.MaximumChallengeLifetime, 10), "--max-proof-age-seconds", strconv.FormatUint(policy.MaximumProofAge, 10), "--max-renewal-term-seconds", strconv.FormatUint(policy.MaximumRenewalTerm, 10)}
	fields := remoteOfflineRun(t, assignmentArgs)
	if fields["assignment_id"] != w.Plan.AssignmentID.String() {
		t.Fatal("assignment differs", fields)
	}
	newAssignment := filepath.Join(t.TempDir(), "assignment")
	remoteOfflineRun(t, append(assignmentArgs, "--mode", "publish", "--assignment-id", fields["assignment_id"], "--out", newAssignment))
	got, err := os.ReadFile(newAssignment)
	want, _ := a.CanonicalBytes()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("published assignment differs", err)
	}
	for _, entry := range []custodyauthority.Entry{f.audit, w.Plan.Admission} {
		c := entry.Command
		purpose := "audit"
		if c.Purpose == custodyauthority.Serve {
			purpose = "serve"
		}
		args := []string{"--kind", "admit", "--purpose", purpose, "--consumer-public-key", fmt.Sprintf("%x", c.ActorPublicKey), "--expected-sequence", strconv.FormatUint(c.ExpectedSequence, 10), "--expected-head", c.ExpectedHead.String()}
		if purpose == "serve" {
			args = append(args, remoteOfflineChallengeArgs(f)...)
		}
		got, _ := remoteOfflineSignEntry(t, f, args, 4)
		if got != entry {
			t.Fatal("offline admission differs from original codec", purpose)
		}
	}
	nonce := filepath.Join(t.TempDir(), "plan.nonce")
	writePruneCLIFile(t, nonce, w.Plan.Nonce[:])
	serveID, _ := w.Plan.Admission.ID()
	planArgs := append([]string{remoteCustodyPlanCommand}, remoteOfflineCommonArgs(f)...)
	planArgs = append(planArgs, remoteOfflineChallengeArgs(f)...)
	planArgs = append(planArgs, "--admission", filepath.Join(f.public, "plan-serve-admission"), "--admission-id", serveID.String(), "--authority-transport-public-key", fmt.Sprintf("%x", w.Plan.AuthorityTransportPublicKey), "--audit-transport-public-key", fmt.Sprintf("%x", w.Plan.AuditorTransportPublicKey), "--nonce-file", nonce)
	encoded, _ := w.Plan.Admission.CanonicalBytes()
	writePruneCLIFile(t, filepath.Join(f.public, "plan-serve-admission"), encoded)
	fields = remoteOfflineRun(t, planArgs)
	if fields["plan_id"] != w.PlanID.String() {
		t.Fatal("plan differs", fields)
	}
	newPlan := filepath.Join(t.TempDir(), "plan")
	remoteOfflineRun(t, append(planArgs, "--mode", "publish", "--plan-id", fields["plan_id"], "--out", newPlan))
	got, err = os.ReadFile(newPlan)
	want, _ = w.Plan.CanonicalBytes()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("published plan differs", err)
	}
	beginArgs := []string{"--kind", "begin", "--purpose", "serve", "--expected-sequence", strconv.FormatUint(w.Begin.Command.ExpectedSequence, 10), "--expected-head", w.Begin.Command.ExpectedHead.String()}
	beginArgs = append(beginArgs, remoteOfflineChallengeArgs(f)...)
	beginArgs = append(beginArgs, remoteOfflinePlanArgs(f)...)
	begin, _ := remoteOfflineSignEntry(t, f, beginArgs, 14)
	if begin != w.Begin {
		t.Fatal("Begin differs from original codec")
	}
	after := remoteCLITrees(t, []string{f.authority, f.pins, f.worker, f.base.config.Audit.JournalPath, f.base.serve.config.Session.JournalPath})
	if !reflect.DeepEqual(before, after) {
		t.Fatal("offline preparation changed live owners")
	}
}

func TestRemoteCustodyOfflineRetryPreservesArtifactWithoutSeed(t *testing.T) {
	f := newRemoteCLIFixture(t)
	args := append([]string{remoteCustodySignCommand}, remoteOfflineCommonArgs(f)...)
	args = append(args, "--kind", "admit", "--purpose", "audit", "--consumer-public-key", fmt.Sprintf("%x", f.intent.ConsumerPublicKey), "--expected-sequence", "0", "--expected-head", f.scope.Worker.Plan.AssignmentID.String())
	review := remoteOfflineRun(t, args)["review_id"]
	key, out := filepath.Join(t.TempDir(), "actor.seed"), filepath.Join(t.TempDir(), "command")
	writePruneCLIFile(t, key, pruneCLIKey(4).Seed())
	signing := append(append([]string{}, args...), "--mode", "sign", "--expected-review-id", review, "--actor-key", key, "--out", out)
	if err := runCustodyCommand(t.Context(), signing, nil, pruneShortWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("lost stdout did not report failure", err)
	}
	retained, err := os.ReadFile(out)
	if err != nil {
		t.Fatal("lost stdout lost immutable signature", err)
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if fields := remoteOfflineRun(t, signing); fields["artifact_reused"] != "true" {
		t.Fatal("retry required signing", fields)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, retained) {
		t.Fatal("retry changed signature")
	}
	cosign := append([]string{}, args...)
	cosign[0] = remoteCustodyCosignCommand
	cosign = append(cosign, "--command", out)
	cosignReview := remoteOfflineRun(t, cosign)["review_id"]
	entryOut := filepath.Join(t.TempDir(), "entry")
	cosign = append(cosign, "--mode", "sign", "--expected-review-id", cosignReview, "--authority-key", f.keyPaths[1], "--out", entryOut)
	if err := runCustodyCommand(t.Context(), cosign, nil, pruneShortWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("lost co-sign output did not report failure", err)
	}
	if err := os.Remove(f.keyPaths[1]); err != nil {
		t.Fatal(err)
	}
	if fields := remoteOfflineRun(t, cosign); fields["artifact_reused"] != "true" {
		t.Fatal("retry required authority signing", fields)
	}
	for _, extra := range [][]string{
		{"--actor-key", key}, {"--out", out}, {"--expected-review-id", review}, {"--command", out}, {"--kind", "drained"}, {"--plan", filepath.Join(f.public, "plan")},
	} {
		if err := runCustodyCommand(t.Context(), append(append([]string{}, args...), extra...), nil, io.Discard); err == nil {
			t.Fatal("accepted irrelevant or effectful review flags", extra)
		}
	}
	bad := append([]string{}, signing...)
	for i := range bad {
		if bad[i] == "--assignment-id" {
			bad[i+1] = pruneCLIHash(253).String()
		}
	}
	if err := runCustodyCommand(t.Context(), bad, nil, io.Discard); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("read missing seed before rejecting public substitution", err)
	}
	conflict := append([]string{}, signing...)
	for i := range conflict {
		if conflict[i] == "--expected-sequence" {
			conflict[i+1] = "1"
		}
		if conflict[i] == "--expected-head" {
			conflict[i+1] = pruneCLIHash(253).String()
		}
	}
	newReviewArgs := append([]string{}, args...)
	for i := range newReviewArgs {
		if newReviewArgs[i] == "--expected-sequence" {
			newReviewArgs[i+1] = "1"
		}
		if newReviewArgs[i] == "--expected-head" {
			newReviewArgs[i+1] = pruneCLIHash(253).String()
		}
	}
	newReview := remoteOfflineRun(t, newReviewArgs)["review_id"]
	for i := range conflict {
		if conflict[i] == "--expected-review-id" {
			conflict[i+1] = newReview
		}
	}
	if err := runCustodyCommand(t.Context(), conflict, nil, io.Discard); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("conflicting artifact was not rejected before key loading", err)
	}
}

func TestRemoteCustodyBootstrapCreatesOnlyReviewedFreshRoots(t *testing.T) {
	f := newRemoteCLIFixture(t)
	w := f.scope.Worker
	authority, pins := filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "pins")
	args := []string{remoteCustodyAuthorityBootstrapCommand, "--assignment", filepath.Join(f.public, "assignment"), "--assignment-id", w.Plan.AssignmentID.String(), "--authority", authority, "--authority-pins", pins}
	review := remoteOfflineRun(t, args)["review_id"]
	for _, path := range []string{authority, pins} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("review initialized root", err)
		}
	}
	if err := runCustodyCommand(t.Context(), append(append([]string{}, args...), "--mode", "create", "--expected-review-id", pruneCLIHash(253).String()), nil, io.Discard); err == nil {
		t.Fatal("created unreviewed roots")
	}
	create := append(append([]string{}, args...), "--mode", "create", "--expected-review-id", review)
	remoteOfflineRun(t, create)
	if err := runCustodyCommand(t.Context(), create, nil, io.Discard); err == nil {
		t.Fatal("reinitialized existing authority")
	}
	if fields := remoteOfflineRun(t, append(args, "--mode", "verify")); fields["confirmed_sequence"] != "0" || fields["confirmed_head"] != w.Plan.AssignmentID.String() {
		t.Fatal(fields)
	}
	worker := filepath.Join(t.TempDir(), "worker")
	args = append([]string{remoteCustodyWorkerPrepareCommand}, remoteOfflineCommonArgs(f)...)
	args = append(args, remoteOfflineChallengeArgs(f)...)
	args = append(args, remoteOfflinePlanArgs(f)...)
	args = append(args, "--begin", filepath.Join(f.public, "begin"), "--begin-id", w.BeginID.String(), "--worker", worker)
	review = remoteOfflineRun(t, args)["review_id"]
	if _, err := os.Lstat(worker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("worker review initialized a root", err)
	}
	create = append(append([]string{}, args...), "--mode", "create", "--expected-review-id", review)
	remoteOfflineRun(t, create)
	if err := runCustodyCommand(t.Context(), create, nil, io.Discard); err == nil {
		t.Fatal("reinitialized existing worker")
	}
	owner, err := remoteworker.Open(t.Context(), worker, w)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Start(t.Context(), w.BeginID); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	before := remoteCLITrees(t, []string{worker})
	fields := remoteOfflineRun(t, append(args, "--mode", "verify"))
	if fields["stage"] != strconv.Itoa(int(remoteworker.Started)) {
		t.Fatal("verify changed the worker branch", fields)
	}
	if !reflect.DeepEqual(before, remoteCLITrees(t, []string{worker})) {
		t.Fatal("verify sealed or changed the worker")
	}
}

func remoteOfflineCompleteEntry(t testing.TB, f *remoteCLIFixture, ticket custodyauthority.Entry, terminalID types.Hash, position custodyauthority.Position) (custodyauthority.Entry, string) {
	t.Helper()
	tid, _ := ticket.ID()
	path := filepath.Join(t.TempDir(), "admission")
	b, _ := ticket.CanonicalBytes()
	writePruneCLIFile(t, path, b)
	purpose := "audit"
	if ticket.Command.Purpose == custodyauthority.Serve {
		purpose = "serve"
	}
	args := []string{"--kind", "complete", "--purpose", purpose, "--expected-sequence", strconv.FormatUint(position.Sequence, 10), "--expected-head", position.HeadID.String(), "--begin", filepath.Join(f.public, "begin"), "--begin-id", f.scope.Worker.BeginID.String(), "--admission", path, "--admission-id", tid.String(), "--terminal", f.terminal, "--terminal-id", terminalID.String()}
	args = append(args, remoteOfflineChallengeArgs(f)...)
	args = append(args, remoteOfflinePlanArgs(f)...)
	return remoteOfflineSignEntry(t, f, args, 4)
}
