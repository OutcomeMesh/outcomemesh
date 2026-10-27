package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type remoteZeroDriver struct {
	run   func([]string) string
	owned func([]string, string) map[string]string
}

func (d remoteZeroDriver) fields(args []string) map[string]string {
	return pruneCLIFields(strings.SplitN(d.run(args), "\n", 2)[0])
}

func remoteZeroLocalDriver(t testing.TB) remoteZeroDriver {
	t.Helper()
	return remoteZeroDriver{
		run: func(args []string) string {
			t.Helper()
			var b bytes.Buffer
			var err error
			if args[0] == managedCustodyIntentCommand {
				err = runManagedCustodyIntent(t.Context(), args, &b)
			} else {
				err = runCustodyCommand(t.Context(), args, nil, &b)
			}
			if err != nil {
				t.Fatal(args[0], err)
			}
			return b.String()
		},
		owned: func(args []string, action string) map[string]string {
			t.Helper()
			s := startCustodyCommandControl(t, args, nil)
			custodyCommandControlLine(t, s, "work_archive_custody_command_ready")
			id := custodyCommandControlReview(t, s)
			if _, err := io.WriteString(s.input, action+" "+id+"\n"); err != nil {
				t.Fatal(err)
			}
			result := custodyCommandControlLine(t, s, "work_archive_custody_command_result")
			if _, err := io.WriteString(s.input, "close\n"); err != nil {
				t.Fatal(err)
			}
			if err := s.wait(t); err != nil {
				t.Fatal(err)
			}
			return result
		},
	}
}

func remoteZeroSign(t testing.TB, d remoteZeroDriver, f *remoteCLIFixture, name string, actor byte, extra []string) custodyauthority.Entry {
	t.Helper()
	a := append([]string{remoteCustodySignCommand}, remoteOfflineCommonArgs(f)...)
	a = append(a, extra...)
	review := d.fields(a)["review_id"]
	command := filepath.Join(f.public, name+".command")
	d.run(append(append([]string{}, a...), "--mode", "sign", "--expected-review-id", review, "--actor-key", f.keyPaths[actor], "--out", command))
	a[0] = remoteCustodyCosignCommand
	a = append(a, "--command", command)
	review = d.fields(a)["review_id"]
	entryPath := filepath.Join(f.public, name)
	d.run(append(a, "--mode", "sign", "--expected-review-id", review, "--authority-key", f.keyPaths[1], "--out", entryPath))
	b, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	e, err := custodyauthority.DecodeEntry(b)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func remoteZeroAdmissionArgs(f *remoteCLIFixture, name, purpose string, entry custodyauthority.Entry) []string {
	a := append([]string{remoteCustodyAdmissionApplyCommand}, remoteOfflineCommonArgs(f)...)
	id, _ := entry.ID()
	a = append(a, "--purpose", purpose, "--authority", f.authority, "--authority-pins", f.pins, "--journal", f.base.config.Audit.JournalPath, "--entry", filepath.Join(f.public, name), "--entry-id", id.String())
	if purpose == "serve" {
		a = append(a, remoteOfflineChallengeArgs(f)...)
	}
	return a
}

// Only immutable archive/receipt/object data and pre-existing seed/nonce inputs
// come from fixture helpers. Every V1 artifact, owner, source and admission below
// is produced through CLI, with fresh roots and no copied live journals.
func bootstrapRemoteZero(t testing.TB, d remoteZeroDriver) *remoteCLIFixture {
	t.Helper()
	base := newManagedCustodyAuditCLIFixture(t)
	f := &remoteCLIFixture{base: base, public: t.TempDir(), authority: filepath.Join(t.TempDir(), "authority"), pins: filepath.Join(t.TempDir(), "pins"), worker: filepath.Join(t.TempDir(), "worker"), intentPath: filepath.Join(t.TempDir(), "intent"), keyPaths: make(map[byte]string)}
	for _, key := range []byte{1, 3, 4, 14, 15, 16, 46} {
		f.keyPaths[key] = filepath.Join(t.TempDir(), fmt.Sprintf("key-%d.seed", key))
		writePruneCLIFile(t, f.keyPaths[key], pruneCLIKey(key).Seed())
	}
	p := base.config.Audit.CustodyPolicy
	policyArgs := []string{"--max-challenge-lifetime-seconds", strconv.FormatUint(p.MaximumChallengeLifetime, 10), "--max-proof-age-seconds", strconv.FormatUint(p.MaximumProofAge, 10), "--max-renewal-term-seconds", strconv.FormatUint(p.MaximumRenewalTerm, 10)}
	archiveArgs := []string{"--manifest", base.serve.manifestPath, "--receipt", base.serve.receiptPath}
	args := append([]string{remoteCustodyAssignmentCommand}, archiveArgs...)
	args = append(args, policyArgs...)
	args = append(args, "--incarnation-id", pruneCLIHash(240).String(), "--authority-public-key", fmt.Sprintf("%x", pruneCLIPublic(1)), "--auditor-public-keys", fmt.Sprintf("%x", pruneCLIPublic(3)), "--consumers", fmt.Sprintf("%x:audit+serve+prune", pruneCLIPublic(4)), "--remote-control-public-key", fmt.Sprintf("%x", pruneCLIPublic(14)), "--remote-transport-public-key", fmt.Sprintf("%x", pruneCLIPublic(15)), "--max-operations", "4", "--max-pending", "2")
	aid := d.fields(args)["assignment_id"]
	d.run(append(args, "--mode", "publish", "--assignment-id", aid, "--out", filepath.Join(f.public, "assignment")))
	id, err := managedCustodyExternalID("assignment", aid)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := loadPruneOfflineAssignment(filepath.Join(f.public, "assignment"), id)
	if err != nil {
		t.Fatal(err)
	}
	f.scope.Worker.Assignment = assignment
	f.scope.Worker.Plan.AssignmentID = id
	metadata := []string{"--assignment", filepath.Join(f.public, "assignment"), "--assignment-id", aid}
	base.config.Audit.JournalPath = filepath.Join(t.TempDir(), "a-source")
	base.config.Audit.ArtifactsPath = filepath.Join(t.TempDir(), "a-artifacts")
	base.serve.config.Session.JournalPath = filepath.Join(t.TempDir(), "b-source")
	for _, role := range []string{"audit", "serve"} {
		args = append([]string{remoteCustodySourceCommand}, metadata...)
		args = append(args, archiveArgs...)
		args = append(args, policyArgs...)
		journal := base.config.Audit.JournalPath
		if role == "serve" {
			journal = base.serve.config.Session.JournalPath
		}
		args = append(args, "--role", role, "--journal", journal)
		if role == "audit" {
			args = append(args, "--artifacts", base.config.Audit.ArtifactsPath)
		}
		review := d.fields(args)["review_id"]
		d.run(append(append([]string{}, args...), "--mode", "create", "--expected-review-id", review))
		if fields := d.fields(append(args, "--mode", "verify")); fields["sequence"] != "0" {
			t.Fatal("source did not start at zero", fields)
		}
	}
	args = append([]string{remoteCustodyAuthorityBootstrapCommand}, metadata...)
	args = append(args, "--authority", f.authority, "--authority-pins", f.pins)
	review := d.fields(args)["review_id"]
	d.run(append(append([]string{}, args...), "--mode", "create", "--expected-review-id", review))
	if fields := d.fields(append(args, "--mode", "verify")); fields["confirmed_sequence"] != "0" || fields["confirmed_head"] != aid {
		t.Fatal("owner did not start at zero", fields)
	}
	nonce := filepath.Join(t.TempDir(), "intent.nonce")
	writePruneCLIFile(t, nonce, base.intent.Nonce[:])
	peer, _ := transportPeer(pruneCLIPublic(15))
	initialID, _ := base.config.Audit.InitialReceipt.ID()
	i := base.intent
	args = append([]string{managedCustodyIntentCommand}, metadata...)
	args = append(args, "--intent", f.intentPath, "--consumer-public-key", fmt.Sprintf("%x", pruneCLIPublic(4)), "--auditor-public-key", fmt.Sprintf("%x", pruneCLIPublic(3)), "--replica-peer-id", peer.String(), "--prior-sequence", "0", "--prior-head-id", (types.Hash{}).String(), "--prior-receipt-id", initialID.String(), "--issued-at", strconv.FormatUint(i.IssuedAt, 10), "--expires-at", strconv.FormatUint(i.ExpiresAt, 10), "--renew-until", strconv.FormatUint(i.RenewUntil, 10), "--samples", strconv.Itoa(int(i.RequestedSamples)), "--nonce-file", nonce)
	iid := d.fields(args)["intent_id"]
	d.run(append(args, "--mode", "publish", "--intent-id", iid))
	intentID, _ := managedCustodyExternalID("intent", iid)
	f.intent, err = workarchive.LoadCustodyAuditIntent(f.intentPath, intentID)
	if err != nil {
		t.Fatal(err)
	}
	f.audit = remoteZeroSign(t, d, f, "audit", 4, []string{"--kind", "admit", "--purpose", "audit", "--consumer-public-key", fmt.Sprintf("%x", pruneCLIPublic(4)), "--expected-sequence", "0", "--expected-head", aid})
	d.owned(remoteZeroAdmissionArgs(f, "audit", "audit", f.audit), "apply")
	args = remoteZeroAdmissionArgs(f, "audit", "audit", f.audit)
	args[0] = remoteCustodyChallengeCommand
	args = append(args, "--artifacts", base.config.Audit.ArtifactsPath, "--auditor-key", f.keyPaths[3])
	prepared := d.owned(args, "prepare")
	// Transfer only the immutable public challenge, never either live source.
	challengeBytes, err := os.ReadFile(filepath.Join(base.config.Audit.ArtifactsPath, "cycle-00000000000000000001", "challenge.omcc"))
	if err != nil {
		t.Fatal(err)
	}
	writePruneCLIFile(t, filepath.Join(f.public, "challenge"), challengeBytes)
	f.scope.Challenge, err = workarchive.DecodeCustodyChallenge(challengeBytes)
	if err != nil {
		t.Fatal(err)
	}
	challengeID, _ := f.scope.Challenge.ID()
	if prepared["challenge_id"] != challengeID.String() {
		t.Fatal("challenge output pin differs", prepared)
	}
	auditID, _ := f.audit.ID()
	args = []string{"--kind", "admit", "--purpose", "serve", "--consumer-public-key", fmt.Sprintf("%x", pruneCLIPublic(4)), "--expected-sequence", "1", "--expected-head", auditID.String()}
	args = append(args, remoteOfflineChallengeArgs(f)...)
	serve := remoteZeroSign(t, d, f, "serve", 4, args)
	d.owned(remoteZeroAdmissionArgs(f, "serve", "serve", serve), "apply")
	nonce = filepath.Join(t.TempDir(), "plan.nonce")
	planNonce := pruneCLIHash(241)
	writePruneCLIFile(t, nonce, planNonce[:])
	serveID, _ := serve.ID()
	args = append([]string{remoteCustodyPlanCommand}, remoteOfflineCommonArgs(f)...)
	args = append(args, remoteOfflineChallengeArgs(f)...)
	args = append(args, "--admission", filepath.Join(f.public, "serve"), "--admission-id", serveID.String(), "--authority-transport-public-key", fmt.Sprintf("%x", pruneCLIPublic(16)), "--audit-transport-public-key", fmt.Sprintf("%x", pruneCLIPublic(46)), "--nonce-file", nonce)
	pid := d.fields(args)["plan_id"]
	d.run(append(args, "--mode", "publish", "--plan-id", pid, "--out", filepath.Join(f.public, "plan")))
	f.scope.Worker.Plan, _, err = remoteOfflinePlan(filepath.Join(f.public, "plan"), pid)
	if err != nil {
		t.Fatal(err)
	}
	f.scope.Worker.PlanID, _ = f.scope.Worker.Plan.ID()
	args = []string{"--kind", "begin", "--purpose", "serve", "--expected-sequence", "2", "--expected-head", serveID.String()}
	args = append(args, remoteOfflineChallengeArgs(f)...)
	args = append(args, remoteOfflinePlanArgs(f)...)
	f.scope.Worker.Begin = remoteZeroSign(t, d, f, "begin", 14, args)
	f.scope.Worker.BeginID, _ = f.scope.Worker.Begin.ID()
	f.scope.Manifest, f.scope.InitialReceipt, f.scope.PreviousReceipt, f.scope.CustodyPolicy = base.config.Audit.Manifest, base.config.Audit.InitialReceipt, base.config.Audit.InitialReceipt, p
	args = append([]string{remoteCustodyWorkerPrepareCommand}, remoteOfflineCommonArgs(f)...)
	args = append(args, remoteOfflineChallengeArgs(f)...)
	args = append(args, remoteOfflinePlanArgs(f)...)
	args = append(args, "--begin", filepath.Join(f.public, "begin"), "--begin-id", f.scope.Worker.BeginID.String(), "--worker", f.worker)
	review = d.fields(args)["review_id"]
	d.run(append(args, "--mode", "create", "--expected-review-id", review))
	output := t.TempDir()
	f.drain, f.terminal = filepath.Join(output, "drain"), filepath.Join(output, "terminal")
	return f
}

func TestRemoteCustodyCLIFromZeroBootstrapAndLifecycle(t *testing.T) {
	f := bootstrapRemoteZero(t, remoteZeroLocalDriver(t))
	b := startRemoteCLIControl(t, f.args("serve", "control"))
	b.send(t, "serve "+b.review(t))
	ready := b.next(t, "remote_custody_serving")
	a := startRemoteCLIControl(t, append(f.args("audit", "control"), "--peer", ready["listen"]))
	for _, action := range []struct{ command, prefix string }{{"prepare", "remote_custody_prepared"}, {"begin", "remote_custody_begun"}, {"execute", "remote_custody_executed"}, {"seal", "remote_custody_metadata"}, {"capture", "remote_custody_captured"}} {
		a.send(t, action.command+" "+a.review(t))
		a.next(t, action.prefix)
	}
	a.close(t)
	terminalBytes, err := os.ReadFile(f.terminal)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := store.DecodeRemoteCustodyTerminal(terminalBytes)
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := terminal.ID()
	// Drain is the exact expected head. Each resulting Complete supplies the
	// next explicit position; no SDK owner read or mutation fills this workflow.
	head, _ := terminal.Drained.ID()
	sequence := terminal.Drained.Command.ExpectedSequence + 1
	for _, ticket := range []custodyauthority.Entry{f.audit, f.scope.Worker.Plan.Admission} {
		entry, path := remoteOfflineCompleteEntry(t, f, ticket, tid, custodyauthority.Position{Sequence: sequence, HeadID: head})
		eid, _ := entry.ID()
		args := append(f.args("audit", "control"), "--terminal-id", tid.String(), "--complete-entry", path, "--complete-entry-id", eid.String())
		// A's retained drain file must carry its independent pin on reopen.
		args = pruneCLISet(args, "drain", "")
		a = startRemoteCLIControl(t, args)
		a.send(t, "apply-complete "+a.review(t))
		a.next(t, "remote_custody_completed")
		a.close(t)
		head, sequence = eid, sequence+1
	}
	b.close(t)
	fields := remoteZeroLocalDriver(t).fields([]string{remoteCustodyAuthorityBootstrapCommand, "--mode", "verify", "--assignment", filepath.Join(f.public, "assignment"), "--assignment-id", f.scope.Worker.Plan.AssignmentID.String(), "--authority", f.authority, "--authority-pins", f.pins})
	if fields["confirmed_sequence"] != "6" || fields["confirmed_head"] != head.String() || fields["pending_operations"] != "0" || fields["active_remote"] != "false" || fields["retained_attempt"] != "false" {
		t.Fatal("incomplete CLI lifecycle", fields)
	}
}
