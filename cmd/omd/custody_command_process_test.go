//go:build integration

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// Start a distinct incarnation at position zero. Existing fixture owners are
// never copied or replayed into it; only immutable archive data and empty source
// journals are reused. Every admission and completion below crosses the actual
// process dispatcher, canonical files and reviewed control pipes.
func newCustodyCommandProcessFixture(t testing.TB) *managedCustodyAuditCLIFixture {
	t.Helper()
	f := newManagedCustodyAuditCLIFixture(t)
	assignment := f.config.Assignment
	assignment.IncarnationID = pruneCLIHash(177)
	id, err := assignment.ID()
	if err != nil {
		t.Fatal(err)
	}
	metadata := t.TempDir()
	f.serve.assignmentPath = filepath.Join(metadata, "assignment.omcaa")
	b, err := assignment.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	writePruneCLIFile(t, f.serve.assignmentPath, b)
	f.config.Assignment, f.serve.config.Assignment = assignment, assignment
	f.config.AuthorityPath = filepath.Join(t.TempDir(), "authority")
	f.config.AuthorityPinsPath = filepath.Join(t.TempDir(), "authority-pins")
	f.serve.config.AuthorityPath, f.serve.config.AuthorityPinsPath = f.config.AuthorityPath, f.config.AuthorityPinsPath
	f.config.Audit.AssignmentID, f.serve.config.Session.AssignmentID = id, id
	owner, err := authoritystore.CreateCoordinatedAuthority(f.config.AuthorityPath, f.config.AuthorityPinsPath, assignment, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	f.intent.AssignmentID = id
	f.intentPath = filepath.Join(t.TempDir(), "intent.omcai")
	if err := workarchive.PublishCustodyAuditIntent(t.Context(), f.intentPath, f.intent); err != nil {
		t.Fatal(err)
	}
	f.config.Audit.IntentPath = f.intentPath
	f.config.Audit.IntentID, err = f.intent.ID()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func signCustodyCommandProcess(t testing.TB, f *managedCustodyAuditCLIFixture, kind, purpose string, position custodyauthority.Position, extra ...string) (custodyauthority.Entry, string) {
	t.Helper()
	args := append([]string{custodyCommandSignCommand}, custodyCommandCLICommonArgs(f)...)
	args = append(args, "--kind", kind, "--purpose", purpose, "--expected-sequence", strconv.FormatUint(position.Sequence, 10), "--expected-head", position.HeadID.String())
	args = append(args, extra...)
	review := outputFields(runProcessCommand(t, 15*time.Second, args...), "work_archive_custody_signing")["review_id"]
	if review == "" {
		t.Fatal("missing consumer review")
	}
	metadata := t.TempDir()
	consumerKey, authorityKey := filepath.Join(metadata, "consumer.seed"), filepath.Join(metadata, "authority.seed")
	writePruneCLIFile(t, consumerKey, pruneCLIKey(4).Seed())
	writePruneCLIFile(t, authorityKey, pruneCLIKey(1).Seed())
	commandPath := filepath.Join(metadata, "command.omcac")
	sign := append(append([]string{}, args...), "--mode", "sign", "--consumer-key", consumerKey, "--expected-review-id", review, "--out", commandPath)
	runProcessCommand(t, 15*time.Second, sign...)
	cosign := append([]string{}, args...)
	cosign[0] = custodyCommandCosignCommand
	cosign = append(cosign, "--command", commandPath)
	review = outputFields(runProcessCommand(t, 15*time.Second, cosign...), "work_archive_custody_signing")["review_id"]
	if review == "" {
		t.Fatal("missing authority review")
	}
	entryPath := filepath.Join(metadata, "entry.omcae")
	cosign = append(cosign, "--mode", "sign", "--authority-key", authorityKey, "--expected-review-id", review, "--out", entryPath)
	runProcessCommand(t, 15*time.Second, cosign...)
	b, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.DecodeEntry(b)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Command.ExpectedSequence != position.Sequence || entry.Command.ExpectedHead != position.HeadID {
		t.Fatal("signing refreshed selected position")
	}
	return entry, entryPath
}

func custodyCommandProcessOwnedArgs(f *managedCustodyAuditCLIFixture, command, purpose, journal string) []string {
	a := append([]string{command}, custodyCommandCLICommonArgs(f)...)
	return append(a, "--purpose", purpose, "--authority", f.config.AuthorityPath, "--authority-pins", f.config.AuthorityPinsPath, "--journal", journal, "--mode", "control")
}

func applyCustodyCommandProcess(t testing.TB, f *managedCustodyAuditCLIFixture, entry custodyauthority.Entry, purpose, path, journal string, extra ...string) authoritystore.Commit {
	t.Helper()
	id, err := entry.ID()
	if err != nil {
		t.Fatal(err)
	}
	args := custodyCommandProcessOwnedArgs(f, custodyCommandApplyCommand, purpose, journal)
	args = append(args, "--entry", path, "--entry-id", id.String())
	args = append(args, extra...)
	const prefix = "work_archive_custody_command"
	p := startManagedCustodyOperatorProcess(t, args, prefix)
	f.assertBusy(t)
	review := reviewManagedCustodyOperatorProcess(t, p, prefix)
	p.send(t, "apply "+review)
	result := outputFields(p.line(t), prefix+"_result")
	if result["entry_id"] != id.String() || result["expected_review_id"] != review || result["execution_started"] != "false" {
		t.Fatal("invalid reviewed apply", result)
	}
	var commit authoritystore.Commit
	if err := json.Unmarshal([]byte(result["commit"]), &commit); err != nil {
		t.Fatal(err, result)
	}
	p.send(t, "close")
	if err := p.wait(t); err != nil {
		t.Fatal(err, p.stderr.String())
	}
	return commit
}

func captureCustodyCommandProcess(t testing.TB, f *managedCustodyAuditCLIFixture, purpose, admissionPath, journal string, admission custodyauthority.Entry) (types.Hash, string) {
	t.Helper()
	id, _ := admission.ID()
	path := filepath.Join(t.TempDir(), "terminal.omct")
	args := custodyCommandProcessOwnedArgs(f, custodyTerminalCommand, purpose, journal)
	args = append(args, "--admission", admissionPath, "--admission-id", id.String(), "--out", path)
	const prefix = "work_archive_custody_command"
	p := startManagedCustodyOperatorProcess(t, args, prefix)
	review := reviewManagedCustodyOperatorProcess(t, p, prefix)
	p.send(t, "capture "+review)
	result := outputFields(p.line(t), prefix+"_result")
	terminalID, err := managedCustodyExternalID("terminal-id", result["terminal_id"])
	if err != nil || result["artifact_published"] != "true" || result["completion_submitted"] != "false" {
		t.Fatal("invalid reviewed capture", result, err)
	}
	p.send(t, "close")
	if err := p.wait(t); err != nil {
		t.Fatal(err, p.stderr.String())
	}
	if _, err := authoritystore.LoadCustodyTerminalFile(path, terminalID); err != nil {
		t.Fatal(err)
	}
	return terminalID, path
}

func TestProcessCustodyCommandWholeTicketLifecycle(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	f := newCustodyCommandProcessFixture(t)
	assignmentID := f.config.Audit.AssignmentID
	initial := f.snapshot(t)
	if initial.Confirmed.Sequence != 0 || initial.Confirmed.HeadID != assignmentID || len(initial.Authority.Operations) != 0 {
		t.Fatal("fixture did not start at zero")
	}
	consumer := "--consumer-public-key"
	public := fmt.Sprintf("%x", pruneCLIPublic(4))
	audit, auditPath := signCustodyCommandProcess(t, f, "admit", "audit", initial.Confirmed, consumer, public)
	auditID, _ := audit.ID()
	if commit := applyCustodyCommandProcess(t, f, audit, "audit", auditPath, f.config.Audit.JournalPath); !commit.Appended || commit.EntryID != auditID {
		t.Fatal("audit admission not appended", commit)
	}
	f.config.Audit.Admission, f.admissionPath = audit, auditPath
	const auditPrefix = "work_archive_custody_managed_audit"
	p := startManagedCustodyOperatorProcess(t, f.args("control"), auditPrefix)
	review := reviewManagedCustodyOperatorProcess(t, p, auditPrefix)
	p.send(t, "prepare "+review)
	prepared := outputFields(p.line(t), auditPrefix+"_prepared")
	if prepared["challenge_id"] != f.serve.config.Session.ChallengeID.String() || prepared["completion_submitted"] != "false" {
		t.Fatal("invalid prepared challenge", prepared)
	}
	p.send(t, "close")
	if err := p.wait(t); err != nil {
		t.Fatal(err, p.stderr.String())
	}
	challengePath := filepath.Join(f.config.Audit.ArtifactsPath, "cycle-00000000000000000001", "challenge.omcc")
	challengeArgs := []string{"--challenge", challengePath, "--challenge-id", f.serve.config.Session.ChallengeID.String()}
	serve, servePath := signCustodyCommandProcess(t, f, "admit", "serve", custodyauthority.Position{Sequence: 1, HeadID: auditID}, append([]string{consumer, public}, challengeArgs...)...)
	serveID, _ := serve.ID()
	if commit := applyCustodyCommandProcess(t, f, serve, "serve", servePath, f.serve.config.Session.JournalPath, challengeArgs...); !commit.Appended || commit.EntryID != serveID {
		t.Fatal("serve admission not appended", commit)
	}
	f.serve.config.Session.Admission, f.serve.admissionPath = serve, servePath
	pair := &managedCustodyPairCLIFixture{audit: f, config: authoritystore.ManagedCustodyPairRuntimeConfig{
		AuthorityPath: f.config.AuthorityPath, AuthorityPinsPath: f.config.AuthorityPinsPath, Assignment: f.config.Assignment, Audit: f.config.Audit,
		Serve: f.serve.config.Session, ObjectPath: f.serve.config.ObjectPath, ObjectPolicy: f.serve.config.ObjectPolicy,
		AuditorPeerID: f.config.AuditorPeerID, ReplicaPeerID: f.serve.config.ServerPeerID}}
	p = startManagedCustodyOperatorProcess(t, pair.args("control"), "work_archive_custody_managed_pair")
	exchangeManagedCustodyPairProcess(t, p)
	p.send(t, "close")
	if err := p.wait(t); err != nil {
		t.Fatal(err, p.stderr.String())
	}
	if heads := pair.heads(t); heads.Audit.Sequence != 1 || heads.Replica.Sequence != 1 {
		t.Fatal("exchange did not commit both journals", heads)
	}
	if after := f.snapshot(t); after.Confirmed.Sequence != 2 || len(after.Authority.Operations) != 2 {
		t.Fatal("exchange implicitly changed authority", after)
	}
	auditTerminal, auditTerminalPath := captureCustodyCommandProcess(t, f, "audit", auditPath, f.config.Audit.JournalPath, audit)
	serveTerminal, serveTerminalPath := captureCustodyCommandProcess(t, f, "serve", servePath, f.serve.config.Session.JournalPath, serve)
	auditExtra := []string{"--admission", auditPath, "--admission-id", auditID.String(), "--terminal", auditTerminalPath, "--terminal-id", auditTerminal.String()}
	auditComplete, auditCompletePath := signCustodyCommandProcess(t, f, "complete", "audit", custodyauthority.Position{Sequence: 2, HeadID: serveID}, auditExtra...)
	auditCompleteID, _ := auditComplete.ID()
	if commit := applyCustodyCommandProcess(t, f, auditComplete, "audit", auditCompletePath, f.config.Audit.JournalPath, auditExtra...); !commit.Appended {
		t.Fatal("audit completion not appended", commit)
	}
	serveExtra := []string{"--admission", servePath, "--admission-id", serveID.String(), "--terminal", serveTerminalPath, "--terminal-id", serveTerminal.String()}
	serveComplete, serveCompletePath := signCustodyCommandProcess(t, f, "complete", "serve", custodyauthority.Position{Sequence: 3, HeadID: auditCompleteID}, serveExtra...)
	serveCompleteID, _ := serveComplete.ID()
	if commit := applyCustodyCommandProcess(t, f, serveComplete, "serve", serveCompletePath, f.serve.config.Session.JournalPath, serveExtra...); !commit.Appended {
		t.Fatal("serve completion not appended", commit)
	}
	final := f.snapshot(t)
	if final.Pending != nil || final.Confirmed.Sequence != 4 || final.Confirmed.HeadID != serveCompleteID || final.Authority.Phase != custodyauthority.Accepting {
		t.Fatal("unexpected final authority", final)
	}
	for _, operation := range final.Authority.Operations {
		if operation.CompletionID.IsZero() || operation.EvidenceID.IsZero() {
			t.Fatal("ticket left open", operation)
		}
	}
	// Exact earlier Complete returns its retained ID while Snapshot describes the
	// current authority (including the later independent Serve completion).
	retry := applyCustodyCommandProcess(t, f, auditComplete, "audit", auditCompletePath, f.config.Audit.JournalPath, auditExtra...)
	if retry.Appended || retry.EntryID != auditCompleteID || retry.Snapshot.Sequence != 4 || retry.Snapshot.HeadID != serveCompleteID {
		t.Fatal("historical retry changed the authority or acknowledgement contract", retry)
	}
}

func TestProcessCustodyCommandLostResult(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	f := newCustodyCommandProcessFixture(t)
	entry, path := signCustodyCommandProcess(t, f, "admit", "audit", f.snapshot(t).Confirmed, "--consumer-public-key", fmt.Sprintf("%x", pruneCLIPublic(4)))
	id, _ := entry.ID()
	args := custodyCommandProcessOwnedArgs(f, custodyCommandApplyCommand, "audit", f.config.Audit.JournalPath)
	args = append(args, "--entry", path, "--entry-id", id.String())
	const prefix = "work_archive_custody_command"
	p := startManagedCustodyOperatorProcess(t, args, prefix)
	review := reviewManagedCustodyOperatorProcess(t, p, prefix)
	// The action is fully reviewed, then its result pipe disappears. This is a
	// real closed native descriptor, after commitment and before observation.
	p.stopOnce.Do(func() { close(p.stopReader); _ = p.output.Close() })
	p.send(t, "apply "+review)
	if err := p.wait(t); err == nil {
		t.Fatal("lost result reported success")
	}
	current := f.snapshot(t)
	if current.Pending != nil || current.Confirmed.Sequence != 1 || current.Confirmed.HeadID != id || len(current.Authority.Operations) != 1 || !current.Authority.Operations[0].CompletionID.IsZero() {
		t.Fatal("lost stdout erased or implicitly completed admission", current)
	}
	retry := applyCustodyCommandProcess(t, f, entry, "audit", path, f.config.Audit.JournalPath)
	if retry.Appended || retry.EntryID != id || retry.Snapshot.Sequence != 1 {
		t.Fatal("explicit retry duplicated admission", retry)
	}
}
