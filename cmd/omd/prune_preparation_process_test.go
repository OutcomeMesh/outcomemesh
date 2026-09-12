//go:build integration

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

type prunePreparationFixture struct {
	*pruneCLIFixture
	requestPath, consumerKey, authorityKey string
}

func newPrunePreparationFixture(t testing.TB) *prunePreparationFixture {
	t.Helper()
	f := newPruneCLIFixture(t)
	old, _ := f.snapshot(t)
	p := &prunePreparationFixture{pruneCLIFixture: f,
		requestPath: filepath.Join(f.root, "request.omcpr"), consumerKey: filepath.Join(f.root, "consumer.key"), authorityKey: filepath.Join(f.root, "authority.key")}
	encoded, err := old.Request.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	writePruneCLIFile(t, p.requestPath, encoded)
	writePruneCLIFile(t, p.consumerKey, pruneCLIKey(4).Seed())
	writePruneCLIFile(t, p.authorityKey, pruneCLIKey(1).Seed())
	// Keep the original fixture intact. Every root used below is new and must
	// be created by the public preparation CLI, not the fixture constructors.
	f.config.AuthorityPath = filepath.Join(f.root, "prepared-authority")
	f.config.AuthorityPinsPath = filepath.Join(f.root, "prepared-authority-pins")
	f.config.ExecutorPath = filepath.Join(f.root, "prepared-executor")
	f.config.ExecutorPinsPath = filepath.Join(f.root, "prepared-executor-pins")
	f.admissionPath = filepath.Join(f.root, "prepared-admission-outbox")
	return p
}

func (p *prunePreparationFixture) bootstrapArgs(name string) []string {
	args := []string{name, "--assignment", p.assignmentPath, "--assignment-id", p.config.AssignmentID.String()}
	if name == pruneAuthorityBootstrapCommand {
		return append(args, "--authority", p.config.AuthorityPath, "--authority-pins", p.config.AuthorityPinsPath)
	}
	return append(args, "--request", p.requestPath, "--request-id", p.config.RequestID.String(), "--executor", p.config.ExecutorPath, "--executor-pins", p.config.ExecutorPinsPath)
}

func (p *prunePreparationFixture) signingArgs() []string {
	return []string{pruneSigningCommand, "--assignment", p.assignmentPath, "--assignment-id", p.config.AssignmentID.String(),
		"--request", p.requestPath, "--request-id", p.config.RequestID.String(), "--kind", "admit", "--expected-sequence", "0", "--expected-head", p.config.AssignmentID.String()}
}

func preparationProcessFields(t testing.TB, args []string) map[string]string {
	t.Helper()
	return pruneCLIFields(runProcessCommand(t, 15*time.Second, args...))
}

func (p *prunePreparationFixture) signEntry(t testing.TB, args []string, stem string, broken bool) (string, custodyauthority.Entry) {
	t.Helper()
	commandPath, entryPath := filepath.Join(p.root, stem+".command"), filepath.Join(p.root, stem+".entry")
	for _, path := range []string{commandPath, entryPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("signing target already exists", path, err)
		}
	}
	review := preparationProcessFields(t, args)
	if review["artifact_published"] != "false" || review["execution_authorized"] != "false" || review["review_id"] == "" {
		t.Fatal("invalid signing review", review)
	}
	sign := append(pruneCLISet(args, "mode", "sign"), "--consumer-key", p.consumerKey, "--expected-review-id", review["review_id"], "--out", commandPath)
	if broken {
		runPruneBrokenOutput(t, sign, nil)
	}
	result := preparationProcessFields(t, sign)
	if result["artifact_published"] != "true" || result["review_id"] != review["review_id"] {
		t.Fatal("consumer signature changed review", result)
	}
	// Publication retries must be byte-identical, never regenerate a command
	// against a new head or replace an existing output artifact.
	before, err := os.ReadFile(commandPath)
	if err != nil {
		t.Fatal(err)
	}
	preparationProcessFields(t, sign)
	after, err := os.ReadFile(commandPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("consumer publication retry replaced bytes", err)
	}
	cosign := append(append([]string{pruneCosigningCommand}, args[1:]...), "--command", commandPath)
	review = preparationProcessFields(t, cosign)
	if review["artifact_published"] != "false" || review["review_id"] == result["review_id"] {
		t.Fatal("co-signing did not use its own signature domain", review)
	}
	cosign = append(pruneCLISet(cosign, "mode", "sign"), "--authority-key", p.authorityKey, "--expected-review-id", review["review_id"], "--out", entryPath)
	if broken {
		runPruneBrokenOutput(t, cosign, nil)
	}
	result = preparationProcessFields(t, cosign)
	encoded, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.DecodeEntry(encoded)
	if err != nil {
		t.Fatal(err)
	}
	id, err := entry.ID()
	if err != nil || result["entry_id"] != id.String() || result["historical_only"] != "true" {
		t.Fatal("published entry disagrees with reviewed output", err, result)
	}
	return entryPath, entry
}

func (p *prunePreparationFixture) prepareOutbox(t testing.TB, name, entryPath, outbox string, entry custodyauthority.Entry, broken bool) (types.Hash, []string) {
	t.Helper()
	entryID, err := entry.ID()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{name, "--assignment", p.assignmentPath, "--assignment-id", p.config.AssignmentID.String(),
		"--entry", entryPath, "--entry-id", entryID.String(), "--client-peer-id", p.config.ClientPeerID.String(), "--server-peer-id", p.config.ServerPeerID.String()}
	review := preparationProcessFields(t, args)
	id, err := pruneExternalID("intent-id", review["intent_id"])
	if err != nil || review["outbox_created"] != "false" || review["receipt_present"] != "false" || review["sent"] != "false" {
		t.Fatal("invalid outbox review", err, review)
	}
	if _, err := os.Lstat(outbox); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("review created outbox", err)
	}
	create := append(pruneCLISet(args, "mode", "create"), "--outbox", outbox, "--intent-id", id.String())
	if broken {
		runPruneBrokenOutput(t, create, nil)
	} else {
		preparationProcessFields(t, create)
	}
	if _, err := runProcessCommandError(15*time.Second, create...); err == nil {
		t.Fatal("create reused an existing outbox")
	}
	verify := pruneCLISet(create, "mode", "verify")
	result := preparationProcessFields(t, verify)
	if result["outbox_verified"] != "true" || result["receipt_present"] != "false" || result["intent_id"] != id.String() {
		t.Fatal("new outbox was not retained exactly", result)
	}
	return id, verify
}

func TestProcessPrunePreparationRoundTrip(t *testing.T) {
	p := newPrunePreparationFixture(t)
	for _, name := range []string{pruneAuthorityBootstrapCommand, pruneExecutorPrepareCommand} {
		args := p.bootstrapArgs(name)
		review := preparationProcessFields(t, args)
		if review["roots_created"] != "false" || review["roots_inspected"] != "false" || review["execution_authorized"] != "false" {
			t.Fatal("bootstrap review overclaimed", review)
		}
	}
	for _, path := range []string{p.config.AuthorityPath, p.config.AuthorityPinsPath, p.config.ExecutorPath, p.config.ExecutorPinsPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("placement review initialized root", path, err)
		}
	}
	for _, name := range []string{pruneAuthorityBootstrapCommand, pruneExecutorPrepareCommand} {
		create := pruneCLISet(p.bootstrapArgs(name), "mode", "create")
		result := preparationProcessFields(t, create)
		if result["owners_closed"] != "true" || result["execution_authorized"] != "false" {
			t.Fatal("bootstrap success before closure", result)
		}
		if _, err := runProcessCommandError(15*time.Second, create...); err == nil {
			t.Fatal("bootstrap create replaced existing roots")
		}
		preparationProcessFields(t, pruneCLISet(create, "mode", "verify"))
	}
	admissionPath, admission := p.signEntry(t, p.signingArgs(), "admit", false)
	if admission != p.admission {
		t.Fatal("reviewed signing changed the existing wire signature domains")
	}
	p.admissionID, _ = p.prepareOutbox(t, pruneAdmissionPrepareCommand, admissionPath, p.admissionPath, admission, false)
	before, authority := p.snapshot(t)
	if before.Stage != authoritystore.PrunePrepared || authority.Authority.Sequence != 0 {
		t.Fatal("offline preparation admitted or executed work")
	}
	address, stop := startPruneCLIProcess(t, p.pruneCLIFixture)
	runPruneProcessDelivery(t, p.deliveryArgs(pruneAdmissionCommand, p.admissionPath, p.admissionID, address))
	stop(runtime.GOOS == "windows")
	if state, authority := p.snapshot(t); state.Stage != authoritystore.PruneAdmitted || authority.Authority.Sequence != 1 || authority.Authority.Pending != 1 {
		t.Fatal("prepared admission did not retain exactly one ticket")
	}
	// The only transition outside the public CLI is a guarded, explicitly
	// offline cancellation through existing owners. This test never opens a
	// WorkChain, authorizes a live prune, or introduces an Execute command.
	executor, coordinator := p.owners(t)
	terminal, err := executor.CancelBeforeStart(t.Context(), coordinator)
	if closeErr := errors.Join(executor.Close(), coordinator.Close()); err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	terminalID, err := terminal.ID()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := terminal.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	terminalPath := filepath.Join(p.root, "cancelled.terminal")
	writePruneCLIFile(t, terminalPath, encoded)
	ticketID, _ := admission.ID()
	completeArgs := pruneCLISet(pruneCLISet(pruneCLISet(p.signingArgs(), "kind", "complete"), "expected-sequence", "1"), "expected-head", ticketID.String())
	completeArgs = append(completeArgs, "--admission", admissionPath, "--admission-id", ticketID.String(), "--terminal", terminalPath, "--terminal-id", terminalID.String())
	entryPath, complete := p.signEntry(t, completeArgs, "complete", false)
	outbox := filepath.Join(p.root, "prepared-completion-outbox")
	intentID, verify := p.prepareOutbox(t, pruneCompletionPrepareCommand, entryPath, outbox, complete, false)
	address, stop = startPruneCLIProcess(t, p.pruneCLIFixture)
	delivered := runPruneProcessDelivery(t, p.deliveryArgs(pruneCompletionCommand, outbox, intentID, address))
	stop(runtime.GOOS == "windows")
	finished, authority := p.snapshot(t)
	if finished.Stage != authoritystore.PruneCancelled || authority.Authority.Sequence != 2 || authority.Authority.Pending != 0 {
		t.Fatal("prepared completion did not drain exactly once")
	}
	// Verification reads the local historical receipt with the server down.
	result := preparationProcessFields(t, verify)
	if result["receipt_present"] != "true" || result["receipt_nonce"] != delivered["nonce"] || result["sent"] != "false" {
		t.Fatal("verify lost the historical receipt or sent work", result)
	}
	for _, name := range []string{pruneAuthorityBootstrapCommand, pruneExecutorPrepareCommand} {
		preparationProcessFields(t, pruneCLISet(p.bootstrapArgs(name), "mode", "verify"))
	}
	if got, coord := p.snapshot(t); !reflect.DeepEqual(got, finished) || !reflect.DeepEqual(coord, authority) {
		t.Fatal("offline verification changed completed state")
	}
}

func TestProcessPrunePreparationBrokenPipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix SIGPIPE regression")
	}
	p := newPrunePreparationFixture(t)
	for _, name := range []string{pruneAuthorityBootstrapCommand, pruneExecutorPrepareCommand} {
		args := pruneCLISet(p.bootstrapArgs(name), "mode", "create")
		runPruneBrokenOutput(t, args, nil)
		preparationProcessFields(t, pruneCLISet(args, "mode", "verify"))
	}
	entryPath, entry := p.signEntry(t, p.signingArgs(), "broken-admit", true)
	p.prepareOutbox(t, pruneAdmissionPrepareCommand, entryPath, p.admissionPath, entry, true)
	// Outbox preparation intentionally requires only an already co-signed
	// typed entry, not live terminal state. This synthetic historical entry
	// is never delivered; test the second publisher's real closed stdout too.
	ticket, _ := entry.ID()
	complete := signPruneCLIEntry(t, custodyauthority.Command{AssignmentID: p.config.AssignmentID,
		ExpectedSequence: 1, ExpectedHead: ticket, Kind: custodyauthority.Complete, TicketID: ticket, EvidenceID: pruneCLIHash(98)})
	encoded, err := complete.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	completePath := filepath.Join(p.root, "broken-complete.entry")
	writePruneCLIFile(t, completePath, encoded)
	p.prepareOutbox(t, pruneCompletionPrepareCommand, completePath, filepath.Join(p.root, "prepared-completion-outbox"), complete, true)
	if state, authority := p.snapshot(t); state.Stage != authoritystore.PrunePrepared || authority.Authority.Sequence != 0 {
		t.Fatal("failed stdout authorized execution")
	}
}
