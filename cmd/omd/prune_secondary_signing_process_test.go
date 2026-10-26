//go:build integration

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

func secondaryProcessSigningReview(t testing.TB, args []string) map[string]string {
	t.Helper()
	fields := preparationProcessFields(t, args)
	for name, want := range map[string]string{"secondary": "true", "historical_only": "true",
		"terminal_durability_proven": "false", "execution_authorized": "false"} {
		if fields[name] != want {
			t.Fatal("secondary signing report changed its scope", name, fields)
		}
	}
	return fields
}

func signSecondaryProcessEntry(t testing.TB, f *pruneSecondarySigningFixture, args []string, broken bool) (string, custodyauthority.Entry) {
	t.Helper()
	before := readPruneSigningDirectory(t, f.root)
	review := secondaryProcessSigningReview(t, args)
	assertPruneSigningDirectory(t, f.root, before)
	primaryID, _ := f.assignment.ID()
	targetID, _ := f.secondary.ID()
	requestID, _ := f.request.ID()
	if review["assignment_id"] != targetID.String() || review["primary_assignment_id"] != primaryID.String() ||
		review["request_id"] != requestID.String() || review["artifact_published"] != "false" {
		t.Fatal("review lost the original request or target assignment", review)
	}
	commandPath, entryPath := filepath.Join(f.root, "secondary.command"), filepath.Join(f.root, "secondary.entry")
	sign := append(pruneCLISet(args, "mode", "sign"), "--consumer-key", f.consumerKey,
		"--expected-review-id", review["review_id"], "--out", commandPath)
	if broken {
		runPruneBrokenOutput(t, sign, nil)
	}
	signed := secondaryProcessSigningReview(t, sign)
	commandBytes, err := os.ReadFile(commandPath)
	if err != nil {
		t.Fatal(err)
	}
	command, err := custodyauthority.DecodeCommand(commandBytes)
	if err != nil || command.AssignmentID != targetID || command.ActorPublicKey != f.request.ConsumerPublicKey ||
		signed["review_id"] != review["review_id"] || signed["artifact_published"] != "true" {
		t.Fatal("consumer signature disagrees with the reviewed target", err, signed)
	}
	secondaryProcessSigningReview(t, sign)
	again, err := os.ReadFile(commandPath)
	if err != nil || !bytes.Equal(commandBytes, again) {
		t.Fatal("exact consumer retry changed bytes", err)
	}
	cosign := append([]string{pruneSecondaryCosigningCommand}, args[1:]...)
	cosign = append(cosign, "--command", commandPath)
	coReview := secondaryProcessSigningReview(t, cosign)
	if coReview["review_id"] == review["review_id"] || coReview["artifact_published"] != "false" {
		t.Fatal("co-signing did not retain its separate reviewed message", coReview)
	}
	cosign = append(pruneCLISet(cosign, "mode", "sign"), "--authority-key", f.authorityKey,
		"--expected-review-id", coReview["review_id"], "--out", entryPath)
	if broken {
		runPruneBrokenOutput(t, cosign, nil)
	}
	coSigned := secondaryProcessSigningReview(t, cosign)
	entryBytes, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.DecodeEntry(entryBytes)
	if err != nil || entry.Command != command || entry.AuthorityPublicKey != f.secondary.AuthorityPublicKey {
		t.Fatal("co-signature changed the consumer command", err)
	}
	id, _ := entry.ID()
	if coSigned["entry_id"] != id.String() || coSigned["review_id"] != coReview["review_id"] {
		t.Fatal("co-signature did not retain the reviewed entry", coSigned)
	}
	secondaryProcessSigningReview(t, cosign)
	again, err = os.ReadFile(entryPath)
	if err != nil || !bytes.Equal(entryBytes, again) {
		t.Fatal("exact authority retry changed bytes", err)
	}
	for name, original := range before {
		after, err := os.ReadFile(filepath.Join(f.root, name))
		if err != nil || !bytes.Equal(original, after) {
			t.Fatal("signing changed an input artifact", name, err)
		}
	}
	for _, file := range mustPruneSigningReadDir(t, f.root) {
		if file.IsDir() {
			t.Fatal("signing initialized an owner or transport directory", file.Name())
		}
	}
	if command.Kind == custodyauthority.Admit {
		if entry != f.secondaryAdmission || command.OperationID != requestID {
			t.Fatal("secondary admission changed the original primary operation ID")
		}
	} else {
		targetTicket, _ := f.secondaryAdmission.ID()
		primaryTicket, _ := f.admission.ID()
		if command.TicketID != targetTicket || review["primary_admission_id"] != primaryTicket.String() ||
			command.TicketID == primaryTicket {
			t.Fatal("secondary completion used the primary ticket as its target", review)
		}
	}
	return entryPath, entry
}

// A typed outbox can retain this signed secondary entry. No delivery is made:
// the existing primary-only command server is not a secondary acceptance path.
func prepareSecondaryProcessOutbox(t testing.TB, f *pruneSecondarySigningFixture, entryPath string,
	entry custodyauthority.Entry, broken bool,
) {
	t.Helper()
	name := pruneAdmissionPrepareCommand
	if entry.Command.Kind == custodyauthority.Complete {
		name = pruneCompletionPrepareCommand
	}
	aid, _ := f.secondary.ID()
	id, _ := entry.ID()
	args := []string{name, "--assignment", f.secondaryAssignmentPath, "--assignment-id", aid.String(),
		"--entry", entryPath, "--entry-id", id.String(), "--client-peer-id", pruneCLIPeer(46).String(),
		"--server-peer-id", pruneCLIPeer(45).String()}
	review := preparationProcessFields(t, args)
	intentID, err := pruneExternalID("intent-id", review["intent_id"])
	if err != nil || review["sent"] != "false" || review["outbox_created"] != "false" ||
		review["terminal_state_verified"] != "false" || review["current_head_verified"] != "false" {
		t.Fatal("outbox review claimed live secondary authority", err, review)
	}
	outbox := filepath.Join(f.root, "secondary-outbox")
	if _, err := os.Lstat(outbox); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("outbox review wrote a destination", err)
	}
	create := append(pruneCLISet(args, "mode", "create"), "--outbox", outbox, "--intent-id", intentID.String())
	if broken {
		runPruneBrokenOutput(t, create, nil)
	} else {
		preparationProcessFields(t, create)
	}
	if _, err := runProcessCommandError(15*time.Second, create...); err == nil {
		t.Fatal("secondary outbox create replaced a retained destination")
	}
	verified := preparationProcessFields(t, pruneCLISet(create, "mode", "verify"))
	if verified["receipt_present"] != "false" || verified["sent"] != "false" || verified["outbox_verified"] != "true" ||
		verified["assignment_id"] != aid.String() || verified["intent_id"] != intentID.String() {
		t.Fatal("outbox did not retain the exact undelivered secondary intent", verified)
	}
	if entry.Command.Kind == custodyauthority.Admit {
		owner, err := authoritystore.OpenAdmissionOutbox(outbox, f.secondary, intentID)
		if err != nil {
			t.Fatal(err)
		}
		state, snapshotErr := owner.Snapshot()
		closeErr := owner.Close()
		if snapshotErr != nil || closeErr != nil || state.Intent.Entry != entry || state.Acknowledgement != nil {
			t.Fatal("retained secondary admission outbox changed intent", snapshotErr, closeErr)
		}
	} else {
		owner, err := authoritystore.OpenCompletionOutbox(outbox, f.secondary, intentID)
		if err != nil {
			t.Fatal(err)
		}
		state, snapshotErr := owner.Snapshot()
		closeErr := owner.Close()
		if snapshotErr != nil || closeErr != nil || state.Intent.Entry != entry || state.Acknowledgement != nil {
			t.Fatal("retained secondary completion outbox changed intent", snapshotErr, closeErr)
		}
	}
	for _, file := range mustPruneSigningReadDir(t, f.root) {
		if file.IsDir() && file.Name() != filepath.Base(outbox) {
			t.Fatal("preparation initialized an unrequested owner or transport", file.Name())
		}
	}
}

func TestProcessPruneSecondarySigningRoundTrip(t *testing.T) {
	help := runProcessCommand(t, 15*time.Second, "help")
	for _, name := range []string{pruneSecondarySigningCommand, pruneSecondaryCosigningCommand} {
		if !strings.Contains(help, name) {
			t.Fatal("main help did not expose explicit secondary signing command", name)
		}
	}
	for _, phase := range []string{"admit", "succeeded", "cancelled"} {
		t.Run(phase, func(t *testing.T) {
			f := newPruneSecondarySigningFixture(t)
			args := f.args
			if phase != "admit" {
				args = f.completion(t, phase == "cancelled")
			}
			// Reject a wrong independent primary pin before any new artifact or
			// role key can be used; the actual process dispatch must preserve it.
			before := readPruneSigningDirectory(t, f.root)
			if output, err := runProcessCommandError(15*time.Second, pruneCLISet(args, "primary-assignment-id", pruneCLIHash(99).String())...); err == nil || strings.Contains(output, "artifact_published=true") {
				t.Fatal("process accepted a substituted primary pin", err, output)
			}
			assertPruneSigningDirectory(t, f.root, before)
			path, entry := signSecondaryProcessEntry(t, f, args, false)
			prepareSecondaryProcessOutbox(t, f, path, entry, false)
		})
	}
}

func TestProcessPruneSecondarySigningBrokenPipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix SIGPIPE regression")
	}
	for _, phase := range []string{"admit", "succeeded", "cancelled"} {
		t.Run(phase, func(t *testing.T) {
			f := newPruneSecondarySigningFixture(t)
			args := f.args
			if phase != "admit" {
				args = f.completion(t, phase == "cancelled")
			}
			path, entry := signSecondaryProcessEntry(t, f, args, true)
			prepareSecondaryProcessOutbox(t, f, path, entry, true)
		})
	}
}
