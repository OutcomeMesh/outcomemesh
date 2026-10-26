package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type pruneSecondarySigningFixture struct {
	*pruneSigningFixture
	secondary                                      custodyauthority.Assignment
	secondaryAdmission                             custodyauthority.Entry
	primaryAssignmentPath, secondaryAssignmentPath string
	args                                           []string
}

func newPruneSecondarySigningFixture(t testing.TB) *pruneSecondarySigningFixture {
	t.Helper()
	f := &pruneSecondarySigningFixture{pruneSigningFixture: newPruneSigningFixture(t)}
	f.secondary = f.assignment
	f.secondary.ReplicaPublicKey = pruneCLIPublic(8)
	f.secondary.InitialReceiptID, f.secondary.CustodyPolicyID, f.secondary.IncarnationID = pruneCLIHash(81), pruneCLIHash(82), pruneCLIHash(83)
	f.secondary.Auditors = append([][32]byte(nil), f.assignment.Auditors...)
	f.secondary.Consumers = append([]custodyauthority.Consumer(nil), f.assignment.Consumers...)
	f.primaryAssignmentPath = filepath.Join(f.root, "assignment.omcaa")
	f.secondaryAssignmentPath = filepath.Join(f.root, "secondary.omcaa")
	encoded, err := f.secondary.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	writePruneCLIFile(t, f.secondaryAssignmentPath, encoded)
	primaryID, _ := f.assignment.ID()
	secondaryID, _ := f.secondary.ID()
	rid, _ := f.request.ID()
	f.args = append([]string(nil), f.pruneSigningFixture.args...)
	f.args[0] = pruneSecondarySigningCommand
	f.args = pruneCLISet(pruneCLISet(pruneCLISet(f.args, "assignment", f.secondaryAssignmentPath), "assignment-id", secondaryID.String()), "expected-head", secondaryID.String())
	f.args = append(f.args, "--primary-assignment", f.primaryAssignmentPath, "--primary-assignment-id", primaryID.String())
	f.secondaryAdmission = signPruneCLIEntry(t, custodyauthority.Command{AssignmentID: secondaryID, ExpectedHead: secondaryID,
		Kind: custodyauthority.Admit, Purpose: custodyauthority.Prune, OperationID: rid})
	return f
}

func (f *pruneSecondarySigningFixture) completion(t testing.TB, cancelled bool) []string {
	t.Helper()
	f.pruneSigningFixture.completion(t, cancelled) // retains the original primary admission and terminal
	ticket, _ := f.secondaryAdmission.ID()
	primaryTicket, _ := f.admission.ID()
	path := filepath.Join(f.root, "secondary-admission.omcae")
	encoded, _ := f.secondaryAdmission.CanonicalBytes()
	writePruneCLIFile(t, path, encoded)
	terminalPath := filepath.Join(f.root, "terminal.omcpt")
	terminal, err := os.ReadFile(terminalPath)
	if err != nil {
		t.Fatal(err)
	}
	var terminalID types.Hash
	if cancelled {
		value, err := authoritystore.DecodePruneCancellation(terminal)
		if err != nil {
			t.Fatal(err)
		}
		terminalID, _ = value.ID()
	} else {
		value, err := workchain.DecodeCanonicalPruneEffect(terminal)
		if err != nil {
			t.Fatal(err)
		}
		terminalID, _ = value.ID()
	}
	args := pruneCLISet(pruneCLISet(pruneCLISet(f.args, "kind", "complete"), "expected-sequence", "1"), "expected-head", ticket.String())
	return append(args, "--admission", path, "--admission-id", ticket.String(), "--primary-admission", filepath.Join(f.root, "admission.omcae"),
		"--primary-admission-id", primaryTicket.String(), "--terminal", terminalPath, "--terminal-id", terminalID.String())
}

func TestPruneSecondarySigningReviewSignCosignAndOutbox(t *testing.T) {
	for _, phase := range []string{"admit", "cancelled", "succeeded"} {
		t.Run(phase, func(t *testing.T) {
			f := newPruneSecondarySigningFixture(t)
			args := f.args
			if phase != "admit" {
				args = f.completion(t, phase == "cancelled")
			}
			before := readPruneSigningDirectory(t, f.root)
			review := pruneSigningReview(t, args)
			assertPruneSigningDirectory(t, f.root, before)
			primaryID, _ := f.assignment.ID()
			secondaryID, _ := f.secondary.ID()
			rid, _ := f.request.ID()
			if review["secondary"] != "true" || review["primary_assignment_id"] != primaryID.String() ||
				review["assignment_id"] != secondaryID.String() || review["request_id"] != rid.String() || review["artifact_published"] != "false" {
				t.Fatal("secondary review lost original primary scope", review)
			}
			commandPath, entryPath := filepath.Join(f.root, "secondary.command"), filepath.Join(f.root, "secondary.entry")
			sign := append(append([]string(nil), args...), "--mode", "sign", "--consumer-key", f.consumerKey, "--expected-review-id", review["review_id"], "--out", commandPath)
			pruneSigningReview(t, sign)
			commandBytes, err := os.ReadFile(commandPath)
			if err != nil {
				t.Fatal(err)
			}
			command, err := custodyauthority.DecodeCommand(commandBytes)
			if err != nil || command.AssignmentID != secondaryID || command.ActorPublicKey != f.request.ConsumerPublicKey {
				t.Fatal("secondary command scope", err)
			}
			if phase == "admit" {
				if command.OperationID != rid || command.Purpose != custodyauthority.Prune || command.Kind != custodyauthority.Admit {
					t.Fatal("secondary admission rewrote primary request")
				}
			} else {
				ticket, _ := f.secondaryAdmission.ID()
				primaryTicket, _ := f.admission.ID()
				if command.TicketID != ticket || command.TicketID == primaryTicket || review["primary_admission_id"] != primaryTicket.String() || command.Kind != custodyauthority.Complete {
					t.Fatal("completion confused primary evidence with secondary ticket")
				}
			}
			pruneSigningReview(t, sign)
			again, _ := os.ReadFile(commandPath)
			if !bytes.Equal(commandBytes, again) {
				t.Fatal("signature retry changed command")
			}
			cosign := append([]string(nil), args...)
			cosign[0] = pruneSecondaryCosigningCommand
			cosign = append(cosign, "--command", commandPath)
			coReview := pruneSigningReview(t, cosign)
			if coReview["review_id"] == review["review_id"] {
				t.Fatal("consumer and authority review domains collapsed")
			}
			cosign = append(cosign, "--mode", "sign", "--authority-key", f.authorityKey, "--expected-review-id", coReview["review_id"], "--out", entryPath)
			pruneSigningReview(t, cosign)
			entryBytes, err := os.ReadFile(entryPath)
			if err != nil {
				t.Fatal(err)
			}
			entry, err := custodyauthority.DecodeEntry(entryBytes)
			if err != nil || entry.Command != command || entry.AuthorityPublicKey != f.secondary.AuthorityPublicKey {
				t.Fatal("secondary co-signature", err)
			}
			pruneSigningReview(t, cosign)
			again, _ = os.ReadFile(entryPath)
			if !bytes.Equal(entryBytes, again) {
				t.Fatal("authority retry changed entry")
			}
			if phase == "admit" && entry != f.secondaryAdmission {
				t.Fatal("same reviewed admission did not reproduce exact canonical entry")
			}
			// Existing typed preparation accepts the secondary entry without
			// claiming its primary-only command server can execute this workflow.
			name := pruneAdmissionPrepareCommand
			if phase != "admit" {
				name = pruneCompletionPrepareCommand
			}
			entryID, _ := entry.ID()
			outboxArgs := []string{name, "--assignment", f.secondaryAssignmentPath, "--assignment-id", secondaryID.String(), "--entry", entryPath,
				"--entry-id", entryID.String(), "--client-peer-id", pruneCLIPeer(46).String(), "--server-peer-id", pruneCLIPeer(45).String()}
			outboxReview := pruneCLIFields(runPrunePrepare(t, outboxArgs))
			outboxArgs = append(outboxArgs, "--outbox", filepath.Join(f.root, "outbox"), "--intent-id", outboxReview["intent_id"], "--mode", "create")
			runPrunePrepare(t, outboxArgs)
			runPrunePrepare(t, pruneCLISet(outboxArgs, "mode", "verify"))
		})
	}
}

func TestPruneSecondarySigningRejectsRepinnedScopeChanges(t *testing.T) {
	for _, field := range []string{"network", "genesis", "activation", "base", "manifest", "statement", "same-assignment", "same-replica", "consumer-missing", "consumer-prune", "request-rewritten", "primary-pin", "secondary-pin", "request-pin", "missing-primary"} {
		t.Run(field, func(t *testing.T) {
			f := newPruneSecondarySigningFixture(t)
			args := append([]string(nil), f.args...)
			changed := f.secondary
			switch field {
			case "network":
				changed.NetworkID++
			case "genesis":
				changed.GenesisID = pruneCLIHash(99)
			case "activation":
				changed.ActivationHeight++
			case "base":
				changed.BaseID = pruneCLIHash(99)
			case "manifest":
				changed.ManifestID = pruneCLIHash(99)
			case "statement":
				changed.StatementID = pruneCLIHash(99)
			case "same-assignment":
				changed = f.assignment
			case "same-replica":
				changed.ReplicaPublicKey = f.assignment.ReplicaPublicKey
			case "consumer-missing":
				changed.Consumers = []custodyauthority.Consumer{{PublicKey: pruneCLIPublic(5), Purposes: custodyauthority.AllPurposes}}
			case "consumer-prune":
				changed.Consumers = []custodyauthority.Consumer{{PublicKey: pruneCLIPublic(4), Purposes: custodyauthority.Audit | custodyauthority.Serve}, {PublicKey: pruneCLIPublic(5), Purposes: custodyauthority.Prune}}
				sort.Slice(changed.Consumers, func(i, j int) bool {
					return bytes.Compare(changed.Consumers[i].PublicKey[:], changed.Consumers[j].PublicKey[:]) < 0
				})
			case "request-rewritten":
				request := f.request
				request.AssignmentID, _ = f.secondary.ID()
				encoded, _ := request.CanonicalBytes()
				path := filepath.Join(f.root, "rewritten-request")
				writePruneCLIFile(t, path, encoded)
				id, _ := request.ID()
				args = pruneCLISet(pruneCLISet(args, "request", path), "request-id", id.String())
			case "primary-pin":
				args = pruneCLISet(args, "primary-assignment-id", pruneCLIHash(99).String())
			case "secondary-pin":
				args = pruneCLISet(args, "assignment-id", pruneCLIHash(99).String())
			case "request-pin":
				args = pruneCLISet(args, "request-id", pruneCLIHash(99).String())
			case "missing-primary":
				args = pruneCLISet(args, "primary-assignment", "")
			}
			encoded, err := changed.CanonicalBytes()
			if err != nil {
				t.Fatal("invalid mutation fixture", err)
			}
			writePruneCLIFile(t, f.secondaryAssignmentPath, encoded)
			if field != "secondary-pin" {
				id, _ := changed.ID()
				args = pruneCLISet(pruneCLISet(args, "assignment-id", id.String()), "expected-head", id.String())
			}
			before := readPruneSigningDirectory(t, f.root)
			var output bytes.Buffer
			if err := runPruneSigning(t.Context(), args, &output); err == nil || output.Len() != 0 {
				t.Fatal("repinned scope substitution accepted", field, err)
			}
			assertPruneSigningDirectory(t, f.root, before)
		})
	}
}

func TestPruneSecondarySigningCompletionRequiresBothAdmissionScopes(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		for _, field := range []string{"primary-pin", "missing-primary", "target-as-primary", "primary-as-target", "primary-head", "target-old-head", "primary-request", "target-request", "target-ticket-terminal", "missing-terminal"} {
			t.Run(map[bool]string{false: "success/", true: "cancelled/"}[cancelled]+field, func(t *testing.T) {
				f := newPruneSecondarySigningFixture(t)
				args := f.completion(t, cancelled)
				primaryID, _ := f.admission.ID()
				targetID, _ := f.secondaryAdmission.ID()
				switch field {
				case "primary-pin":
					args = pruneCLISet(args, "primary-admission-id", pruneCLIHash(99).String())
				case "missing-primary":
					args = pruneCLISet(args, "primary-admission", "")
				case "target-as-primary":
					args = pruneCLISet(pruneCLISet(args, "primary-admission", filepath.Join(f.root, "secondary-admission.omcae")), "primary-admission-id", targetID.String())
				case "primary-as-target":
					args = pruneCLISet(pruneCLISet(args, "admission", filepath.Join(f.root, "admission.omcae")), "admission-id", primaryID.String())
				case "primary-head":
					args = pruneCLISet(args, "expected-head", primaryID.String())
				case "target-old-head":
					args = pruneCLISet(args, "expected-sequence", "2")
				case "primary-request", "target-request":
					entry, path, pin := f.admission, filepath.Join(f.root, "admission.omcae"), "primary-admission-id"
					if field == "target-request" {
						entry, path, pin = f.secondaryAdmission, filepath.Join(f.root, "secondary-admission.omcae"), "admission-id"
					}
					command := entry.Command
					command.OperationID = pruneCLIHash(99)
					entry = signPruneCLIEntry(t, command)
					encoded, _ := entry.CanonicalBytes()
					writePruneCLIFile(t, path, encoded)
					id, _ := entry.ID()
					args = pruneCLISet(args, pin, id.String())
				case "target-ticket-terminal":
					path := filepath.Join(f.root, "terminal.omcpt")
					encoded, _ := os.ReadFile(path)
					var id types.Hash
					if cancelled {
						terminal, _ := authoritystore.DecodePruneCancellation(encoded)
						terminal.TicketID = targetID
						encoded, _ = terminal.CanonicalBytes()
						id, _ = terminal.ID()
					} else {
						terminal, _ := workchain.DecodeCanonicalPruneEffect(encoded)
						terminal.Operation.TicketID = targetID
						encoded, _ = terminal.CanonicalBytes()
						id, _ = terminal.ID()
					}
					writePruneCLIFile(t, path, encoded)
					args = pruneCLISet(args, "terminal-id", id.String())
				case "missing-terminal":
					args = pruneCLISet(args, "terminal", "")
				}
				var out bytes.Buffer
				before := readPruneSigningDirectory(t, f.root)
				if err := runPruneSigning(t.Context(), args, &out); err == nil || out.Len() != 0 {
					t.Fatal("completion scope substitution accepted", err)
				}
				assertPruneSigningDirectory(t, f.root, before)
			})
		}
	}
}

func TestPruneSecondarySigningRejectsFlagsKeysAndPublicationConflicts(t *testing.T) {
	f := newPruneSecondarySigningFixture(t)
	review := pruneSigningReview(t, f.args)
	path := filepath.Join(f.root, "new-command")
	sign := append(append([]string(nil), f.args...), "--mode", "sign", "--consumer-key", f.consumerKey, "--expected-review-id", review["review_id"], "--out", path)
	for name, args := range map[string][]string{
		"review key":                     append(append([]string(nil), f.args...), "--consumer-key", ""),
		"review output":                  append(append([]string(nil), f.args...), "--out", ""),
		"review expected":                append(append([]string(nil), f.args...), "--expected-review-id", ""),
		"primary admission on admit":     append(append([]string(nil), f.args...), "--primary-admission", ""),
		"primary admission pin on admit": append(append([]string(nil), f.args...), "--primary-admission-id", ""),
		"unknown":                        append(append([]string(nil), f.args...), "--execute", "true"),
		"duplicate":                      append(append([]string(nil), f.args...), "--primary-assignment-id", pruneCLIHash(99).String()),
		"wrong role":                     pruneCLISet(sign, "consumer-key", f.authorityKey),
		"wrong review before key":        pruneCLISet(pruneCLISet(sign, "expected-review-id", pruneCLIHash(99).String()), "consumer-key", filepath.Join(f.root, "missing-seed")),
	} {
		t.Run(name, func(t *testing.T) {
			before := readPruneSigningDirectory(t, f.root)
			if err := runPruneSigning(t.Context(), args, io.Discard); err == nil {
				t.Fatal("invalid signing accepted")
			}
			assertPruneSigningDirectory(t, f.root, before)
		})
	}
	bad := pruneCLISet(pruneCLISet(sign, "primary-assignment-id", pruneCLIHash(99).String()), "consumer-key", filepath.Join(f.root, "missing-seed"))
	if err := runPruneSigning(t.Context(), bad, io.Discard); !errors.Is(err, custodyauthority.ErrAssignment) {
		t.Fatal("key read preceded scope validation", err)
	}
	bad = pruneCLISet(pruneCLISet(sign, "expected-review-id", pruneCLIHash(99).String()), "consumer-key", filepath.Join(f.root, "missing-seed"))
	if err := runPruneSigning(t.Context(), bad, io.Discard); !errors.Is(err, custodyauthority.ErrPruneReview) {
		t.Fatal("key read preceded review validation", err)
	}
	writePruneCLIFile(t, path, []byte("existing artifact"))
	if err := runPruneSigning(t.Context(), sign, io.Discard); err == nil {
		t.Fatal("conflicting output overwritten")
	}
	before, _ := os.ReadFile(path)
	if string(before) != "existing artifact" {
		t.Fatal("conflict mutated output")
	}
	path = filepath.Join(f.root, "published-command")
	sign = pruneCLISet(sign, "out", path)
	failure := errors.New("disconnected output")
	if err := runPruneSigning(t.Context(), sign, pruneSigningFailWriter{failure}); !errors.Is(err, failure) {
		t.Fatal("stdout error lost", err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("stdout failure removed published signature", err)
	}
	if _, err := custodyauthority.DecodeCommand(encoded); err != nil {
		t.Fatal(err)
	}
	pruneSigningReview(t, sign)
	for _, name := range []string{pruneSigningCommand, pruneCosigningCommand} {
		args := append([]string(nil), f.pruneSigningFixture.args...)
		args[0] = name
		args = append(args, "--primary-assignment", f.primaryAssignmentPath)
		if err := runPruneSigning(t.Context(), args, io.Discard); err == nil {
			t.Fatal("primary command silently accepted secondary flags")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runPruneSigning(ctx, f.args, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestPruneSecondaryCosigningChecksExactConsumerCommand(t *testing.T) {
	f := newPruneSecondarySigningFixture(t)
	path := filepath.Join(f.root, "consumer-command")
	encoded, _ := f.secondaryAdmission.Command.CanonicalBytes()
	writePruneCLIFile(t, path, encoded)
	args := append([]string(nil), f.args...)
	args[0] = pruneSecondaryCosigningCommand
	args = append(args, "--command", path)
	review := pruneSigningReview(t, args)
	sign := append(append([]string(nil), args...), "--mode", "sign", "--authority-key", f.authorityKey,
		"--expected-review-id", review["review_id"], "--out", filepath.Join(f.root, "entry"))
	for _, bad := range [][]string{pruneCLISet(sign, "authority-key", f.consumerKey), pruneCLISet(sign, "expected-review-id", review["command_review_id"]),
		append(append([]string(nil), args...), "--authority-key", "")} {
		if err := runPruneSigning(t.Context(), bad, io.Discard); err == nil {
			t.Fatal("wrong authority or review accepted")
		}
	}
	command := f.secondaryAdmission.Command
	command.OperationID = pruneCLIHash(99)
	command, err := command.Sign(pruneCLIKey(4))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = command.CanonicalBytes()
	writePruneCLIFile(t, path, encoded)
	if err := runPruneSigning(t.Context(), args, io.Discard); !errors.Is(err, custodyauthority.ErrPruneReview) {
		t.Fatal("valid signature for changed operation accepted", err)
	}
}
