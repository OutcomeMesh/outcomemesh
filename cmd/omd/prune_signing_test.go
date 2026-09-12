package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

type pruneSigningFixture struct {
	root                      string
	assignment                custodyauthority.Assignment
	request                   authoritystore.PruneRequest
	admission                 custodyauthority.Entry
	args                      []string
	consumerKey, authorityKey string
}

func newPruneSigningFixture(t testing.TB) *pruneSigningFixture {
	t.Helper()
	f := &pruneSigningFixture{root: t.TempDir()}
	a := custodyauthority.Assignment{NetworkID: 77, GenesisID: pruneCLIHash(1), ActivationHeight: 10,
		BaseID: pruneCLIHash(2), ManifestID: pruneCLIHash(3), StatementID: pruneCLIHash(4), InitialReceiptID: pruneCLIHash(5),
		CustodyPolicyID: pruneCLIHash(6), IncarnationID: pruneCLIHash(7), AuthorityPublicKey: pruneCLIPublic(1), ReplicaPublicKey: pruneCLIPublic(2),
		Auditors: [][32]byte{pruneCLIPublic(3)}, Consumers: []custodyauthority.Consumer{{PublicKey: pruneCLIPublic(4), Purposes: custodyauthority.AllPurposes}},
		MaximumOperations: 4, MaximumPending: 2}
	f.assignment = a
	aid, _ := a.ID()
	f.request = authoritystore.PruneRequest{AssignmentID: aid, ConsumerPublicKey: pruneCLIPublic(4), StorageID: pruneCLIHash(90),
		Boundary: workchain.CanonicalFloor{Pruned: true, BaseID: a.BaseID,
			Anchor:        storage.Tip{ID: pruneCLIHash(10), Height: a.ActivationHeight, Timestamp: 100, Target: pruneCLIHash(11), StateRoot: pruneCLIHash(12), CumulativeWork: []byte{1}},
			AncestryNodes: 2, AncestryRoot: pruneCLIHash(13), StatementID: a.StatementID, ManifestID: a.ManifestID,
			AvailabilityID: pruneCLIHash(14), VerifiedAt: 100, RetainUntil: 1000}}
	rid, err := f.request.ID()
	if err != nil {
		t.Fatal(err)
	}
	assignmentPath, requestPath := filepath.Join(f.root, "assignment.omcaa"), filepath.Join(f.root, "request.omcpr")
	encoded, _ := a.CanonicalBytes()
	writePruneCLIFile(t, assignmentPath, encoded)
	encoded, _ = f.request.CanonicalBytes()
	writePruneCLIFile(t, requestPath, encoded)
	f.consumerKey, f.authorityKey = filepath.Join(f.root, "consumer.key"), filepath.Join(f.root, "authority.key")
	writePruneCLIFile(t, f.consumerKey, pruneCLIKey(4).Seed())
	writePruneCLIFile(t, f.authorityKey, pruneCLIKey(1).Seed())
	f.args = []string{pruneSigningCommand, "--assignment", assignmentPath, "--assignment-id", aid.String(),
		"--request", requestPath, "--request-id", rid.String(), "--kind", "admit", "--expected-sequence", "0", "--expected-head", aid.String()}
	f.admission = signPruneCLIEntry(t, custodyauthority.Command{AssignmentID: aid, ExpectedHead: aid, Kind: custodyauthority.Admit, Purpose: custodyauthority.Prune, OperationID: rid})
	return f
}

func (f *pruneSigningFixture) completion(t testing.TB, cancelled bool) []string {
	t.Helper()
	args := pruneCLISet(f.args, "kind", "complete")
	ticket, _ := f.admission.ID()
	args = pruneCLISet(args, "expected-sequence", "1")
	args = pruneCLISet(args, "expected-head", ticket.String())
	admissionPath, terminalPath := filepath.Join(f.root, "admission.omcae"), filepath.Join(f.root, "terminal.omcpt")
	encoded, _ := f.admission.CanonicalBytes()
	writePruneCLIFile(t, admissionPath, encoded)
	rid, _ := f.request.ID()
	var terminalID types.Hash
	if cancelled {
		cancellation := authoritystore.PruneCancellation{AssignmentID: f.request.AssignmentID, RequestID: rid, TicketID: ticket, BindingID: pruneCLIHash(91)}
		encoded, _ = cancellation.CanonicalBytes()
		terminalID, _ = cancellation.ID()
	} else {
		effect := workchain.CanonicalPruneEffect{Operation: workchain.CanonicalPruneOperation{AssignmentID: f.request.AssignmentID, TicketID: ticket, StorageID: f.request.StorageID, Boundary: f.request.Boundary},
			VerifiedAt: 101, Report: workchain.CanonicalPruneReport{PreviousFloorID: pruneCLIHash(92), FloorID: f.request.Boundary.Anchor.ID,
				RemovedNodes: 1, RetainedNodes: 1, ArchivedHeaders: f.request.Boundary.AncestryNodes - 2, AddedHistoryBytes: 1, ReleasedHistoryBytes: 1}}
		var err error
		encoded, err = effect.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		terminalID, _ = effect.ID()
	}
	writePruneCLIFile(t, terminalPath, encoded)
	return append(args, "--admission", admissionPath, "--admission-id", ticket.String(), "--terminal", terminalPath, "--terminal-id", terminalID.String())
}

func pruneSigningReview(t testing.TB, args []string) map[string]string {
	t.Helper()
	var out bytes.Buffer
	if err := runPruneSigning(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	fields := pruneCLIFields(out.String())
	if fields["historical_only"] != "true" || fields["execution_authorized"] != "false" || fields["terminal_durability_proven"] != "false" {
		t.Fatalf("overstated authority: %s", out.String())
	}
	return fields
}

func TestPruneSigningOfflineReviewAndExactPublication(t *testing.T) {
	for _, phase := range []string{"admit", "cancelled", "succeeded"} {
		t.Run(phase, func(t *testing.T) {
			f := newPruneSigningFixture(t)
			args := f.args
			if phase != "admit" {
				args = f.completion(t, phase == "cancelled")
			}
			before := readPruneSigningDirectory(t, f.root)
			review := pruneSigningReview(t, args)
			if review["artifact_published"] != "false" {
				t.Fatal("review claimed publication")
			}
			assertPruneSigningDirectory(t, f.root, before)
			commandPath := filepath.Join(f.root, "consumer-command.omcac")
			signArgs := append(append([]string(nil), args...), "--mode", "sign", "--consumer-key", f.consumerKey, "--expected-review-id", review["review_id"], "--out", commandPath)
			signedReport := pruneSigningReview(t, signArgs)
			if signedReport["artifact_published"] != "true" {
				t.Fatal("signature publication not reported")
			}
			encoded, err := os.ReadFile(commandPath)
			if err != nil {
				t.Fatal(err)
			}
			command, err := custodyauthority.DecodeCommand(encoded)
			if err != nil || command.ActorPublicKey != f.request.ConsumerPublicKey {
				t.Fatalf("command: %v", err)
			}
			pruneSigningReview(t, signArgs)
			again, _ := os.ReadFile(commandPath)
			if !bytes.Equal(encoded, again) {
				t.Fatal("retry changed signature")
			}
			cosignArgs := append([]string(nil), args...)
			cosignArgs[0] = pruneCosigningCommand
			cosignArgs = append(cosignArgs, "--command", commandPath)
			coReview := pruneSigningReview(t, cosignArgs)
			if coReview["review_id"] == review["review_id"] {
				t.Fatal("signature domains collapsed")
			}
			entryPath := filepath.Join(f.root, "authority-entry.omcae")
			coSign := append(cosignArgs, "--mode", "sign", "--authority-key", f.authorityKey, "--expected-review-id", coReview["review_id"], "--out", entryPath)
			coSignedReport := pruneSigningReview(t, coSign)
			entryBytes, err := os.ReadFile(entryPath)
			if err != nil {
				t.Fatal(err)
			}
			entry, err := custodyauthority.DecodeEntry(entryBytes)
			if err != nil || entry.Command != command || entry.AuthorityPublicKey != f.assignment.AuthorityPublicKey {
				t.Fatalf("entry: %v", err)
			}
			id, _ := entry.ID()
			if coSignedReport["entry_id"] != id.String() {
				t.Fatal("incorrect entry identity")
			}
			pruneSigningReview(t, coSign)
			// Only requested artifacts exist: no journals, chain, key generation
			// or transport state has been bootstrapped by either signer.
			for _, entry := range mustPruneSigningReadDir(t, f.root) {
				if entry.IsDir() {
					t.Fatalf("signing bootstrapped a directory: %s", entry.Name())
				}
			}
		})
	}
}

func TestPruneSigningRejectsFlagsPinsAndKeysWithoutPublication(t *testing.T) {
	f := newPruneSigningFixture(t)
	review := pruneSigningReview(t, f.args)
	outPath := filepath.Join(f.root, "must-not-exist")
	signing := append(append([]string(nil), f.args...), "--mode", "sign", "--consumer-key", f.consumerKey, "--expected-review-id", review["review_id"], "--out", outPath)
	cases := map[string][]string{
		"unknown mode":          pruneCLISet(f.args, "mode", "execute"),
		"review empty key":      append(append([]string(nil), f.args...), "--consumer-key", ""),
		"review empty output":   append(append([]string(nil), f.args...), "--out", ""),
		"review empty expected": append(append([]string(nil), f.args...), "--expected-review-id", ""),
		"irrelevant evidence":   append(append([]string(nil), f.args...), "--terminal", ""),
		"irrelevant admission":  append(append([]string(nil), f.args...), "--admission-id", ""),
		"duplicate pin":         append(append([]string(nil), f.args...), "--request-id", pruneCLIHash(5).String()),
		"wrong assignment pin":  pruneCLISet(signing, "assignment-id", pruneCLIHash(5).String()),
		"wrong request pin":     pruneCLISet(signing, "request-id", pruneCLIHash(5).String()),
		"zero sequence absent":  pruneCLISet(signing, "expected-sequence", ""),
		"leading zero":          pruneCLISet(signing, "expected-sequence", "00"),
		"negative sequence":     pruneCLISet(signing, "expected-sequence", "-1"),
		"overflow sequence":     pruneCLISet(signing, "expected-sequence", "18446744073709551616"),
		"impossible sequence":   pruneCLISet(pruneCLISet(signing, "expected-sequence", "7"), "expected-head", pruneCLIHash(55).String()),
		"wrong initial head":    pruneCLISet(signing, "expected-head", pruneCLIHash(55).String()),
		"wrong key":             pruneCLISet(signing, "consumer-key", f.authorityKey),
		"wrong review":          pruneCLISet(signing, "expected-review-id", pruneCLIHash(55).String()),
		"missing key":           pruneCLISet(signing, "consumer-key", ""),
		"missing out":           pruneCLISet(signing, "out", ""),
		"stop forbidden":        pruneCLISet(signing, "kind", "stop"),
		"positional":            append(append([]string(nil), signing...), "extra"),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			before := readPruneSigningDirectory(t, f.root)
			var out bytes.Buffer
			if err := runPruneSigning(t.Context(), args, &out); err == nil || out.Len() != 0 {
				t.Fatalf("accepted bad input: %v output=%s", err, out.String())
			}
			assertPruneSigningDirectory(t, f.root, before)
		})
	}
	badReviewMissingKey := pruneCLISet(pruneCLISet(signing, "expected-review-id", pruneCLIHash(55).String()), "consumer-key", filepath.Join(f.root, "missing-key"))
	if err := runPruneSigning(t.Context(), badReviewMissingKey, io.Discard); !errors.Is(err, custodyauthority.ErrPruneReview) {
		t.Fatalf("read key before review validation: %v", err)
	}
	for _, size := range []int{31, 33, 64} {
		path := filepath.Join(f.root, "bad-key")
		writePruneCLIFile(t, path, make([]byte, size))
		if err := runPruneSigning(t.Context(), pruneCLISet(signing, "consumer-key", path), io.Discard); err == nil {
			t.Fatalf("accepted key size %d", size)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runPruneSigning(ctx, signing, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
	if err := runPruneSigning(nil, signing, io.Discard); err == nil {
		t.Fatal("nil context")
	}
	if err := runPruneSigning(t.Context(), signing, nil); err == nil {
		t.Fatal("nil output")
	}
	if _, err := os.Stat(outPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failure published output")
	}
}

func TestPruneSigningCompletionProofSubstitution(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{true: "cancelled", false: "succeeded"}[cancelled], func(t *testing.T) {
			f := newPruneSigningFixture(t)
			args := f.completion(t, cancelled)
			for name, bad := range map[string][]string{
				"admission pin":        pruneCLISet(args, "admission-id", pruneCLIHash(55).String()),
				"terminal pin":         pruneCLISet(args, "terminal-id", pruneCLIHash(55).String()),
				"before admission":     pruneCLISet(args, "expected-sequence", "0"),
				"immediate wrong head": pruneCLISet(args, "expected-head", pruneCLIHash(55).String()),
				"later old head":       pruneCLISet(args, "expected-sequence", "2"),
				"after static limit":   pruneCLISet(pruneCLISet(args, "expected-sequence", "9"), "expected-head", pruneCLIHash(55).String()),
			} {
				t.Run(name, func(t *testing.T) {
					if err := runPruneSigning(t.Context(), bad, io.Discard); err == nil {
						t.Fatal("bad completion accepted")
					}
				})
			}
			pruneSigningReview(t, pruneCLISet(pruneCLISet(args, "expected-sequence", "8"), "expected-head", pruneCLIHash(55).String()))
			terminalPath := filepath.Join(f.root, "terminal.omcpt")
			original, _ := os.ReadFile(terminalPath)
			mutations := map[string]func([]byte) ([]byte, types.Hash){}
			if cancelled {
				for _, field := range []string{"assignment", "request", "ticket"} {
					mutations[field] = func(input []byte) ([]byte, types.Hash) {
						c, _ := authoritystore.DecodePruneCancellation(input)
						switch field {
						case "assignment":
							c.AssignmentID = pruneCLIHash(55)
						case "request":
							c.RequestID = pruneCLIHash(55)
						case "ticket":
							c.TicketID = pruneCLIHash(55)
						}
						b, _ := c.CanonicalBytes()
						id, _ := c.ID()
						return b, id
					}
				}
			} else {
				for _, field := range []string{"assignment", "ticket", "storage", "boundary"} {
					mutations[field] = func(input []byte) ([]byte, types.Hash) {
						e, _ := workchain.DecodeCanonicalPruneEffect(input)
						switch field {
						case "assignment":
							e.Operation.AssignmentID = pruneCLIHash(55)
						case "ticket":
							e.Operation.TicketID = pruneCLIHash(55)
						case "storage":
							e.Operation.StorageID = pruneCLIHash(55)
						case "boundary":
							e.Operation.Boundary.AvailabilityID = pruneCLIHash(55)
						}
						b, _ := e.CanonicalBytes()
						id, _ := e.ID()
						return b, id
					}
				}
			}
			for name, mutate := range mutations {
				t.Run(name, func(t *testing.T) {
					changed, id := mutate(original)
					writePruneCLIFile(t, terminalPath, changed)
					if err := runPruneSigning(t.Context(), pruneCLISet(args, "terminal-id", id.String()), io.Discard); err == nil {
						t.Fatal("independently pinned but mismatched terminal accepted")
					}
				})
			}
			for _, malformed := range [][]byte{append(append([]byte(nil), original...), 0), make([]byte, workchain.MaximumCanonicalPruneEffectBytes+1), {1}} {
				writePruneCLIFile(t, terminalPath, malformed)
				if err := runPruneSigning(t.Context(), args, io.Discard); err == nil {
					t.Fatal("noncanonical terminal accepted")
				}
			}
		})
	}
}

func TestPruneSigningCosignRejectsChangedCommandAndWrongAuthority(t *testing.T) {
	f := newPruneSigningFixture(t)
	commandPath := filepath.Join(f.root, "signed-command.omcac")
	original, _ := f.admission.Command.CanonicalBytes()
	writePruneCLIFile(t, commandPath, original)
	args := append([]string(nil), f.args...)
	args[0] = pruneCosigningCommand
	args = append(args, "--command", commandPath)
	review := pruneSigningReview(t, args)
	sign := append(append([]string(nil), args...), "--mode", "sign", "--authority-key", f.authorityKey, "--expected-review-id", review["review_id"], "--out", filepath.Join(f.root, "entry.omcae"))
	for name, bad := range map[string][]string{
		"wrong authority":            pruneCLISet(sign, "authority-key", f.consumerKey),
		"consumer review ID":         pruneCLISet(sign, "expected-review-id", review["command_review_id"]),
		"wrong expected head":        pruneCLISet(sign, "expected-head", pruneCLIHash(55).String()),
		"review empty authority key": append(append([]string(nil), args...), "--authority-key", ""),
	} {
		t.Run(name, func(t *testing.T) {
			if err := runPruneSigning(t.Context(), bad, io.Discard); err == nil {
				t.Fatal("invalid cosign accepted")
			}
		})
	}
	for _, mutate := range []func(*custodyauthority.Command){
		func(c *custodyauthority.Command) { c.OperationID = pruneCLIHash(55) },
		func(c *custodyauthority.Command) { c.ExpectedSequence = 1; c.ExpectedHead = pruneCLIHash(55) },
		func(c *custodyauthority.Command) { c.Purpose = custodyauthority.Audit },
	} {
		c := f.admission.Command
		mutate(&c)
		c.Signature = [64]byte{}
		c, err := c.Sign(pruneCLIKey(4))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := c.CanonicalBytes()
		writePruneCLIFile(t, commandPath, b)
		if err := runPruneSigning(t.Context(), args, io.Discard); err == nil {
			t.Fatal("valid signature on substituted command accepted")
		}
	}
	corrupt := append([]byte(nil), original...)
	corrupt[len(corrupt)-1] ^= 1
	for _, b := range [][]byte{corrupt, append(append([]byte(nil), original...), 0), original[:len(original)-1]} {
		writePruneCLIFile(t, commandPath, b)
		if err := runPruneSigning(t.Context(), args, io.Discard); err == nil {
			t.Fatal("invalid command bytes accepted")
		}
	}
}

type pruneSigningFailWriter struct{ err error }

func (w pruneSigningFailWriter) Write([]byte) (int, error) { return 0, w.err }

func TestPruneSigningPublicationConflictAndOutputFailure(t *testing.T) {
	f := newPruneSigningFixture(t)
	review := pruneSigningReview(t, f.args)
	out := filepath.Join(f.root, "command.omcac")
	args := append(append([]string(nil), f.args...), "--mode", "sign", "--consumer-key", f.consumerKey, "--expected-review-id", review["review_id"], "--out", out)
	writePruneCLIFile(t, out, []byte("existing reviewed artifact"))
	if err := runPruneSigning(t.Context(), args, io.Discard); err == nil {
		t.Fatal("conflicting artifact overwritten")
	}
	before, _ := os.ReadFile(out)
	if string(before) != "existing reviewed artifact" {
		t.Fatal("conflict changed output")
	}
	args = pruneCLISet(args, "out", filepath.Join(f.root, "new-command.omcac"))
	failure := errors.New("output disconnected")
	if err := runPruneSigning(t.Context(), args, pruneSigningFailWriter{failure}); !errors.Is(err, failure) {
		t.Fatalf("output failure lost: %v", err)
	}
	encoded, err := os.ReadFile(filepath.Join(f.root, "new-command.omcac"))
	if err != nil {
		t.Fatal("published artifact lost after stdout failure")
	}
	if _, err := custodyauthority.DecodeCommand(encoded); err != nil {
		t.Fatal(err)
	}
	pruneSigningReview(t, args)
	for _, source := range []string{f.consumerKey, filepath.Join(f.root, "request.omcpr"), filepath.Join(f.root, "assignment.omcaa")} {
		original, _ := os.ReadFile(source)
		if err := runPruneSigning(t.Context(), pruneCLISet(args, "out", source), io.Discard); err == nil {
			t.Fatal("source overwritten")
		}
		after, _ := os.ReadFile(source)
		if !bytes.Equal(original, after) {
			t.Fatal("source mutated")
		}
	}
}

func mustPruneSigningReadDir(t testing.TB, path string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}
func readPruneSigningDirectory(t testing.TB, path string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for _, entry := range mustPruneSigningReadDir(t, path) {
		if entry.IsDir() {
			t.Fatal("unexpected directory")
		}
		b, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = b
	}
	return result
}
func assertPruneSigningDirectory(t testing.TB, path string, want map[string][]byte) {
	t.Helper()
	got := readPruneSigningDirectory(t, path)
	if len(got) != len(want) {
		t.Fatal("offline review changed directory")
	}
	for name, b := range want {
		if !bytes.Equal(got[name], b) {
			t.Fatalf("offline review changed %s", name)
		}
	}
	for name := range got {
		if strings.HasPrefix(name, ".outcomemesh-") {
			t.Fatal("temporary signing artifact retained")
		}
	}
}
