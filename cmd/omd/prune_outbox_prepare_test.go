package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

type prunePrepareFixture struct {
	root, assignmentPath, entryPath string
	assignment                      custodyauthority.Assignment
	entry                           custodyauthority.Entry
	name                            string
}

func newPrunePrepareFixture(t testing.TB, admission bool) *prunePrepareFixture {
	t.Helper()
	f := &prunePrepareFixture{root: t.TempDir(), name: pruneAdmissionPrepareCommand}
	f.assignment = custodyauthority.Assignment{NetworkID: 77, GenesisID: pruneCLIHash(1), ActivationHeight: 10,
		BaseID: pruneCLIHash(2), ManifestID: pruneCLIHash(3), StatementID: pruneCLIHash(4), InitialReceiptID: pruneCLIHash(5),
		CustodyPolicyID: pruneCLIHash(6), IncarnationID: pruneCLIHash(7), AuthorityPublicKey: pruneCLIPublic(1), ReplicaPublicKey: pruneCLIPublic(2),
		Auditors: [][32]byte{pruneCLIPublic(3)}, Consumers: []custodyauthority.Consumer{{PublicKey: pruneCLIPublic(4), Purposes: custodyauthority.AllPurposes}},
		MaximumOperations: 4, MaximumPending: 2}
	aid, _ := f.assignment.ID()
	c := custodyauthority.Command{AssignmentID: aid, ExpectedHead: aid, Kind: custodyauthority.Admit,
		Purpose: custodyauthority.Prune, OperationID: pruneCLIHash(50)}
	if !admission {
		f.name = pruneCompletionPrepareCommand
		c = custodyauthority.Command{AssignmentID: aid, ExpectedHead: pruneCLIHash(51), ExpectedSequence: 1,
			Kind: custodyauthority.Complete, TicketID: pruneCLIHash(52), EvidenceID: pruneCLIHash(53)}
	}
	f.entry = signPruneCLIEntry(t, c)
	f.assignmentPath, f.entryPath = filepath.Join(f.root, "assignment.omcaa"), filepath.Join(f.root, "entry.omcae")
	f.write(t)
	return f
}

func (f *prunePrepareFixture) write(t testing.TB) {
	t.Helper()
	a, err := f.assignment.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.entry.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	writePruneCLIFile(t, f.assignmentPath, a)
	writePruneCLIFile(t, f.entryPath, e)
}

func (f *prunePrepareFixture) args() []string {
	aid, _ := f.assignment.ID()
	eid, _ := f.entry.ID()
	return []string{f.name, "--assignment", f.assignmentPath, "--assignment-id", aid.String(), "--entry", f.entryPath,
		"--entry-id", eid.String(), "--client-peer-id", pruneCLIPeer(46).String(), "--server-peer-id", pruneCLIPeer(45).String()}
}

func (f *prunePrepareFixture) intentID(t testing.TB) types.Hash {
	t.Helper()
	var id types.Hash
	var err error
	if f.name == pruneAdmissionPrepareCommand {
		id, err = (authoritystore.AdmissionIntent{ClientPeerID: pruneCLIPeer(46), ServerPeerID: pruneCLIPeer(45), Entry: f.entry}).ID()
	} else {
		id, err = (authoritystore.CompletionIntent{ClientPeerID: pruneCLIPeer(46), ServerPeerID: pruneCLIPeer(45), Entry: f.entry}).ID()
	}
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *prunePrepareFixture) retainArgs(t testing.TB, mode, path string) []string {
	t.Helper()
	return append(f.args(), "--mode", mode, "--outbox", path, "--intent-id", f.intentID(t).String())
}

func runPrunePrepare(t testing.TB, args []string) string {
	t.Helper()
	var output bytes.Buffer
	if err := runPruneOutboxPrepare(t.Context(), args, &output); err != nil {
		t.Fatal(err)
	}
	fields := pruneCLIFields(output.String())
	for name, want := range map[string]string{"historical_only": "true", "sent": "false", "execution_authorized": "false", "terminal_state_verified": "false", "current_head_verified": "false", "automatic_retry": "false"} {
		if fields[name] != want {
			t.Fatalf("%s overclaims scope: %s", name, output.String())
		}
	}
	return output.String()
}

func prunePrepareTree(t testing.TB, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if info.Mode().IsRegular() {
			encoded, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += string(encoded)
		}
		result[path] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPruneOutboxPrepareReviewIsPureAndDeterministic(t *testing.T) {
	for _, admission := range []bool{true, false} {
		f := newPrunePrepareFixture(t, admission)
		t.Run(f.name, func(t *testing.T) {
			before := prunePrepareTree(t, f.root)
			first := runPrunePrepare(t, f.args())
			if explicit := runPrunePrepare(t, append(f.args(), "--mode", "review")); explicit != first {
				t.Fatal("explicit review changed deterministic output")
			}
			fields := pruneCLIFields(first)
			if fields["intent_id"] != f.intentID(t).String() || fields["outbox_created"] != "false" || fields["outbox_verified"] != "false" || fields["receipt_present"] != "false" || fields["receipt_nonce"] != (types.Hash{}).String() {
				t.Fatal("review claimed a retained outbox or receipt", first)
			}
			for _, pin := range []string{"client-peer-id", "server-peer-id"} {
				changed := pruneCLIFields(runPrunePrepare(t, pruneCLISet(f.args(), pin, pruneCLIPeer(47).String())))
				if changed["intent_id"] == fields["intent_id"] || changed["entry_id"] != fields["entry_id"] {
					t.Fatal("intent failed to bind independent transport role", pin)
				}
			}
			for _, flag := range []string{"outbox", "intent-id"} {
				for _, value := range []string{"", filepath.Join(f.root, "must-not-exist")} {
					var output bytes.Buffer
					if err := runPruneOutboxPrepare(t.Context(), append(f.args(), "--"+flag, value), &output); err == nil || output.Len() != 0 {
						t.Fatal("review accepted a write/verification flag", flag, value, err)
					}
				}
			}
			if after := prunePrepareTree(t, f.root); !reflect.DeepEqual(before, after) {
				t.Fatal("review changed filesystem contents")
			}
			c := f.entry.Command
			c.ExpectedHead = pruneCLIHash(59)
			f.entry = signPruneCLIEntry(t, c)
			f.write(t)
			changed := pruneCLIFields(runPrunePrepare(t, f.args()))
			if changed["intent_id"] == fields["intent_id"] || changed["entry_id"] == fields["entry_id"] {
				t.Fatal("changed signed head did not change IDs")
			}
		})
	}
}

func TestPruneOutboxPrepareCreateVerifyAndPreservation(t *testing.T) {
	for _, admission := range []bool{true, false} {
		f := newPrunePrepareFixture(t, admission)
		t.Run(f.name, func(t *testing.T) {
			path := filepath.Join(f.root, "outbox")
			verify := f.retainArgs(t, "verify", path)
			if err := runPruneOutboxPrepare(t.Context(), verify, io.Discard); err == nil {
				t.Fatal("verification initialized a missing outbox")
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("missing verification changed filesystem", err)
			}
			create := f.retainArgs(t, "create", path)
			if err := runPruneOutboxPrepare(t.Context(), pruneCLISet(create, "intent-id", pruneCLIHash(60).String()), io.Discard); err == nil {
				t.Fatal("creation accepted wrong independent intent pin")
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("bad intent published an outbox", err)
			}
			created := pruneCLIFields(runPrunePrepare(t, create))
			if created["outbox_created"] != "true" || created["outbox_verified"] != "true" || created["receipt_present"] != "false" {
				t.Fatal("bad creation report", created)
			}
			before := prunePrepareTree(t, f.root)
			if err := runPruneOutboxPrepare(t.Context(), create, io.Discard); err == nil {
				t.Fatal("re-created existing outbox")
			}
			verified := runPrunePrepare(t, verify)
			if runPrunePrepare(t, verify) != verified {
				t.Fatal("verification did not release lock or changed history")
			}
			fields := pruneCLIFields(verified)
			if fields["outbox_created"] != "false" || fields["outbox_verified"] != "true" || fields["receipt_present"] != "false" {
				t.Fatal("bad verification report", fields)
			}
			if after := prunePrepareTree(t, f.root); !reflect.DeepEqual(before, after) {
				t.Fatal("verify or rejected recreate changed retained files")
			}
			// A fully valid different entry and its matching new intent pin must
			// not verify the old root, even though both commands share a scope.
			c := f.entry.Command
			c.ExpectedHead = pruneCLIHash(61)
			f.entry = signPruneCLIEntry(t, c)
			f.write(t)
			if err := runPruneOutboxPrepare(t.Context(), f.retainArgs(t, "verify", path), io.Discard); err == nil {
				t.Fatal("verified old outbox as a different reviewed intent")
			}
			parentMissing := filepath.Join(f.root, "missing-parent", "outbox")
			if err := runPruneOutboxPrepare(t.Context(), f.retainArgs(t, "create", parentMissing), io.Discard); err == nil {
				t.Fatal("creation silently bootstrapped parent directories")
			}
		})
	}
}

func TestPruneOutboxPrepareOutputFailuresPreserveRoot(t *testing.T) {
	for _, admission := range []bool{true, false} {
		f := newPrunePrepareFixture(t, admission)
		t.Run(f.name, func(t *testing.T) {
			fault := errors.New("stdout unavailable")
			before := prunePrepareTree(t, f.root)
			if err := runPruneOutboxPrepare(t.Context(), f.args(), pruneFailWriter{fault}); !errors.Is(err, fault) {
				t.Fatal(err)
			}
			if after := prunePrepareTree(t, f.root); !reflect.DeepEqual(before, after) {
				t.Fatal("failed review output changed files")
			}
			path := filepath.Join(f.root, "outbox")
			if err := runPruneOutboxPrepare(t.Context(), f.retainArgs(t, "create", path), pruneFailWriter{fault}); !errors.Is(err, fault) {
				t.Fatal(err)
			}
			verified := runPrunePrepare(t, f.retainArgs(t, "verify", path))
			if pruneCLIFields(verified)["receipt_present"] != "false" {
				t.Fatal("failed output caused a delivery")
			}
			before = prunePrepareTree(t, f.root)
			if err := runPruneOutboxPrepare(t.Context(), f.retainArgs(t, "verify", path), pruneFailWriter{fault}); !errors.Is(err, fault) {
				t.Fatal(err)
			}
			if after := prunePrepareTree(t, f.root); !reflect.DeepEqual(before, after) || runPrunePrepare(t, f.retainArgs(t, "verify", path)) != verified {
				t.Fatal("failed verification output changed retained history or leaked lock")
			}
		})
	}
}

func TestPruneOutboxPrepareBusyAndPartialRootsStayIntact(t *testing.T) {
	for _, admission := range []bool{true, false} {
		f := newPrunePrepareFixture(t, admission)
		t.Run(f.name, func(t *testing.T) {
			path := filepath.Join(f.root, "outbox")
			runPrunePrepare(t, f.retainArgs(t, "create", path))
			var owner io.Closer
			var err error
			if admission {
				owner, err = authoritystore.OpenAdmissionOutbox(path, f.assignment, f.intentID(t))
			} else {
				owner, err = authoritystore.OpenCompletionOutbox(path, f.assignment, f.intentID(t))
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = owner.Close() })
			before := prunePrepareTree(t, path)
			if err := runPruneOutboxPrepare(t.Context(), f.retainArgs(t, "verify", path), io.Discard); !errors.Is(err, authoritystore.ErrBusy) {
				t.Fatal("verification bypassed another owner's lock", err)
			}
			if err := runPruneOutboxPrepare(t.Context(), f.retainArgs(t, "create", path), io.Discard); err == nil {
				t.Fatal("creation replaced a busy outbox")
			}
			if after := prunePrepareTree(t, path); !reflect.DeepEqual(before, after) {
				t.Fatal("busy root modified")
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			runPrunePrepare(t, f.retainArgs(t, "verify", path))
			partial := filepath.Join(f.root, "partial")
			if err := os.Mkdir(partial, 0o700); err != nil {
				t.Fatal(err)
			}
			writePruneCLIFile(t, filepath.Join(partial, "operator-note"), []byte("retain failed preparation for inspection"))
			before = prunePrepareTree(t, partial)
			for _, mode := range []string{"create", "verify"} {
				if err := runPruneOutboxPrepare(t.Context(), f.retainArgs(t, mode, partial), io.Discard); err == nil {
					t.Fatal("partial root was accepted or reinitialized", mode)
				}
			}
			if after := prunePrepareTree(t, partial); !reflect.DeepEqual(before, after) {
				t.Fatal("partial root repaired or reset implicitly")
			}
		})
	}
}

func TestPruneOutboxPrepareRejectsTrustAndFlagAmbiguity(t *testing.T) {
	for _, admission := range []bool{true, false} {
		f := newPrunePrepareFixture(t, admission)
		t.Run(f.name, func(t *testing.T) {
			base := f.args()
			before := prunePrepareTree(t, f.root)
			var cases [][]string
			for i := 1; i+1 < len(base); i += 2 {
				cases = append(cases, append(append([]string(nil), base[:i]...), base[i+2:]...))
				cases = append(cases, append(append([]string(nil), base...), base[i], base[i+1]))
			}
			for _, name := range []string{"assignment-id", "entry-id", "client-peer-id", "server-peer-id"} {
				for _, value := range []string{"", "abc", (types.Hash{}).String()} {
					cases = append(cases, pruneCLISet(base, name, value))
				}
			}
			for _, name := range []string{"assignment-id", "entry-id"} {
				cases = append(cases, pruneCLISet(base, name, pruneCLIHash(64).String()))
			}
			cases = append(cases, pruneCLISet(base, "client-peer-id", pruneCLIPeer(45).String()))
			for _, name := range []string{"client-peer-id", "server-peer-id"} {
				for _, actor := range []byte{1, 2, 3, 4} {
					cases = append(cases, pruneCLISet(base, name, pruneCLIPeer(actor).String()))
				}
			}
			for _, mode := range []string{"", "send", "reset", "Create"} {
				cases = append(cases, append(append([]string(nil), base...), "--mode", mode))
			}
			for _, mode := range []string{"create", "verify"} {
				cases = append(cases, append(append([]string(nil), base...), "--mode", mode))
				cases = append(cases, append(append([]string(nil), base...), "--mode", mode, "--outbox", filepath.Join(f.root, "missing")))
				cases = append(cases, append(append([]string(nil), base...), "--mode", mode, "--intent-id", f.intentID(t).String()))
			}
			for _, name := range []string{"key", "peer", "listen", "timeout", "force", "sign", "execute"} {
				cases = append(cases, append(append([]string(nil), base...), "--"+name, "unused"))
			}
			cases = append(cases, append(append([]string(nil), base...), "positional"))
			cases = append(cases, append([]string{"unknown-command"}, base[1:]...))
			for i, args := range cases {
				var output bytes.Buffer
				if err := runPruneOutboxPrepare(t.Context(), args, &output); err == nil || output.Len() != 0 {
					t.Fatalf("case %d accepted ambiguous trust or flags: %v; %v", i, args, err)
				}
			}
			if after := prunePrepareTree(t, f.root); !reflect.DeepEqual(before, after) {
				t.Fatal("invalid review modified files")
			}
		})
	}
	f := newPrunePrepareFixture(t, true)
	if err := runPruneOutboxPrepare(nil, f.args(), io.Discard); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := runPruneOutboxPrepare(t.Context(), nil, io.Discard); err == nil {
		t.Fatal("no command accepted")
	}
	if err := runPruneOutboxPrepare(t.Context(), f.args(), nil); err == nil {
		t.Fatal("nil output accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runPruneOutboxPrepare(ctx, f.args(), io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled context accepted", err)
	}
}

func TestPruneOutboxPrepareRejectsSignedWrongScopeAndBounds(t *testing.T) {
	for _, admission := range []bool{true, false} {
		f := newPrunePrepareFixture(t, admission)
		t.Run(f.name, func(t *testing.T) {
			original := f.entry
			mutations := []struct {
				name      string
				mutate    func(*custodyauthority.Command)
				actor     byte
				authority byte
			}{
				{"assignment", func(c *custodyauthority.Command) { c.AssignmentID = pruneCLIHash(71) }, 4, 1},
				{"foreign-consumer", func(*custodyauthority.Command) {}, 8, 1},
				{"authority-as-consumer", func(*custodyauthority.Command) {}, 1, 1},
				{"replica-as-consumer", func(*custodyauthority.Command) {}, 2, 1},
				{"auditor-as-consumer", func(*custodyauthority.Command) {}, 3, 1},
				{"foreign-authority", func(*custodyauthority.Command) {}, 4, 8},
				{"sequence", func(c *custodyauthority.Command) { c.ExpectedSequence = 2*uint64(f.assignment.MaximumOperations) + 2 }, 4, 1},
				{"wrong-kind", func(c *custodyauthority.Command) {
					c.Kind, c.Purpose, c.OperationID, c.TicketID, c.EvidenceID = custodyauthority.Stop, 0, types.Hash{}, types.Hash{}, pruneCLIHash(72)
				}, 1, 1},
			}
			if admission {
				mutations = append(mutations, struct {
					name      string
					mutate    func(*custodyauthority.Command)
					actor     byte
					authority byte
				}{"other-purpose", func(c *custodyauthority.Command) { c.Purpose = custodyauthority.Audit }, 4, 1})
			}
			for _, test := range mutations {
				t.Run(test.name, func(t *testing.T) {
					c := original.Command
					c.ActorPublicKey = [32]byte{}
					test.mutate(&c)
					var err error
					c, err = c.Sign(pruneCLIKey(test.actor))
					if err != nil {
						t.Fatal(err)
					}
					f.entry, err = custodyauthority.SignEntry(c, pruneCLIKey(test.authority))
					if err != nil {
						t.Fatal(err)
					}
					f.write(t)
					var output bytes.Buffer
					if err := runPruneOutboxPrepare(t.Context(), f.args(), &output); err == nil || output.Len() != 0 {
						t.Fatal("accepted signed but wrong scope", err)
					}
				})
			}
			// The static boundary itself is allowed: this is not a live head
			// query, and review must not pretend to resolve remote liveness.
			c := original.Command
			if admission {
				c.ExpectedSequence = 2 * (uint64(f.assignment.MaximumOperations) - 1)
			} else {
				c.ExpectedSequence = 2*uint64(f.assignment.MaximumOperations) + 1
			}
			f.entry = signPruneCLIEntry(t, c)
			f.write(t)
			runPrunePrepare(t, f.args())
			c.ExpectedSequence++
			f.entry = signPruneCLIEntry(t, c)
			f.write(t)
			if err := runPruneOutboxPrepare(t.Context(), f.args(), io.Discard); err == nil {
				t.Fatal("accepted first impossible static sequence")
			}
			// Preserve assignment coverage but remove this actor's Prune role.
			f.assignment.Consumers = []custodyauthority.Consumer{{PublicKey: pruneCLIPublic(4), Purposes: custodyauthority.Audit | custodyauthority.Serve}, {PublicKey: pruneCLIPublic(8), Purposes: custodyauthority.Prune}}
			sort.Slice(f.assignment.Consumers, func(i, j int) bool {
				return bytes.Compare(f.assignment.Consumers[i].PublicKey[:], f.assignment.Consumers[j].PublicKey[:]) < 0
			})
			c = original.Command
			c.AssignmentID, _ = f.assignment.ID()
			f.entry = signPruneCLIEntry(t, c)
			f.write(t)
			if err := runPruneOutboxPrepare(t.Context(), f.args(), io.Discard); !errors.Is(err, custodyauthority.ErrActor) {
				t.Fatal("consumer without Prune purpose accepted", err)
			}
		})
	}
}

func TestPruneOutboxPrepareRejectsNoncanonicalArtifacts(t *testing.T) {
	for _, admission := range []bool{true, false} {
		f := newPrunePrepareFixture(t, admission)
		t.Run(f.name, func(t *testing.T) {
			args := f.args()
			encoded, _ := f.entry.CanonicalBytes()
			for _, offset := range []int{0, 9, 10 + 9, 10 + custodyauthority.MaximumCommandBytes - 1, len(encoded) - 1} {
				bad := append([]byte(nil), encoded...)
				bad[offset] ^= 1
				writePruneCLIFile(t, f.entryPath, bad)
				if err := runPruneOutboxPrepare(t.Context(), args, io.Discard); err == nil {
					t.Fatal("accepted corrupted shape/signature", offset)
				}
			}
			for _, bad := range [][]byte{nil, encoded[:len(encoded)-1], append(append([]byte(nil), encoded...), 0), bytes.Repeat([]byte{1}, 2*custodyauthority.MaximumEntryBytes)} {
				writePruneCLIFile(t, f.entryPath, bad)
				if err := runPruneOutboxPrepare(t.Context(), args, io.Discard); err == nil {
					t.Fatal("accepted noncanonical or over-limit entry", len(bad))
				}
			}
			f.write(t)
			alias := filepath.Join(f.root, "entry-alias")
			if err := os.Symlink(f.entryPath, alias); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{alias, f.root, filepath.Join(f.root, "missing-entry")} {
				if err := runPruneOutboxPrepare(t.Context(), pruneCLISet(args, "entry", path), io.Discard); err == nil {
					t.Fatal("accepted unsafe/missing entry source", path)
				}
			}
		})
	}
}

func TestPruneOutboxPrepareVerifyLocalReceiptsOffline(t *testing.T) {
	f := newPruneCLIFixture(t)
	address, stop := startPruneCLI(t, f)
	admissionReport := pruneCLIFields(runPruneCLIDelivery(t, f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address)))
	stop()
	completionPath, completionID := f.prepareCompletion(t)
	completion, err := authoritystore.OpenCompletionOutbox(completionPath, f.assignment, completionID)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := completion.Snapshot()
	if err = errors.Join(err, completion.Close()); err != nil {
		t.Fatal(err)
	}
	address, stop = startPruneCLI(t, f)
	completionReport := pruneCLIFields(runPruneCLIDelivery(t, f.deliveryArgs(pruneCompletionCommand, completionPath, completionID, address)))
	stop()
	for _, test := range []struct {
		name, path string
		id         types.Hash
		entry      custodyauthority.Entry
		report     map[string]string
	}{
		{pruneAdmissionPrepareCommand, f.admissionPath, f.admissionID, f.admission, admissionReport},
		{pruneCompletionPrepareCommand, completionPath, completionID, cs.Intent.Entry, completionReport},
	} {
		t.Run(test.name, func(t *testing.T) {
			entryPath := filepath.Join(f.root, test.name+".omcae")
			encoded, _ := test.entry.CanonicalBytes()
			writePruneCLIFile(t, entryPath, encoded)
			eid, _ := test.entry.ID()
			args := []string{test.name, "--mode", "verify", "--assignment", f.assignmentPath, "--assignment-id", f.config.AssignmentID.String(),
				"--entry", entryPath, "--entry-id", eid.String(), "--client-peer-id", f.config.ClientPeerID.String(), "--server-peer-id", f.config.ServerPeerID.String(),
				"--outbox", test.path, "--intent-id", test.id.String()}
			before := prunePrepareTree(t, test.path)
			fields := pruneCLIFields(runPrunePrepare(t, args))
			if fields["receipt_present"] != "true" || fields["receipt_nonce"] != test.report["nonce"] || fields["entry_id"] != test.report["entry_id"] || fields["outbox_created"] != "false" {
				t.Fatal("verification lost or overclaimed historical receipt", fields)
			}
			if after := prunePrepareTree(t, test.path); !reflect.DeepEqual(before, after) {
				t.Fatal("receipt verification modified outbox")
			}
			wrongPath := completionPath
			if test.name == pruneCompletionPrepareCommand {
				wrongPath = f.admissionPath
			}
			if err := runPruneOutboxPrepare(t.Context(), pruneCLISet(args, "outbox", wrongPath), io.Discard); err == nil {
				t.Fatal("verified wrong typed journal")
			}
			if strings.Contains(runPrunePrepare(t, args), "delivery_confirmed=true") {
				t.Fatal("offline verification claimed a fresh authenticated exchange")
			}
		})
	}
}
