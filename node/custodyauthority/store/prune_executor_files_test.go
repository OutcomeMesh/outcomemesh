package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

func purePruneRequest(t testing.TB) PruneRequest {
	t.Helper()
	a := testAssignment()
	return PruneRequest{AssignmentID: testAssignmentID(t), ConsumerPublicKey: testPublic(4), Boundary: workchain.CanonicalFloor{
		Pruned: true, BaseID: a.BaseID, Anchor: storage.Tip{ID: testHash(21), Height: a.ActivationHeight, Timestamp: 100, Target: testHash(22), StateRoot: testHash(23), CumulativeWork: []byte{1}},
		AncestryNodes: 2, AncestryRoot: testHash(24), StatementID: a.StatementID, ManifestID: a.ManifestID, AvailabilityID: testHash(25), VerifiedAt: 100, RetainUntil: 1000}}
}

func TestPruneRequestCodecAndBindings(t *testing.T) {
	r := purePruneRequest(t)
	encoded, err := r.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.ID()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 377 || id.String() != "5d1c7f0b6cf71484eee050f5e072b938f0fdb81bebe3a8f68b83ddf5505508ac" {
		t.Fatalf("request vector changed: bytes=%d id=%s", len(encoded), id)
	}
	decoded, err := DecodePruneRequest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := decoded.CanonicalBytes()
	if !bytes.Equal(again, encoded) {
		t.Fatal("request roundtrip")
	}
	if err := validatePruneRequest(testAssignment(), decoded, id); err != nil {
		t.Fatal(err)
	}
	for length := 0; length < len(encoded); length++ {
		if _, err := DecodePruneRequest(encoded[:length]); err == nil {
			t.Fatal("accepted truncation", length)
		}
	}
	for _, bad := range [][]byte{append(append([]byte(nil), encoded...), 0), make([]byte, MaximumPruneRequestBytes+1)} {
		if _, err := DecodePruneRequest(bad); err == nil {
			t.Fatal("accepted malformed request size")
		}
	}
	for _, offset := range []int{0, 8, 9} {
		bad := append([]byte(nil), encoded...)
		bad[offset] ^= 1
		if _, err := DecodePruneRequest(bad); err == nil {
			t.Fatal("bad envelope")
		}
	}
	for name, mutate := range map[string]func(*PruneRequest){
		"assignment": func(r *PruneRequest) { r.AssignmentID = testHash(99) }, "consumer": func(r *PruneRequest) { r.ConsumerPublicKey = testPublic(2) },
		"base": func(r *PruneRequest) { r.Boundary.BaseID = testHash(99) }, "manifest": func(r *PruneRequest) { r.Boundary.ManifestID = testHash(99) },
		"statement": func(r *PruneRequest) { r.Boundary.StatementID = testHash(99) }, "below-activation": func(r *PruneRequest) { r.Boundary.Anchor.Height-- },
		"wrong-count": func(r *PruneRequest) { r.Boundary.AncestryNodes++ }, "tagged-floor": func(r *PruneRequest) { r.Boundary.PruneTicketID = testHash(99) },
		"zero-consumer": func(r *PruneRequest) { r.ConsumerPublicKey = [32]byte{} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := purePruneRequest(t)
			mutate(&bad)
			bid, _ := bad.ID()
			if err := validatePruneRequest(testAssignment(), bad, bid); err == nil {
				t.Fatal("invalid request binding")
			}
		})
	}
	if err := validatePruneRequest(testAssignment(), r, testHash(99)); err == nil {
		t.Fatal("wrong request pin")
	}
}

func FuzzDecodePruneRequest(f *testing.F) {
	r := purePruneRequest(f)
	encoded, err := r.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	r.StorageID = testHash(91)
	bound, err := r.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(bound)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		request, err := DecodePruneRequest(input)
		if err != nil {
			return
		}
		encoded, err := request.CanonicalBytes()
		if err != nil || !bytes.Equal(encoded, input) {
			t.Fatal("noncanonical accepted request")
		}
		if id, err := request.ID(); err != nil || id.IsZero() {
			t.Fatal("missing request commitment")
		}
	})
}

func TestPruneExecutorOwnsRequestAndChecksLifecycle(t *testing.T) {
	request := purePruneRequest(t)
	id, _ := request.ID()
	assignment := testAssignment()
	path := filepath.Join(t.TempDir(), "executor")
	executor, err := CreatePruneExecutor(path, assignment, request, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = executor.Close() })
	// Neither input slices nor returned evidence may mutate the private request
	// or its independently selected trust set.
	request.Boundary.Anchor.CumulativeWork[0] ^= 1
	assignment.Consumers[0].PublicKey[0] ^= 1
	assignment.Auditors[0][0] ^= 1
	snapshot := pruneSnapshot(t, executor)
	if got, err := snapshot.Request.ID(); err != nil || got != id {
		t.Fatal("request retained caller aliases", err)
	}
	snapshot.Request.Boundary.Anchor.CumulativeWork[0] ^= 1
	if got, _ := executor.assignment.ID(); got != testAssignmentID(t) {
		t.Fatal("assignment retained caller aliases")
	}
	if got, _ := pruneSnapshot(t, executor).Request.ID(); got != id {
		t.Fatal("snapshot exposes private request")
	}
	authorize := func() (uint64, error) { t.Error("invalid lifecycle executed work"); return 200, nil }
	if _, err := executor.Execute(t.Context(), nil, nil, authorize); !errors.Is(err, ErrPruneStage) {
		t.Fatal("prepared execution", err)
	}
	if _, err := executor.Recover(t.Context(), nil); !errors.Is(err, ErrPruneStage) {
		t.Fatal("prepared recovery", err)
	}
	if err := executor.BindAdmission(nil, nil, custodyauthority.Entry{}); !errors.Is(err, ErrPruneRequest) {
		t.Fatal("nil bind context", err)
	}
	if _, err := executor.Execute(nil, nil, nil, authorize); !errors.Is(err, ErrPruneRequest) {
		t.Fatal("nil execution context", err)
	}
	if _, err := executor.Execute(t.Context(), nil, nil, nil); !errors.Is(err, ErrPruneRequest) {
		t.Fatal("nil authorization", err)
	}
	if _, err := executor.Recover(nil, nil); !errors.Is(err, ErrPruneRequest) {
		t.Fatal("nil recovery context", err)
	}
	if err := executor.Close(); err != nil {
		t.Fatal(err)
	}
	for _, closed := range []*PruneExecutor{nil, executor} {
		if _, err := closed.Snapshot(); !errors.Is(err, ErrClosed) {
			t.Fatal("closed snapshot", err)
		}
		if err := closed.BindAdmission(t.Context(), nil, custodyauthority.Entry{}); !errors.Is(err, ErrClosed) {
			t.Fatal("closed admission", err)
		}
		if _, err := closed.Execute(t.Context(), nil, nil, authorize); !errors.Is(err, ErrClosed) {
			t.Fatal("closed execution", err)
		}
		if _, err := closed.Recover(t.Context(), nil); !errors.Is(err, ErrClosed) {
			t.Fatal("closed recovery", err)
		}
		if err := closed.Close(); err != nil {
			t.Fatal("repeated close", err)
		}
	}
}

func TestPruneExecutorDrainsAlreadyStoppingAfterChainReopen(t *testing.T) {
	f := newPruneFixture(t)
	f.admit(t, false)
	f.stop(t)
	if err := f.executor.BindAdmission(t.Context(), f.coordinator, f.admission); err != nil {
		t.Fatal("stopping prevented admission retention", err)
	}
	if err := f.chain.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) {
		t.Error("closed chain reached authorization")
		return 200, nil
	}); !errors.Is(err, storage.ErrClosed) {
		t.Fatal("closed chain started work", err)
	}
	if s := pruneSnapshot(t, f.executor); s.Stage != PruneAdmitted {
		t.Fatal("closed chain consumed the start")
	}
	f.reopen(t)
	result, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil })
	if err != nil || !result.Applied {
		t.Fatal("stopping prevented admitted drain", err)
	}
	f.complete(t, result.Effect)
}

func TestPruneExecutorRejectsUncommittedOrSubstitutedAdmission(t *testing.T) {
	f := newPruneFixture(t)
	c := custodyauthority.Command{AssignmentID: f.request.AssignmentID, ExpectedHead: f.request.AssignmentID, Kind: custodyauthority.Admit, Purpose: custodyauthority.Prune, OperationID: f.id}
	c, err := c.Sign(testKey(4))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := custodyauthority.SignEntry(c, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.executor.BindAdmission(t.Context(), f.coordinator, signed); !errors.Is(err, custodyauthority.ErrOperation) {
		t.Fatal("signature used as current permit", err)
	}
	if s := pruneSnapshot(t, f.executor); s.Stage != PrunePrepared {
		t.Fatal("unknown admission retained")
	}
	f.admit(t, false)
	for _, kind := range []string{"operation", "purpose", "actor", "authority", "signature"} {
		t.Run(kind, func(t *testing.T) {
			command := f.admission.Command
			command.Signature = [64]byte{}
			authorityKey := testKey(1)
			actorKey := testKey(4)
			switch kind {
			case "operation":
				command.OperationID = testHash(88)
			case "purpose":
				command.Purpose = custodyauthority.Audit
			case "actor":
				command.ActorPublicKey = [32]byte{}
				actorKey = testKey(2)
			case "authority":
				authorityKey = testKey(2)
			}
			command, err := command.Sign(actorKey)
			if err != nil {
				t.Fatal(err)
			}
			bad, err := custodyauthority.SignEntry(command, authorityKey)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "signature" {
				bad.Signature[0] ^= 1
			}
			if err := f.executor.BindAdmission(t.Context(), f.coordinator, bad); err == nil {
				t.Fatal("substituted admission retained")
			}
		})
	}
	if err := f.executor.BindAdmission(t.Context(), f.coordinator, f.admission); err != nil {
		t.Fatal(err)
	}
	// A different local history with the same assignment is not a fallback.
	foreign, _, _ := newTestCoordinator(t)
	if _, err := f.executor.Execute(t.Context(), foreign, f.chain, func() (uint64, error) { t.Error("unknown ticket executed"); return 200, nil }); !errors.Is(err, custodyauthority.ErrOperation) {
		t.Fatal(err)
	}
	if s := pruneSnapshot(t, f.executor); s.Stage != PruneAdmitted {
		t.Fatal("missing authority history started effect")
	}
}

func TestPruneExecutorRejectsMalformedAndMissingJournalParts(t *testing.T) {
	for _, mode := range []string{"request-pin", "assignment", "ready", "unknown-root", "unknown-record", "record-gap", "admission-signature", "start-binding", "result-binding", "record-symlink", "pending-name", "pending-oversized", "missing-request", "missing-lock", "missing-ready", "missing-records"} {
		t.Run(mode, func(t *testing.T) {
			f := newPruneFixture(t)
			f.admit(t, true)
			if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil }); err != nil {
				t.Fatal(err)
			}
			_ = f.executor.Close()
			pin := f.id
			root := func(name string) string { return filepath.Join(f.executorPath, name) }
			record := func(index int) string { return root(filepath.Join(pruneRecordsName, pruneRecordNames[index])) }
			corrupt := func(path string) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 1
				writeTestFile(t, path, data)
			}
			switch mode {
			case "request-pin":
				pin[0] ^= 1
			case "assignment":
				corrupt(root(assignmentName))
			case "ready":
				corrupt(root(pruneReadyName))
			case "unknown-root":
				writeTestFile(t, root("extra"), nil)
			case "unknown-record":
				writeTestFile(t, root(filepath.Join(pruneRecordsName, "04-extra")), nil)
			case "record-gap":
				if err := os.Remove(record(1)); err != nil {
					t.Fatal(err)
				}
			case "admission-signature":
				corrupt(record(0))
			case "start-binding":
				corrupt(record(1))
			case "result-binding":
				encoded, err := os.ReadFile(record(2))
				if err != nil {
					t.Fatal(err)
				}
				effect, err := workchain.DecodeCanonicalPruneEffect(encoded)
				if err != nil {
					t.Fatal(err)
				}
				effect.Operation.AssignmentID[0] ^= 1
				encoded, _ = effect.CanonicalBytes()
				writeTestFile(t, record(2), encoded)
			case "record-symlink":
				target := filepath.Join(t.TempDir(), "record")
				if err := os.Rename(record(2), target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, record(2)); err != nil {
					t.Fatal(err)
				}
			case "pending-name":
				writeTestFile(t, root(filepath.Join(pendingName, "entry-not-decimal")), nil)
			case "pending-oversized":
				writeTestFile(t, root(filepath.Join(pendingName, "entry-1")), make([]byte, workchain.MaximumCanonicalPruneEffectBytes+1))
			case "missing-request":
				if err := os.Remove(root(pruneRequestName)); err != nil {
					t.Fatal(err)
				}
			case "missing-lock":
				if err := os.Remove(root(pruneLockName)); err != nil {
					t.Fatal(err)
				}
			case "missing-ready":
				if err := os.Remove(root(pruneReadyName)); err != nil {
					t.Fatal(err)
				}
			case "missing-records":
				if err := os.Rename(root(pruneRecordsName), filepath.Join(t.TempDir(), "records")); err != nil {
					t.Fatal(err)
				}
			}
			if opened, err := OpenPruneExecutor(f.executorPath, testAssignment(), pin); err == nil {
				_ = opened.Close()
				t.Fatal("malformed journal reopened")
			}
		})
	}
}

func TestPruneExecutorLiveOwnershipAndRecordReplacement(t *testing.T) {
	f := newPruneFixture(t)
	if opened, err := OpenPruneExecutor(f.executorPath, testAssignment(), f.id); !errors.Is(err, ErrBusy) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("two executor owners", err)
	}
	f.admit(t, true)
	path := filepath.Join(f.executorPath, pruneRecordsName, pruneRecordNames[0])
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(t.TempDir(), "retained-admission")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, encoded)
	if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { t.Error("replaced owner executed"); return 200, nil }); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	if _, err := f.executor.Snapshot(); !errors.Is(err, ErrUncertain) {
		t.Fatal("poisoned snapshot readable")
	}
}

func TestPruneExecutorRequiredDirectorySyncFailure(t *testing.T) {
	for _, part := range []string{"admission", "start", "result"} {
		t.Run(part, func(t *testing.T) {
			f := newPruneFixture(t)
			f.admit(t, part != "admission")
			injected := errors.New("directory sync failed")
			armed := part != "result"
			f.executor.hooks.at = func(stage string) error {
				if stage == "prune-result-before-write" {
					armed = true
				}
				return nil
			}
			f.executor.hooks.syncEntriesDirectory = func(path string) error {
				if armed {
					return injected
				}
				return syncDirectory(path)
			}
			var err error
			if part == "admission" {
				err = f.executor.BindAdmission(t.Context(), f.coordinator, f.admission)
			} else {
				_, err = f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil })
			}
			if !errors.Is(err, injected) || !errors.Is(err, ErrUncertain) {
				t.Fatal("sync failure not poisoned", err)
			}
			f.reopen(t)
			want := map[string]PruneStage{"admission": PruneAdmitted, "start": PruneStarted, "result": PruneSucceeded}[part]
			if s := pruneSnapshot(t, f.executor); s.Stage != want {
				t.Fatal("visible record recovery not re-synced", s.Stage)
			}
		})
	}
}
