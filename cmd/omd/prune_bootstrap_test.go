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
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

type pruneBootstrapFixture struct {
	root, assignmentPath, requestPath, writer, pins string
	assignment                                      custodyauthority.Assignment
	assignmentID, requestID                         types.Hash
	request                                         authoritystore.PruneRequest
}

func newPruneBootstrapFixture(t testing.TB) *pruneBootstrapFixture {
	t.Helper()
	f := &pruneBootstrapFixture{root: t.TempDir()}
	f.assignment = custodyauthority.Assignment{NetworkID: 77, GenesisID: pruneCLIHash(1), ActivationHeight: 10,
		BaseID: pruneCLIHash(2), ManifestID: pruneCLIHash(3), StatementID: pruneCLIHash(4), InitialReceiptID: pruneCLIHash(5),
		CustodyPolicyID: pruneCLIHash(6), IncarnationID: pruneCLIHash(7), AuthorityPublicKey: pruneCLIPublic(1), ReplicaPublicKey: pruneCLIPublic(2),
		Auditors: [][32]byte{pruneCLIPublic(3)}, Consumers: []custodyauthority.Consumer{{PublicKey: pruneCLIPublic(4), Purposes: custodyauthority.AllPurposes}},
		MaximumOperations: 4, MaximumPending: 2}
	var err error
	f.assignmentID, err = f.assignment.ID()
	if err != nil {
		t.Fatal(err)
	}
	a := f.assignment
	f.request = authoritystore.PruneRequest{AssignmentID: f.assignmentID, ConsumerPublicKey: pruneCLIPublic(4), StorageID: pruneCLIHash(90),
		Boundary: workchain.CanonicalFloor{Pruned: true, BaseID: a.BaseID,
			Anchor:        storage.Tip{ID: pruneCLIHash(10), Height: a.ActivationHeight, Timestamp: 100, Target: pruneCLIHash(11), StateRoot: pruneCLIHash(12), CumulativeWork: []byte{1}},
			AncestryNodes: 2, AncestryRoot: pruneCLIHash(13), StatementID: a.StatementID, ManifestID: a.ManifestID,
			AvailabilityID: pruneCLIHash(14), VerifiedAt: 100, RetainUntil: 1000}}
	f.requestID, err = f.request.ID()
	if err != nil {
		t.Fatal(err)
	}
	f.assignmentPath, f.requestPath = filepath.Join(f.root, "assignment.omcaa"), filepath.Join(f.root, "request.omcpr")
	f.writer, f.pins = filepath.Join(f.root, "writer"), filepath.Join(f.root, "pins")
	encoded, _ := f.assignment.CanonicalBytes()
	writePruneCLIFile(t, f.assignmentPath, encoded)
	encoded, _ = f.request.CanonicalBytes()
	writePruneCLIFile(t, f.requestPath, encoded)
	return f
}

func (f *pruneBootstrapFixture) args(name string) []string {
	args := []string{name, "--assignment", f.assignmentPath, "--assignment-id", f.assignmentID.String()}
	if name == pruneAuthorityBootstrapCommand {
		return append(args, "--authority", f.writer, "--authority-pins", f.pins)
	}
	return append(args, "--executor", f.writer, "--executor-pins", f.pins, "--request", f.requestPath, "--request-id", f.requestID.String())
}

func pruneBootstrapFiles(t testing.TB, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			files[name] = "directory"
			return nil
		}
		data, err := os.ReadFile(path)
		files[name] = string(data)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return files
}

func (f *pruneBootstrapFixture) assertUnusedAndClosed(t testing.TB, name string) {
	t.Helper()
	if name == pruneAuthorityBootstrapCommand {
		owner, err := authoritystore.OpenCoordinator(f.writer, f.pins, f.assignment, f.assignmentID)
		if err != nil {
			t.Fatal(err)
		}
		state, err := owner.Snapshot()
		if err := errors.Join(err, owner.Close()); err != nil {
			t.Fatal(err)
		}
		if state.Authority.Sequence != 0 || state.Authority.Phase != custodyauthority.Accepting || state.Pending != nil || state.Confirmed.HeadID != f.assignmentID {
			t.Fatal("offline bootstrap advanced authority")
		}
		return
	}
	owner, err := authoritystore.OpenPinnedPruneExecutor(f.writer, f.pins, f.assignment, f.requestID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := owner.Snapshot()
	if err := errors.Join(err, owner.Close()); err != nil {
		t.Fatal(err)
	}
	if state.Stage != authoritystore.PrunePrepared || state.Protection == nil || state.Protection.Pending != nil || state.RequestID != f.requestID {
		t.Fatal("offline bootstrap admitted or executed work")
	}
}

func TestPruneBootstrapReviewCreateAndRepeatedVerify(t *testing.T) {
	for _, name := range []string{pruneAuthorityBootstrapCommand, pruneExecutorPrepareCommand} {
		t.Run(name, func(t *testing.T) {
			f := newPruneBootstrapFixture(t)
			before := pruneBootstrapFiles(t, f.root)
			var output bytes.Buffer
			if err := runPruneBootstrap(t.Context(), f.args(name), &output); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), "roots_created=false") || !strings.Contains(output.String(), "non_authoritative=true") || !strings.Contains(output.String(), "execution_authorized=false") {
				t.Fatalf("review claimed authority: %s", &output)
			}
			if !reflect.DeepEqual(before, pruneBootstrapFiles(t, f.root)) {
				t.Fatal("default review changed disk")
			}
			if err := runPruneBootstrap(t.Context(), append(f.args(name), "--mode", "verify"), io.Discard); err == nil {
				t.Fatal("verification initialized missing roots")
			}
			if !reflect.DeepEqual(before, pruneBootstrapFiles(t, f.root)) {
				t.Fatal("failed verification changed disk")
			}
			output.Reset()
			if err := runPruneBootstrap(t.Context(), append(f.args(name), "--mode", "create"), &output); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), "owners_closed=true") || !strings.Contains(output.String(), "historical_only=true") || !strings.Contains(output.String(), "automatic_resume=false") {
				t.Fatalf("bootstrap output overstated observation: %s", &output)
			}
			f.assertUnusedAndClosed(t, name)
			before = pruneBootstrapFiles(t, f.root)
			for range 2 {
				output.Reset()
				if err := runPruneBootstrap(t.Context(), append(f.args(name), "--mode", "verify"), &output); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(output.String(), "observed_") || !strings.Contains(output.String(), "retained_attempt=false") {
					t.Fatalf("verification failed to separate observation: %s", &output)
				}
			}
			if !reflect.DeepEqual(before, pruneBootstrapFiles(t, f.root)) {
				t.Fatal("repeated verification changed history")
			}
			output.Reset()
			if err := runPruneBootstrap(t.Context(), append(f.args(name), "--mode", "create"), &output); !errors.Is(err, os.ErrExist) || output.Len() != 0 {
				t.Fatalf("repeat bootstrap accepted existing roots: %v %s", err, &output)
			}
			if !reflect.DeepEqual(before, pruneBootstrapFiles(t, f.root)) {
				t.Fatal("refused create changed existing history")
			}
		})
	}
}

func TestPruneBootstrapRequiresExplicitPinsAndUnambiguousFlags(t *testing.T) {
	for _, name := range []string{pruneAuthorityBootstrapCommand, pruneExecutorPrepareCommand} {
		t.Run(name, func(t *testing.T) {
			f := newPruneBootstrapFixture(t)
			before := pruneBootstrapFiles(t, f.root)
			base := f.args(name)
			for index := 1; index < len(base); index += 2 {
				flagName := base[index]
				t.Run("missing-"+flagName, func(t *testing.T) {
					args := append(append([]string{}, base[:index]...), base[index+2:]...)
					if err := runPruneBootstrap(t.Context(), args, io.Discard); err == nil {
						t.Fatal("missing required field accepted")
					}
				})
				t.Run("duplicate-"+flagName, func(t *testing.T) {
					args := append(append([]string{}, base...), flagName, base[index+1])
					if err := runPruneBootstrap(t.Context(), args, io.Discard); err == nil {
						t.Fatal("duplicate reviewed field accepted")
					}
				})
			}
			for _, extra := range [][]string{{"--mode", "reset"}, {"--mode", "review", "--mode", "create"}, {"--key", "unused"}, {"--peer", "unused"}, {"positional"}} {
				if err := runPruneBootstrap(t.Context(), append(f.args(name), extra...), io.Discard); err == nil {
					t.Fatalf("unexpected arguments accepted: %v", extra)
				}
			}
			for _, replacement := range []string{strings.Repeat("0", 64), pruneCLIHash(99).String(), "not-an-id"} {
				args := f.args(name)
				args[4] = replacement
				if err := runPruneBootstrap(t.Context(), args, io.Discard); err == nil {
					t.Fatal("untrusted assignment ID accepted")
				}
			}
			if !reflect.DeepEqual(before, pruneBootstrapFiles(t, f.root)) {
				t.Fatal("rejected flags created roots")
			}
		})
	}
}

func TestPruneBootstrapRejectsOverlappingAndPartialRoots(t *testing.T) {
	for _, name := range []string{pruneAuthorityBootstrapCommand, pruneExecutorPrepareCommand} {
		t.Run(name, func(t *testing.T) {
			for _, existing := range []string{"writer", "pins"} {
				f := newPruneBootstrapFixture(t)
				path := f.writer
				if existing == "pins" {
					path = f.pins
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				before := pruneBootstrapFiles(t, f.root)
				if err := runPruneBootstrap(t.Context(), append(f.args(name), "--mode", "create"), io.Discard); !errors.Is(err, os.ErrExist) {
					t.Fatalf("partial initialization replaced or attached: %v", err)
				}
				if !reflect.DeepEqual(before, pruneBootstrapFiles(t, f.root)) {
					t.Fatal("existing-root preflight created the other root")
				}
			}
			for _, placement := range []string{"same", "nested", "symlink", "missing-parent"} {
				f := newPruneBootstrapFixture(t)
				if err := os.Mkdir(f.writer, 0o700); err != nil {
					t.Fatal(err)
				}
				switch placement {
				case "same":
					f.pins = f.writer
				case "nested":
					f.pins = filepath.Join(f.writer, "pins")
				case "symlink":
					if err := os.Symlink(f.writer, f.pins); err != nil {
						t.Fatal(err)
					}
				case "missing-parent":
					f.pins = filepath.Join(f.root, "missing", "pins")
				}
				for _, mode := range []string{"review", "create", "verify"} {
					if err := runPruneBootstrap(t.Context(), append(f.args(name), "--mode", mode), io.Discard); err == nil {
						t.Fatalf("invalid placement %s accepted in mode %s", placement, mode)
					}
				}
			}
		})
	}
}

type pruneBootstrapWriter func([]byte) (int, error)

func (write pruneBootstrapWriter) Write(data []byte) (int, error) { return write(data) }

func TestPruneBootstrapClosesOwnersBeforeOutputAndPreservesWriteFailure(t *testing.T) {
	for _, name := range []string{pruneAuthorityBootstrapCommand, pruneExecutorPrepareCommand} {
		t.Run(name, func(t *testing.T) {
			f := newPruneBootstrapFixture(t)
			failure := errors.New("bootstrap stdout unavailable")
			calls := 0
			output := pruneBootstrapWriter(func([]byte) (int, error) {
				calls++
				f.assertUnusedAndClosed(t, name)
				return 0, failure
			})
			if err := runPruneBootstrap(t.Context(), append(f.args(name), "--mode", "create"), output); !errors.Is(err, failure) || calls != 1 {
				t.Fatalf("stdout failure hidden: calls=%d err=%v", calls, err)
			}
			before := pruneBootstrapFiles(t, f.root)
			if err := runPruneBootstrap(t.Context(), append(f.args(name), "--mode", "create"), io.Discard); !errors.Is(err, os.ErrExist) {
				t.Fatal("stdout failure caused bootstrap retry to recreate roots")
			}
			if err := runPruneBootstrap(t.Context(), append(f.args(name), "--mode", "verify"), io.Discard); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, pruneBootstrapFiles(t, f.root)) {
				t.Fatal("post-output-error verification changed retained data")
			}
		})
	}
}

func TestPruneBootstrapReviewDoesNotAcquireBusyOwners(t *testing.T) {
	for _, name := range []string{pruneAuthorityBootstrapCommand, pruneExecutorPrepareCommand} {
		t.Run(name, func(t *testing.T) {
			f := newPruneBootstrapFixture(t)
			var closeOwner func() error
			if name == pruneAuthorityBootstrapCommand {
				owner, err := authoritystore.CreateCoordinatedAuthority(f.writer, f.pins, f.assignment, f.assignmentID)
				if err != nil {
					t.Fatal(err)
				}
				closeOwner = owner.Close
			} else {
				owner, err := authoritystore.CreatePinnedPruneExecutor(f.writer, f.pins, f.assignment, f.request, f.requestID)
				if err != nil {
					t.Fatal(err)
				}
				closeOwner = owner.Close
			}
			t.Cleanup(func() { _ = closeOwner() })
			before := pruneBootstrapFiles(t, f.root)
			var output bytes.Buffer
			if err := runPruneBootstrap(t.Context(), f.args(name), &output); err != nil || !strings.Contains(output.String(), "roots_inspected=false") {
				t.Fatalf("review tried to inspect a live owner: %v %s", err, &output)
			}
			output.Reset()
			if err := runPruneBootstrap(t.Context(), append(f.args(name), "--mode", "verify"), &output); !errors.Is(err, authoritystore.ErrBusy) || output.Len() != 0 {
				t.Fatalf("verification bypassed retained owner: %v %s", err, &output)
			}
			if !reflect.DeepEqual(before, pruneBootstrapFiles(t, f.root)) {
				t.Fatal("busy-owner observation changed history")
			}
			if err := closeOwner(); err != nil {
				t.Fatal(err)
			}
			f.assertUnusedAndClosed(t, name)
		})
	}
}

func TestPruneBootstrapInvalidContextAndArtifacts(t *testing.T) {
	f := newPruneBootstrapFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, runContext := range []context.Context{nil, ctx} {
		if err := runPruneBootstrap(runContext, f.args(pruneAuthorityBootstrapCommand), io.Discard); err == nil {
			t.Fatal("invalid context accepted")
		}
	}
	if err := runPruneBootstrap(t.Context(), nil, io.Discard); err == nil {
		t.Fatal("missing command accepted")
	}
	if err := runPruneBootstrap(t.Context(), []string{"unsupported"}, io.Discard); err == nil {
		t.Fatal("unsupported command accepted")
	}
	if err := runPruneBootstrap(t.Context(), f.args(pruneAuthorityBootstrapCommand), nil); err == nil {
		t.Fatal("missing output accepted")
	}
	for _, change := range []string{"zero-storage", "wrong-consumer", "wrong-anchor", "wrong-request-pin", "trailing", "oversize", "symlink"} {
		t.Run(change, func(t *testing.T) {
			f := newPruneBootstrapFixture(t)
			switch change {
			case "zero-storage":
				f.request.StorageID = types.Hash{}
			case "wrong-consumer":
				f.request.ConsumerPublicKey = pruneCLIPublic(9)
			case "wrong-anchor":
				f.request.Boundary.Anchor.Height++
			}
			encoded, err := f.request.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			f.requestID, _ = f.request.ID()
			switch change {
			case "wrong-request-pin":
				f.requestID = pruneCLIHash(99)
			case "trailing":
				encoded = append(encoded, 0)
			case "oversize":
				encoded = make([]byte, authoritystore.MaximumPruneRequestBytes+1)
			}
			writePruneCLIFile(t, f.requestPath, encoded)
			if change == "symlink" {
				alias := filepath.Join(f.root, "request-alias")
				if err := os.Symlink(f.requestPath, alias); err != nil {
					t.Fatal(err)
				}
				f.requestPath = alias
			}
			for _, mode := range []string{"review", "create", "verify"} {
				if err := runPruneBootstrap(t.Context(), append(f.args(pruneExecutorPrepareCommand), "--mode", mode), io.Discard); err == nil {
					t.Fatal("invalid retained request accepted")
				}
			}
			for _, path := range []string{f.writer, f.pins} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("rejected artifact initialized roots")
				}
			}
		})
	}
}
