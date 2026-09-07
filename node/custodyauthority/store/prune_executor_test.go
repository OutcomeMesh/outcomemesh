package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

type pruneFixture struct {
	chain                                            *workchain.Store
	executor                                         *PruneExecutor
	coordinator                                      *Coordinator
	chainPath, executorPath, authorityPath, pinsPath string
	executorPinsPath                                 string
	chainPositionPinsPath                            string
	base                                             workchain.Base
	parameters                                       workblock.Parameters
	policy                                           workchain.Policy
	request                                          PruneRequest
	id                                               types.Hash
	admission                                        custodyauthority.Entry
}

func pruneChainConfig() (workchain.Base, workblock.Parameters, workchain.Policy) {
	var target types.Hash
	target[1] = 0x7f
	for i := 2; i < len(target); i++ {
		target[i] = 0xff
	}
	a := testAssignment()
	p := workblock.Parameters{NetworkID: a.NetworkID, BlockSubsidy: 10220, RewardMaturity: 100, ActivationHeight: a.ActivationHeight,
		DifficultyAnchorTimestamp: 1699999940, DifficultyAnchorTarget: target, TargetSpacing: 60, ASERTHalfLife: 7200, FeeDelay: 3}
	initial := state.Empty()
	b := workchain.Base{Tip: storage.Tip{ID: a.BaseID, Height: a.ActivationHeight - 1, Timestamp: p.DifficultyAnchorTimestamp, Target: target,
		StateRoot: initial.Root(), CumulativeWork: []byte{1}}, State: initial, RecentTimestamps: []uint64{p.DifficultyAnchorTimestamp}}
	policy := workchain.DefaultPolicy()
	policy.CanonicalRetention = 1
	return b, p, policy
}

func newPruneFixture(t testing.TB) *pruneFixture {
	return newPruneFixtureWithStorageID(t, types.Hash{})
}

func newPruneFixtureWithStorageID(t testing.TB, storageID types.Hash) *pruneFixture {
	return newPruneFixtureWithStoragePositions(t, storageID, false)
}

func newPruneFixtureWithStoragePositions(t testing.TB, storageID types.Hash, positions bool) *pruneFixture {
	t.Helper()
	f := &pruneFixture{}
	f.base, f.parameters, f.policy = pruneChainConfig()
	f.chainPath = filepath.Join(t.TempDir(), "chain")
	var err error
	if positions {
		f.chainPositionPinsPath = filepath.Join(t.TempDir(), "database-position-pins")
		f.chain, err = workchain.CreatePositionPinnedWithPolicy(f.chainPath, f.chainPositionPinsPath, f.base, f.parameters, f.policy, storageID)
	} else if storageID.IsZero() {
		f.chain, err = workchain.OpenWithPolicy(f.chainPath, f.base, f.parameters, f.policy)
	} else {
		f.chain, err = workchain.CreateBoundWithPolicy(f.chainPath, f.base, f.parameters, f.policy, storageID)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.chain.Close() })
	parent, timestamp := f.base.Tip.ID, f.base.Tip.Timestamp
	var anchorID types.Hash
	for i := range 5 {
		timestamp += f.parameters.TargetSpacing
		payload, _, err := f.chain.Prepare(parent, timestamp, nil)
		if err != nil {
			t.Fatal(err)
		}
		inclusion, _ := workgraph.InclusionRoot(nil)
		template, err := payload.SealTemplate(types.Address(testHash(byte(40+i))), inclusion, nil)
		if err != nil {
			t.Fatal(err)
		}
		anchor, _, err := workgraph.MineAnchor(context.Background(), template, 0)
		if err != nil {
			t.Fatal(err)
		}
		block, _, err := payload.Finalize(anchor, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.chain.Commit(block, timestamp); err != nil {
			t.Fatal(err)
		}
		parent, _ = block.Header.ID()
		if i == 2 {
			anchorID = parent
		}
	}
	anchor, err := f.chain.TipByID(anchorID)
	if err != nil {
		t.Fatal(err)
	}
	root, count, err := f.chain.SelectedAncestryCommitment(anchorID)
	if err != nil {
		t.Fatal(err)
	}
	a := testAssignment()
	f.request = PruneRequest{AssignmentID: testAssignmentID(t), ConsumerPublicKey: testPublic(4), StorageID: storageID, Boundary: workchain.CanonicalFloor{
		Pruned: true, BaseID: a.BaseID, Anchor: anchor, AncestryNodes: count, AncestryRoot: root, StatementID: a.StatementID,
		ManifestID: a.ManifestID, AvailabilityID: testHash(60), VerifiedAt: 100, RetainUntil: 1000}}
	f.id, err = f.request.ID()
	if err != nil {
		t.Fatal(err)
	}
	f.executorPath = filepath.Join(t.TempDir(), "executor")
	if storageID.IsZero() {
		f.executor, err = CreatePruneExecutor(f.executorPath, a, f.request, f.id)
	} else {
		f.executorPinsPath = filepath.Join(t.TempDir(), "independent-pins")
		f.executor, err = CreatePinnedPruneExecutor(f.executorPath, f.executorPinsPath, a, f.request, f.id)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.executor.Close() })
	f.coordinator, f.authorityPath, f.pinsPath = newTestCoordinator(t)
	return f
}

func (f *pruneFixture) admit(t testing.TB, bind bool) {
	t.Helper()
	snapshot := testCoordination(t, f.coordinator).Authority
	command := custodyauthority.Command{AssignmentID: f.request.AssignmentID, ExpectedSequence: snapshot.Sequence, ExpectedHead: snapshot.HeadID,
		Kind: custodyauthority.Admit, Purpose: custodyauthority.Prune, OperationID: f.id}
	command, err := command.Sign(testKey(4))
	if err != nil {
		t.Fatal(err)
	}
	f.admission, err = custodyauthority.SignEntry(command, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	appendCoordinated(t, f.coordinator, f.admission)
	if bind {
		if err := f.executor.BindAdmission(t.Context(), f.coordinator, f.admission); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *pruneFixture) reopen(t testing.TB) {
	t.Helper()
	_ = f.executor.Close()
	_ = f.coordinator.Close()
	_ = f.chain.Close()
	var err error
	if f.executorPinsPath == "" {
		f.executor, err = OpenPruneExecutor(f.executorPath, testAssignment(), f.id)
	} else {
		f.executor, err = OpenPinnedPruneExecutor(f.executorPath, f.executorPinsPath, testAssignment(), f.id)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.coordinator = testOpenCoordinator(t, f.authorityPath, f.pinsPath)
	if f.chainPositionPinsPath != "" {
		f.chain, err = workchain.OpenPositionPinnedWithPolicy(f.chainPath, f.chainPositionPinsPath, f.base, f.parameters, f.policy, f.request.StorageID)
	} else if f.request.StorageID.IsZero() {
		f.chain, err = workchain.OpenWithPolicy(f.chainPath, f.base, f.parameters, f.policy)
	} else {
		f.chain, err = workchain.OpenBoundWithPolicy(f.chainPath, f.base, f.parameters, f.policy, f.request.StorageID)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func pruneSnapshot(t testing.TB, e *PruneExecutor) PruneExecution {
	t.Helper()
	s, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func samePruneEffect(a, b workchain.CanonicalPruneEffect) bool {
	l, le := a.CanonicalBytes()
	r, re := b.CanonicalBytes()
	return le == nil && re == nil && bytes.Equal(l, r)
}

func (f *pruneFixture) stop(t testing.TB) types.Hash {
	t.Helper()
	s := testCoordination(t, f.coordinator).Authority
	if s.Phase == custodyauthority.Stopping {
		return s.StopID
	}
	return appendCoordinated(t, f.coordinator, testEntry(t, s, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(80))).EntryID
}

func (f *pruneFixture) complete(t testing.TB, effect workchain.CanonicalPruneEffect) {
	t.Helper()
	stop := f.stop(t)
	s := testCoordination(t, f.coordinator).Authority
	retire := testEntry(t, s, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop)
	if _, err := f.coordinator.Append(t.Context(), retire); !errors.Is(err, custodyauthority.ErrOutstanding) {
		t.Fatal("effect result silently closed ticket", err)
	}
	id, err := effect.ID()
	if err != nil {
		t.Fatal(err)
	}
	ticket, _ := f.admission.ID()
	appendCoordinated(t, f.coordinator, testEntry(t, s, custodyauthority.Complete, types.Hash{}, ticket, id))
	appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop))
}

func TestPruneExecutorRunsOnceAndKeepsResultAfterRetirement(t *testing.T) {
	f := newPruneFixture(t)
	if s := pruneSnapshot(t, f.executor); s.Stage != PrunePrepared || s.Admission != nil || s.Effect != nil {
		t.Fatal("bootstrap executed work")
	}
	f.admit(t, true)
	f.reopen(t)
	var calls, applied atomic.Int32
	var wg sync.WaitGroup
	results := make(chan workchain.CanonicalPruneEffect, 16)
	for range 16 {
		wg.Go(func() {
			result, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { calls.Add(1); return 200, nil })
			if err != nil {
				t.Error(err)
				return
			}
			if result.Applied {
				applied.Add(1)
			}
			results <- result.Effect
		})
	}
	wg.Wait()
	close(results)
	if calls.Load() != 1 || applied.Load() != 1 {
		t.Fatal("execution repeated", calls.Load(), applied.Load())
	}
	var first workchain.CanonicalPruneEffect
	for result := range results {
		if first.Operation.TicketID.IsZero() {
			first = result
		}
		if !samePruneEffect(first, result) {
			t.Fatal("retry changed result")
		}
	}
	if s := pruneSnapshot(t, f.executor); s.Stage != PruneSucceeded || s.Effect == nil {
		t.Fatal("success not retained")
	}
	// Public snapshots/results cannot mutate the in-memory journal.
	copy := pruneSnapshot(t, f.executor)
	copy.Request.Boundary.Anchor.CumulativeWork[0] ^= 1
	copy.Effect.Operation.Boundary.Anchor.CumulativeWork[0] ^= 1
	f.complete(t, first)
	f.reopen(t)
	result, err := f.executor.Execute(t.Context(), nil, nil, func() (uint64, error) { t.Error("retired result reauthorized"); return 900, nil })
	if err != nil || result.Applied || !samePruneEffect(first, result.Effect) {
		t.Fatal("old evidence became a new execution", err)
	}
	if s := testCoordination(t, f.coordinator); s.Authority.Phase != custodyauthority.Retired || s.Authority.Pending != 0 {
		t.Fatal("retry changed authority")
	}
}

func TestPruneExecutorGuardHoldsThroughResultPublication(t *testing.T) {
	f := newPruneFixture(t)
	f.admit(t, true)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	f.executor.hooks.at = func(stage string) error {
		if stage == "prune-result-before-write" {
			close(entered)
			<-release
		}
		return nil
	}
	s := testCoordination(t, f.coordinator).Authority
	stop := testEntry(t, s, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(80))
	returned := make(chan error, 1)
	go func() {
		_, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil })
		returned <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("result publication not reached")
	}
	if f.coordinator.mu.TryLock() {
		f.coordinator.mu.Unlock()
		t.Fatal("authority guard ended before durable result")
	}
	ticket, _ := f.admission.ID()
	if _, found, err := f.chain.CanonicalPruneEffect(ticket); err != nil || !found {
		t.Fatal("result publication preceded atomic effect", err)
	}
	stopped := make(chan error, 1)
	go func() { _, err := f.coordinator.Append(t.Context(), stop); stopped <- err }()
	select {
	case <-returned:
		t.Fatal("result escaped before retention")
	default:
	}
	select {
	case <-stopped:
		t.Fatal("stop crossed result publication")
	default:
	}
	once.Do(func() { close(release) })
	if err := <-returned; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if s := testCoordination(t, f.coordinator).Authority; s.Pending != 1 || s.Phase != custodyauthority.Stopping {
		t.Fatal("wrong drain state")
	}
}

func TestPruneExecutorInterruptedStartNeverAutomaticallyReexecutes(t *testing.T) {
	for _, mode := range []string{"before-effect", "authorize-error", "after-effect", "result-failure"} {
		t.Run(mode, func(t *testing.T) {
			f := newPruneFixture(t)
			f.admit(t, true)
			injected := errors.New("interrupted execution")
			f.executor.hooks.at = func(stage string) error {
				if (mode == "before-effect" && stage == "prune-before-effect") || (mode == "after-effect" && stage == "prune-after-effect") || (mode == "result-failure" && stage == "prune-result-before-write") {
					return injected
				}
				return nil
			}
			result, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) {
				if mode == "authorize-error" {
					return 0, injected
				}
				return 200, nil
			})
			if !errors.Is(err, injected) || result.Applied || !result.Effect.Operation.TicketID.IsZero() {
				t.Fatal("uncertain effect returned result", err)
			}
			f.reopen(t)
			if s := pruneSnapshot(t, f.executor); s.Stage != PruneStarted || s.Effect != nil {
				t.Fatal("reopen invented terminal state")
			}
			if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { t.Error("started work reexecuted"); return 200, nil }); !errors.Is(err, ErrPruneOutcome) {
				t.Fatal(err)
			}
			result, err = f.executor.Recover(t.Context(), f.chain)
			hadEffect := mode == "after-effect" || mode == "result-failure"
			if hadEffect {
				if err != nil || result.Applied {
					t.Fatal("positive result recovery failed", err)
				}
				f.complete(t, result.Effect)
			} else {
				if !errors.Is(err, ErrPruneOutcome) {
					t.Fatal("missing effect became completion", err)
				}
				stop := f.stop(t)
				s := testCoordination(t, f.coordinator).Authority
				if _, err := f.coordinator.Append(t.Context(), testEntry(t, s, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop)); !errors.Is(err, custodyauthority.ErrOutstanding) {
					t.Fatal("unresolved effect retired", err)
				}
			}
		})
	}
}

func TestPruneExecutorCancellationAndCurrentAuthority(t *testing.T) {
	for _, mode := range []string{"before-bind", "before-start", "after-start", "after-effect", "completed", "closed-authority", "foreign-context"} {
		t.Run(mode, func(t *testing.T) {
			f := newPruneFixture(t)
			f.admit(t, false)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "before-bind" {
				cancel()
				if err := f.executor.BindAdmission(ctx, f.coordinator, f.admission); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if s := pruneSnapshot(t, f.executor); s.Stage != PrunePrepared {
					t.Fatal("cancel bound admission")
				}
				return
			}
			if err := f.executor.BindAdmission(ctx, f.coordinator, f.admission); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "before-start":
				cancel()
			case "after-start", "after-effect":
				f.executor.hooks.at = func(stage string) error {
					if (mode == "after-start" && stage == "prune-start-after-apply") || (mode == "after-effect" && stage == "prune-after-effect") {
						cancel()
					}
					return nil
				}
			case "completed":
				ticket, _ := f.admission.ID()
				appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Complete, types.Hash{}, ticket, testHash(99)))
			case "closed-authority":
				_ = f.coordinator.Close()
			case "foreign-context":
				_ = f.chain.Close()
				p := f.parameters
				p.NetworkID++
				var err error
				f.chain, err = workchain.OpenWithPolicy(filepath.Join(t.TempDir(), "foreign"), f.base, p, f.policy)
				if err != nil {
					t.Fatal(err)
				}
			}
			result, err := f.executor.Execute(ctx, f.coordinator, f.chain, func() (uint64, error) {
				if mode != "after-effect" {
					t.Error("denied attempt reached authorization")
				}
				return 200, nil
			})
			if mode == "after-effect" {
				if err != nil || !result.Applied || pruneSnapshot(t, f.executor).Stage != PruneSucceeded {
					t.Fatal("cancel after effect abandoned result", err)
				}
				return
			}
			if err == nil || result.Applied {
				t.Fatal("denied attempt executed", err)
			}
			want := PruneAdmitted
			if mode == "after-start" {
				want = PruneStarted
			}
			if s := pruneSnapshot(t, f.executor); s.Stage != want {
				t.Fatal("wrong cancellation phase", s.Stage)
			}
		})
	}
}

func TestPruneExecutorPublicationFailures(t *testing.T) {
	for _, part := range []string{"prune-admission", "prune-start", "prune-result"} {
		for _, stage := range appendStages {
			t.Run(part+"/"+stage, func(t *testing.T) {
				f := newPruneFixture(t)
				f.admit(t, part != "prune-admission")
				injected := errors.New("record durability failed")
				f.executor.hooks.at = func(at string) error {
					if at == part+"-"+stage {
						return injected
					}
					return nil
				}
				var err error
				if part == "prune-admission" {
					err = f.executor.BindAdmission(t.Context(), f.coordinator, f.admission)
				} else {
					var result workchain.CanonicalPruneCommit
					result, err = f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil })
					if result.Applied || !result.Effect.Operation.TicketID.IsZero() {
						t.Fatal("failed publication exposed result")
					}
				}
				if !errors.Is(err, injected) || !errors.Is(err, ErrUncertain) {
					t.Fatal("writer not poisoned", err)
				}
				if _, err := f.executor.Snapshot(); !errors.Is(err, ErrUncertain) {
					t.Fatal("failed writer readable", err)
				}
				f.reopen(t)
				s := pruneSnapshot(t, f.executor)
				want := PrunePrepared
				if part == "prune-start" {
					want = PruneAdmitted
				}
				if part == "prune-result" {
					want = PruneStarted
				}
				if isPublishedStage(stage) {
					want++
				}
				if s.Stage != want {
					t.Fatalf("phase=%v want=%v", s.Stage, want)
				}
				if part == "prune-result" {
					result, err := f.executor.Recover(t.Context(), f.chain)
					if err != nil || result.Applied {
						t.Fatal("committed effect recovery", err)
					}
					f.complete(t, result.Effect)
				}
			})
		}
	}
}

func TestPruneExecutorInitializerFailuresAndBoundedPending(t *testing.T) {
	for _, stage := range []string{"prune-before-ready", "prune-ready-file-synced", "prune-ready-directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			f := newPruneFixture(t)
			path := filepath.Join(t.TempDir(), "partial")
			injected := errors.New("initialization interrupted")
			created, err := createPruneExecutor(path, testAssignment(), f.request, f.id, storeHooks{at: func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			}})
			if created != nil || !errors.Is(err, injected) {
				t.Fatal("initialization success", err)
			}
			if _, err := CreatePruneExecutor(path, testAssignment(), f.request, f.id); !errors.Is(err, os.ErrExist) {
				t.Fatal("partial root rebuilt", err)
			}
			opened, err := OpenPruneExecutor(path, testAssignment(), f.id)
			if stage == "prune-before-ready" {
				if opened != nil || err == nil {
					t.Fatal("missing ready accepted")
				}
			} else {
				if err != nil {
					t.Fatal("initializer retained lock", err)
				}
				_ = opened.Close()
			}
		})
	}
	f := newPruneFixture(t)
	f.admit(t, true)
	for i := range MaximumPendingFiles {
		writeTestFile(t, filepath.Join(f.executorPath, pendingName, fmt.Sprintf("entry-%d", i)), nil)
	}
	if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { t.Error("full pending budget executed"); return 200, nil }); !errors.Is(err, custodyauthority.ErrLimit) {
		t.Fatal(err)
	}
	if s := pruneSnapshot(t, f.executor); s.Stage != PruneAdmitted {
		t.Fatal("capacity exhaustion started work")
	}
	writeTestFile(t, filepath.Join(f.executorPath, pendingName, "entry-excess"), nil)
	_ = f.executor.Close()
	if opened, err := OpenPruneExecutor(f.executorPath, testAssignment(), f.id); err == nil {
		_ = opened.Close()
		t.Fatal("unbounded pending scan")
	}
}
