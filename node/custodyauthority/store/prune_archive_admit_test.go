package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func newArchiveSecondaryFixture(t testing.TB, renewals []int) (*archivePruneFixture, ArchivePruneInventory) {
	t.Helper()
	p := newArchivePruneFixtureWithAdmissions(t, renewals, false)
	return p, retainArchiveInventory(t, p)
}

func admitArchiveSecondary(ctx context.Context, p *archivePruneFixture, inventory ArchivePruneInventory) (Commit, error) {
	return p.f.executor.AdmitPreparedArchiveSecondary(ctx, p.operations[0].Coordinator, p.operations[1].Coordinator,
		p.inventoryPath, p.inventoryID, p.policyID, inventory.Admissions[1])
}

func reopenArchiveSecondary(t testing.TB, p *archivePruneFixture) {
	t.Helper()
	if err := p.f.executor.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	p.f.executor, err = OpenPinnedPruneExecutor(p.f.executorPath, p.f.executorPinsPath, p.policy.Assignments[0], p.f.id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.f.executor.Close() })
	for i := range p.operations {
		old := p.operations[i].Coordinator
		path, pins := old.authority.path, old.journal.path
		if err := old.Close(); err != nil {
			t.Fatal(err)
		}
		c, err := OpenCoordinator(path, pins, p.policy.Assignments[i], p.operations[i].Binding.AssignmentID)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		p.operations[i].Coordinator = c
	}
	p.f.coordinator = p.operations[0].Coordinator
}

func TestArchiveSecondaryAdmissionBothModesAndExecution(t *testing.T) {
	for _, renewals := range [][]int{nil, {2, 1}} {
		p, inventory := newArchiveSecondaryFixture(t, renewals)
		before, primary := pruneSnapshot(t, p.f.executor), testCoordination(t, p.f.coordinator)
		usage, _, err := p.f.chain.HistoryUsage()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.execute(t.Context()); err == nil {
			t.Fatal("execution accepted a merely co-signed secondary candidate")
		}
		var stages []string
		setCoordinatorHooks(p.operations[1].Coordinator, storeHooks{at: func(stage string) error {
			stages = append(stages, stage)
			for _, mu := range []*sync.Mutex{&p.f.executor.mu, &p.operations[0].Coordinator.mu, &p.operations[1].Coordinator.mu} {
				if mu.TryLock() {
					mu.Unlock()
					t.Error("secondary publication released an owner guard")
				}
			}
			return nil
		}})
		p.f.executor.hooks.at = func(stage string) error {
			if stage == "archive-secondary-inventory-synced" {
				for _, mu := range []*sync.Mutex{&p.f.executor.mu, &p.operations[0].Coordinator.mu, &p.operations[1].Coordinator.mu} {
					if mu.TryLock() {
						mu.Unlock()
						t.Error("admission released an owner guard")
					}
				}
			}
			return nil
		}
		result, err := admitArchiveSecondary(t.Context(), p, inventory)
		if err != nil || !result.Appended || result.EntryID != p.operations[1].Binding.TicketID || result.Snapshot.Pending != 1 {
			t.Fatal("exact secondary admission failed", err)
		}
		if !reflect.DeepEqual(stages, pruneCompletionStages()) {
			t.Fatal("secondary acknowledgement preceded confirmation", stages)
		}
		if current := testCoordination(t, p.operations[1].Coordinator); current.Pending != nil || current.Confirmed != position(result.Snapshot) {
			t.Fatal("secondary confirmation absent")
		}
		if result.Snapshot.Operations[0].OperationID != p.f.id {
			t.Fatal("secondary request replaced original primary ID")
		}
		if after, _, err := p.f.chain.HistoryUsage(); err != nil || after != usage ||
			!reflect.DeepEqual(before, pruneSnapshot(t, p.f.executor)) || !reflect.DeepEqual(primary, testCoordination(t, p.f.coordinator)) {
			t.Fatal("secondary admission changed executor, primary or storage", err)
		}
		reopenArchiveSecondary(t, p)
		for range 2 {
			result, err := admitArchiveSecondary(t.Context(), p, inventory)
			if err != nil || result.Appended {
				t.Fatal("retry duplicated admission", err)
			}
		}
		if result, err := p.execute(t.Context()); err != nil || !result.Applied {
			t.Fatal("newly admitted secondary did not satisfy guarded execution", err)
		}
		terminal := inspectPreparedArchive(t, p)
		if result, err := admitArchiveSecondary(t.Context(), p, inventory); err != nil || result.Appended ||
			!reflect.DeepEqual(terminal, pruneSnapshot(t, p.f.executor)) {
			t.Fatal("historical retry after success changed execution", err)
		}
	}
}

func TestArchiveSecondaryAdmissionRejectsBeforeWrites(t *testing.T) {
	for _, mode := range []string{"inventory-pin", "policy-pin", "missing-file", "corrupt-file", "primary-as-secondary", "relabelled-owner", "wrong-ticket", "rewritten-request", "executor-pair", "unbound-executor", "no-primary-admission", "completed-primary", "pending-primary", "stopped-secondary", "pending-secondary", "started", "cancelled-executor", "nil-context", "cancelled-context", "overlap"} {
		t.Run(mode, func(t *testing.T) {
			p, inventory := newArchiveSecondaryFixture(t, nil)
			ctx := t.Context()
			primary, secondary := p.operations[0].Coordinator, p.operations[1].Coordinator
			entry := inventory.Admissions[1]
			saveChanged := func() {
				p.inventoryID, _ = inventory.ID()
				p.policyID, _ = inventory.PolicyID()
				p.inventoryPath = filepath.Join(t.TempDir(), "different.ompi")
				if err := SaveArchivePruneInventoryFile(p.inventoryPath, inventory, p.inventoryID, p.policyID); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "inventory-pin":
				p.inventoryID = testHash(99)
			case "policy-pin":
				p.policyID = testHash(99)
			case "missing-file":
				p.inventoryPath = filepath.Join(t.TempDir(), "missing")
			case "corrupt-file":
				writeTestFile(t, p.inventoryPath, []byte("corrupt"))
			case "primary-as-secondary":
				secondary, entry = primary, inventory.Admissions[0]
			case "relabelled-owner":
				primary, secondary = secondary, primary
			case "wrong-ticket":
				command := entry.Command
				command.ExpectedSequence++
				command, _ = command.Sign(testKey(4))
				entry, _ = custodyauthority.SignEntry(command, testKey(1))
			case "rewritten-request":
				request := inventory.Request
				request.AssignmentID = secondary.assignmentID
				command := entry.Command
				command.OperationID, _ = request.ID()
				command, _ = command.Sign(testKey(4))
				entry, _ = custodyauthority.SignEntry(command, testKey(1))
			case "executor-pair":
				inventory.Policy.ExecutorBindingID = testHash(99)
				saveChanged()
			case "unbound-executor", "no-primary-admission":
				_ = p.f.executor.Close()
				var err error
				p.f.executorPath = filepath.Join(t.TempDir(), "other-executor")
				if mode == "unbound-executor" {
					request := p.f.request
					request.StorageID = types.Hash{} // raw executors cannot carry a storage-bound request
					id, _ := request.ID()
					p.f.executor, err = CreatePruneExecutor(p.f.executorPath, p.policy.Assignments[0], request, id)
				} else {
					p.f.executorPinsPath = filepath.Join(t.TempDir(), "other-pins")
					p.f.executor, err = CreatePinnedPruneExecutor(p.f.executorPath, p.f.executorPinsPath, p.policy.Assignments[0], p.f.request, p.f.id)
					if err == nil {
						inventory.Policy.ExecutorBindingID = pruneSnapshot(t, p.f.executor).Protection.BindingID
						saveChanged()
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = p.f.executor.Close() })
			case "completed-primary":
				appendCoordinated(t, primary, testEntry(t, testCoordination(t, primary).Authority, custodyauthority.Complete,
					types.Hash{}, p.operations[0].Binding.TicketID, testHash(97)))
			case "pending-primary", "pending-secondary":
				owner := primary
				if mode == "pending-secondary" {
					owner = secondary
				}
				cancelled, cancel := context.WithCancel(ctx)
				setCoordinatorHooks(owner, storeHooks{at: func(at string) error {
					if at == "intent-after-apply" {
						cancel()
					}
					return nil
				}})
				stop := testEntry(t, testCoordination(t, owner).Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(80))
				if _, err := owner.Append(cancelled, stop); !errors.Is(err, ErrPendingAttempt) {
					t.Fatal(err)
				}
				cancel()
			case "stopped-secondary":
				appendCoordinated(t, secondary, testEntry(t, testCoordination(t, secondary).Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(80)))
			case "started":
				fault := errors.New("stop after start")
				p.f.executor.hooks.at = func(at string) error {
					if at == "prune-before-effect" {
						return fault
					}
					return nil
				}
				if _, err := p.f.executor.Execute(ctx, primary, p.f.chain, func() (uint64, error) { return p.f.request.Boundary.VerifiedAt, nil }); !errors.Is(err, fault) {
					t.Fatal(err)
				}
			case "cancelled-executor":
				if _, err := p.f.executor.CancelBeforeStart(ctx, primary); err != nil {
					t.Fatal(err)
				}
			case "nil-context":
				ctx = nil
			case "cancelled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "overlap":
				p.inventoryPath = filepath.Join(filepath.Dir(secondary.authority.path), "inventory.ompi")
				if err := SaveArchivePruneInventoryFile(p.inventoryPath, inventory, p.inventoryID, p.policyID); err != nil {
					t.Fatal(err)
				}
			}
			before, target := pruneSnapshot(t, p.f.executor), testCoordination(t, secondary)
			result, err := p.f.executor.AdmitPreparedArchiveSecondary(ctx, primary, secondary, p.inventoryPath, p.inventoryID, p.policyID, entry)
			if err == nil || !reflect.DeepEqual(result, Commit{}) {
				t.Fatal("invalid admission acknowledged", err)
			}
			if !reflect.DeepEqual(target, testCoordination(t, secondary)) || !reflect.DeepEqual(before, pruneSnapshot(t, p.f.executor)) {
				t.Fatal("rejection changed retained state")
			}
		})
	}
}

func TestArchiveSecondaryAdmissionRetainedAttemptOutlivesPrimary(t *testing.T) {
	for _, point := range []string{"intent-after-apply", "authority-after-apply", "confirm-after-apply"} {
		p, inventory := newArchiveSecondaryFixture(t, nil)
		ctx, cancel := context.WithCancel(t.Context())
		fault := errors.New("secondary publication interruption")
		setCoordinatorHooks(p.operations[1].Coordinator, storeHooks{at: func(at string) error {
			if at == point {
				if point == "intent-after-apply" {
					cancel()
					return nil
				}
				return fault
			}
			return nil
		}})
		if _, err := admitArchiveSecondary(ctx, p, inventory); err == nil {
			t.Fatal("interruption acknowledged")
		}
		cancel()
		reopenArchiveSecondary(t, p)
		if _, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator); err != nil {
			t.Fatal(err)
		}
		if _, err := p.f.executor.Complete(t.Context(), p.f.coordinator, pruneCompletionEntry(t, p.f)); err != nil {
			t.Fatal(err)
		}
		terminal := pruneSnapshot(t, p.f.executor)
		result, err := admitArchiveSecondary(t.Context(), p, inventory)
		if err != nil || result.EntryID != p.operations[1].Binding.TicketID || result.Appended != (point == "intent-after-apply") ||
			testCoordination(t, p.operations[1].Coordinator).Pending != nil || !reflect.DeepEqual(terminal, pruneSnapshot(t, p.f.executor)) {
			t.Fatal("exact retained attempt could not be reconciled after primary drained", err)
		}
		// Historical ACKs remain readable after the secondary completes/retires.
		c := p.operations[1].Coordinator
		appendCoordinated(t, c, testEntry(t, testCoordination(t, c).Authority, custodyauthority.Complete, types.Hash{}, result.EntryID, testHash(96)))
		stop := appendCoordinated(t, c, testEntry(t, testCoordination(t, c).Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(80)))
		appendCoordinated(t, c, testEntry(t, testCoordination(t, c).Authority, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop.EntryID))
		if result, err := admitArchiveSecondary(t.Context(), p, inventory); err != nil || result.Appended || result.Snapshot.Phase != custodyauthority.Retired {
			t.Fatal("retired historical decision lost", err)
		}
	}
}

func TestArchiveSecondaryAdmissionPublicationFailures(t *testing.T) {
	for _, stage := range pruneCompletionStages() {
		t.Run(stage, func(t *testing.T) {
			p, inventory := newArchiveSecondaryFixture(t, nil)
			before := pruneSnapshot(t, p.f.executor)
			fault := errors.New("secondary admission failed")
			setCoordinatorHooks(p.operations[1].Coordinator, storeHooks{at: func(at string) error {
				if at == stage {
					return fault
				}
				return nil
			}})
			if result, err := admitArchiveSecondary(t.Context(), p, inventory); !errors.Is(err, fault) || !reflect.DeepEqual(result, Commit{}) {
				t.Fatal("fault acknowledged admission", err)
			}
			if _, err := admitArchiveSecondary(t.Context(), p, inventory); !errors.Is(err, ErrUncertain) {
				t.Fatal("uncertain owner reused", err)
			}
			part, suffix, _ := strings.Cut(stage, "-")
			prepared := part != "intent" || isPublishedStage(suffix)
			decided := part == "confirm" || part == "authority" && isPublishedStage(suffix)
			confirmed := part == "confirm" && isPublishedStage(suffix)
			for range 2 {
				reopenArchiveSecondary(t, p)
				assertArchiveSecondaryRecovery(t, p, inventory, before, prepared, decided, confirmed)
			}
			result, err := admitArchiveSecondary(t.Context(), p, inventory)
			if err != nil || result.Appended == decided || testCoordination(t, p.operations[1].Coordinator).Pending != nil {
				t.Fatal("exact secondary retry failed", err)
			}
		})
	}
}

func assertArchiveSecondaryRecovery(t testing.TB, p *archivePruneFixture, inventory ArchivePruneInventory, executor PruneExecution, prepared, decided, confirmed bool) {
	t.Helper()
	state, err := custodyauthority.NewState(p.policy.Assignments[1], p.operations[1].Binding.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := state.Snapshot()
	if err := state.Apply(inventory.Admissions[1]); err != nil {
		t.Fatal(err)
	}
	after, _ := state.Snapshot()
	checkRecoveredCoordination(t, p.operations[1].Coordinator, inventory.Admissions[1], before, after, prepared, decided, confirmed)
	if !reflect.DeepEqual(executor, pruneSnapshot(t, p.f.executor)) || testCoordination(t, p.f.coordinator).Authority.Sequence != 1 {
		t.Fatal("secondary recovery changed primary/executor")
	}
}

func TestArchiveSecondaryAdmissionInventoryFence(t *testing.T) {
	for _, mode := range []string{"changed", "missing", "cancelled"} {
		p, inventory := newArchiveSecondaryFixture(t, nil)
		ctx, cancel := context.WithCancel(t.Context())
		p.f.executor.hooks.at = func(stage string) error {
			if stage == "archive-secondary-before-inventory-sync" {
				switch mode {
				case "changed":
					writeTestFile(t, p.inventoryPath, []byte("changed"))
				case "missing":
					if err := os.Rename(p.inventoryPath, p.inventoryPath+".retained"); err != nil {
						return err
					}
				}
			}
			if stage == "archive-secondary-inventory-synced" && mode == "cancelled" {
				cancel()
			}
			return nil
		}
		if _, err := admitArchiveSecondary(ctx, p, inventory); err == nil {
			t.Fatal("changed/missing/cancelled preparation admitted")
		}
		cancel()
		if current := testCoordination(t, p.operations[1].Coordinator); current.Pending != nil || current.Authority.Sequence != 0 {
			t.Fatal("pre-admission fence changed secondary")
		}
	}
}

func TestArchiveSecondaryAdmissionStoppingPrimaryAndConcurrentRetries(t *testing.T) {
	p, inventory := newArchiveSecondaryFixture(t, nil)
	p.f.stop(t) // Already admitted primary work can drain while Stopping.
	var group sync.WaitGroup
	results := make(chan Commit, 8)
	for range 8 {
		group.Go(func() {
			result, err := admitArchiveSecondary(t.Context(), p, inventory)
			if err != nil {
				t.Error(err)
			}
			results <- result
		})
	}
	group.Wait()
	close(results)
	appended := 0
	for result := range results {
		if result.Appended {
			appended++
		}
		if result.EntryID != p.operations[1].Binding.TicketID {
			t.Fatal("concurrent retry changed ticket")
		}
	}
	if appended != 1 || testCoordination(t, p.operations[1].Coordinator).Authority.Sequence != 1 {
		t.Fatal("concurrent retry admitted more than once")
	}
	if result, err := p.execute(t.Context()); err != nil || !result.Applied {
		t.Fatal("admitted primary work did not drain", err)
	}
	// Even historical admission cannot relabel the inventory of a bound start.
	inventory.Mode = ArchivePruneLineage
	p.inventoryID, _ = inventory.ID()
	p.policyID, _ = inventory.PolicyID()
	p.inventoryPath = filepath.Join(t.TempDir(), "different.ompi")
	if err := SaveArchivePruneInventoryFile(p.inventoryPath, inventory, p.inventoryID, p.policyID); err != nil {
		t.Fatal(err)
	}
	if _, err := admitArchiveSecondary(t.Context(), p, inventory); !errors.Is(err, ErrPruneInventory) {
		t.Fatal("historical retry substituted a bound inventory", err)
	}
}

func TestArchiveSecondaryAdmissionPendingExecutorAndClosedOwners(t *testing.T) {
	p, inventory := newArchiveSecondaryFixture(t, nil)
	for _, owners := range [][2]*Coordinator{{nil, p.operations[1].Coordinator}, {p.f.coordinator, nil}} {
		if _, err := p.f.executor.AdmitPreparedArchiveSecondary(t.Context(), owners[0], owners[1], p.inventoryPath, p.inventoryID, p.policyID, inventory.Admissions[1]); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	}
	if _, err := (*PruneExecutor)(nil).AdmitPreparedArchiveSecondary(t.Context(), p.f.coordinator, p.operations[1].Coordinator, p.inventoryPath, p.inventoryID, p.policyID, inventory.Admissions[1]); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	fault := errors.New("unconfirmed primary cancellation")
	p.f.executor.pins.hooks.at = func(at string) error {
		if at == "pins-cancel-confirm-before-publish" {
			return fault
		}
		return nil
	}
	if _, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator); !errors.Is(err, fault) {
		t.Fatal("missed pending executor boundary", err)
	}
	reopenArchiveSecondary(t, p)
	if _, err := admitArchiveSecondary(t.Context(), p, inventory); !errors.Is(err, ErrPrunePinPending) {
		t.Fatal("unconfirmed executor authorized secondary", err)
	}
	if current := testCoordination(t, p.operations[1].Coordinator); current.Authority.Sequence != 0 || current.Pending != nil {
		t.Fatal("pending executor caused a secondary intent")
	}
	if err := p.f.executor.ResumePinnedTransition(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := p.operations[1].Coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := admitArchiveSecondary(t.Context(), p, inventory); !errors.Is(err, ErrClosed) {
		t.Fatal("closed secondary reused", err)
	}
}
