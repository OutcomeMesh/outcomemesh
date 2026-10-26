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
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func archiveSecondaryTerminalFixture(t testing.TB, outcome string, renewals []int) (*archivePruneFixture, ArchivePruneInventory) {
	t.Helper()
	p, inventory := newArchiveSecondaryFixture(t, renewals)
	if _, err := admitArchiveSecondary(t.Context(), p, inventory); err != nil {
		t.Fatal(err)
	}
	if outcome == "cancelled" {
		if _, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator); err != nil {
			t.Fatal(err)
		}
	} else if result, err := p.execute(t.Context()); err != nil || !result.Applied {
		t.Fatal("could not retain archive outcome", err)
	}
	return p, inventory
}

func archiveSecondaryCompletionEntry(t testing.TB, p *archivePruneFixture) custodyauthority.Entry {
	t.Helper()
	state := pruneSnapshot(t, p.f.executor)
	var evidence types.Hash
	var err error
	if state.Cancellation != nil {
		evidence, err = state.Cancellation.ID()
	} else if state.Effect != nil {
		evidence, err = state.Effect.ID()
	} else {
		t.Fatal("fixture has no terminal outcome")
	}
	if err != nil {
		t.Fatal(err)
	}
	return testEntry(t, testCoordination(t, p.operations[1].Coordinator).Authority, custodyauthority.Complete,
		types.Hash{}, p.operations[1].Binding.TicketID, evidence)
}

func completeArchiveSecondary(ctx context.Context, p *archivePruneFixture, entry custodyauthority.Entry) (Commit, error) {
	return p.f.executor.CompletePreparedArchiveSecondary(ctx, p.operations[1].Coordinator,
		p.inventoryPath, p.inventoryID, p.policyID, entry)
}

func TestArchiveSecondaryCompletionBothOutcomesAndModes(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		for _, lineage := range []bool{false, true} {
			t.Run(outcome+map[bool]string{false: "/initial", true: "/lineage"}[lineage], func(t *testing.T) {
				var renewals []int
				if lineage {
					renewals = []int{2, 1}
				}
				p, _ := archiveSecondaryTerminalFixture(t, outcome, renewals)
				terminal := pruneSnapshot(t, p.f.executor)
				usage, _, err := p.f.chain.HistoryUsage()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := p.f.executor.Complete(t.Context(), p.f.coordinator, pruneCompletionEntry(t, p.f)); err != nil {
					t.Fatal(err)
				}
				if err := p.f.coordinator.Close(); err != nil {
					t.Fatal(err)
				}
				secondary := p.operations[1].Coordinator
				path, pins := secondary.authority.path, secondary.journal.path
				stop := appendCoordinated(t, secondary, testEntry(t, testCoordination(t, secondary).Authority,
					custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(80)))
				entry := archiveSecondaryCompletionEntry(t, p)
				var stages []string
				assertGuards := func() {
					for _, mu := range []*sync.Mutex{&p.f.executor.mu, &secondary.mu} {
						if mu.TryLock() {
							mu.Unlock()
							t.Error("completion released an owner guard")
						}
					}
				}
				p.f.executor.hooks.at = func(at string) error {
					if at == "archive-secondary-complete-inventory-synced" {
						assertGuards()
					}
					return nil
				}
				setCoordinatorHooks(secondary, storeHooks{at: func(at string) error {
					stages = append(stages, at)
					assertGuards()
					return nil
				}})
				if err := p.f.chain.Close(); err != nil {
					t.Fatal(err)
				}
				result, err := completeArchiveSecondary(t.Context(), p, entry)
				id, _ := entry.ID()
				if err != nil || !result.Appended || result.EntryID != id || result.Snapshot.Pending != 0 || result.Snapshot.Phase != custodyauthority.Stopping {
					t.Fatal("secondary did not drain with primary/database closed", err)
				}
				if !reflect.DeepEqual(stages, pruneCompletionStages()) || testCoordination(t, secondary).Pending != nil {
					t.Fatal("completion returned before independent confirmation", stages)
				}
				operation := result.Snapshot.Operations[0]
				if operation.CompletionID != id || operation.EvidenceID != entry.Command.EvidenceID || operation.OperationID != p.f.id {
					t.Fatal("completion changed original operation or evidence")
				}
				setCoordinatorHooks(secondary, storeHooks{})
				appendCoordinated(t, secondary, testEntry(t, testCoordination(t, secondary).Authority,
					custodyauthority.Retire, types.Hash{}, types.Hash{}, stop.EntryID))
				if err := secondary.Close(); err != nil {
					t.Fatal(err)
				}
				secondary, err = OpenCoordinator(path, pins, p.policy.Assignments[1], p.operations[1].Binding.AssignmentID)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = secondary.Close() })
				p.operations[1].Coordinator = secondary
				for range 2 {
					result, err := completeArchiveSecondary(t.Context(), p, entry)
					if err != nil || result.Appended || result.Snapshot.Phase != custodyauthority.Retired || result.Snapshot.Operations[0] != operation {
						t.Fatal("historical retry changed retired operation", err)
					}
				}
				p.f.chain, err = workchain.OpenPositionPinnedWithPolicy(p.f.chainPath, p.f.chainPositionPinsPath,
					p.f.base, p.f.parameters, p.f.policy, p.f.request.StorageID)
				if err != nil {
					t.Fatal(err)
				}
				if after, _, err := p.f.chain.HistoryUsage(); err != nil || after != usage || !reflect.DeepEqual(terminal, pruneSnapshot(t, p.f.executor)) {
					t.Fatal("completion changed executor or database", err)
				}
				if outcome == "cancelled" && !terminal.ArchiveInventoryID.IsZero() {
					t.Fatal("cancellation acquired an inventory start binding")
				}
			})
		}
	}
}

func TestArchiveSecondaryCompletionRejectsSignedBindings(t *testing.T) {
	p, _ := archiveSecondaryTerminalFixture(t, "succeeded", nil)
	valid := archiveSecondaryCompletionEntry(t, p)
	before, terminal := testCoordination(t, p.operations[1].Coordinator), pruneSnapshot(t, p.f.executor)
	for _, field := range []string{"assignment", "primary", "ticket", "evidence", "consumer", "authority", "head", "sequence", "kind", "consumer-signature", "authority-signature"} {
		t.Run(field, func(t *testing.T) {
			command := valid.Command
			actor, authority := byte(4), byte(1)
			switch field {
			case "assignment":
				command.AssignmentID = testHash(97)
			case "primary":
				command.AssignmentID, command.TicketID = p.f.request.AssignmentID, p.operations[0].Binding.TicketID
			case "ticket":
				command.TicketID = testHash(97)
			case "evidence":
				command.EvidenceID = testHash(97)
			case "consumer":
				actor = 5
			case "authority":
				authority = 6
			case "head":
				command.ExpectedHead = testHash(97)
			case "sequence":
				command.ExpectedSequence++
			case "kind":
				command.Kind, command.TicketID = custodyauthority.Stop, types.Hash{}
				actor = 1
			}
			command.ActorPublicKey = [32]byte{}
			command, err := command.Sign(testKey(actor))
			if err != nil {
				t.Fatal(err)
			}
			entry, err := custodyauthority.SignEntry(command, testKey(authority))
			if err != nil {
				t.Fatal(err)
			}
			if field == "consumer-signature" {
				entry.Command.Signature[0] ^= 1
			}
			if field == "authority-signature" {
				entry.Signature[0] ^= 1
			}
			if result, err := completeArchiveSecondary(t.Context(), p, entry); err == nil || !reflect.DeepEqual(result, Commit{}) {
				t.Fatal("wrong signed completion acknowledged", err)
			}
			if !reflect.DeepEqual(before, testCoordination(t, p.operations[1].Coordinator)) || !reflect.DeepEqual(terminal, pruneSnapshot(t, p.f.executor)) {
				t.Fatal("invalid completion changed history")
			}
		})
	}
}

func TestArchiveSecondaryCompletionRequiresConfirmedTerminal(t *testing.T) {
	for _, stage := range []string{"admitted", "legacy-success", "prune-before-effect", "prune-after-effect", "pins-result-confirm-before-publish", "pins-cancel-confirm-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			p, _ := newArchiveSecondaryFixture(t, nil)
			inventory, err := LoadArchivePruneInventoryFile(p.inventoryPath, p.inventoryID, p.policyID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := admitArchiveSecondary(t.Context(), p, inventory); err != nil {
				t.Fatal(err)
			}
			if stage == "legacy-success" {
				if result, err := p.f.executor.ExecuteArchive(t.Context(), p.f.chain, p.policy, p.policyID, p.operations,
					p.replicas, p.path, p.f.base, p.f.parameters, workarchive.DefaultLimits()); err != nil || !result.Applied {
					t.Fatal(err)
				}
			} else if stage != "admitted" {
				fault := errors.New("unfinished executor transition")
				hook := func(at string) error {
					if at == stage {
						return fault
					}
					return nil
				}
				p.f.executor.hooks.at, p.f.executor.pins.hooks.at = hook, hook
				if strings.Contains(stage, "cancel") {
					_, err = p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator)
				} else {
					_, err = p.execute(t.Context())
				}
				if !errors.Is(err, fault) {
					t.Fatal("missed executor boundary", err)
				}
				reopenArchiveSecondary(t, p)
			}
			state, before := pruneSnapshot(t, p.f.executor), testCoordination(t, p.operations[1].Coordinator)
			evidence := testHash(98)
			if state.Effect != nil {
				evidence, _ = state.Effect.ID()
			} else if state.Cancellation != nil {
				evidence, _ = state.Cancellation.ID()
			}
			entry := testEntry(t, before.Authority, custodyauthority.Complete, types.Hash{}, p.operations[1].Binding.TicketID, evidence)
			if result, err := completeArchiveSecondary(t.Context(), p, entry); err == nil || !reflect.DeepEqual(result, Commit{}) {
				t.Fatal("unfinished or unbound outcome completed secondary", err)
			}
			if !reflect.DeepEqual(before, testCoordination(t, p.operations[1].Coordinator)) || !reflect.DeepEqual(state, pruneSnapshot(t, p.f.executor)) {
				t.Fatal("ineligible outcome changed history")
			}
		})
	}
}

func TestArchiveSecondaryCompletionInventoryAndAdmissionChecks(t *testing.T) {
	for _, mode := range []string{"inventory-pin", "policy-pin", "missing-file", "corrupt-file", "different-inventory", "different-primary", "different-secondary", "missing-admission", "unrelated-pending", "overlap", "nil-context", "cancelled-context", "wrong-owner"} {
		t.Run(mode, func(t *testing.T) {
			p, inventory := newArchiveSecondaryFixture(t, nil)
			if mode != "missing-admission" {
				if _, err := admitArchiveSecondary(t.Context(), p, inventory); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator); err != nil {
				t.Fatal(err)
			}
			entry := archiveSecondaryCompletionEntry(t, p)
			ctx := t.Context()
			target := p.operations[1].Coordinator
			save := func() {
				var err error
				p.inventoryID, err = inventory.ID()
				if err != nil {
					t.Fatal(err)
				}
				p.policyID, _ = inventory.PolicyID()
				p.inventoryPath = filepath.Join(t.TempDir(), "changed.ompi")
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
			case "different-inventory":
				inventory.Policy.ExecutorBindingID = testHash(99)
				save()
			case "different-primary", "different-secondary":
				i := 0
				if mode == "different-secondary" {
					i = 1
				}
				command := inventory.Admissions[i].Command
				command.ExpectedSequence++
				command, _ = command.Sign(testKey(4))
				inventory.Admissions[i], _ = custodyauthority.SignEntry(command, testKey(1))
				save()
				if i == 1 {
					command = entry.Command
					command.TicketID, _ = inventory.Admissions[1].ID()
					command, _ = command.Sign(testKey(4))
					entry, _ = custodyauthority.SignEntry(command, testKey(1))
				}
			case "unrelated-pending":
				pending, cancel := context.WithCancel(ctx)
				setCoordinatorHooks(target, storeHooks{at: func(at string) error {
					if at == "intent-after-apply" {
						cancel()
					}
					return nil
				}})
				stop := testEntry(t, testCoordination(t, target).Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(80))
				_, err := target.Append(pending, stop)
				cancel()
				if !errors.Is(err, ErrPendingAttempt) {
					t.Fatal(err)
				}
			case "overlap":
				p.inventoryPath = filepath.Join(filepath.Dir(target.authority.path), "inventory.ompi")
				if err := SaveArchivePruneInventoryFile(p.inventoryPath, inventory, p.inventoryID, p.policyID); err != nil {
					t.Fatal(err)
				}
			case "nil-context":
				ctx = nil
			case "cancelled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "wrong-owner":
				target = p.f.coordinator
			}
			before, terminal := testCoordination(t, target), pruneSnapshot(t, p.f.executor)
			result, err := p.f.executor.CompletePreparedArchiveSecondary(ctx, target, p.inventoryPath, p.inventoryID, p.policyID, entry)
			if err == nil || !reflect.DeepEqual(result, Commit{}) || !reflect.DeepEqual(before, testCoordination(t, target)) || !reflect.DeepEqual(terminal, pruneSnapshot(t, p.f.executor)) {
				t.Fatal("invalid scope changed authority/executor", err)
			}
		})
	}
}

func TestArchiveSecondaryCompletionPublicationFaults(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		for _, stage := range pruneCompletionStages() {
			t.Run(outcome+"/"+stage, func(t *testing.T) {
				p, _ := archiveSecondaryTerminalFixture(t, outcome, nil)
				entry := archiveSecondaryCompletionEntry(t, p)
				before, terminal := testCoordination(t, p.operations[1].Coordinator).Authority, pruneSnapshot(t, p.f.executor)
				state, err := custodyauthority.NewState(p.policy.Assignments[1], p.operations[1].Binding.AssignmentID)
				if err != nil {
					t.Fatal(err)
				}
				inventory, err := LoadArchivePruneInventoryFile(p.inventoryPath, p.inventoryID, p.policyID)
				if err != nil {
					t.Fatal(err)
				}
				if err := state.Apply(inventory.Admissions[1]); err != nil {
					t.Fatal(err)
				}
				if err := state.Apply(entry); err != nil {
					t.Fatal(err)
				}
				after, _ := state.Snapshot()
				fault := errors.New("secondary completion interrupted")
				setCoordinatorHooks(p.operations[1].Coordinator, storeHooks{at: func(at string) error {
					if at == stage {
						return fault
					}
					return nil
				}})
				if result, err := completeArchiveSecondary(t.Context(), p, entry); !errors.Is(err, fault) || !errors.Is(err, ErrUncertain) || !reflect.DeepEqual(result, Commit{}) {
					t.Fatal("fault acknowledged completion", err)
				}
				if _, err := completeArchiveSecondary(t.Context(), p, entry); !errors.Is(err, ErrUncertain) {
					t.Fatal("uncertain owner reused", err)
				}
				part, suffix, _ := strings.Cut(stage, "-")
				prepared := part != "intent" || isPublishedStage(suffix)
				decided := part == "confirm" || part == "authority" && isPublishedStage(suffix)
				confirmed := part == "confirm" && isPublishedStage(suffix)
				for range 2 {
					reopenArchiveSecondary(t, p)
					checkRecoveredCoordination(t, p.operations[1].Coordinator, entry, before, after, prepared, decided, confirmed)
					if !reflect.DeepEqual(terminal, pruneSnapshot(t, p.f.executor)) {
						t.Fatal("completion recovery changed terminal executor")
					}
				}
				result, err := completeArchiveSecondary(t.Context(), p, entry)
				if err != nil || result.Appended == decided || result.Snapshot.Pending != 0 || testCoordination(t, p.operations[1].Coordinator).Pending != nil {
					t.Fatal("exact retry failed to confirm completion", err)
				}
			})
		}
	}
}

func TestArchiveSecondaryCompletionInventoryFenceAndConcurrency(t *testing.T) {
	for _, mode := range []string{"missing", "changed", "cancelled"} {
		p, _ := archiveSecondaryTerminalFixture(t, "cancelled", nil)
		entry := archiveSecondaryCompletionEntry(t, p)
		before := testCoordination(t, p.operations[1].Coordinator)
		ctx, cancel := context.WithCancel(t.Context())
		p.f.executor.hooks.at = func(at string) error {
			if at == "archive-secondary-complete-before-inventory-sync" {
				if mode == "changed" {
					writeTestFile(t, p.inventoryPath, []byte("changed"))
				} else if mode == "missing" {
					return os.Rename(p.inventoryPath, p.inventoryPath+".retained")
				}
			}
			if at == "archive-secondary-complete-inventory-synced" && mode == "cancelled" {
				cancel()
			}
			return nil
		}
		if result, err := completeArchiveSecondary(ctx, p, entry); err == nil || !reflect.DeepEqual(result, Commit{}) {
			t.Fatal("inventory fence acknowledged completion", err)
		}
		cancel()
		if !reflect.DeepEqual(before, testCoordination(t, p.operations[1].Coordinator)) {
			t.Fatal("pre-write fence changed authority")
		}
	}
	p, _ := archiveSecondaryTerminalFixture(t, "cancelled", nil)
	entry := archiveSecondaryCompletionEntry(t, p)
	var group sync.WaitGroup
	results := make(chan Commit, 8)
	for range 8 {
		group.Go(func() {
			result, err := completeArchiveSecondary(t.Context(), p, entry)
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
		if result.Snapshot.Pending != 0 {
			t.Fatal("concurrent retry failed to drain")
		}
	}
	if appended != 1 || testCoordination(t, p.operations[1].Coordinator).Authority.Sequence != 2 {
		t.Fatal("concurrent completion duplicated authority decisions")
	}
	if _, err := p.f.executor.CompletePreparedArchiveSecondary(t.Context(), nil, p.inventoryPath, p.inventoryID, p.policyID, entry); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := (*PruneExecutor)(nil).CompletePreparedArchiveSecondary(t.Context(), p.operations[1].Coordinator, p.inventoryPath, p.inventoryID, p.policyID, entry); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := p.operations[1].Coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := completeArchiveSecondary(t.Context(), p, entry); !errors.Is(err, ErrClosed) {
		t.Fatal("closed owner reused", err)
	}
}

func TestArchiveSecondaryCompletionCancellationInventorySemantics(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		p, inventory := archiveSecondaryTerminalFixture(t, outcome, nil)
		entry := archiveSecondaryCompletionEntry(t, p)
		inventory.Mode = ArchivePruneLineage
		p.inventoryID, _ = inventory.ID()
		p.policyID, _ = inventory.PolicyID()
		p.inventoryPath = filepath.Join(t.TempDir(), "reviewed-lineage.ompi")
		if err := SaveArchivePruneInventoryFile(p.inventoryPath, inventory, p.inventoryID, p.policyID); err != nil {
			t.Fatal(err)
		}
		before := pruneSnapshot(t, p.f.executor)
		result, err := completeArchiveSecondary(t.Context(), p, entry)
		if outcome == "succeeded" {
			if !errors.Is(err, ErrPruneInventory) || !reflect.DeepEqual(result, Commit{}) || testCoordination(t, p.operations[1].Coordinator).Authority.Pending != 1 {
				t.Fatal("success acquired a different inventory binding", err)
			}
		} else if err != nil || !result.Appended || result.Snapshot.Pending != 0 {
			t.Fatal("same-request cancellation incorrectly required an inventory start binding", err)
		}
		if !reflect.DeepEqual(before, pruneSnapshot(t, p.f.executor)) {
			t.Fatal("completion changed executor inventory history")
		}
	}
}

func TestArchiveSecondaryCompletionAfterRetainedAdmissionRecovery(t *testing.T) {
	p, inventory := newArchiveSecondaryFixture(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	setCoordinatorHooks(p.operations[1].Coordinator, storeHooks{at: func(at string) error {
		if at == "intent-after-apply" {
			cancel()
		}
		return nil
	}})
	_, err := admitArchiveSecondary(ctx, p, inventory)
	cancel()
	if !errors.Is(err, ErrPendingAttempt) {
		t.Fatal("secondary intent was not retained", err)
	}
	setCoordinatorHooks(p.operations[1].Coordinator, storeHooks{})
	if _, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator); err != nil {
		t.Fatal(err)
	}
	if _, err := p.f.executor.Complete(t.Context(), p.f.coordinator, pruneCompletionEntry(t, p.f)); err != nil {
		t.Fatal(err)
	}
	terminal := pruneSnapshot(t, p.f.executor)
	entry := archiveSecondaryCompletionEntry(t, p)
	if _, err := completeArchiveSecondary(t.Context(), p, entry); !errors.Is(err, ErrPendingAttempt) {
		t.Fatal("completion displaced the retained admission intent", err)
	}
	if result, err := admitArchiveSecondary(t.Context(), p, inventory); err != nil || !result.Appended {
		t.Fatal("exact admission recovery after primary drain failed", err)
	}
	entry = archiveSecondaryCompletionEntry(t, p)
	if result, err := completeArchiveSecondary(t.Context(), p, entry); err != nil || !result.Appended || result.Snapshot.Pending != 0 {
		t.Fatal("recovered secondary could not drain with cancellation", err)
	}
	if !reflect.DeepEqual(terminal, pruneSnapshot(t, p.f.executor)) {
		t.Fatal("secondary reconciliation changed terminal executor")
	}
}
