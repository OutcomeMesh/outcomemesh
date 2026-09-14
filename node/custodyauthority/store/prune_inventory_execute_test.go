package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func retainArchiveInventory(t testing.TB, p *archivePruneFixture) ArchivePruneInventory {
	t.Helper()
	prepared := archiveInventoryFixture(t, p)
	p.inventoryPath = filepath.Join(t.TempDir(), "prepared.ompi")
	p.inventoryID, _ = prepared.ID()
	if err := SaveArchivePruneInventoryFile(p.inventoryPath, prepared, p.inventoryID, p.policyID); err != nil {
		t.Fatal(err)
	}
	return prepared
}

func inspectPreparedArchive(t testing.TB, p *archivePruneFixture) PruneExecution {
	t.Helper()
	state, err := p.f.executor.InspectArchiveInventory(p.inventoryPath, p.inventoryID, p.policyID)
	if err != nil {
		t.Fatal(err)
	}
	if state.ArchiveInventoryID != p.inventoryID || state.Protection == nil || state.Protection.Pending != nil {
		t.Fatal("lost confirmed inventory binding")
	}
	return state
}

func TestPreparedArchiveExecutionBindsBothModes(t *testing.T) {
	for _, mode := range []string{"initial", "lineage"} {
		t.Run(mode, func(t *testing.T) {
			var p *archivePruneFixture
			if mode == "lineage" {
				p = newArchivePruneFixtureWithRenewals(t, []int{2, 1})
			} else {
				p = newArchivePruneFixture(t)
			}
			retainArchiveInventory(t, p)
			if _, err := p.f.executor.InspectArchiveInventory(p.inventoryPath, p.inventoryID, p.policyID); err == nil {
				t.Fatal("prepared package certified execution")
			}
			// Exact matching is independent of caller order, unlike retained codec order.
			p.operations[0], p.operations[1] = p.operations[1], p.operations[0]
			p.replicas[0], p.replicas[1] = p.replicas[1], p.replicas[0]
			result, err := p.execute(t.Context())
			if err != nil || !result.Applied || result.Effect.Report.RemovedNodes == 0 {
				t.Fatal("bound archive did not execute", err)
			}
			state := inspectPreparedArchive(t, p)
			if state.Stage != PruneSucceeded || state.Effect == nil || !reflect.DeepEqual(*state.Effect, result.Effect) {
				t.Fatal("missing exact succeeded effect")
			}
			ticket, _ := state.Admission.ID()
			want := pruneInventoryStartedBytes(p.f.id, ticket, p.inventoryID)
			for _, path := range []string{filepath.Join(p.f.executorPath, pruneRecordsName, pruneRecordNames[1]), filepath.Join(p.f.executorPinsPath, intentsName, pruneRecordNames[1])} {
				encoded, err := readRegular(path, workchain.MaximumCanonicalPruneEffectBytes)
				if err != nil || !bytes.Equal(want, encoded) {
					t.Fatal("start binding absent from one journal", err)
				}
			}
			if _, err := p.execute(t.Context()); !errors.Is(err, ErrPruneStage) {
				t.Fatal("repeated bound execution", err)
			}
			for _, operation := range p.operations {
				s := testCoordination(t, operation.Coordinator)
				if s.Authority.Pending != 1 || s.Authority.Sequence != 1 || s.Pending != nil {
					t.Fatal("automatic secondary completion")
				}
			}
			if err := p.f.executor.Close(); err != nil {
				t.Fatal(err)
			}
			p.f.executor, err = OpenPinnedPruneExecutor(p.f.executorPath, p.f.executorPinsPath, p.policy.Assignments[0], p.f.id)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.f.executor.Close() })
			if reopened := inspectPreparedArchive(t, p); !reflect.DeepEqual(reopened, state) {
				t.Fatal("reopen changed inventory provenance")
			}
			before, _, err := p.f.chain.HistoryUsage()
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := p.f.executor.Recover(t.Context(), p.f.chain)
			if err != nil || recovered.Applied || !reflect.DeepEqual(recovered.Effect, result.Effect) {
				t.Fatal("recovery repeated effect", err)
			}
			after, _, err := p.f.chain.HistoryUsage()
			if err != nil || before != after {
				t.Fatal("inspection/recovery changed storage", err)
			}
		})
	}
}

func TestPreparedArchiveRejectsBeforeStart(t *testing.T) {
	for _, mode := range []string{"wrong-inventory-pin", "wrong-policy-pin", "missing-package", "corrupt-package", "package-overlap", "different-pair", "different-ticket", "different-receipt", "completed-secondary", "initial-with-lineage", "lineage-without-proof", "cancelled", "nil-context"} {
		t.Run(mode, func(t *testing.T) {
			var p *archivePruneFixture
			if mode == "lineage-without-proof" {
				p = newArchivePruneFixtureWithRenewals(t, []int{1, 1})
			} else {
				p = newArchivePruneFixture(t)
			}
			prepared := retainArchiveInventory(t, p)
			ctx := t.Context()
			switch mode {
			case "wrong-inventory-pin":
				p.inventoryID = testHash(99)
			case "wrong-policy-pin":
				p.policyID = testHash(99)
			case "missing-package":
				p.inventoryPath = filepath.Join(t.TempDir(), "missing")
			case "corrupt-package":
				writeTestFile(t, p.inventoryPath, []byte("damaged"))
			case "package-overlap":
				// Valid retained package in a replica tree, not an owned DB/journal.
				p.inventoryPath = filepath.Join(p.replicas[0].Directory, "prepared.ompi")
				if err := SaveArchivePruneInventoryFile(p.inventoryPath, prepared, p.inventoryID, p.policyID); err != nil {
					t.Fatal(err)
				}
			case "different-pair":
				prepared.Policy.ExecutorBindingID = testHash(99)
				p.policyID, _ = prepared.PolicyID()
				p.inventoryID, _ = prepared.ID()
				p.inventoryPath = filepath.Join(t.TempDir(), "other.ompi")
				if err := SaveArchivePruneInventoryFile(p.inventoryPath, prepared, p.inventoryID, p.policyID); err != nil {
					t.Fatal(err)
				}
			case "different-ticket":
				// A different co-signed candidate in the package must not borrow
				// the real current ticket, even though both name the same request.
				c := p.operations[1].Coordinator
				s := testCoordination(t, c).Authority
				command := prepared.Admissions[1].Command
				command.ExpectedSequence, command.ExpectedHead = s.Sequence, s.HeadID
				command, err := command.Sign(testKey(4))
				if err != nil {
					t.Fatal(err)
				}
				entry, err := custodyauthority.SignEntry(command, testKey(1))
				if err != nil {
					t.Fatal(err)
				}
				prepared.Admissions[1] = entry
				p.inventoryID, _ = prepared.ID()
				p.inventoryPath = filepath.Join(t.TempDir(), "other-ticket.ompi")
				if err := SaveArchivePruneInventoryFile(p.inventoryPath, prepared, p.inventoryID, p.policyID); err != nil {
					t.Fatal(err)
				}
			case "different-receipt":
				p.replicas[1].Receipt = p.replicas[0].Receipt
			case "completed-secondary":
				c := p.operations[1].Coordinator
				appendCoordinated(t, c, testEntry(t, testCoordination(t, c).Authority, custodyauthority.Complete, types.Hash{}, p.operations[1].Binding.TicketID, testHash(98)))
			case "initial-with-lineage":
				p.lineages = []workarchive.CustodyReceiptLineage{{}}
			case "lineage-without-proof":
				p.lineages = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			}
			before := pruneSnapshot(t, p.f.executor)
			if result, err := p.execute(ctx); err == nil || result.Applied {
				t.Fatal("invalid prepared execution accepted", err)
			}
			if !reflect.DeepEqual(before, pruneSnapshot(t, p.f.executor)) {
				t.Fatal("rejection changed executor prefix")
			}
			if _, err := os.Stat(p.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected before replay but published evidence", err)
			}
		})
	}
}

func TestPreparedArchivePackageFenceAndStartRecovery(t *testing.T) {
	for _, stage := range []string{"package-changed", "package-missing", "cancel-after-sync", "pending-start-gap", "pending-start-present", "confirmed-start", "effect", "pending-result"} {
		t.Run(stage, func(t *testing.T) {
			p := newArchivePruneFixture(t)
			retainArchiveInventory(t, p)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fault := errors.New("controlled prepared-archive interruption")
			hook := func(at string) error {
				if at == "archive-before-start" {
					if stage == "package-changed" {
						writeTestFile(t, p.inventoryPath, []byte("changed after replay"))
					}
					if stage == "package-missing" {
						if err := os.Rename(p.inventoryPath, p.inventoryPath+".saved"); err != nil {
							t.Fatal(err)
						}
					}
				}
				if stage == "cancel-after-sync" && at == "archive-inventory-synced" {
					cancel()
				}
				want := map[string]string{"pending-start-gap": "pins-start-intent-after-publish", "pending-start-present": "prune-start-after-publish",
					"confirmed-start": "prune-before-effect", "effect": "prune-after-effect", "pending-result": "pins-result-confirm-before-publish"}[stage]
				if want != "" && at == want {
					return fault
				}
				return nil
			}
			p.f.executor.hooks, p.f.executor.pins.hooks = storeHooks{at: hook}, storeHooks{at: hook}
			if _, err := p.execute(ctx); err == nil {
				t.Fatal("missed interruption")
			}
			_ = p.f.executor.Close()
			var err error
			p.f.executor, err = OpenPinnedPruneExecutor(p.f.executorPath, p.f.executorPinsPath, p.policy.Assignments[0], p.f.id)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.f.executor.Close() })
			state := pruneSnapshot(t, p.f.executor)
			if stage == "package-changed" || stage == "package-missing" || stage == "cancel-after-sync" {
				if state.Stage != PruneAdmitted || !state.ArchiveInventoryID.IsZero() || state.Protection.Pending != nil {
					t.Fatal("pre-start rejection created bound start")
				}
				return
			}
			if state.Protection.Pending != nil {
				if _, err := p.f.executor.InspectArchiveInventory(p.inventoryPath, p.inventoryID, p.policyID); !errors.Is(err, ErrPrunePinPending) {
					t.Fatal("pending provenance presented confirmed", err)
				}
				if err := p.f.executor.ResumePinnedTransition(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			state = inspectPreparedArchive(t, p)
			hasEffect := stage == "effect" || stage == "pending-result"
			if _, err := p.execute(t.Context()); err == nil {
				t.Fatal("recovered start re-executed")
			}
			before, _, err := p.f.chain.HistoryUsage()
			if err != nil {
				t.Fatal(err)
			}
			result, err := p.f.executor.Recover(t.Context(), p.f.chain)
			if hasEffect {
				if err != nil || result.Applied || inspectPreparedArchive(t, p).Stage != PruneSucceeded {
					t.Fatal("positive recovery lost binding", err)
				}
			} else if !errors.Is(err, ErrPruneOutcome) || state.Stage != PruneStarted {
				t.Fatal("absence resolved an unknown start", err)
			}
			after, _, err := p.f.chain.HistoryUsage()
			if err != nil || before != after {
				t.Fatal("recovery repeated deletion", err)
			}
		})
	}
}

func TestPreparedArchiveCannotRelabelOldExecution(t *testing.T) {
	p := newArchivePruneFixture(t)
	retainArchiveInventory(t, p)
	path := p.inventoryPath
	p.inventoryPath = "" // old ExecuteArchive, no inventory binding
	if _, err := p.execute(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !pruneSnapshot(t, p.f.executor).ArchiveInventoryID.IsZero() {
		t.Fatal("old path acquired inventory provenance")
	}
	if _, err := p.f.executor.InspectArchiveInventory(path, p.inventoryID, p.policyID); !errors.Is(err, ErrPruneInventory) {
		t.Fatal("old effect certified a package retroactively", err)
	}
	if _, err := p.f.executor.Recover(t.Context(), p.f.chain); err != nil {
		t.Fatal(err)
	}
	if _, err := p.f.executor.InspectArchiveInventory(path, p.inventoryID, p.policyID); !errors.Is(err, ErrPruneInventory) {
		t.Fatal("recovery retrofitted inventory", err)
	}
}

func TestPreparedArchiveRefusesPreexistingStorageEffect(t *testing.T) {
	for _, afterReplay := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-call", true: "after-replay"}[afterReplay], func(t *testing.T) {
			p := newArchivePruneFixture(t)
			retainArchiveInventory(t, p)
			applyRaw := func() {
				ticket, _ := p.f.admission.ID()
				result, err := p.f.chain.PruneCanonicalPrefixOnce(workchain.CanonicalPruneOperation{
					AssignmentID: p.f.request.AssignmentID, TicketID: ticket, StorageID: p.f.request.StorageID, Boundary: p.f.request.Boundary},
					func() (uint64, error) { return uint64(time.Now().Unix()), nil })
				if err != nil || !result.Applied {
					t.Fatal("fixture effect", err)
				}
			}
			if afterReplay {
				p.f.executor.hooks.at = func(at string) error {
					if at == "archive-before-start" {
						applyRaw()
					}
					return nil
				}
			} else {
				applyRaw()
			}
			if _, err := p.execute(t.Context()); !errors.Is(err, ErrPruneInventory) {
				t.Fatal("old database effect relabelled as managed execution", err)
			}
			state := pruneSnapshot(t, p.f.executor)
			if state.Stage != PruneAdmitted || !state.ArchiveInventoryID.IsZero() || state.Protection.Pending != nil {
				t.Fatal("cached effect acquired a bound start")
			}
		})
	}
}

func TestPruneInventoryStartCodecAndBinding(t *testing.T) {
	r := purePruneRequest(t)
	id, _ := r.ID()
	ticket, inventoryID := testHash(70), testHash(71)
	old, bound := pruneStartedBytes(id, ticket), pruneInventoryStartedBytes(id, ticket, inventoryID)
	if len(old) != 74 || len(bound) != 106 || !bytes.Equal(old, pruneInventoryStartedBytes(id, ticket, types.Hash{})) {
		t.Fatal("start versions changed")
	}
	for _, value := range []struct {
		encoded []byte
		want    types.Hash
	}{{old, types.Hash{}}, {bound, inventoryID}} {
		got, err := decodePruneInventoryStart(value.encoded, id, ticket)
		if err != nil || got != value.want {
			t.Fatal("start binding roundtrip", err)
		}
	}
	for n := range len(bound) {
		if _, err := decodePruneInventoryStart(bound[:n], id, ticket); err == nil {
			t.Fatal("truncated start accepted", n)
		}
	}
	zero := bytes.Clone(bound)
	clear(zero[74:])
	version := bytes.Clone(bound)
	version[9] = 2
	for _, bad := range [][]byte{zero, version, append(bytes.Clone(bound), 0), pruneInventoryStartedBytes(id, testHash(99), inventoryID)} {
		if _, err := decodePruneInventoryStart(bad, id, ticket); err == nil {
			t.Fatal("bad bound start accepted")
		}
	}
	state := PruneExecution{Request: r, Stage: PruneStarted, ArchiveInventoryID: inventoryID}
	if checkPruneExecutionBinding(state, testHash(90)) == nil {
		t.Fatal("unbound storage accepted")
	}
	state.Request.StorageID = testHash(91)
	if checkPruneExecutionBinding(state, types.Hash{}) == nil {
		t.Fatal("raw journal accepted archive provenance")
	}
	if err := checkPruneExecutionBinding(state, testHash(90)); err != nil {
		t.Fatal(err)
	}
	position := PrunePosition{Stage: PruneAdmitted, HeadID: ticket}
	if nextPrunePosition(position, old) == nextPrunePosition(position, bound) || nextPrunePosition(position, bound) == nextPrunePosition(position, pruneInventoryStartedBytes(id, ticket, testHash(72))) {
		t.Fatal("protected head ignored inventory binding")
	}
}

func TestPreparedArchiveHoldsGuardsAndRejectsOneRootDowngrade(t *testing.T) {
	p := newArchivePruneFixture(t)
	retainArchiveInventory(t, p)
	reached := false
	p.f.executor.hooks.at = func(at string) error {
		if at != "archive-inventory-synced" {
			return nil
		}
		reached = true
		for _, operation := range p.operations {
			if operation.Coordinator.mu.TryLock() {
				operation.Coordinator.mu.Unlock()
				t.Error("inventory fence released required guard")
			}
		}
		return nil
	}
	if _, err := p.execute(t.Context()); err != nil || !reached {
		t.Fatal("guarded inventory fence not reached", err)
	}
	state := inspectPreparedArchive(t, p)
	if err := p.f.executor.Close(); err != nil {
		t.Fatal(err)
	}
	ticket, _ := state.Admission.ID()
	startPath := filepath.Join(p.f.executorPath, pruneRecordsName, pruneRecordNames[1])
	writeTestFile(t, startPath, pruneStartedBytes(p.f.id, ticket))
	other, err := OpenPinnedPruneExecutor(p.f.executorPath, p.f.executorPinsPath, p.policy.Assignments[0], p.f.id)
	if other != nil {
		_ = other.Close()
	}
	if err == nil {
		t.Fatal("one-root downgrade erased protected inventory history")
	}
}
