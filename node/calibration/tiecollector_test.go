package calibration

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestTieCollectorCompletesValidPairAndClosesEveryOtherSlot(t *testing.T) {
	collector, config := testTieCollector(t, testStartedAt)
	plan := config.Plan
	tested := liveTieAdmission(plan, 0, plan.TestedMiner, "tested-a", types.Hash{})
	tested.SelectedID = tested.ID
	if added, err := collector.Observe(tested); err != nil || !added {
		t.Fatalf("tested admission added=%t err=%v", added, err)
	}
	if added, err := collector.Observe(tested); err != nil || added {
		t.Fatalf("duplicate admission added=%t err=%v", added, err)
	}
	control := liveTieAdmission(plan, 0, plan.ControlMiner, "control-a", tested.ID)
	if added, err := collector.Observe(control); err != nil || !added {
		t.Fatalf("control admission added=%t err=%v", added, err)
	}
	status, err := collector.Status()
	if err != nil || status.ClosedSlots != 1 || status.CompletedTrials != 1 || status.NoPairSlots != 0 ||
		status.NextSequence != 2 || status.Complete {
		t.Fatalf("pair status=%+v err=%v", status, err)
	}

	// Slot two has no pair. The fixed grace prevents an in-flight admission
	// observed before the boundary from losing a race with the timer.
	if err := collector.Advance(plan.Slots[1].EndedAt + TieReceiptClosureGraceSeconds - 1); err != nil {
		t.Fatal(err)
	}
	status, _ = collector.Status()
	if status.ClosedSlots != 1 {
		t.Fatalf("slot closed before grace: %+v", status)
	}
	if err := collector.Advance(plan.Slots[1].EndedAt + TieReceiptClosureGraceSeconds); err != nil {
		t.Fatal(err)
	}

	// Multiple anchors for one precommitted role invalidate slot three. It is
	// explicitly closed as NoPair rather than choosing a favorable candidate.
	firstTested := liveTieAdmission(plan, 2, plan.TestedMiner, "tested-c-1", types.Hash{})
	firstTested.SelectedID = firstTested.ID
	if _, err := collector.Observe(firstTested); err != nil {
		t.Fatal(err)
	}
	secondTested := liveTieAdmission(plan, 2, plan.TestedMiner, "tested-c-2", types.Hash{})
	secondTested.SelectedID = secondTested.ID
	if _, err := collector.Observe(secondTested); err != nil {
		t.Fatal(err)
	}
	thirdControl := liveTieAdmission(plan, 2, plan.ControlMiner, "control-c", firstTested.ID)
	if _, err := collector.Observe(thirdControl); err != nil {
		t.Fatal(err)
	}
	status, _ = collector.Status()
	if !status.InvalidCurrent {
		t.Fatalf("ambiguous role was not marked invalid: %+v", status)
	}
	if err := collector.Advance(plan.Slots[2].EndedAt + TieReceiptClosureGraceSeconds); err != nil {
		t.Fatal(err)
	}
	status, err = collector.Status()
	if err != nil || !status.Complete || status.ClosedSlots != 3 || status.CompletedTrials != 1 ||
		status.NoPairSlots != 2 || status.NextSequence != 4 {
		t.Fatalf("complete status=%+v err=%v", status, err)
	}
	_, receipts, aggregate, err := LoadTieReceiptFile(config.ReceiptPath, plan.Binding())
	if err != nil {
		t.Fatal(err)
	}
	adoptions, trials, err := aggregate.EvidenceCounters()
	if err != nil || len(receipts) != 3 || receipts[0].SelectedAnchorID != tested.ID ||
		adoptions != 3 || trials != 3 {
		t.Fatalf("receipts=%+v aggregate=%+v counters=%d/%d err=%v", receipts, aggregate, adoptions, trials, err)
	}
}

func TestTieCollectorRestartsPartialPairAndReconcilesReceiptCommit(t *testing.T) {
	collector, config := testTieCollector(t, testStartedAt)
	plan := config.Plan
	tested := liveTieAdmission(plan, 0, plan.TestedMiner, "restart-tested", types.Hash{})
	tested.SelectedID = tested.ID
	if _, err := collector.Observe(tested); err != nil {
		t.Fatal(err)
	}
	stalePending, err := os.ReadFile(config.PendingPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.Close(tested.ObservedAt); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenTieCollector(config, tested.ObservedAt+1)
	if err != nil {
		t.Fatal(err)
	}
	control := liveTieAdmission(plan, 0, plan.ControlMiner, "restart-control", tested.ID)
	if _, err := restarted.Observe(control); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.PendingPath, stalePending, 0o600); err != nil {
		t.Fatal(err)
	}
	reconciled, err := OpenTieCollector(config, control.ObservedAt+1)
	if err != nil {
		t.Fatal(err)
	}
	status, err := reconciled.Status()
	if err != nil || status.ClosedSlots != 1 || status.NextSequence != 2 || status.InvalidCurrent {
		t.Fatalf("reconciled status=%+v err=%v", status, err)
	}
	pending, err := loadTiePending(config.PendingPath, plan, reconciled.planID)
	if err != nil || pending.Sequence != 2 || pending.PreviousID != status.LastReceiptID ||
		pending.Tested.Present || pending.Control.Present {
		t.Fatalf("reconciled pending=%+v err=%v", pending, err)
	}
}

func TestTieCollectorRecoversPairPersistedBeforeReceiptWrite(t *testing.T) {
	collector, config := testTieCollector(t, testStartedAt)
	plan := config.Plan
	tested := liveTieAdmission(plan, 0, plan.TestedMiner, "write-fault-tested", types.Hash{})
	tested.SelectedID = tested.ID
	if _, err := collector.Observe(tested); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(config.ReceiptPath, 0o700); err != nil {
		t.Fatal(err)
	}
	control := liveTieAdmission(plan, 0, plan.ControlMiner, "write-fault-control", tested.ID)
	if _, err := collector.Observe(control); err == nil {
		t.Fatal("receipt rename fault was accepted")
	}
	if err := os.Remove(config.ReceiptPath); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenTieCollector(config, control.ObservedAt+1)
	if err != nil {
		t.Fatal(err)
	}
	status, err := recovered.Status()
	if err != nil || status.ClosedSlots != 1 || status.CompletedTrials != 1 || status.NextSequence != 2 {
		t.Fatalf("recovered status=%+v err=%v", status, err)
	}
	_, receipts, _, err := LoadTieReceiptFile(config.ReceiptPath, plan.Binding())
	if err != nil || len(receipts) != 1 || receipts[0].SelectedAnchorID != tested.ID {
		t.Fatalf("recovered receipts=%+v err=%v", receipts, err)
	}
}

func TestTieCollectorRejectsClockRollbackAndMalformedAdmission(t *testing.T) {
	collector, config := testTieCollector(t, testStartedAt)
	if err := collector.Advance(testStartedAt - 1); !errors.Is(err, ErrClock) {
		t.Fatalf("clock rollback error=%v, want ErrClock", err)
	}
	if _, err := collector.Observe(TieAdmission{}); !errors.Is(err, ErrObservation) {
		t.Fatalf("malformed admission error=%v, want ErrObservation", err)
	}
	if err := collector.Close(testStartedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Status(); !errors.Is(err, ErrTieCollectorClosed) {
		t.Fatalf("closed status error=%v", err)
	}
	if _, err := OpenTieCollector(TieCollectorConfig{
		Plan: config.Plan, Binding: config.Binding, PrivateKey: testTieCoordinatorKey(),
		ReceiptPath: config.ReceiptPath, PendingPath: config.PendingPath,
	}, testStartedAt); !errors.Is(err, ErrTieCollectorConfig) {
		t.Fatalf("wrong observer key error=%v, want ErrTieCollectorConfig", err)
	}
}

func TestTieCollectorChargesWrongPrecommittedDeliveryOrderAsNoPair(t *testing.T) {
	collector, config := testTieCollector(t, testStartedAt)
	plan := config.Plan
	control := liveTieAdmission(plan, 0, plan.ControlMiner, "wrong-order-control", types.Hash{})
	control.SelectedID = control.ID
	if _, err := collector.Observe(control); err != nil {
		t.Fatal(err)
	}
	tested := liveTieAdmission(plan, 0, plan.TestedMiner, "wrong-order-tested", control.ID)
	if _, err := collector.Observe(tested); err != nil {
		t.Fatal(err)
	}
	status, err := collector.Status()
	if err != nil || !status.InvalidCurrent || status.ClosedSlots != 0 {
		t.Fatalf("wrong-order status=%+v err=%v", status, err)
	}
	if err := collector.Advance(plan.Slots[0].EndedAt + TieReceiptClosureGraceSeconds); err != nil {
		t.Fatal(err)
	}
	_, receipts, aggregate, err := LoadTieReceiptFile(config.ReceiptPath, plan.Binding())
	if err != nil || len(receipts) != 1 || receipts[0].Status != TieTrialNoPair ||
		aggregate.NoPairSlots != 1 || aggregate.ConservativeAdoptions != 1 {
		t.Fatalf("wrong-order receipts=%+v aggregate=%+v err=%v", receipts, aggregate, err)
	}
}

func TestTiePendingCanonicalRoundTripAndBounds(t *testing.T) {
	plan, _ := testTiePlan(t)
	planID, _ := plan.ID()
	pending := newTiePending(planID, 1, types.Hash{})
	pending.FirstRole = TieRoleTested
	pending.LatestSelectedID = types.DomainHash("test/tie-pending/selected")
	pending.Tested = tieCandidate{
		Present: true, ID: types.DomainHash("test/tie-pending/id"),
		ParentID: types.DomainHash("test/tie-pending/parent"), Height: plan.ActivationHeight,
		ObservedAt: plan.Slots[0].StartedAt, SelectedID: pending.LatestSelectedID,
	}
	encoded, err := pending.canonicalBytes(plan, planID)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeTiePending(encoded, plan, planID)
	if err != nil || decoded != pending {
		t.Fatalf("decoded pending=%+v err=%v", decoded, err)
	}
	legacy := append([]byte(nil), encoded...)
	legacy[len(tiePendingMagic)] = 0
	legacy[len(tiePendingMagic)+1] = 0
	if _, err := decodeTiePending(legacy, plan, planID); !errors.Is(err, ErrPending) {
		t.Fatalf("legacy pending error=%v", err)
	}
	if _, err := decodeTiePending(append(encoded, 0), plan, planID); !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("trailing pending error=%v", err)
	}
	if _, err := decodeTiePending(make([]byte, MaximumTiePendingBytes+1), plan, planID); !errors.Is(err, ErrPending) {
		t.Fatalf("oversize pending error=%v", err)
	}
}

func FuzzDecodeTiePendingNeverPanics(f *testing.F) {
	plan, _ := testTiePlan(f)
	planID, _ := plan.ID()
	pending := newTiePending(planID, 1, types.Hash{})
	encoded, err := pending.canonicalBytes(plan, planID)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = decodeTiePending(input, plan, planID)
	})
}

func testTieCollector(t testing.TB, now uint64) (*TieCollector, TieCollectorConfig) {
	t.Helper()
	plan, binding := testTiePlan(t)
	root := t.TempDir()
	config := TieCollectorConfig{
		Plan: plan, Binding: binding, PrivateKey: testTieObserverKey(),
		ReceiptPath: filepath.Join(root, "tie-receipts.omtr"),
		PendingPath: filepath.Join(root, "tie-receipts.pending"),
	}
	collector, err := OpenTieCollector(config, now)
	if err != nil {
		t.Fatal(err)
	}
	return collector, config
}

func liveTieAdmission(plan TiePlan, slotIndex int, miner types.Address, label string, selected types.Hash) TieAdmission {
	slot := plan.Slots[slotIndex]
	return TieAdmission{
		ID:       types.DomainHash("test/tie-collector/anchor/" + label),
		ParentID: types.DomainHash("test/tie-collector/parent", []byte{byte(slotIndex)}),
		Height:   plan.ActivationHeight + uint64(slotIndex), ObservedAt: slot.StartedAt + 2,
		Miner: miner, SelectedID: selected,
	}
}
