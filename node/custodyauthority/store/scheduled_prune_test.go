package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type scheduledPruneFixture struct {
	archive     *archivePruneFixture
	inventory   ScheduledPruneInventory
	id          types.Hash
	path        string
	sources     []ScheduledPruneSource
	operations  []RequiredOperation
	executor    *PruneExecutor
	migrationID types.Hash
}

func TestCustodyScheduledPruneAfterRadixActivation(t *testing.T) {
	f := newScheduledPruneFixture(t)
	p := f.archive.f
	for {
		tip, err := p.chain.Tip()
		if err != nil {
			t.Fatal(err)
		}
		if tip.Height > p.parameters.RadixActivationHeight {
			break
		}
		at := tip.Timestamp + p.parameters.TargetSpacing
		payload, _, err := p.chain.Prepare(tip.ID, at, nil)
		if err != nil {
			t.Fatal(err)
		}
		inclusion, _ := workgraph.InclusionRoot(nil)
		template, err := payload.SealTemplate(types.Address(testHash(150)), inclusion, nil)
		if err != nil {
			t.Fatal(err)
		}
		anchor, _, err := workgraph.MineAnchor(t.Context(), template, 0)
		if err != nil {
			t.Fatal(err)
		}
		block, _, err := payload.Finalize(anchor, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.chain.Commit(block, at); err != nil {
			t.Fatal(err)
		}
	}
	before, err := p.chain.Snapshot()
	if err != nil || before.CommitmentVersion() != state.CommitmentRadixV1 {
		t.Fatal("did not cross activation", err)
	}
	if _, err := f.execute(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := p.chain.Close(); err != nil {
		t.Fatal(err)
	}
	p.chain, err = workchain.OpenRadixMigratedPositionPinnedWithPolicy(p.chainPath, p.chainPositionPinsPath, p.base, p.parameters, p.policy, p.request.StorageID, f.migrationID)
	if err != nil {
		t.Fatal("cold activated storage", err)
	}
	after, err := p.chain.Snapshot()
	if err != nil || after.Root() != before.Root() || after.CommitmentVersion() != state.CommitmentRadixV1 || !reflect.DeepEqual(after.Resources(), before.Resources()) {
		t.Fatal("pruning changed radix resources", err)
	}
}

func newScheduledPruneFixture(t testing.TB, fence ...prunefence.Policy) *scheduledPruneFixture {
	t.Helper()
	p, original, cp := scheduledQuorumFixture(t)
	f := &scheduledPruneFixture{archive: p, path: filepath.Join(t.TempDir(), "scheduled.inventory")}
	v := ScheduledPruneInventory{Checkpoint: cp, OriginalPolicy: p.policy.CheckpointPolicy, ReplicaPolicy: p.policy.ReplicaPolicy}
	var evidence []workarchive.ScheduledReplicaEvidence
	var receipts []workarchive.ScheduledReplicaReceipt
	for i, s := range original {
		evidence = append(evidence, workarchive.ScheduledReplicaEvidence{Proof: s.Schedule.Proof, Lineage: p.lineages[i]})
		receipts = append(receipts, s.Receipt)
	}
	now := p.f.request.Boundary.VerifiedAt
	bundle, err := workarchive.CreateScheduledAvailabilityBundle(t.Context(), cp, p.policy.CheckpointPolicy, p.policy.ReplicaPolicy, p.policy.Assignments, evidence, receipts, now)
	if err != nil {
		t.Fatal(err)
	}
	bid, _ := bundle.ID()
	sid, _ := cp.Statement.ID()
	retain := receipts[0].Original.RetainUntil
	for _, r := range receipts {
		retain = min(retain, r.Original.RetainUntil)
	}
	v.Request = PruneRequest{AssignmentID: original[0].AssignmentID, ScheduleID: original[0].Schedule.ExpectedID, ConsumerPublicKey: testPublic(4), StorageID: p.f.request.StorageID, Boundary: workchain.CanonicalFloor{Pruned: true, RadixActivationHeight: cp.Statement.RadixActivationHeight, BaseID: cp.Statement.BaseID, Anchor: cp.Statement.Anchor, AncestryNodes: cp.Statement.AncestryNodes, AncestryRoot: cp.Statement.AncestryRoot, StatementID: sid, ManifestID: cp.Statement.ArchiveManifestID, AvailabilityID: bid, VerifiedAt: now, RetainUntil: retain}}
	if len(fence) == 1 {
		v.FencePolicy = &fence[0]
		v.Request.FencePolicyID, _ = fence[0].ID()
	}
	rid, _ := v.Request.ID()
	f.executor, err = CreatePinnedPruneExecutor(filepath.Join(t.TempDir(), "executor"), filepath.Join(t.TempDir(), "executor-pins"), original[0].Assignment, v.Request, rid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.executor.Close() })
	v.ExecutorBindingID = pruneSnapshot(t, f.executor).Protection.BindingID
	review, err := p.f.chain.ReviewRadixSchedule(t.Context(), cp.Statement.RadixActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	f.migrationID = review.ID()
	if _, err := p.f.chain.MigrateRadixSchedule(t.Context(), cp.Statement.RadixActivationHeight, f.migrationID); err != nil {
		t.Fatal(err)
	}
	protection, err := p.f.chain.StorageProtection()
	if err != nil {
		t.Fatal(err)
	}
	v.StoragePairID = protection.PairID
	for i, s := range original {
		directory := filepath.Join(t.TempDir(), "radix-archive")
		if _, _, err := workarchive.MigrateRadixArchiveDirectory(p.replicas[i].Directory, directory, p.policy.Checkpoint, cp, p.policy.CheckpointPolicy, p.f.base, p.f.parameters, workarchive.DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		owner, err := OpenCoordinator(s.AuthorityPath, s.AuthorityPinsPath, s.Assignment, s.AssignmentID)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { owner.Close() })
		draft, err := BuildScheduledPruneAdmission(s.Assignment, s.Schedule.Proof, s.Schedule.Policy, v.Request, testCoordination(t, owner).Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		entry := managedCommandApplyTestSign(t, draft)
		if i == 0 {
			if _, err := f.executor.Admit(t.Context(), owner, entry); err != nil {
				t.Fatal(err)
			}
		} else {
			appendCoordinated(t, owner, entry)
		}
		ticket, _ := entry.ID()
		f.operations = append(f.operations, RequiredOperation{Coordinator: owner, Binding: OperationBinding{AssignmentID: s.AssignmentID, ScheduleID: s.Schedule.ExpectedID, TicketID: ticket, ConsumerPublicKey: v.Request.ConsumerPublicKey, OperationID: rid, Purpose: custodyauthority.Prune}})
		v.Replicas = append(v.Replicas, ScheduledPruneReplica{Assignment: s.Assignment, Proof: s.Schedule.Proof, Receipt: s.Receipt, Admission: entry})
		f.sources = append(f.sources, ScheduledPruneSource{AssignmentID: s.AssignmentID, Directory: directory, JournalPath: s.JournalPath, CustodyPolicy: s.CustodyPolicy, JournalLimits: s.JournalLimits})
	}
	p.f.parameters.RadixActivationHeight = cp.Statement.RadixActivationHeight
	f.inventory = v
	f.id, err = v.ID()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveScheduledPruneInventory(t.Context(), f.path, v, f.id); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *scheduledPruneFixture) execute(ctx context.Context) (workchain.CanonicalPruneCommit, error) {
	return f.executor.ExecuteScheduledArchive(ctx, f.archive.f.chain, f.path, f.id, f.operations, f.sources, f.archive.f.base, f.archive.f.parameters, workarchive.DefaultLimits())
}
func TestCustodyScheduledPrunePreservesOriginalAccountingAndColdState(t *testing.T) {
	f := newScheduledPruneFixture(t)
	p := f.archive.f
	before, err := p.chain.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	tip, err := p.chain.Tip()
	if err != nil {
		t.Fatal(err)
	}
	var obligations []custodyauthority.Snapshot
	for _, op := range f.operations {
		obligations = append(obligations, testCoordination(t, op.Coordinator).Authority)
	}
	if _, err := f.executor.Execute(t.Context(), f.operations[0].Coordinator, p.chain, func() (uint64, error) { return f.inventory.Request.Boundary.VerifiedAt, nil }); !errors.Is(err, ErrPruneArchivePolicy) {
		t.Fatal("legacy execution adopted schedule", err)
	}
	result, err := f.execute(t.Context())
	if err != nil || !result.Applied || result.Effect.Report.RemovedNodes == 0 {
		t.Fatal("scheduled prune", err)
	}
	if result.Effect.Operation.ScheduleID != f.inventory.Request.ScheduleID || result.Effect.Operation.Boundary.RadixActivationHeight != p.parameters.RadixActivationHeight {
		t.Fatal("effect lost schedule")
	}
	for i, op := range f.operations {
		if !reflect.DeepEqual(obligations[i], testCoordination(t, op.Coordinator).Authority) {
			t.Fatal("execution completed or reset obligations")
		}
	}
	if _, err := f.execute(t.Context()); !errors.Is(err, ErrPruneStage) {
		t.Fatal("executed twice", err)
	}
	if err := p.chain.Close(); err != nil {
		t.Fatal(err)
	}
	p.chain, err = workchain.OpenRadixMigratedPositionPinnedWithPolicy(p.chainPath, p.chainPositionPinsPath, p.base, p.parameters, p.policy, p.request.StorageID, f.migrationID)
	if err != nil {
		t.Fatal("cold storage", err)
	}
	after, err := p.chain.Snapshot()
	if err != nil || after.Root() != before.Root() {
		t.Fatal("pruning changed resource accounting", err)
	}
	afterTip, _ := p.chain.Tip()
	if afterTip.ID != tip.ID {
		t.Fatal("pruning changed tip")
	}
	floor, _ := p.chain.CanonicalFloor()
	if floor.RadixActivationHeight != p.parameters.RadixActivationHeight {
		t.Fatal("floor lost schedule")
	}
	recovered, err := f.executor.Recover(t.Context(), p.chain)
	if err != nil || recovered.Applied || !reflect.DeepEqual(recovered.Effect, result.Effect) {
		t.Fatal("recovery refreshed effect", err)
	}
	effectID, _ := result.Effect.ID()
	for i, op := range f.operations {
		pos := testCoordination(t, op.Coordinator).Confirmed
		c, err := (custodyauthority.Command{Version: custodyauthority.ScheduleVersion2, ScheduleID: op.Binding.ScheduleID, AssignmentID: op.Binding.AssignmentID, ExpectedSequence: pos.Sequence, ExpectedHead: pos.HeadID, Kind: custodyauthority.Complete, TicketID: op.Binding.TicketID, EvidenceID: effectID}).Sign(testKey(4))
		if err != nil {
			t.Fatal(err)
		}
		entry, err := custodyauthority.SignEntry(c, testKey(1))
		if err != nil {
			t.Fatal(err)
		}
		for retry := 0; retry < 2; retry++ {
			commit, err := f.executor.CompleteScheduledArchiveReplica(t.Context(), op.Coordinator, f.path, f.id, entry)
			if err != nil || commit.Appended != (retry == 0) {
				t.Fatal("completion retry", err)
			}
		}
		snap := testCoordination(t, op.Coordinator).Authority
		if snap.Pending != obligations[i].Pending-1 || len(snap.Operations) != len(obligations[i].Operations) {
			t.Fatal("completion reset old obligations")
		}
	}
}
