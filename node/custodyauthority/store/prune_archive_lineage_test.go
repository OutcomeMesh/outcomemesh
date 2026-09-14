package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func archiveFixtureLineage(t testing.TB, p *archivePruneFixture, manifest workarchive.Manifest, assignment custodyauthority.Assignment,
	replica workarchive.Replica, policy workarchive.CustodyPolicy, renewals int, now uint64,
) (workarchive.CustodyReceiptLineage, workarchive.ReplicaReceipt) {
	t.Helper()
	id, _ := assignment.ID()
	encoded, _ := manifest.CanonicalBytes()
	lineage := workarchive.CustodyReceiptLineage{AssignmentID: id, Manifest: encoded, InitialReceipt: replica.Receipt, Policy: policy}
	current := replica.Receipt
	objects, err := workarchive.OpenObjectStore(filepath.Join(t.TempDir(), "objects"), workarchive.DefaultObjectStorePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objects.ImportArchiveDirectory(replica.Directory, p.policy.Checkpoint, p.policy.CheckpointPolicy, p.f.base, p.f.parameters, workarchive.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	seed := byte(61)
	if current.ReplicaPublicKey != testPublic(seed) {
		seed = 62
	}
	var head types.Hash
	for i := 0; i < renewals; i++ {
		at := now - 100 + uint64(i)*10
		challenge, err := workarchive.CreateCustodyChallenge(manifest, current, testKey(3), at, 60, 1, current.RetainUntil+100)
		if err != nil {
			t.Fatal(err)
		}
		batch, proof, err := workarchive.AnswerCustodyChallenge(objects, manifest, current, challenge, policy, testKey(seed), at)
		if err != nil {
			t.Fatal(err)
		}
		renewed, err := workarchive.RenewReplicaReceipt(manifest, current, challenge, batch, proof, policy, testKey(seed), at)
		if err != nil {
			t.Fatal(err)
		}
		entry := workarchive.CustodyJournalEntry{Version: workarchive.CustodyJournalEntryVersion0, Sequence: uint64(i) + 1, PreviousEntryID: head, PreviousReceipt: current,
			Record: workarchive.CustodyRecord{Version: workarchive.CustodyRecordVersion0, Challenge: challenge, Batch: batch, Proof: proof, RenewedReceipt: renewed}}
		encoded, err := entry.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		lineage.Entries = append(lineage.Entries, encoded)
		head, _ = entry.ID()
		current = renewed
	}
	return lineage, current
}

func TestArchivePruneLineageReplaysRenewalsWithAllGuards(t *testing.T) {
	p := newArchivePruneFixtureWithRenewals(t, []int{2, 1})
	initialID, _ := p.policy.ID()
	if initialID == p.policyID {
		t.Fatal("lineage policy reused initial-only pin")
	}
	for _, pin := range []types.Hash{initialID, p.policyID} {
		if _, err := p.f.executor.ExecuteArchive(t.Context(), p.f.chain, p.policy, pin, p.operations, p.replicas, p.path, p.f.base, p.f.parameters, workarchive.DefaultLimits()); err == nil {
			t.Fatal("old path accepted renewals")
		}
	}
	reached := false
	p.f.executor.hooks.at = func(at string) error {
		if at == "archive-after-lineage" {
			reached = true
			for _, op := range p.operations {
				if op.Coordinator.mu.TryLock() {
					op.Coordinator.mu.Unlock()
					t.Error("lineage released authority guard")
				}
			}
		}
		return nil
	}
	result, err := p.execute(t.Context())
	if err != nil || !result.Applied || !reached {
		t.Fatal("renewed pruning failed", err)
	}
	for _, op := range p.operations {
		if testCoordination(t, op.Coordinator).Authority.Pending != 1 {
			t.Fatal("completed authority automatically")
		}
	}
	if state := pruneSnapshot(t, p.f.executor); state.Stage != PruneSucceeded || state.Protection.Pending != nil {
		t.Fatal("result not confirmed")
	}
}

func TestArchivePruneLineageRefusesChangedEvidenceBeforeStart(t *testing.T) {
	for _, mode := range []string{"missing", "duplicate", "gap", "policy", "manifest", "initial", "assignment", "selected", "pin", "legacy-pin", "entry-budget", "byte-budget", "completed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			p := newArchivePruneFixtureWithRenewals(t, []int{2, 1})
			ctx := t.Context()
			switch mode {
			case "missing":
				p.lineages = p.lineages[:1]
			case "duplicate":
				p.lineages[1] = p.lineages[0]
			case "gap":
				p.lineages[0].Entries = p.lineages[0].Entries[1:]
			case "policy":
				p.lineages[0].Policy.MaximumProofAge++
			case "manifest":
				p.lineages[0].Manifest = []byte{0}
			case "initial":
				p.lineages[0].InitialReceipt = p.replicas[0].Receipt
			case "assignment":
				p.lineages[0].AssignmentID[0] ^= 1
			case "selected":
				p.replicas[0].Receipt = p.lineages[0].InitialReceipt
			case "pin":
				p.policyID[0] ^= 1
			case "legacy-pin":
				p.policyID, _ = p.policy.ID()
			case "entry-budget":
				p.lineages[0].Entries = make([][]byte, workarchive.MaximumReceiptLineageEntries+1)
			case "byte-budget":
				chunk := make([]byte, 1<<20)
				p.lineages[0].Entries = make([][]byte, 257)
				for i := range p.lineages[0].Entries {
					p.lineages[0].Entries[i] = chunk
				}
			case "completed":
				c := p.operations[1].Coordinator
				appendCoordinated(t, c, testEntry(t, testCoordination(t, c).Authority, custodyauthority.Complete, types.Hash{}, p.operations[1].Binding.TicketID, testHash(98)))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before := pruneSnapshot(t, p.f.executor)
			if result, err := p.execute(ctx); err == nil || result.Applied {
				t.Fatal("invalid lineage accepted", err)
			}
			if !reflect.DeepEqual(before, pruneSnapshot(t, p.f.executor)) {
				t.Fatal("rejection started execution")
			}
			if _, err := os.Lstat(p.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejection published evidence", err)
			}
		})
	}
}

func TestArchivePruneLineageDetachesEveryEvidenceBuffer(t *testing.T) {
	p := newArchivePruneFixtureWithRenewals(t, []int{2, 1})
	// Inputs may be reordered, and no accepted caller buffer remains aliased.
	p.lineages[0], p.lineages[1] = p.lineages[1], p.lineages[0]
	p.f.executor.hooks.at = func(at string) error {
		if at == "archive-before-verification" {
			for i := range p.lineages {
				p.lineages[i].Manifest[0] ^= 1
				p.lineages[i].Policy.TrustedAuditors[0] = [32]byte{}
				for _, entry := range p.lineages[i].Entries {
					entry[0] ^= 1
				}
				p.lineages[i].Entries = nil
			}
		}
		return nil
	}
	if result, err := p.execute(t.Context()); err != nil || !result.Applied {
		t.Fatal("accepted input changed", err)
	}
}

func TestArchivePruneLineageAggregateBudgetIsCheckedBeforeCopy(t *testing.T) {
	p := newArchivePruneFixtureWithRenewals(t, []int{2, 1})
	chunk := bytes.Repeat([]byte{1}, 1<<20)
	for i := range p.lineages {
		p.lineages[i].Entries = make([][]byte, 129)
		for j := range p.lineages[i].Entries {
			p.lineages[i].Entries[j] = chunk
		}
	}
	if got, err := detachArchiveLineages(t.Context(), p.lineages, p.policy.Assignments); got != nil || !errors.Is(err, workarchive.ErrReceiptLineage) {
		t.Fatal("per-replica budgets bypassed aggregate cap", err)
	}
}

func TestArchivePruneLineageCancellationPreservesUnknownStart(t *testing.T) {
	for _, point := range []string{"archive-after-lineage", "prune-before-effect"} {
		t.Run(point, func(t *testing.T) {
			p := newArchivePruneFixtureWithRenewals(t, []int{2, 1})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p.f.executor.hooks.at = func(at string) error {
				if at == point {
					cancel()
				}
				return nil
			}
			if _, err := p.execute(ctx); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			want := PruneAdmitted
			if point == "prune-before-effect" {
				want = PruneStarted
			}
			if state := pruneSnapshot(t, p.f.executor); state.Stage != want || state.Protection.Pending != nil {
				t.Fatal("wrong cancellation state")
			}
			if want == PruneStarted {
				if _, err := p.execute(t.Context()); !errors.Is(err, ErrPruneOutcome) {
					t.Fatal("retained start retried", err)
				}
			} else if _, err := os.Lstat(p.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cancel before archive replay published evidence", err)
			}
			for _, op := range p.operations {
				if testCoordination(t, op.Coordinator).Authority.Pending != 1 {
					t.Fatal("cancellation completed authority")
				}
			}
		})
	}
}

func TestArchivePruneLineageAlsoAcceptsExactInitialReceipts(t *testing.T) {
	p := newArchivePruneFixture(t)
	manifest, err := workarchive.VerifyArchiveDirectory(p.replicas[0].Directory, p.policy.Checkpoint, p.policy.CheckpointPolicy, p.f.base, p.f.parameters, workarchive.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	policy := workarchive.CustodyPolicy{TrustedAuditors: p.policy.Assignments[0].Auditors, MaximumChallengeLifetime: 60, MaximumProofAge: 100, MaximumRenewalTerm: 20_000}
	for i, replica := range p.replicas {
		lineage, _ := archiveFixtureLineage(t, p, manifest, p.policy.Assignments[i], replica, policy, 0, replica.Receipt.StoredAt)
		p.lineages = append(p.lineages, lineage)
	}
	p.policyID, err = p.policy.LineageID()
	if err != nil {
		t.Fatal(err)
	}
	if result, err := p.execute(t.Context()); err != nil || !result.Applied {
		t.Fatal("initial prefix rejected", err)
	}
}
