package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func archiveLineageExtractSources(t testing.TB, p *archivePruneFixture) []ArchivePruneLineageSource {
	t.Helper()
	sources := make([]ArchivePruneLineageSource, len(p.lineages))
	for i, lineage := range p.lineages {
		manifest, err := workarchive.DecodeManifest(lineage.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "journal")
		journal, _, err := workarchive.OpenOrCreateCustodyJournal(path, manifest, lineage.InitialReceipt, lineage.Policy)
		if err != nil {
			t.Fatal(err)
		}
		for _, encoded := range lineage.Entries {
			entry, err := workarchive.DecodeCustodyJournalEntry(encoded)
			if err != nil {
				t.Fatal(err)
			}
			actual, applied, err := journal.Append(entry.Record)
			actualBytes, encodeErr := actual.CanonicalBytes()
			if err != nil || encodeErr != nil || !applied || !bytes.Equal(actualBytes, encoded) {
				t.Fatal("fixture journal changed original canonical entry", err, encodeErr)
			}
		}
		if _, err := journal.Rotate(); err != nil {
			t.Fatal(err)
		}
		checkpoint, err := workarchive.CaptureCustodyCheckpoint(path, "", manifest, lineage.InitialReceipt, lineage.Policy)
		if err != nil {
			t.Fatal(err)
		}
		id, err := checkpoint.ID()
		if err != nil {
			t.Fatal(err)
		}
		policy := lineage.Policy
		policy.TrustedAuditors = append([][32]byte(nil), policy.TrustedAuditors...)
		sources[i] = ArchivePruneLineageSource{AssignmentID: lineage.AssignmentID, JournalPath: path,
			Checkpoint: checkpoint, CheckpointID: id, Manifest: bytes.Clone(lineage.Manifest),
			InitialReceipt: lineage.InitialReceipt, Policy: policy}
	}
	return sources
}

func TestPruneLineageExtractionRetainsExactEvidenceAndFeedsGuardedExecution(t *testing.T) {
	for _, renewals := range [][]int{{0, 0}, {2, 0}, {2, 1}} {
		t.Run(fmt.Sprintf("renewals_%d_%d", renewals[0], renewals[1]), func(t *testing.T) {
			p, inventory, prepared := lineageEvidenceFixture(t, renewals)
			sources := archiveLineageExtractSources(t, p)
			sources[0], sources[1] = sources[1], sources[0]
			before := pruneSnapshot(t, p.f.executor)
			owners := []Coordination{testCoordination(t, p.operations[0].Coordinator), testCoordination(t, p.operations[1].Coordinator)}
			storage, err := p.f.chain.StorageProtection()
			if err != nil {
				t.Fatal(err)
			}
			extracted, err := ExtractArchivePruneLineageEvidence(t.Context(), inventory, p.inventoryID, p.policyID, sources)
			if err != nil || extracted.id != prepared.id || !bytes.Equal(lineageEvidenceBytes(extracted), lineageEvidenceBytes(prepared)) {
				t.Fatal("extraction changed evidence format, bytes or pinned order", err)
			}
			for _, source := range sources {
				manifest, _ := workarchive.DecodeManifest(source.Manifest)
				if err := workarchive.VerifyCustodyCheckpoint(source.Checkpoint, source.CheckpointID, source.JournalPath, "", manifest, source.InitialReceipt, source.Policy); err != nil {
					t.Fatal("extraction changed a source journal", err)
				}
			}
			path := filepath.Join(t.TempDir(), "extracted.omple")
			for range 2 {
				if err := SaveArchivePruneLineageEvidenceFile(t.Context(), path, extracted, extracted.id); err != nil {
					t.Fatal(err)
				}
			}
			loaded, err := LoadArchivePruneLineageEvidenceFile(t.Context(), path, inventory, p.inventoryID, p.policyID, extracted.id)
			if err != nil || loaded.id != prepared.id {
				t.Fatal("extracted evidence did not use the existing retained format", err)
			}
			storageAfter, err := p.f.chain.StorageProtection()
			if err != nil || !reflect.DeepEqual(storage, storageAfter) || !reflect.DeepEqual(before, pruneSnapshot(t, p.f.executor)) {
				t.Fatal("historical extraction touched live execution", err)
			}
			for i, operation := range p.operations {
				if !reflect.DeepEqual(owners[i], testCoordination(t, operation.Coordinator)) {
					t.Fatal("extraction changed live authority")
				}
			}
			// Source buffers may be reused after the synchronous extraction.
			for i := range sources {
				sources[i].Manifest[0] ^= 1
				sources[i].Policy.TrustedAuditors[0][0] ^= 1
			}
			p.lineages, err = extracted.Lineages(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if result, err := p.execute(t.Context()); err != nil || !result.Applied {
				t.Fatal("extracted history did not feed the separate guarded executor", err)
			}
			if state := inspectPreparedArchive(t, p); state.ArchiveInventoryID != p.inventoryID {
				t.Fatal("extraction replaced the original inventory start binding")
			}
		})
	}
}

func TestPruneLineageExtractionRejectsWrongScopeAndSources(t *testing.T) {
	p, inventory, _ := lineageEvidenceFixture(t, []int{2, 1})
	sources := archiveLineageExtractSources(t, p)
	for _, name := range []string{"inventory-pin", "policy-pin", "missing", "duplicate", "unknown-assignment", "checkpoint-pin", "selected-receipt", "initial", "policy", "nil-context", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			input := append([]ArchivePruneLineageSource(nil), sources...)
			ctx, inventoryID, policyID := t.Context(), p.inventoryID, p.policyID
			switch name {
			case "inventory-pin":
				inventoryID = testHash(99)
			case "policy-pin":
				policyID = testHash(99)
			case "missing":
				input = input[:1]
			case "duplicate":
				input[1] = input[0]
			case "unknown-assignment":
				input[0].AssignmentID = testHash(99)
			case "checkpoint-pin":
				input[0].CheckpointID = testHash(99)
			case "selected-receipt":
				// A newer source checkpoint cannot change the receipt selected by
				// the inventory, even if its external checkpoint ID is re-pinned.
				input[0].Checkpoint.ReceiptID, _ = input[0].InitialReceipt.ID()
				input[0].CheckpointID, _ = input[0].Checkpoint.ID()
			case "initial":
				input[0].InitialReceipt = inventory.Availability.Receipts[0]
			case "policy":
				input[0].Policy.MaximumProofAge++
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			evidence, err := ExtractArchivePruneLineageEvidence(ctx, inventory, inventoryID, policyID, input)
			if err == nil || !evidence.id.IsZero() {
				t.Fatal("invalid source scope returned usable evidence", err)
			}
			if name == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled extraction concealed cancellation", err)
			}
		})
	}
	initial := archiveInventoryFixture(t, newArchivePruneFixture(t))
	initialID, _ := initial.ID()
	initialPolicy, _ := initial.PolicyID()
	if evidence, err := ExtractArchivePruneLineageEvidence(t.Context(), initial, initialID, initialPolicy, sources); err == nil || !evidence.id.IsZero() {
		t.Fatal("initial-only inventory silently enabled lineage extraction")
	}
	missing := append([]ArchivePruneLineageSource(nil), sources...)
	missing[0].JournalPath = filepath.Join(t.TempDir(), "absent")
	if evidence, err := ExtractArchivePruneLineageEvidence(t.Context(), inventory, p.inventoryID, p.policyID, missing); err == nil || !evidence.id.IsZero() {
		t.Fatal("missing source became valid evidence")
	}
	if _, err := os.Lstat(missing[0].JournalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("extraction bootstrapped a missing source", err)
	}
}

func TestPruneLineageExtractionHistoryCannotReopenCompletedAuthority(t *testing.T) {
	p, inventory, _ := lineageEvidenceFixture(t, []int{2, 1})
	sources := archiveLineageExtractSources(t, p)
	secondary := p.operations[1].Coordinator
	appendCoordinated(t, secondary, testEntry(t, testCoordination(t, secondary).Authority, custodyauthority.Complete,
		types.Hash{}, p.operations[1].Binding.TicketID, testHash(98)))
	before := pruneSnapshot(t, p.f.executor)
	evidence, err := ExtractArchivePruneLineageEvidence(t.Context(), inventory, p.inventoryID, p.policyID, sources)
	if err != nil {
		t.Fatal("historical extraction incorrectly required live pending authority", err)
	}
	p.lineages, err = evidence.Lineages(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := p.execute(t.Context()); err == nil || result.Applied || !reflect.DeepEqual(before, pruneSnapshot(t, p.f.executor)) {
		t.Fatal("extracted historical bytes bypassed completed live authority", err)
	}
}
