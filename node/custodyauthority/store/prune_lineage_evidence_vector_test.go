package store

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// Frozen disposable signatures/bodies from the local two-replica fixture, with
// one renewal each. Public TEST seeds only; no secrets, paths or authority roots.
// Static seeds make fuzz worker corpora independent of clock/random storage IDs.
func fixedPruneLineageEvidence(t testing.TB) (ArchivePruneInventory, []byte, types.Hash, types.Hash, types.Hash) {
	t.Helper()
	data, err := os.ReadFile("testdata/prune_lineage_evidence_v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Inventory, Evidence               []byte
		InventoryID, PolicyID, EvidenceID string
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	inventory, err := DecodeArchivePruneInventory(vector.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := inventory.ID()
	policyID, _ := inventory.PolicyID()
	evidenceID := types.DomainHash(archivePruneLineageEvidenceDomain, vector.Evidence)
	if id.String() != vector.InventoryID || policyID.String() != vector.PolicyID || evidenceID.String() != vector.EvidenceID ||
		evidenceID.String() != "9052483c729475add9d271a7039be21d6740a492f9d52a55b83e625a7326efca" {
		t.Fatal("retained lineage v0 fixture changed")
	}
	return inventory, vector.Evidence, id, policyID, evidenceID
}

func TestPruneLineageEvidenceGolden(t *testing.T) {
	inventory, encoded, inventoryID, policyID, id := fixedPruneLineageEvidence(t)
	got, err := decodeLineageEvidence(t.Context(), bytes.NewReader(encoded), int64(len(encoded)), inventory, inventoryID, policyID, id)
	if err != nil || !bytes.Equal(encoded, lineageEvidenceBytes(got)) {
		t.Fatal("frozen canonical format changed", err)
	}
	clear(encoded)
	lineages, err := got.Lineages(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	again, err := PrepareArchivePruneLineageEvidence(t.Context(), inventory, inventoryID, policyID, lineages)
	if err != nil || again.id != id {
		t.Fatal("decoder retained input or preparation changed canonical bytes", err)
	}
}

func FuzzDecodePruneLineageEvidence(f *testing.F) {
	inventory, seed, inventoryID, policyID, _ := fixedPruneLineageEvidence(f)
	f.Add(seed)
	f.Add(seed[:76])
	f.Add([]byte("OMCPLEVD"))
	f.Fuzz(func(t *testing.T, data []byte) {
		// A smoke input cap, not a production limit. Unit tests separately cover
		// the full aggregate count/byte caps without large fuzz-worker buffers.
		if len(data) > 1<<20 {
			return
		}
		id := types.DomainHash(archivePruneLineageEvidenceDomain, data)
		got, err := decodeLineageEvidence(t.Context(), bytes.NewReader(data), int64(len(data)), inventory, inventoryID, policyID, id)
		if err != nil {
			if !got.id.IsZero() {
				t.Fatal("invalid input returned usable evidence")
			}
			return
		}
		if got.id != id || !bytes.Equal(data, lineageEvidenceBytes(got)) {
			t.Fatal("non-canonical stream accepted")
		}
	})
}
