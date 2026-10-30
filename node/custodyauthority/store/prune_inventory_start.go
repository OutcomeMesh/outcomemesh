package store

import (
	"bytes"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// Version 0 remains byte-for-byte unchanged. Version 1 appends an independently
// pinned prepared-inventory ID, selected only after guarded archive verification.
// Older readers reject version 1; no downgrade or journal rewrite is supported.
func pruneInventoryStartedBytes(requestID, ticketID, inventoryID types.Hash) []byte {
	if inventoryID.IsZero() {
		return pruneStartedBytes(requestID, ticketID)
	}
	encoded := append([]byte("OMCPSTRT\x00\x01"), requestID[:]...)
	encoded = append(encoded, ticketID[:]...)
	return append(encoded, inventoryID[:]...)
}

func decodePruneInventoryStart(encoded []byte, requestID, ticketID types.Hash) (types.Hash, error) {
	if bytes.Equal(encoded, pruneStartedBytes(requestID, ticketID)) {
		return types.Hash{}, nil
	}
	if len(encoded) != 10+3*types.HashSize {
		return types.Hash{}, ErrPruneStage
	}
	var inventoryID types.Hash
	copy(inventoryID[:], encoded[10+2*types.HashSize:])
	if inventoryID.IsZero() || !bytes.Equal(encoded, pruneInventoryStartedBytes(requestID, ticketID, inventoryID)) {
		return types.Hash{}, ErrPruneStage
	}
	return inventoryID, nil
}

func checkPruneExecutionBinding(next PruneExecution, binding types.Hash) error {
	if next.FenceClaim != nil && next.FenceClaim.Candidate.Binding.ExecutorBindingID != binding {
		return ErrPruneInventory
	}
	if !next.ArchiveInventoryID.IsZero() && (binding.IsZero() || next.Request.StorageID.IsZero() ||
		(next.Stage != PruneStarted && next.Stage != PruneSucceeded)) {
		return ErrPruneInventory
	}
	return checkCancellationBinding(next, binding)
}
