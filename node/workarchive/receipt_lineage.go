package workarchive

import (
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

const (
	// These are local acceptance budgets, not consensus or journal limits.
	MaximumReceiptLineageEntries = 1_024
	MaximumReceiptLineageBytes   = 256 << 20
)

var ErrReceiptLineage = errors.New("custody receipt lineage does not match the pinned assignment and selected receipt")

// CustodyReceiptLineage is historical evidence, not a grant, a latest-head proof
// or a new file format. Manifest and Entries contain existing canonical encodings.
// Entries must be a complete prefix from sequence 1, including every renewal.
// An initial selected receipt requires an empty prefix. No journal is opened,
// resumed, activated or declared durable by this value or its verification.
type CustodyReceiptLineage struct {
	AssignmentID   types.Hash
	Manifest       []byte
	InitialReceipt ReplicaReceipt
	Policy         CustodyPolicy
	Entries        [][]byte
}

// VerifyCustodyReceiptLineage verifies a complete historical prefix at each
// record's signed response time. It does NOT claim that these receipts are fresh
// now. Live callers must separately hold current assignment authority and replay
// the selected replica, with fresh time checks through their final storage batch.
// Inputs must remain immutable during this synchronous, read-only verification.
func VerifyCustodyReceiptLineage(ctx context.Context, lineage CustodyReceiptLineage,
	assignment custodyauthority.Assignment, expectedAssignmentID types.Hash, selected ReplicaReceipt,
) error {
	if ctx == nil {
		return ErrReceiptLineage
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if expectedAssignmentID.IsZero() || lineage.AssignmentID != expectedAssignmentID ||
		lineage.InitialReceipt.Version != ReplicaReceiptVersion0 || len(lineage.Manifest) == 0 || len(lineage.Manifest) > MaximumManifestBytes ||
		len(lineage.Entries) > MaximumReceiptLineageEntries || len(lineage.Policy.TrustedAuditors) > custodyauthority.MaximumMembers {
		return ErrReceiptLineage
	}
	remaining := MaximumReceiptLineageBytes - len(lineage.Manifest)
	for _, encoded := range lineage.Entries {
		if len(encoded) == 0 || len(encoded) > MaximumCustodyJournalEntryBytes || len(encoded) > remaining {
			return ErrReceiptLineage
		}
		remaining -= len(encoded)
	}
	id, err := assignment.ID()
	if err != nil || id != expectedAssignmentID {
		return ErrReceiptLineage
	}
	manifest, err := DecodeManifest(lineage.Manifest)
	if err != nil {
		return errors.Join(ErrReceiptLineage, err)
	}
	// Reconstruct all archive, initial-receipt, custody-policy and auditor fields;
	// copying an assignment ID onto evidence from another scope is insufficient.
	rebuilt, err := CreateCustodyAuthorityAssignment(manifest, lineage.InitialReceipt, lineage.Policy,
		assignment.IncarnationID, assignment.AuthorityPublicKey, assignment.Consumers, assignment.MaximumOperations, assignment.MaximumPending)
	if err != nil {
		return errors.Join(ErrReceiptLineage, err)
	}
	rebuiltID, rebuiltErr := rebuilt.ID()
	if rebuiltErr != nil || rebuiltID != id {
		return ErrReceiptLineage
	}
	current, head := lineage.InitialReceipt, (types.Hash{})
	for i, encoded := range lineage.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry, err := DecodeCustodyJournalEntry(encoded)
		if err != nil || entry.Verify(manifest, lineage.Policy, uint64(i)+1, head, current) != nil {
			return errors.Join(ErrReceiptLineage, err)
		}
		head, err = entry.ID()
		if err != nil {
			return errors.Join(ErrReceiptLineage, err)
		}
		current = entry.Record.RenewedReceipt
	}
	if current != selected {
		return ErrReceiptLineage
	}
	return ctx.Err()
}
