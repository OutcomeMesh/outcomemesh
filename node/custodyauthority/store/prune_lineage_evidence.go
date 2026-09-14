package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// The body budget is shared across ALL replicas; the extra space is only for
// bounded framing, initial receipts and custody policies, never more bodies.
const MaximumArchivePruneLineageEvidenceBytes = workarchive.MaximumReceiptLineageBytes + (256 << 10)

const archivePruneLineageEvidenceDomain = "OMESH/custody-prune/lineage-evidence/id/v0"

var ErrPruneLineageEvidence = errors.New("invalid retained archive-prune lineage evidence or independent pin")

// ArchivePruneLineageEvidence is an immutable, detached historical preparation.
// Only the constructor and pinned file loader can populate it. It commits exact
// canonical bodies, inventory and policy, not live admission, the latest journal
// head, historical Audit admissions, replica durability or execution provenance.
type ArchivePruneLineageEvidence struct {
	id       types.Hash
	lineages []workarchive.CustodyReceiptLineage
	parts    [][]byte
	size     int64
}

func (evidence ArchivePruneLineageEvidence) ID() (types.Hash, error) {
	if evidence.id.IsZero() {
		return types.Hash{}, ErrPruneLineageEvidence
	}
	return evidence.id, nil
}

// Lineages returns a fresh copy for the existing ExecutePreparedArchive API.
// That API re-verifies it under live owner guards. Its Started record commits
// the INVENTORY ID, not this file ID; retain both independent pins separately.
func (evidence ArchivePruneLineageEvidence) Lineages(ctx context.Context) ([]workarchive.CustodyReceiptLineage, error) {
	if ctx == nil || evidence.id.IsZero() {
		return nil, ErrPruneLineageEvidence
	}
	result := make([]workarchive.CustodyReceiptLineage, len(evidence.lineages))
	for i, lineage := range evidence.lineages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lineage.Manifest = bytes.Clone(lineage.Manifest)
		lineage.Policy.TrustedAuditors = append([][32]byte(nil), lineage.Policy.TrustedAuditors...)
		lineage.Entries = make([][]byte, len(evidence.lineages[i].Entries))
		for j, encoded := range evidence.lineages[i].Entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			lineage.Entries[j] = bytes.Clone(encoded)
		}
		result[i] = lineage
	}
	return result, ctx.Err()
}

// PrepareArchivePruneLineageEvidence requires an independently pinned LINEAGE
// inventory and one complete prefix per assignment, including empty prefixes for
// initial receipts. It orders by the inventory, bounds before copying, then fully
// verifies every renewal at its signed response time. No filesystem or owner is
// opened or changed. Caller inputs must not change during this synchronous call.
func PrepareArchivePruneLineageEvidence(ctx context.Context, inventory ArchivePruneInventory,
	expectedInventoryID, expectedPolicyID types.Hash, lineages []workarchive.CustodyReceiptLineage,
) (ArchivePruneLineageEvidence, error) {
	if err := checkLineageEvidenceInventory(ctx, inventory, expectedInventoryID, expectedPolicyID); err != nil {
		return ArchivePruneLineageEvidence{}, err
	}
	detached, err := detachArchiveLineages(ctx, lineages, inventory.Policy.Assignments)
	if err != nil {
		return ArchivePruneLineageEvidence{}, errors.Join(ErrPruneLineageEvidence, err)
	}
	return verifiedLineageEvidence(ctx, inventory, expectedInventoryID, expectedPolicyID, detached)
}

func checkLineageEvidenceInventory(ctx context.Context, inventory ArchivePruneInventory, inventoryID, policyID types.Hash) error {
	if ctx == nil {
		return ErrPruneLineageEvidence
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if inventory.Mode != ArchivePruneLineage || inventory.Verify(inventoryID, policyID) != nil {
		return ErrPruneLineageEvidence
	}
	return nil
}

// The constructor detached these buffers; the decoder allocated them itself.
// Neither path lets unverified caller buffers reach the opaque result.
func verifiedLineageEvidence(ctx context.Context, inventory ArchivePruneInventory, inventoryID, policyID types.Hash,
	lineages []workarchive.CustodyReceiptLineage,
) (ArchivePruneLineageEvidence, error) {
	for i, assignment := range inventory.Policy.Assignments {
		id, _ := assignment.ID()
		if err := workarchive.VerifyCustodyReceiptLineage(ctx, lineages[i], assignment, id, inventory.Availability.Receipts[i]); err != nil {
			return ArchivePruneLineageEvidence{}, errors.Join(ErrPruneLineageEvidence, err)
		}
	}
	evidence := ArchivePruneLineageEvidence{lineages: lineages}
	header := codec.NewEncoder(76)
	header.Fixed([]byte("OMCPLEVD"))
	header.U16(0)
	header.Fixed(inventoryID[:])
	header.Fixed(policyID[:])
	header.U16(uint16(len(lineages)))
	evidence.parts = append(evidence.parts, header.Bytes())
	field := func(body []byte) {
		length := codec.NewEncoder(4)
		length.U32(uint32(len(body)))
		evidence.parts = append(evidence.parts, length.Bytes(), body)
	}
	for _, lineage := range lineages {
		id := lineage.AssignmentID
		evidence.parts = append(evidence.parts, id[:])
		field(lineage.Manifest)
		receipt, _ := lineage.InitialReceipt.CanonicalBytes()
		field(receipt)
		policy := codec.NewEncoder(28 + len(lineage.Policy.TrustedAuditors)*32)
		policy.U64(lineage.Policy.MaximumChallengeLifetime)
		policy.U64(lineage.Policy.MaximumProofAge)
		policy.U64(lineage.Policy.MaximumRenewalTerm)
		policy.U16(uint16(len(lineage.Policy.TrustedAuditors)))
		for _, key := range lineage.Policy.TrustedAuditors {
			policy.Fixed(key[:])
		}
		policy.U16(uint16(len(lineage.Entries)))
		evidence.parts = append(evidence.parts, policy.Bytes())
		for _, entry := range lineage.Entries {
			field(entry)
		}
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(archivePruneLineageEvidenceDomain))
	for _, part := range evidence.parts {
		evidence.size += int64(len(part))
		if err := writeLineageEvidencePart(ctx, hash, part); err != nil {
			return ArchivePruneLineageEvidence{}, err
		}
	}
	if evidence.size > MaximumArchivePruneLineageEvidenceBytes {
		return ArchivePruneLineageEvidence{}, ErrPruneLineageEvidence
	}
	copy(evidence.id[:], hash.Sum(nil))
	if err := ctx.Err(); err != nil {
		return ArchivePruneLineageEvidence{}, err
	}
	return evidence, nil
}

// Streaming avoids concatenating a second evidence-sized buffer. Cancellation
// is checked at most every 64 KiB of regular-file I/O, not just per large entry.
func writeLineageEvidencePart(ctx context.Context, writer io.Writer, part []byte) error {
	for len(part) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(len(part), 64<<10)
		written, err := writer.Write(part[:n])
		if err != nil {
			return err
		}
		if written != n {
			return io.ErrShortWrite
		}
		part = part[n:]
	}
	return ctx.Err()
}

type lineageEvidenceReader struct {
	ctx       context.Context
	reader    io.Reader
	remaining int64
	err       error
}

func (r *lineageEvidenceReader) fixed(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || int64(n) > r.remaining {
		r.err = ErrPruneLineageEvidence
		return nil
	}
	if r.err = r.ctx.Err(); r.err != nil {
		return nil
	}
	result := make([]byte, n)
	for offset := 0; offset < n; {
		if r.err = r.ctx.Err(); r.err != nil {
			return nil
		}
		end := min(n, offset+(64<<10))
		if _, r.err = io.ReadFull(r.reader, result[offset:end]); r.err != nil {
			return nil
		}
		offset = end
	}
	r.remaining -= int64(n)
	return result
}

func (r *lineageEvidenceReader) number(n int) uint64 {
	b := r.fixed(n)
	if r.err != nil {
		return 0
	}
	switch n {
	case 2:
		return uint64(binary.BigEndian.Uint16(b))
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	default:
		return binary.BigEndian.Uint64(b)
	}
}

func (r *lineageEvidenceReader) body(limit int, budget *int) []byte {
	n := r.number(4)
	if n == 0 || n > uint64(limit) || n > uint64(*budget) {
		r.err = errors.Join(ErrPruneLineageEvidence, r.err)
		return nil
	}
	*budget -= int(n)
	return r.fixed(int(n))
}

// The file loader first authenticates the bounded stream against its external
// hash. This parser also checks every count/length before allocating, enforces a
// single aggregate budget, then rehashes the exact decoded canonical value.
func decodeLineageEvidence(ctx context.Context, reader io.Reader, size int64, inventory ArchivePruneInventory,
	inventoryID, policyID, expectedID types.Hash,
) (ArchivePruneLineageEvidence, error) {
	if ctx == nil || expectedID.IsZero() || size < 76 || size > MaximumArchivePruneLineageEvidenceBytes {
		return ArchivePruneLineageEvidence{}, ErrPruneLineageEvidence
	}
	r := &lineageEvidenceReader{ctx: ctx, reader: reader, remaining: size}
	if !bytes.Equal(r.fixed(8), []byte("OMCPLEVD")) || r.number(2) != 0 ||
		!bytes.Equal(r.fixed(32), inventoryID[:]) || !bytes.Equal(r.fixed(32), policyID[:]) {
		return ArchivePruneLineageEvidence{}, errors.Join(ErrPruneLineageEvidence, r.err)
	}
	n := r.number(2)
	if r.err != nil || n == 0 || n > workarchive.MaximumReplicas || int(n) != len(inventory.Policy.Assignments) {
		return ArchivePruneLineageEvidence{}, errors.Join(ErrPruneLineageEvidence, r.err)
	}
	lineages := make([]workarchive.CustodyReceiptLineage, int(n))
	remainingBytes, remainingEntries := workarchive.MaximumReceiptLineageBytes, workarchive.MaximumReceiptLineageEntries
	for i := range lineages {
		lineage := &lineages[i]
		copy(lineage.AssignmentID[:], r.fixed(32))
		aid, _ := inventory.Policy.Assignments[i].ID()
		if lineage.AssignmentID != aid {
			return ArchivePruneLineageEvidence{}, errors.Join(ErrPruneLineageEvidence, r.err)
		}
		lineage.Manifest = r.body(workarchive.MaximumManifestBytes, &remainingBytes)
		receiptBudget := workarchive.MaximumReplicaReceiptBytes
		receipt := r.body(receiptBudget, &receiptBudget)
		var err error
		lineage.InitialReceipt, err = workarchive.DecodeReplicaReceipt(receipt)
		if r.err != nil || err != nil {
			return ArchivePruneLineageEvidence{}, errors.Join(ErrPruneLineageEvidence, r.err, err)
		}
		p := &lineage.Policy
		p.MaximumChallengeLifetime, p.MaximumProofAge, p.MaximumRenewalTerm = r.number(8), r.number(8), r.number(8)
		keys := r.number(2)
		if r.err != nil || keys == 0 || keys > custodyauthority.MaximumMembers || int64(keys)*32 > r.remaining {
			return ArchivePruneLineageEvidence{}, errors.Join(ErrPruneLineageEvidence, r.err)
		}
		p.TrustedAuditors = make([][32]byte, int(keys))
		for j := range p.TrustedAuditors {
			copy(p.TrustedAuditors[j][:], r.fixed(32))
		}
		entries := r.number(2)
		if r.err != nil || entries > uint64(remainingEntries) || int64(entries)*4 > r.remaining {
			return ArchivePruneLineageEvidence{}, errors.Join(ErrPruneLineageEvidence, r.err)
		}
		remainingEntries -= int(entries)
		lineage.Entries = make([][]byte, int(entries))
		for j := range lineage.Entries {
			lineage.Entries[j] = r.body(workarchive.MaximumCustodyJournalEntryBytes, &remainingBytes)
		}
		if r.err != nil {
			return ArchivePruneLineageEvidence{}, errors.Join(ErrPruneLineageEvidence, r.err)
		}
	}
	if r.remaining != 0 || r.err != nil {
		return ArchivePruneLineageEvidence{}, errors.Join(ErrPruneLineageEvidence, r.err)
	}
	evidence, err := verifiedLineageEvidence(ctx, inventory, inventoryID, policyID, lineages)
	if err != nil || evidence.id != expectedID || evidence.size != size {
		return ArchivePruneLineageEvidence{}, errors.Join(ErrPruneLineageEvidence, err)
	}
	return evidence, ctx.Err()
}
