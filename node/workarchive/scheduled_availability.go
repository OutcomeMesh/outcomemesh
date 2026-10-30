package workarchive

import (
	"bytes"
	"context"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

var scheduledAvailabilityMagic = []byte("OMWSAVL0")

// ScheduledAvailabilityBundle commits the target archive and each replica's
// explicit schedule consent. Original receipt times remain authoritative.
// Verification is a point-in-time inspection, never a pruning permit.
type ScheduledAvailabilityBundle struct {
	StatementID, ManifestID, AnchorID types.Hash
	RadixActivationHeight             uint64
	Receipts                          []ScheduledReplicaReceipt
}

type ScheduledReplicaEvidence struct {
	Proof   CustodyScheduleProof
	Lineage CustodyReceiptLineage
}

func (b ScheduledAvailabilityBundle) CanonicalBytes() ([]byte, error) {
	if b.StatementID.IsZero() || b.ManifestID.IsZero() || b.AnchorID.IsZero() || b.RadixActivationHeight == 0 || len(b.Receipts) < MinimumReplicas || len(b.Receipts) > MaximumReplicas {
		return nil, ErrAvailability
	}
	e := codec.NewEncoder(256)
	e.Fixed(scheduledAvailabilityMagic)
	e.U16(0)
	for _, h := range []types.Hash{b.StatementID, b.ManifestID, b.AnchorID} {
		e.Fixed(h[:])
	}
	e.U64(b.RadixActivationHeight)
	e.Uvarint(uint64(len(b.Receipts)))
	locations := make(map[types.Hash]bool)
	scopes := make(map[types.Hash]bool)
	for i, r := range b.Receipts {
		if (i > 0 && bytes.Compare(b.Receipts[i-1].Original.ReplicaPublicKey[:], r.Original.ReplicaPublicKey[:]) >= 0) || locations[r.Original.LocationID] || scopes[r.ScheduleID] {
			return nil, ErrAvailability
		}
		locations[r.Original.LocationID] = true
		scopes[r.ScheduleID] = true
		raw, err := r.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		e.BytesField(raw)
	}
	raw := e.Bytes()
	if len(raw) > MaximumAvailabilityBundleBytes {
		return nil, ErrAvailability
	}
	return raw, nil
}

func DecodeScheduledAvailabilityBundle(raw []byte) (ScheduledAvailabilityBundle, error) {
	var b ScheduledAvailabilityBundle
	if len(raw) == 0 || len(raw) > MaximumAvailabilityBundleBytes {
		return b, ErrAvailability
	}
	d := codec.NewDecoder(raw)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, scheduledAvailabilityMagic) {
		return b, ErrAvailability
	}
	version, err := d.U16()
	if err != nil || version != 0 {
		return b, ErrAvailability
	}
	for _, h := range []*types.Hash{&b.StatementID, &b.ManifestID, &b.AnchorID} {
		v, err := d.Fixed(types.HashSize)
		if err != nil {
			return b, ErrAvailability
		}
		copy(h[:], v)
	}
	b.RadixActivationHeight, err = d.U64()
	if err != nil {
		return b, err
	}
	n, err := d.ListLength(MaximumReplicas)
	if err != nil || n < MinimumReplicas {
		return b, ErrAvailability
	}
	b.Receipts = make([]ScheduledReplicaReceipt, n)
	for i := range b.Receipts {
		v, err := d.BytesField(MaximumScheduledReceiptBytes)
		if err != nil {
			return b, err
		}
		b.Receipts[i], err = DecodeScheduledReplicaReceipt(v)
		if err != nil {
			return b, err
		}
	}
	if d.Finish() != nil {
		return b, ErrAvailability
	}
	encoded, err := b.CanonicalBytes()
	if err != nil || !bytes.Equal(encoded, raw) {
		return b, ErrAvailability
	}
	return b, nil
}

func (b ScheduledAvailabilityBundle) ID() (types.Hash, error) {
	raw, err := b.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/workgraph/archive/scheduled-availability/id/v0", raw), nil
}

// Verify requires independently retained assignments and original attestor and
// replica policies. No trust list is inferred from the submitted evidence.
// All replicas must prove one exact old prefix and one exact target statement.
func (b ScheduledAvailabilityBundle) Verify(ctx context.Context, target Checkpoint, oldPolicy Policy, replicaPolicy ReplicaPolicy,
	assignments []custodyauthority.Assignment, evidence []ScheduledReplicaEvidence, now uint64) error {
	if ctx == nil {
		return ErrAvailability
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(assignments) != len(b.Receipts) || len(evidence) != len(b.Receipts) || len(b.Receipts) > MaximumReplicas || replicaPolicy.validate() != nil || len(b.Receipts) < int(replicaPolicy.RequiredReplicas) {
		return ErrAvailability
	}
	if _, err := b.CanonicalBytes(); err != nil {
		return err
	}
	targetID, err := target.Statement.ID()
	if err != nil || targetID != b.StatementID || target.Statement.ArchiveManifestID != b.ManifestID || target.Statement.Anchor.ID != b.AnchorID || target.Statement.RadixActivationHeight != b.RadixActivationHeight || oldPolicy.Binding.RadixActivationHeight != 0 {
		return ErrAvailability
	}
	// Bound aggregate evidence before any expensive replay. Per-lineage validation
	// also enforces canonical records, policy limits and the full original prefix.
	remaining := MaximumReceiptLineageBytes
	for _, v := range evidence {
		if len(v.Lineage.Entries) > MaximumReceiptLineageEntries {
			return ErrAvailability
		}
		for _, raw := range [][]byte{v.Proof.OriginalManifest, v.Proof.TargetManifest, v.Lineage.Manifest} {
			if len(raw) > MaximumManifestBytes || len(raw) > remaining {
				return ErrAvailability
			}
			remaining -= len(raw)
		}
		for _, raw := range v.Lineage.Entries {
			if len(raw) > MaximumCustodyJournalEntryBytes || len(raw) > remaining {
				return ErrAvailability
			}
			remaining -= len(raw)
		}
	}
	trusted := make(map[[32]byte]bool)
	for _, k := range replicaPolicy.TrustedReplicas {
		trusted[k] = true
	}
	originalAssignments := make(map[types.Hash]custodyauthority.Assignment)
	for _, a := range assignments {
		id, err := a.ID()
		if err != nil {
			return err
		}
		if _, ok := originalAssignments[id]; ok {
			return ErrAvailability
		}
		originalAssignments[id] = a
	}
	proofs := make(map[types.Hash]ScheduledReplicaEvidence)
	for _, v := range evidence {
		id, err := v.Proof.ID()
		if err != nil {
			return err
		}
		if _, ok := proofs[id]; ok {
			return ErrAvailability
		}
		proofs[id] = v
	}
	var oldStatement, oldManifest types.Hash
	used := make(map[types.Hash]bool)
	for i, r := range b.Receipts {
		if err := ctx.Err(); err != nil {
			return err
		}
		v, ok := proofs[r.ScheduleID]
		if !ok || !trusted[r.Original.ReplicaPublicKey] {
			return ErrAvailability
		}
		a, ok := originalAssignments[v.Proof.AssignmentID]
		if !ok || used[v.Proof.AssignmentID] {
			return ErrAvailability
		}
		used[v.Proof.AssignmentID] = true
		nextID, err := v.Proof.TargetCheckpoint.Statement.ID()
		if err != nil || nextID != targetID {
			return ErrAvailability
		}
		priorID, err := v.Proof.OriginalCheckpoint.Statement.ID()
		if err != nil {
			return err
		}
		if i == 0 {
			oldStatement = priorID
			oldManifest = a.ManifestID
		} else if priorID != oldStatement || a.ManifestID != oldManifest {
			return ErrAvailability
		}
		if err := r.Verify(ctx, v.Proof, a, oldPolicy, v.Lineage); err != nil {
			return err
		}
		if err := r.VerifyAvailabilityTime(replicaPolicy, now); err != nil {
			return err
		}
	}
	targetPolicy := oldPolicy
	targetPolicy.Binding.RadixActivationHeight = target.Statement.RadixActivationHeight
	if err := target.Verify(targetPolicy); err != nil {
		return err
	}
	return ctx.Err()
}

func CreateScheduledAvailabilityBundle(ctx context.Context, target Checkpoint, oldPolicy Policy, policy ReplicaPolicy,
	assignments []custodyauthority.Assignment, evidence []ScheduledReplicaEvidence, receipts []ScheduledReplicaReceipt, now uint64) (ScheduledAvailabilityBundle, error) {
	if len(receipts) < MinimumReplicas || len(receipts) > MaximumReplicas {
		return ScheduledAvailabilityBundle{}, ErrAvailability
	}
	id, err := target.Statement.ID()
	if err != nil {
		return ScheduledAvailabilityBundle{}, err
	}
	b := ScheduledAvailabilityBundle{StatementID: id, ManifestID: target.Statement.ArchiveManifestID, AnchorID: target.Statement.Anchor.ID, RadixActivationHeight: target.Statement.RadixActivationHeight, Receipts: append([]ScheduledReplicaReceipt(nil), receipts...)}
	sort.Slice(b.Receipts, func(i, j int) bool {
		return bytes.Compare(b.Receipts[i].Original.ReplicaPublicKey[:], b.Receipts[j].Original.ReplicaPublicKey[:]) < 0
	})
	if err := b.Verify(ctx, target, oldPolicy, policy, assignments, evidence, now); err != nil {
		return ScheduledAvailabilityBundle{}, err
	}
	return b, nil
}
