package workarchive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

const MaximumCustodyScheduleBytes = 2*MaximumManifestBytes + 2*MaximumCheckpointBytes + 2*MaximumReplicaReceiptBytes + 128
const MaximumScheduledReceiptBytes = MaximumReplicaReceiptBytes + 128

var ErrCustodySchedule = errors.New("custody schedule transition does not preserve the original assignment and receipt lineage")
var custodyScheduleMagic = []byte("OMWCSCH0")
var scheduledReceiptMagic = []byte("OMWSRCP0")

// CustodyScheduleProof links one original assignment and exact journal cursor to
// a signed same-prefix archive successor. It is historical evidence, not a live
// grant. Authority activation remains a separate, independently pinned append.
// Neither this proof nor its receipt wrapper changes any deadline or budget.
type CustodyScheduleProof struct {
	AssignmentID                         types.Hash
	OriginalManifest, TargetManifest     []byte
	OriginalCheckpoint, TargetCheckpoint Checkpoint
	InitialReceipt, SelectedReceipt      ReplicaReceipt
	JournalSequence                      uint64
	JournalHeadID                        types.Hash
}

func (p CustodyScheduleProof) CanonicalBytes() ([]byte, error) {
	if p.AssignmentID.IsZero() || len(p.OriginalManifest) == 0 || len(p.OriginalManifest) > MaximumManifestBytes || len(p.TargetManifest) == 0 || len(p.TargetManifest) > MaximumManifestBytes ||
		p.JournalSequence > MaximumReceiptLineageEntries || (p.JournalSequence == 0) != p.JournalHeadID.IsZero() {
		return nil, ErrCustodySchedule
	}
	original, err := DecodeManifest(p.OriginalManifest)
	if err != nil {
		return nil, err
	}
	target, err := DecodeManifest(p.TargetManifest)
	if err != nil {
		return nil, err
	}
	if original.Version != ManifestVersion1 || target.Version != ManifestVersion2 || original.VerifyStatement(p.OriginalCheckpoint.Statement) != nil || target.VerifyStatement(p.TargetCheckpoint.Statement) != nil {
		return nil, ErrCustodySchedule
	}
	oldCP, err := p.OriginalCheckpoint.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	newCP, err := p.TargetCheckpoint.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	initial, err := p.InitialReceipt.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	selected, err := p.SelectedReceipt.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	if p.InitialReceipt.Version != ReplicaReceiptVersion0 || p.InitialReceipt.Binding != original.Binding || p.SelectedReceipt.Binding != original.Binding ||
		p.InitialReceipt.ReplicaPublicKey != p.SelectedReceipt.ReplicaPublicKey || p.InitialReceipt.ManifestID != p.SelectedReceipt.ManifestID ||
		p.InitialReceipt.StatementID != p.SelectedReceipt.StatementID || p.InitialReceipt.AnchorID != p.SelectedReceipt.AnchorID ||
		(p.JournalSequence == 0 && p.SelectedReceipt != p.InitialReceipt) || (p.JournalSequence > 0 && p.SelectedReceipt.Version != ReplicaReceiptVersion1) {
		return nil, ErrCustodySchedule
	}
	e := codec.NewEncoder(len(p.OriginalManifest) + len(p.TargetManifest) + len(oldCP) + len(newCP) + len(initial) + len(selected) + 128)
	e.Fixed(custodyScheduleMagic)
	e.U16(0)
	e.Fixed(p.AssignmentID[:])
	e.U64(p.JournalSequence)
	e.Fixed(p.JournalHeadID[:])
	for _, b := range [][]byte{p.OriginalManifest, p.TargetManifest, oldCP, newCP, initial, selected} {
		e.BytesField(b)
	}
	if e.Len() > MaximumCustodyScheduleBytes {
		return nil, ErrCustodySchedule
	}
	return e.Bytes(), nil
}
func DecodeCustodyScheduleProof(b []byte) (CustodyScheduleProof, error) {
	var p CustodyScheduleProof
	if len(b) > MaximumCustodyScheduleBytes || len(b) < 82 {
		return p, ErrCustodySchedule
	}
	d := codec.NewDecoder(b)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, custodyScheduleMagic) {
		return p, ErrCustodySchedule
	}
	version, err := d.U16()
	if err != nil || version != 0 {
		return p, ErrCustodySchedule
	}
	v, err := d.Fixed(32)
	if err != nil {
		return p, err
	}
	copy(p.AssignmentID[:], v)
	if p.JournalSequence, err = d.U64(); err != nil {
		return p, err
	}
	v, err = d.Fixed(32)
	if err != nil {
		return p, err
	}
	copy(p.JournalHeadID[:], v)
	if p.OriginalManifest, err = d.BytesField(MaximumManifestBytes); err != nil {
		return p, err
	}
	if p.TargetManifest, err = d.BytesField(MaximumManifestBytes); err != nil {
		return p, err
	}
	v, err = d.BytesField(MaximumCheckpointBytes)
	if err != nil {
		return p, err
	}
	if p.OriginalCheckpoint, err = DecodeCheckpoint(v); err != nil {
		return p, err
	}
	v, err = d.BytesField(MaximumCheckpointBytes)
	if err != nil {
		return p, err
	}
	if p.TargetCheckpoint, err = DecodeCheckpoint(v); err != nil {
		return p, err
	}
	v, err = d.BytesField(MaximumReplicaReceiptBytes)
	if err != nil {
		return p, err
	}
	if p.InitialReceipt, err = DecodeReplicaReceipt(v); err != nil {
		return p, err
	}
	v, err = d.BytesField(MaximumReplicaReceiptBytes)
	if err != nil {
		return p, err
	}
	if p.SelectedReceipt, err = DecodeReplicaReceipt(v); err != nil {
		return p, err
	}
	if err = d.Finish(); err != nil {
		return p, err
	}
	canonical, err := p.CanonicalBytes()
	if err != nil || !bytes.Equal(canonical, b) {
		return CustodyScheduleProof{}, errors.Join(ErrCustodySchedule, err)
	}
	return p, nil
}
func (p CustodyScheduleProof) ID() (types.Hash, error) {
	b, err := p.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/workgraph/archive/custody-schedule/id/v0", b), nil
}

// Verify uses the independently retained original assignment and attestor policy.
// A signed renewed receipt is not enough to prove journal continuity: consumers
// of a portable receipt must additionally call VerifyLineage below.
func (p CustodyScheduleProof) Verify(assignment custodyauthority.Assignment, policy Policy) error {
	if _, err := p.CanonicalBytes(); err != nil {
		return err
	}
	id, err := assignment.ID()
	if err != nil || assignment.Version != custodyauthority.Version0 || id != p.AssignmentID {
		return ErrCustodySchedule
	}
	old, _ := DecodeManifest(p.OriginalManifest)
	next, _ := DecodeManifest(p.TargetManifest)
	if err = VerifyRadixArchiveTransition(old, next, p.OriginalCheckpoint, p.TargetCheckpoint, policy); err != nil {
		return err
	}
	manifestID, _ := old.ID()
	statementID, _ := p.OriginalCheckpoint.Statement.ID()
	initialID, _ := p.InitialReceipt.ID()
	if assignment.NetworkID != old.Binding.NetworkID || assignment.GenesisID != old.Binding.GenesisID || assignment.ActivationHeight != old.Binding.ActivationHeight || assignment.BaseID != old.Binding.BaseID ||
		assignment.ManifestID != manifestID || assignment.StatementID != statementID || assignment.InitialReceiptID != initialID || assignment.ReplicaPublicKey != p.InitialReceipt.ReplicaPublicKey ||
		p.InitialReceipt.ManifestID != manifestID || p.InitialReceipt.StatementID != statementID || p.InitialReceipt.AnchorID != old.Anchor.ID {
		return ErrCustodySchedule
	}
	return nil
}

// VerifyLineage proves that selected is at or after the exact migration cursor in
// the original journal. No earlier or competing receipt can replace that prefix.
func (p CustodyScheduleProof) VerifyLineage(ctx context.Context, assignment custodyauthority.Assignment, policy Policy, lineage CustodyReceiptLineage, selected ReplicaReceipt) error {
	if err := p.Verify(assignment, policy); err != nil {
		return err
	}
	if !bytes.Equal(lineage.Manifest, p.OriginalManifest) || lineage.InitialReceipt != p.InitialReceipt || uint64(len(lineage.Entries)) < p.JournalSequence {
		return ErrCustodySchedule
	}
	if err := VerifyCustodyReceiptLineage(ctx, lineage, assignment, p.AssignmentID, selected); err != nil {
		return err
	}
	if p.JournalSequence == 0 {
		return nil
	}
	pivot, err := DecodeCustodyJournalEntry(lineage.Entries[p.JournalSequence-1])
	if err != nil {
		return err
	}
	id, err := pivot.ID()
	if err != nil || id != p.JournalHeadID || pivot.Record.RenewedReceipt != p.SelectedReceipt {
		return ErrCustodySchedule
	}
	return nil
}

// ScheduledReplicaReceipt adds explicit schedule consent to an original signed
// receipt. StoredAt/RetainUntil are read ONLY from Original; migration creates no
// renewal timestamp, extra storage credit, sampling result or retention reset.
type ScheduledReplicaReceipt struct {
	ScheduleID types.Hash
	Original   ReplicaReceipt
	Signature  [ed25519.SignatureSize]byte
}

func (r ScheduledReplicaReceipt) unsignedBytes() ([]byte, error) {
	if r.ScheduleID.IsZero() {
		return nil, ErrCustodySchedule
	}
	b, err := r.Original.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	e := codec.NewEncoder(len(b) + 64)
	e.Fixed(scheduledReceiptMagic)
	e.U16(0)
	e.Fixed(r.ScheduleID[:])
	e.BytesField(b)
	return e.Bytes(), nil
}
func (r ScheduledReplicaReceipt) CanonicalBytes() ([]byte, error) {
	b, err := r.unsignedBytes()
	if err != nil {
		return nil, err
	}
	h := types.DomainHash("OMESH/workgraph/archive/scheduled-receipt/signature/v0", b)
	if !ed25519.Verify(r.Original.ReplicaPublicKey[:], h[:], r.Signature[:]) {
		return nil, ErrCustodySchedule
	}
	return append(b, r.Signature[:]...), nil
}
func DecodeScheduledReplicaReceipt(b []byte) (ScheduledReplicaReceipt, error) {
	var r ScheduledReplicaReceipt
	if len(b) > MaximumScheduledReceiptBytes || len(b) < 107 {
		return r, ErrCustodySchedule
	}
	d := codec.NewDecoder(b)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, scheduledReceiptMagic) {
		return r, ErrCustodySchedule
	}
	version, err := d.U16()
	if err != nil || version != 0 {
		return r, ErrCustodySchedule
	}
	v, err := d.Fixed(32)
	if err != nil {
		return r, err
	}
	copy(r.ScheduleID[:], v)
	v, err = d.BytesField(MaximumReplicaReceiptBytes)
	if err != nil {
		return r, err
	}
	if r.Original, err = DecodeReplicaReceipt(v); err != nil {
		return r, err
	}
	v, err = d.Fixed(64)
	if err != nil {
		return r, err
	}
	copy(r.Signature[:], v)
	if err = d.Finish(); err != nil {
		return r, err
	}
	canonical, err := r.CanonicalBytes()
	if err != nil || !bytes.Equal(canonical, b) {
		return ScheduledReplicaReceipt{}, errors.Join(ErrCustodySchedule, err)
	}
	return r, nil
}
func (r ScheduledReplicaReceipt) ID() (types.Hash, error) {
	b, err := r.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/workgraph/archive/scheduled-receipt/id/v0", b), nil
}

func CreateScheduledReplicaReceipt(ctx context.Context, p CustodyScheduleProof, assignment custodyauthority.Assignment, policy Policy, lineage CustodyReceiptLineage, selected ReplicaReceipt, key ed25519.PrivateKey) (ScheduledReplicaReceipt, error) {
	if err := p.VerifyLineage(ctx, assignment, policy, lineage, selected); err != nil {
		return ScheduledReplicaReceipt{}, err
	}
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()), key) || !bytes.Equal(key.Public().(ed25519.PublicKey), selected.ReplicaPublicKey[:]) {
		return ScheduledReplicaReceipt{}, ErrCustodySchedule
	}
	id, err := p.ID()
	if err != nil {
		return ScheduledReplicaReceipt{}, err
	}
	r := ScheduledReplicaReceipt{ScheduleID: id, Original: selected}
	b, err := r.unsignedBytes()
	if err != nil {
		return r, err
	}
	h := types.DomainHash("OMESH/workgraph/archive/scheduled-receipt/signature/v0", b)
	copy(r.Signature[:], ed25519.Sign(key, h[:]))
	return r, nil
}
func (r ScheduledReplicaReceipt) Verify(ctx context.Context, p CustodyScheduleProof, assignment custodyauthority.Assignment, policy Policy, lineage CustodyReceiptLineage) error {
	if _, err := r.CanonicalBytes(); err != nil {
		return err
	}
	id, err := p.ID()
	if err != nil || r.ScheduleID != id {
		return ErrCustodySchedule
	}
	return p.VerifyLineage(ctx, assignment, policy, lineage, r.Original)
}

// VerifyAvailabilityTime applies the ORIGINAL receipt's freshness and retention
// conditions. Verify and trusted-replica quorum selection are also mandatory.
func (r ScheduledReplicaReceipt) VerifyAvailabilityTime(policy ReplicaPolicy, now uint64) error {
	if _, err := r.CanonicalBytes(); err != nil {
		return err
	}
	if err := policy.validate(); err != nil {
		return err
	}
	return r.Original.verifyAvailabilityTime(policy, now)
}

// custodyScheduleCursor is an immutable minimum prefix, checked during EVERY
// replay on this handle. It does not rewrite the historical journal header.
type custodyScheduleCursor struct {
	sequence uint64
	head     types.Hash
	receipt  ReplicaReceipt
}

// OpenScheduledCustodyJournal opens only an existing original journal and proves
// that it contains the migration prefix. Subsequent decisions, cached delivery
// and appends retain that check, including after a directory is replaced.
func OpenScheduledCustodyJournal(ctx context.Context, path string, proof CustodyScheduleProof, assignment custodyauthority.Assignment,
	attestors Policy, policy CustodyPolicy, limits CustodyJournalLimits) (*CustodyJournal, CustodyJournalState, error) {
	if err := proof.Verify(assignment, attestors); err != nil {
		return nil, CustodyJournalState{}, err
	}
	manifest, err := DecodeManifest(proof.OriginalManifest)
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	reconstructed, err := CreateCustodyAuthorityAssignment(manifest, proof.InitialReceipt, policy, assignment.IncarnationID, assignment.AuthorityPublicKey, assignment.Consumers, assignment.MaximumOperations, assignment.MaximumPending)
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	id, err := reconstructed.ID()
	if err != nil || id != proof.AssignmentID {
		return nil, CustodyJournalState{}, ErrCustodySchedule
	}
	journal, _, err := OpenExistingCustodyJournalWithLimits(ctx, path, manifest, proof.InitialReceipt, policy, limits)
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	journal.schedule = &custodyScheduleCursor{sequence: proof.JournalSequence, head: proof.JournalHeadID, receipt: proof.SelectedReceipt}
	state, err := journal.State()
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	return journal, state, nil
}

// ScheduleLineage exports the complete, bounded original prefix while retaining
// its decision lock. It neither renews the receipt nor grants execution rights.
func (d *CustodyJournalDecision) ScheduleLineage(ctx context.Context, proof CustodyScheduleProof, assignment custodyauthority.Assignment, policy Policy) (CustodyReceiptLineage, ReplicaReceipt, error) {
	var empty CustodyReceiptLineage
	if d == nil || ctx == nil {
		return empty, ReplicaReceipt{}, ErrCustodySchedule
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.check(); err != nil {
		return empty, ReplicaReceipt{}, err
	}
	state, err := d.journal.scanContext(ctx)
	if err != nil {
		return empty, ReplicaReceipt{}, err
	}
	if state.Sequence > MaximumReceiptLineageEntries {
		return empty, ReplicaReceipt{}, ErrCustodySchedule
	}
	manifest, err := d.journal.manifest.CanonicalBytes()
	if err != nil {
		return empty, ReplicaReceipt{}, err
	}
	cp := d.journal.policy
	cp.TrustedAuditors = append([][32]byte(nil), cp.TrustedAuditors...)
	l := CustodyReceiptLineage{AssignmentID: proof.AssignmentID, Manifest: manifest, InitialReceipt: state.InitialReceipt, Policy: cp}
	size := uint64(len(manifest))
	for i := uint64(1); i <= state.Sequence; i++ {
		if err := ctx.Err(); err != nil {
			return empty, ReplicaReceipt{}, err
		}
		entry, err := d.journal.loadSequence(i)
		if err != nil {
			return empty, ReplicaReceipt{}, err
		}
		b, err := entry.CanonicalBytes()
		if err != nil {
			return empty, ReplicaReceipt{}, err
		}
		size += uint64(len(b))
		if size > MaximumReceiptLineageBytes {
			return empty, ReplicaReceipt{}, ErrCustodySchedule
		}
		l.Entries = append(l.Entries, b)
	}
	if err := proof.VerifyLineage(ctx, assignment, policy, l, state.CurrentReceipt); err != nil {
		return empty, ReplicaReceipt{}, err
	}
	return l, state.CurrentReceipt, nil
}
