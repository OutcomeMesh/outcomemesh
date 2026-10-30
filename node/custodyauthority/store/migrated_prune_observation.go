package store

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const MaximumMigratedPruneObservationBytes = 2048

var ErrPruneObservation = errors.New("prune observation requires a confirmed original start, open ticket and readable protected storage")

// MigratedPruneObservation is an unsigned historical report, not a terminal
// outcome or a proof of no effect. Absence is local to StoragePosition. Neither
// branch authorizes completion, cancellation, deletion or replacement owners.
// Paths, clock values and keys are deliberately not part of the portable report.
type MigratedPruneObservation struct {
	InventoryID, PolicyID, ScheduleID            types.Hash
	AssignmentID, RequestID, TicketID            types.Hash
	ExecutorBindingID, ExecutorHeadID            types.Hash
	StorageID, StoragePairID, StorageMigrationID types.Hash
	Authority                                    custodyauthority.Position
	AuthorityPhase                               custodyauthority.Phase
	StoragePosition                              workchain.StoragePosition
	RadixActivationHeight                        uint64
	Effect                                       *workchain.CanonicalPruneEffect
}

func (o MigratedPruneObservation) hashes() []types.Hash {
	return []types.Hash{o.InventoryID, o.PolicyID, o.ScheduleID, o.AssignmentID,
		o.RequestID, o.TicketID, o.ExecutorBindingID, o.ExecutorHeadID, o.StorageID,
		o.StoragePairID, o.StorageMigrationID, o.Authority.HeadID, o.StoragePosition.CommitID}
}

func (o MigratedPruneObservation) CanonicalBytes() ([]byte, error) {
	for _, id := range o.hashes() {
		if id.IsZero() {
			return nil, ErrPruneObservation
		}
	}
	if o.Authority.Sequence < 2 || o.Authority.Sequence == ^uint64(0) ||
		(o.AuthorityPhase != custodyauthority.Accepting && o.AuthorityPhase != custodyauthority.Stopping) ||
		o.StoragePosition.Sequence == 0 || o.StoragePosition.Sequence > workchain.MaximumStoragePositions || o.RadixActivationHeight == 0 {
		return nil, ErrPruneObservation
	}
	var effect []byte
	if o.Effect != nil {
		e := o.Effect.Operation
		if e.AssignmentID != o.AssignmentID || e.TicketID != o.TicketID || e.StorageID != o.StorageID || !e.ScheduleID.IsZero() {
			return nil, ErrPruneObservation
		}
		var err error
		effect, err = o.Effect.CanonicalBytes()
		if err != nil {
			return nil, err
		}
	}
	e := codec.NewEncoder(MaximumMigratedPruneObservationBytes)
	e.Fixed([]byte("OMCPMOBS"))
	e.U16(0)
	for _, id := range o.hashes() {
		e.Fixed(id[:])
	}
	e.U64(o.Authority.Sequence)
	e.U8(uint8(o.AuthorityPhase))
	e.U64(o.StoragePosition.Sequence)
	e.U64(o.RadixActivationHeight)
	e.BytesField(effect)
	return e.Bytes(), nil
}

func DecodeMigratedPruneObservation(raw []byte) (MigratedPruneObservation, error) {
	var o MigratedPruneObservation
	if len(raw) > MaximumMigratedPruneObservationBytes {
		return o, ErrPruneObservation
	}
	d := codec.NewDecoder(raw)
	magic, err := d.Fixed(10)
	if err != nil || !bytes.Equal(magic, []byte("OMCPMOBS\x00\x00")) {
		return o, ErrPruneObservation
	}
	for _, id := range []*types.Hash{&o.InventoryID, &o.PolicyID, &o.ScheduleID,
		&o.AssignmentID, &o.RequestID, &o.TicketID, &o.ExecutorBindingID, &o.ExecutorHeadID,
		&o.StorageID, &o.StoragePairID, &o.StorageMigrationID, &o.Authority.HeadID, &o.StoragePosition.CommitID} {
		v, err := d.Fixed(types.HashSize)
		if err != nil {
			return MigratedPruneObservation{}, err
		}
		copy(id[:], v)
	}
	if o.Authority.Sequence, err = d.U64(); err != nil {
		return MigratedPruneObservation{}, err
	}
	phase, err := d.U8()
	if err != nil {
		return MigratedPruneObservation{}, err
	}
	o.AuthorityPhase = custodyauthority.Phase(phase)
	if o.StoragePosition.Sequence, err = d.U64(); err != nil {
		return MigratedPruneObservation{}, err
	}
	if o.RadixActivationHeight, err = d.U64(); err != nil {
		return MigratedPruneObservation{}, err
	}
	effect, err := d.BytesField(workchain.MaximumCanonicalPruneEffectBytes)
	if err != nil {
		return MigratedPruneObservation{}, err
	}
	if len(effect) != 0 {
		v, err := workchain.DecodeCanonicalPruneEffect(effect)
		if err != nil {
			return MigratedPruneObservation{}, err
		}
		o.Effect = &v
	}
	canonical, err := o.CanonicalBytes()
	if err != nil || !bytes.Equal(canonical, raw) {
		return MigratedPruneObservation{}, ErrPruneObservation
	}
	return o, nil
}

func (o MigratedPruneObservation) ID() (types.Hash, error) {
	raw, err := o.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-prune/migrated-observation/id/v0", raw), nil
}

// Verify checks content and context against independent pins. It does not verify
// an operator signature, journal inclusion, fresh storage access or global absence.
func (o MigratedPruneObservation) Verify(c MigratedPruneContext, migrationID types.Hash) error {
	if _, err := o.ID(); err != nil {
		return err
	}
	b, err := c.bindings()
	if err != nil {
		return err
	}
	r := c.Inventory.Request
	if migrationID.IsZero() || o.StorageMigrationID != migrationID || c.Proof.AssignmentID != r.AssignmentID ||
		o.InventoryID != c.InventoryID || o.PolicyID != c.PolicyID || o.ScheduleID != c.ScheduleID ||
		o.AssignmentID != r.AssignmentID || o.RequestID != c.Inventory.Policy.RequestID || o.TicketID != b.ticket ||
		o.ExecutorBindingID != c.Inventory.Policy.ExecutorBindingID || o.StorageID != r.StorageID ||
		o.StoragePairID != c.Inventory.Policy.StoragePairID || o.RadixActivationHeight != c.Proof.TargetCheckpoint.Statement.RadixActivationHeight ||
		o.Authority.Sequence < b.primaryEntry.Command.ExpectedSequence+2 || o.Authority.HeadID == b.ticket {
		return ErrPruneObservation
	}
	admission, _ := b.primaryEntry.CanonicalBytes()
	position := nextPrunePosition(PrunePosition{Stage: PrunePrepared, HeadID: o.RequestID}, admission)
	position = nextPrunePosition(position, pruneInventoryStartedBytes(o.RequestID, o.TicketID, o.InventoryID))
	if o.ExecutorHeadID != position.HeadID {
		return ErrPruneObservation
	}
	if o.Effect != nil {
		_, err = (MigratedPruneOutcome{Effect: o.Effect}).EvidenceID(c)
	}
	return err
}

func LoadMigratedPruneObservation(path string, expected types.Hash, c MigratedPruneContext, migrationID types.Hash) (MigratedPruneObservation, error) {
	if expected.IsZero() {
		return MigratedPruneObservation{}, ErrPruneObservation
	}
	raw, err := readRegular(path, MaximumMigratedPruneObservationBytes)
	if err != nil {
		return MigratedPruneObservation{}, err
	}
	o, err := DecodeMigratedPruneObservation(raw)
	if err != nil {
		return MigratedPruneObservation{}, err
	}
	id, _ := o.ID()
	if id != expected {
		return MigratedPruneObservation{}, ErrPruneObservation
	}
	if err := o.Verify(c, migrationID); err != nil {
		return MigratedPruneObservation{}, err
	}
	return o, nil
}
