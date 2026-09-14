package store

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const MaximumArchivePruneInventoryBytes = 1 << 20

type ArchivePruneMode uint16

const (
	ArchivePruneInitial ArchivePruneMode = iota
	ArchivePruneLineage
)

var ErrPruneInventory = errors.New("invalid prepared archive-prune inventory or independent pin")

// ArchivePruneInventory retains PREPARATION, never execution provenance. It
// contains no private keys, paths, live owners, lineage bodies or storage effect.
// Admissions are co-signed historical entries, not proof of current pending
// state or confirmed publication. The caller must independently protect both
// the inventory ID and the selected mode's policy ID before loading/using it.
// Assignments, receipts and admissions have the same strict replica-key order.
type ArchivePruneInventory struct {
	Version      uint16
	Mode         ArchivePruneMode
	Request      PruneRequest
	Policy       ArchivePrunePolicy
	Availability workarchive.AvailabilityBundle
	Admissions   []custodyauthority.Entry
}

func (inventory ArchivePruneInventory) PolicyID() (types.Hash, error) {
	switch inventory.Mode {
	case ArchivePruneInitial:
		return inventory.Policy.ID()
	case ArchivePruneLineage:
		return inventory.Policy.LineageID()
	default:
		return types.Hash{}, ErrPruneInventory
	}
}

func (inventory ArchivePruneInventory) validate() error {
	p := inventory.Policy
	if inventory.Version != 0 || len(inventory.Admissions) != len(p.Assignments) ||
		len(inventory.Admissions) > workarchive.MaximumReplicas || len(inventory.Availability.Receipts) != len(p.Assignments) ||
		inventory.Request.StorageID.IsZero() {
		return ErrPruneInventory
	}
	if _, err := inventory.PolicyID(); err != nil {
		return errors.Join(ErrPruneInventory, err)
	}
	rid, err := inventory.Request.ID()
	if err != nil || rid != p.RequestID {
		return ErrPruneInventory
	}
	// This checks consistency at the RETAINED request time. It neither reads a
	// clock nor asserts that any replica is available or fresh now.
	bundle, boundary := inventory.Availability, inventory.Request.Boundary
	if err := bundle.Verify(p.Checkpoint, p.CheckpointPolicy, p.ReplicaPolicy, boundary.VerifiedAt); err != nil {
		return errors.Join(ErrPruneInventory, err)
	}
	bundleID, _ := bundle.ID()
	retainUntil := bundle.Receipts[0].RetainUntil
	primary := false
	for i, assignment := range p.Assignments {
		aid, _ := assignment.ID()
		receipt := bundle.Receipts[i]
		receiptID, _ := receipt.ID() // bundle.Verify already checked signatures
		if receipt.ReplicaPublicKey != assignment.ReplicaPublicKey ||
			(inventory.Mode == ArchivePruneInitial && receipt.Version != workarchive.ReplicaReceiptVersion0) ||
			(receipt.Version == workarchive.ReplicaReceiptVersion0 && receiptID != assignment.InitialReceiptID) {
			return ErrPruneInventory
		}
		retainUntil = min(retainUntil, receipt.RetainUntil)
		entry := inventory.Admissions[i]
		command := entry.Command
		if _, err := entry.ID(); err != nil || entry.AuthorityPublicKey != assignment.AuthorityPublicKey ||
			command.AssignmentID != aid || command.Kind != custodyauthority.Admit || command.Purpose != custodyauthority.Prune ||
			command.OperationID != rid || command.ActorPublicKey != inventory.Request.ConsumerPublicKey {
			return ErrPruneInventory
		}
		allowed := false
		for _, consumer := range assignment.Consumers {
			allowed = allowed || (consumer.PublicKey == command.ActorPublicKey && consumer.Purposes&custodyauthority.Prune != 0)
		}
		if !allowed {
			return ErrPruneInventory
		}
		if aid == inventory.Request.AssignmentID {
			if err := validatePruneRequest(assignment, inventory.Request, rid); err != nil {
				return errors.Join(ErrPruneInventory, err)
			}
			primary = true
		}
	}
	statement := p.Checkpoint.Statement
	expected := workchain.CanonicalFloor{Pruned: true, BaseID: statement.BaseID, Anchor: statement.Anchor,
		AncestryNodes: statement.AncestryNodes, AncestryRoot: statement.AncestryRoot,
		StatementID: bundle.StatementID, ManifestID: bundle.ManifestID, AvailabilityID: bundleID,
		VerifiedAt: boundary.VerifiedAt, RetainUntil: retainUntil}
	want, err := expected.CanonicalBytes()
	actual, actualErr := boundary.CanonicalBytes()
	if !primary || err != nil || actualErr != nil || !bytes.Equal(want, actual) {
		return ErrPruneInventory
	}
	return nil
}

// CanonicalBytes verifies only the bounded package's internal historical
// consistency. Lineage mode DECLARES the requirement to supply/verify complete
// prefixes at execution; selected renewal signatures alone cannot satisfy it.
func (inventory ArchivePruneInventory) CanonicalBytes() ([]byte, error) {
	if err := inventory.validate(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder(4096)
	e.Fixed([]byte("OMCPINVT"))
	e.U16(inventory.Version)
	e.U16(uint16(inventory.Mode))
	request, _ := inventory.Request.CanonicalBytes()
	e.BytesField(request)
	p := inventory.Policy
	for _, id := range []types.Hash{p.RequestID, p.ExecutorBindingID, p.StoragePairID} {
		e.Fixed(id[:])
	}
	checkpoint, _ := p.Checkpoint.CanonicalBytes()
	e.BytesField(checkpoint)
	// The validated checkpoint statement carries the exact policy binding.
	e.U16(p.CheckpointPolicy.RequiredAttestations)
	encodeInventoryKeys(e, p.CheckpointPolicy.TrustedAttestors)
	e.U16(p.ReplicaPolicy.RequiredReplicas)
	e.U64(p.ReplicaPolicy.MaximumReceiptAge)
	e.U64(p.ReplicaPolicy.MinimumRemainingTerm)
	encodeInventoryKeys(e, p.ReplicaPolicy.TrustedReplicas)
	e.Uvarint(uint64(len(p.Assignments)))
	for i, assignment := range p.Assignments {
		encoded, _ := assignment.CanonicalBytes()
		e.BytesField(encoded)
		entry, _ := inventory.Admissions[i].CanonicalBytes()
		e.BytesField(entry)
	}
	bundle, _ := inventory.Availability.CanonicalBytes()
	e.BytesField(bundle)
	if e.Len() > MaximumArchivePruneInventoryBytes {
		return nil, ErrPruneInventory
	}
	return e.Bytes(), nil
}

func encodeInventoryKeys(e *codec.Encoder, keys [][32]byte) {
	e.Uvarint(uint64(len(keys)))
	for _, key := range keys {
		e.Fixed(key[:])
	}
}

func decodeInventoryKeys(d *codec.Decoder) ([][32]byte, error) {
	n, err := d.ListLength(workarchive.MaximumReplicas)
	if err != nil || n == 0 || n > d.Remaining()/32 {
		return nil, ErrPruneInventory
	}
	keys := make([][32]byte, n)
	for i := range keys {
		encoded, _ := d.Fixed(32)
		copy(keys[i][:], encoded)
	}
	return keys, nil
}

func DecodeArchivePruneInventory(input []byte) (ArchivePruneInventory, error) {
	if len(input) == 0 || len(input) > MaximumArchivePruneInventoryBytes {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	d := codec.NewDecoder(input)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, []byte("OMCPINVT")) {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	var inventory ArchivePruneInventory
	if inventory.Version, err = d.U16(); err != nil || inventory.Version != 0 {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	mode, err := d.U16()
	if err != nil || mode > uint16(ArchivePruneLineage) {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	inventory.Mode = ArchivePruneMode(mode)
	request, err := d.BytesField(MaximumPruneRequestBytes)
	if err != nil {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	if inventory.Request, err = DecodePruneRequest(request); err != nil {
		return ArchivePruneInventory{}, errors.Join(ErrPruneInventory, err)
	}
	p := &inventory.Policy
	for _, id := range []*types.Hash{&p.RequestID, &p.ExecutorBindingID, &p.StoragePairID} {
		encoded, err := d.Fixed(types.HashSize)
		if err != nil {
			return ArchivePruneInventory{}, ErrPruneInventory
		}
		copy(id[:], encoded)
	}
	checkpoint, err := d.BytesField(workarchive.MaximumCheckpointBytes)
	if err != nil {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	if p.Checkpoint, err = workarchive.DecodeCheckpoint(checkpoint); err != nil {
		return ArchivePruneInventory{}, errors.Join(ErrPruneInventory, err)
	}
	s := p.Checkpoint.Statement
	p.CheckpointPolicy.Binding = workarchive.Binding{NetworkID: s.NetworkID, GenesisID: s.GenesisID, ActivationHeight: s.ActivationHeight, BaseID: s.BaseID}
	if p.CheckpointPolicy.RequiredAttestations, err = d.U16(); err != nil {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	if p.CheckpointPolicy.TrustedAttestors, err = decodeInventoryKeys(d); err != nil {
		return ArchivePruneInventory{}, err
	}
	if p.ReplicaPolicy.RequiredReplicas, err = d.U16(); err != nil {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	if p.ReplicaPolicy.MaximumReceiptAge, err = d.U64(); err != nil {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	if p.ReplicaPolicy.MinimumRemainingTerm, err = d.U64(); err != nil {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	if p.ReplicaPolicy.TrustedReplicas, err = decodeInventoryKeys(d); err != nil {
		return ArchivePruneInventory{}, err
	}
	n, err := d.ListLength(workarchive.MaximumReplicas)
	if err != nil || n == 0 || n > d.Remaining()/custodyauthority.MaximumEntryBytes {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	p.Assignments = make([]custodyauthority.Assignment, n)
	inventory.Admissions = make([]custodyauthority.Entry, n)
	for i := range p.Assignments {
		assignment, err := d.BytesField(custodyauthority.MaximumAssignmentBytes)
		if err != nil {
			return ArchivePruneInventory{}, ErrPruneInventory
		}
		if p.Assignments[i], err = custodyauthority.DecodeAssignment(assignment); err != nil {
			return ArchivePruneInventory{}, errors.Join(ErrPruneInventory, err)
		}
		entry, err := d.BytesField(custodyauthority.MaximumEntryBytes)
		if err != nil {
			return ArchivePruneInventory{}, ErrPruneInventory
		}
		if inventory.Admissions[i], err = custodyauthority.DecodeEntry(entry); err != nil {
			return ArchivePruneInventory{}, errors.Join(ErrPruneInventory, err)
		}
	}
	bundle, err := d.BytesField(workarchive.MaximumAvailabilityBundleBytes)
	if err != nil || d.Finish() != nil {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	if inventory.Availability, err = workarchive.DecodeAvailabilityBundle(bundle); err != nil {
		return ArchivePruneInventory{}, errors.Join(ErrPruneInventory, err)
	}
	if err := inventory.validate(); err != nil {
		return ArchivePruneInventory{}, err
	}
	return inventory, nil
}

func (inventory ArchivePruneInventory) ID() (types.Hash, error) {
	encoded, err := inventory.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return archivePruneInventoryID(encoded), nil
}

func archivePruneInventoryID(encoded []byte) types.Hash {
	return types.DomainHash("OMESH/custody-prune/prepared-inventory/id/v0", encoded)
}

// Verify checks two externally retained pins. Computing either expected pin
// from the input being checked would provide no independent protection.
func (inventory ArchivePruneInventory) Verify(expectedInventoryID, expectedPolicyID types.Hash) error {
	id, err := inventory.ID()
	policyID, policyErr := inventory.PolicyID()
	if err != nil || policyErr != nil || expectedInventoryID.IsZero() || expectedPolicyID.IsZero() || id != expectedInventoryID || policyID != expectedPolicyID {
		return errors.Join(ErrPruneInventory, err, policyErr)
	}
	return nil
}
