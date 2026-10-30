package store

import (
	"bytes"
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const MaximumScheduledPruneInventoryBytes = 64 << 20

var ErrScheduledPrune = errors.New("scheduled pruning requires exact original assignments, protected owners and retained quorum evidence")

type ScheduledPruneReplica struct {
	Assignment custodyauthority.Assignment
	Proof      workarchive.CustodyScheduleProof
	Receipt    workarchive.ScheduledReplicaReceipt
	Admission  custodyauthority.Entry
}

// ScheduledPruneInventory is immutable preparation, never a grant. It commits
// original assignments and admissions, target schedule, trust policy and both
// storage pair identities. Full live journal lineages are required at execution.
type ScheduledPruneInventory struct {
	Request                          PruneRequest
	ExecutorBindingID, StoragePairID types.Hash
	Checkpoint                       workarchive.Checkpoint
	OriginalPolicy                   workarchive.Policy
	ReplicaPolicy                    workarchive.ReplicaPolicy
	Replicas                         []ScheduledPruneReplica // strict original replica key order
}

func (v ScheduledPruneInventory) Bundle() (workarchive.ScheduledAvailabilityBundle, error) {
	id, err := v.Checkpoint.Statement.ID()
	if err != nil {
		return workarchive.ScheduledAvailabilityBundle{}, err
	}
	b := workarchive.ScheduledAvailabilityBundle{StatementID: id, ManifestID: v.Checkpoint.Statement.ArchiveManifestID, AnchorID: v.Checkpoint.Statement.Anchor.ID, RadixActivationHeight: v.Checkpoint.Statement.RadixActivationHeight}
	if len(v.Replicas) < workarchive.MinimumReplicas || len(v.Replicas) > workarchive.MaximumReplicas {
		return b, ErrScheduledPrune
	}
	for _, s := range v.Replicas {
		b.Receipts = append(b.Receipts, s.Receipt)
	}
	if _, err := b.CanonicalBytes(); err != nil {
		return b, err
	}
	return b, nil
}

func (v ScheduledPruneInventory) validate() error { return v.validateMode(false) }

func (v ScheduledPruneInventory) validateMode(plan bool) error {
	if v.Request.ScheduleID.IsZero() || v.Request.StorageID.IsZero() || (!plan && v.ExecutorBindingID.IsZero()) || (plan && !v.ExecutorBindingID.IsZero()) || v.StoragePairID.IsZero() || v.OriginalPolicy.Binding.RadixActivationHeight != 0 {
		return ErrScheduledPrune
	}
	rid, err := v.Request.ID()
	if err != nil {
		return err
	}
	b, err := v.Bundle()
	if err != nil {
		return err
	}
	bid, _ := b.ID()
	if len(v.Replicas) < int(v.ReplicaPolicy.RequiredReplicas) {
		return ErrScheduledPrune
	}
	targetPolicy := v.OriginalPolicy
	targetPolicy.Binding.RadixActivationHeight = b.RadixActivationHeight
	if err := v.Checkpoint.Verify(targetPolicy); err != nil {
		return err
	}
	primary := false
	var oldStatement types.Hash
	retain := b.Receipts[0].Original.RetainUntil
	budget := MaximumScheduledPruneInventoryBytes
	for i, s := range v.Replicas {
		for _, raw := range [][]byte{s.Proof.OriginalManifest, s.Proof.TargetManifest} {
			if len(raw) > budget {
				return ErrScheduledPrune
			}
			budget -= len(raw)
		}
		aid, err := s.Assignment.ID()
		if err != nil {
			return err
		}
		sid, err := s.Proof.ID()
		if err != nil {
			return err
		}
		if err := s.Proof.Verify(s.Assignment, v.OriginalPolicy); err != nil {
			return err
		}
		if s.Proof.AssignmentID != aid || s.Receipt.ScheduleID != sid || s.Receipt.Original.ReplicaPublicKey != s.Assignment.ReplicaPublicKey || s.Receipt.Original.ManifestID != s.Assignment.ManifestID || s.Receipt.Original.StatementID != s.Assignment.StatementID || s.Receipt.Original.Binding != v.OriginalPolicy.Binding {
			return ErrScheduledPrune
		}
		targetID, _ := s.Proof.TargetCheckpoint.Statement.ID()
		priorID, _ := s.Proof.OriginalCheckpoint.Statement.ID()
		if targetID != b.StatementID || (i > 0 && priorID != oldStatement) {
			return ErrScheduledPrune
		}
		oldStatement = priorID
		if i > 0 && bytes.Compare(v.Replicas[i-1].Assignment.ReplicaPublicKey[:], s.Assignment.ReplicaPublicKey[:]) >= 0 {
			return ErrScheduledPrune
		}
		trusted := false
		for _, key := range v.ReplicaPolicy.TrustedReplicas {
			trusted = trusted || key == s.Assignment.ReplicaPublicKey
		}
		if !trusted {
			return ErrScheduledPrune
		}
		if err := s.Receipt.VerifyAvailabilityTime(v.ReplicaPolicy, v.Request.Boundary.VerifiedAt); err != nil {
			return err
		}
		retain = min(retain, s.Receipt.Original.RetainUntil)
		if plan {
			if s.Admission != (custodyauthority.Entry{}) {
				return ErrScheduledPrune
			}
		} else {
			if _, err := s.Admission.ID(); err != nil {
				return err
			}
			c := s.Admission.Command
			if c.Version != custodyauthority.ScheduleVersion2 || c.ScheduleID != sid || c.Kind != custodyauthority.Admit || c.Purpose != custodyauthority.Prune || c.OperationID != rid || c.AssignmentID != aid || c.ActorPublicKey != v.Request.ConsumerPublicKey || s.Admission.AuthorityPublicKey != s.Assignment.AuthorityPublicKey {
				return ErrScheduledPrune
			}
		}
		allowed := false
		for _, member := range s.Assignment.Consumers {
			allowed = allowed || (member.PublicKey == v.Request.ConsumerPublicKey && member.Purposes&custodyauthority.Prune != 0)
		}
		if !allowed {
			return ErrScheduledPrune
		}
		if aid == v.Request.AssignmentID {
			if primary || sid != v.Request.ScheduleID || validatePruneRequest(s.Assignment, v.Request, rid) != nil {
				return ErrScheduledPrune
			}
			primary = true
		}
	}
	st := v.Checkpoint.Statement
	expected := workchain.CanonicalFloor{Pruned: true, RadixActivationHeight: st.RadixActivationHeight, BaseID: st.BaseID, Anchor: st.Anchor, AncestryNodes: st.AncestryNodes, AncestryRoot: st.AncestryRoot, StatementID: b.StatementID, ManifestID: b.ManifestID, AvailabilityID: bid, VerifiedAt: v.Request.Boundary.VerifiedAt, RetainUntil: retain}
	actual, err := v.Request.Boundary.CanonicalBytes()
	want, werr := expected.CanonicalBytes()
	if !primary || err != nil || werr != nil || !bytes.Equal(actual, want) {
		return ErrScheduledPrune
	}
	return nil
}

func (v ScheduledPruneInventory) CanonicalBytes() ([]byte, error) { return v.canonicalMode(false) }

func (v ScheduledPruneInventory) canonicalMode(plan bool) ([]byte, error) {
	if err := v.validateMode(plan); err != nil {
		return nil, err
	}
	e := codec.NewEncoder(4096)
	magic := "OMCSPINV"
	if plan {
		magic = "OMCSPPLN"
	}
	e.Fixed([]byte(magic))
	e.U16(0)
	request, _ := v.Request.CanonicalBytes()
	e.BytesField(request)
	e.Fixed(v.ExecutorBindingID[:])
	e.Fixed(v.StoragePairID[:])
	cp, _ := v.Checkpoint.CanonicalBytes()
	e.BytesField(cp)
	e.U16(v.OriginalPolicy.RequiredAttestations)
	encodeInventoryKeys(e, v.OriginalPolicy.TrustedAttestors)
	e.U16(v.ReplicaPolicy.RequiredReplicas)
	e.U64(v.ReplicaPolicy.MaximumReceiptAge)
	e.U64(v.ReplicaPolicy.MinimumRemainingTerm)
	encodeInventoryKeys(e, v.ReplicaPolicy.TrustedReplicas)
	e.Uvarint(uint64(len(v.Replicas)))
	for _, s := range v.Replicas {
		a, _ := s.Assignment.CanonicalBytes()
		p, _ := s.Proof.CanonicalBytes()
		r, _ := s.Receipt.CanonicalBytes()
		var entry []byte
		if !plan {
			entry, _ = s.Admission.CanonicalBytes()
		}
		for _, raw := range [][]byte{a, p, r, entry} {
			if e.Len()+len(raw)+10 > MaximumScheduledPruneInventoryBytes {
				return nil, ErrScheduledPrune
			}
			e.BytesField(raw)
		}
	}
	if e.Len() > MaximumScheduledPruneInventoryBytes {
		return nil, ErrScheduledPrune
	}
	return e.Bytes(), nil
}
func (v ScheduledPruneInventory) ID() (types.Hash, error) {
	raw, err := v.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-prune/scheduled-inventory/id/v0", raw), nil
}

func DecodeScheduledPruneInventory(raw []byte) (ScheduledPruneInventory, error) {
	return decodeScheduledPruneMode(raw, false)
}

func decodeScheduledPruneMode(raw []byte, plan bool) (ScheduledPruneInventory, error) {
	var v ScheduledPruneInventory
	if len(raw) == 0 || len(raw) > MaximumScheduledPruneInventoryBytes {
		return v, ErrScheduledPrune
	}
	d := codec.NewDecoder(raw)
	magic, err := d.Fixed(8)
	wantMagic := "OMCSPINV"
	if plan {
		wantMagic = "OMCSPPLN"
	}
	if err != nil || !bytes.Equal(magic, []byte(wantMagic)) {
		return v, ErrScheduledPrune
	}
	version, err := d.U16()
	if err != nil || version != 0 {
		return v, ErrScheduledPrune
	}
	r, err := d.BytesField(MaximumPruneRequestBytes)
	if err != nil {
		return v, err
	}
	v.Request, err = DecodePruneRequest(r)
	if err != nil {
		return v, err
	}
	for _, id := range []*types.Hash{&v.ExecutorBindingID, &v.StoragePairID} {
		b, err := d.Fixed(types.HashSize)
		if err != nil {
			return v, err
		}
		copy(id[:], b)
	}
	cp, err := d.BytesField(workarchive.MaximumCheckpointBytes)
	if err != nil {
		return v, err
	}
	v.Checkpoint, err = workarchive.DecodeCheckpoint(cp)
	if err != nil {
		return v, err
	}
	st := v.Checkpoint.Statement
	v.OriginalPolicy.Binding = workarchive.Binding{NetworkID: st.NetworkID, GenesisID: st.GenesisID, ActivationHeight: st.ActivationHeight, BaseID: st.BaseID}
	v.OriginalPolicy.RequiredAttestations, err = d.U16()
	if err != nil {
		return v, err
	}
	v.OriginalPolicy.TrustedAttestors, err = decodeInventoryKeys(d)
	if err != nil {
		return v, err
	}
	v.ReplicaPolicy.RequiredReplicas, err = d.U16()
	if err != nil {
		return v, err
	}
	v.ReplicaPolicy.MaximumReceiptAge, err = d.U64()
	if err != nil {
		return v, err
	}
	v.ReplicaPolicy.MinimumRemainingTerm, err = d.U64()
	if err != nil {
		return v, err
	}
	v.ReplicaPolicy.TrustedReplicas, err = decodeInventoryKeys(d)
	if err != nil {
		return v, err
	}
	n, err := d.ListLength(workarchive.MaximumReplicas)
	if err != nil || n < workarchive.MinimumReplicas {
		return v, ErrScheduledPrune
	}
	v.Replicas = make([]ScheduledPruneReplica, n)
	for i := range v.Replicas {
		s := &v.Replicas[i]
		a, err := d.BytesField(custodyauthority.MaximumAssignmentBytes)
		if err != nil {
			return v, err
		}
		s.Assignment, err = custodyauthority.DecodeAssignment(a)
		if err != nil {
			return v, err
		}
		p, err := d.BytesField(workarchive.MaximumCustodyScheduleBytes)
		if err != nil {
			return v, err
		}
		s.Proof, err = workarchive.DecodeCustodyScheduleProof(p)
		if err != nil {
			return v, err
		}
		r, err := d.BytesField(workarchive.MaximumScheduledReceiptBytes)
		if err != nil {
			return v, err
		}
		s.Receipt, err = workarchive.DecodeScheduledReplicaReceipt(r)
		if err != nil {
			return v, err
		}
		entry, err := d.BytesField(custodyauthority.MaximumEntryBytes)
		if err != nil {
			return v, err
		}
		if plan {
			if len(entry) != 0 {
				return v, ErrScheduledPrune
			}
		} else {
			s.Admission, err = custodyauthority.DecodeEntry(entry)
		}
		if err != nil {
			return v, err
		}
	}
	if d.Finish() != nil {
		return v, ErrScheduledPrune
	}
	encoded, err := v.canonicalMode(plan)
	if err != nil || !bytes.Equal(raw, encoded) {
		return v, errors.Join(ErrScheduledPrune, err)
	}
	return v, nil
}

func SaveScheduledPruneInventory(ctx context.Context, path string, v ScheduledPruneInventory, expected types.Hash) error {
	id, err := v.ID()
	if err != nil || expected.IsZero() || id != expected {
		return errors.Join(ErrScheduledPrune, err)
	}
	raw, err := v.CanonicalBytes()
	if err != nil {
		return err
	}
	return publishCustodyArtifactBytes(ctx, path, raw)
}
func LoadScheduledPruneInventory(path string, expected types.Hash) (ScheduledPruneInventory, error) {
	raw, err := readRegular(path, MaximumScheduledPruneInventoryBytes)
	if err != nil {
		return ScheduledPruneInventory{}, err
	}
	if expected.IsZero() || types.DomainHash("OMESH/custody-prune/scheduled-inventory/id/v0", raw) != expected {
		return ScheduledPruneInventory{}, ErrScheduledPrune
	}
	return DecodeScheduledPruneInventory(raw)
}

// BuildScheduledPruneAdmission is static reviewed preparation. No ticket is
// admitted and no current position is discovered by this helper.
func BuildScheduledPruneAdmission(a custodyauthority.Assignment, proof workarchive.CustodyScheduleProof, oldPolicy workarchive.Policy, request PruneRequest, position custodyauthority.Position) (custodyauthority.Command, error) {
	if err := proof.Verify(a, oldPolicy); err != nil {
		return custodyauthority.Command{}, err
	}
	aid, _ := a.ID()
	sid, _ := proof.ID()
	rid, err := request.ID()
	if err != nil || request.ScheduleID.IsZero() || request.Boundary.RadixActivationHeight != proof.TargetCheckpoint.Statement.RadixActivationHeight || request.Boundary.ManifestID != proof.TargetCheckpoint.Statement.ArchiveManifestID {
		return custodyauthority.Command{}, ErrScheduledPrune
	}
	st := proof.TargetCheckpoint.Statement
	boundary := request.Boundary
	if (aid == request.AssignmentID && sid != request.ScheduleID) || boundary.BaseID != st.BaseID || !bytes.Equal(boundary.Anchor.CanonicalBytes(), st.Anchor.CanonicalBytes()) || boundary.AncestryNodes != st.AncestryNodes || boundary.AncestryRoot != st.AncestryRoot {
		return custodyauthority.Command{}, ErrScheduledPrune
	}
	targetID, _ := st.ID()
	if targetID != request.Boundary.StatementID || position.Sequence < 1 || position.Sequence > 2*uint64(a.MaximumOperations)-1 || position.HeadID.IsZero() || position.HeadID == aid {
		return custodyauthority.Command{}, ErrScheduledPrune
	}
	allowed := false
	for _, member := range a.Consumers {
		allowed = allowed || (member.PublicKey == request.ConsumerPublicKey && member.Purposes&custodyauthority.Prune != 0)
	}
	if !allowed {
		return custodyauthority.Command{}, custodyauthority.ErrActor
	}
	return custodyauthority.Command{Version: custodyauthority.ScheduleVersion2, AssignmentID: aid, ScheduleID: sid, ExpectedSequence: position.Sequence, ExpectedHead: position.HeadID, Kind: custodyauthority.Admit, Purpose: custodyauthority.Prune, OperationID: rid, ActorPublicKey: request.ConsumerPublicKey}, nil
}
