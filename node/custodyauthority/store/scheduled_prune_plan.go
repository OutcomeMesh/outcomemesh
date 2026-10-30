package store

import (
	"bytes"
	"context"
	"errors"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// ScheduledPrunePlan fixes the request and quorum before any new admission or
// executor exists. ExecutorBindingID and every Admission must be zero. The
// separate magic and ID domain prevent a plan from being used as an inventory.
type ScheduledPrunePlan ScheduledPruneInventory

func (p ScheduledPrunePlan) CanonicalBytes() ([]byte, error) {
	return ScheduledPruneInventory(p).canonicalMode(true)
}
func (p ScheduledPrunePlan) ID() (types.Hash, error) {
	raw, err := p.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-prune/scheduled-plan/id/v0", raw), nil
}
func DecodeScheduledPrunePlan(raw []byte) (ScheduledPrunePlan, error) {
	v, err := decodeScheduledPruneMode(raw, true)
	return ScheduledPrunePlan(v), err
}
func LoadScheduledPrunePlan(path string, expected types.Hash) (ScheduledPrunePlan, error) {
	raw, err := readRegular(path, MaximumScheduledPruneInventoryBytes)
	if err != nil {
		return ScheduledPrunePlan{}, err
	}
	if expected.IsZero() || types.DomainHash("OMESH/custody-prune/scheduled-plan/id/v0", raw) != expected {
		return ScheduledPrunePlan{}, ErrScheduledPrune
	}
	return DecodeScheduledPrunePlan(raw)
}
func SaveScheduledPrunePlan(ctx context.Context, path string, p ScheduledPrunePlan, expected types.Hash) error {
	if ctx == nil {
		return ErrScheduledPrune
	}
	id, err := p.ID()
	if err != nil || expected.IsZero() || id != expected {
		return errors.Join(ErrScheduledPrune, err)
	}
	raw, _ := p.CanonicalBytes()
	return publishCustodyArtifactBytes(ctx, path, raw)
}

// PrepareScheduledPrunePlan inspects the existing original owners and journals.
// verifiedAt is the fixed request time, never the live authorization clock. IDs
// for the protected database are independent operator inputs, checked again by
// execution. Preparation grants no authority and never changes owner history.
func PrepareScheduledPrunePlan(ctx context.Context, sources []ScheduledCustodyReplicaSource, cp workarchive.Checkpoint, oldPolicy workarchive.Policy, policy workarchive.ReplicaPolicy, primary, storageID, pairID types.Hash, consumer [32]byte, verifiedAt uint64, now func() uint64) (ScheduledPrunePlan, error) {
	if ctx == nil || now == nil || primary.IsZero() || storageID.IsZero() || pairID.IsZero() || verifiedAt == 0 {
		return ScheduledPrunePlan{}, ErrScheduledPrune
	}
	var checked uint64
	bundle, err := InspectScheduledCustodyQuorum(ctx, sources, cp, oldPolicy, policy, func() uint64 { checked = now(); return checked })
	if err != nil {
		return ScheduledPrunePlan{}, err
	}
	if verifiedAt > checked {
		return ScheduledPrunePlan{}, ErrScheduledPrune
	}
	bid, _ := bundle.ID()
	sid, _ := cp.Statement.ID()
	st := cp.Statement
	p := ScheduledPrunePlan{StoragePairID: pairID, Checkpoint: cp, OriginalPolicy: oldPolicy, ReplicaPolicy: policy}
	retain := bundle.Receipts[0].Original.RetainUntil
	var scope types.Hash
	for _, s := range sources {
		p.Replicas = append(p.Replicas, ScheduledPruneReplica{Assignment: s.Assignment, Proof: s.Schedule.Proof, Receipt: s.Receipt})
		retain = min(retain, s.Receipt.Original.RetainUntil)
		if s.AssignmentID == primary {
			scope = s.Schedule.ExpectedID
		}
	}
	sort.Slice(p.Replicas, func(i, j int) bool {
		return bytes.Compare(p.Replicas[i].Assignment.ReplicaPublicKey[:], p.Replicas[j].Assignment.ReplicaPublicKey[:]) < 0
	})
	p.Request = PruneRequest{AssignmentID: primary, ScheduleID: scope, StorageID: storageID, ConsumerPublicKey: consumer, Boundary: workchain.CanonicalFloor{Pruned: true, RadixActivationHeight: st.RadixActivationHeight, BaseID: st.BaseID, Anchor: st.Anchor, AncestryNodes: st.AncestryNodes, AncestryRoot: st.AncestryRoot, StatementID: sid, ManifestID: st.ArchiveManifestID, AvailabilityID: bid, VerifiedAt: verifiedAt, RetainUntil: retain}}
	raw, err := p.CanonicalBytes()
	if err != nil {
		return ScheduledPrunePlan{}, err
	}
	return DecodeScheduledPrunePlan(raw)
}

func (p ScheduledPrunePlan) Replica(id types.Hash) (ScheduledPruneReplica, error) {
	for _, s := range p.Replicas {
		aid, err := s.Assignment.ID()
		if err == nil && aid == id {
			return s, nil
		}
	}
	return ScheduledPruneReplica{}, custodyauthority.ErrAssignment
}

func (p ScheduledPrunePlan) BindInventory(v ScheduledPruneInventory) error {
	if err := v.validate(); err != nil {
		return err
	}
	v.ExecutorBindingID = types.Hash{}
	v.Replicas = append([]ScheduledPruneReplica(nil), v.Replicas...)
	for i := range v.Replicas {
		v.Replicas[i].Admission = custodyauthority.Entry{}
	}
	have, err := ScheduledPrunePlan(v).ID()
	want, werr := p.ID()
	if err != nil || werr != nil || have != want {
		return errors.Join(ErrScheduledPrune, err, werr)
	}
	return nil
}

func BuildScheduledPruneCompletion(p ScheduledPrunePlan, v ScheduledPruneInventory, effect workchain.CanonicalPruneEffect, assignmentID types.Hash, position custodyauthority.Position) (custodyauthority.Command, error) {
	if err := p.BindInventory(v); err != nil {
		return custodyauthority.Command{}, err
	}
	var primary, selected custodyauthority.Entry
	var assignment custodyauthority.Assignment
	for _, s := range v.Replicas {
		aid, _ := s.Assignment.ID()
		if aid == v.Request.AssignmentID {
			primary = s.Admission
		}
		if aid == assignmentID {
			selected = s.Admission
			assignment = s.Assignment
		}
	}
	if primary == (custodyauthority.Entry{}) || selected == (custodyauthority.Entry{}) || !pruneEffectMatches(v.Request, primary, effect) {
		return custodyauthority.Command{}, ErrPruneCompletion
	}
	ticket, _ := selected.ID()
	eid, err := effect.ID()
	if err != nil {
		return custodyauthority.Command{}, err
	}
	if position.Sequence <= selected.Command.ExpectedSequence || (position.Sequence == selected.Command.ExpectedSequence+1) != (position.HeadID == ticket) {
		return custodyauthority.Command{}, custodyauthority.ErrHead
	}
	draft := custodyauthority.Command{Version: custodyauthority.ScheduleVersion2, AssignmentID: assignmentID, ScheduleID: selected.Command.ScheduleID, ExpectedSequence: position.Sequence, ExpectedHead: position.HeadID, Kind: custodyauthority.Complete, TicketID: ticket, EvidenceID: eid, ActorPublicKey: v.Request.ConsumerPublicKey}
	if _, err := custodyauthority.ScheduledPruneCommandReviewID(assignment, draft); err != nil {
		return custodyauthority.Command{}, err
	}
	return draft, nil
}
