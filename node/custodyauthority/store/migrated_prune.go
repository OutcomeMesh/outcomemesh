package store

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

var ErrMigratedPrune = errors.New("migrated prune resolution requires the original inventory, ticket, schedule and retained outcome")

// MigratedPruneContext describes an old archive-bound request and one original
// assignment's confirmed schedule transition. It never rewrites the request.
// Inventory/policy/schedule IDs are independent operator pins, not live grants.
type MigratedPruneContext struct {
	Inventory                         ArchivePruneInventory
	InventoryID, PolicyID, ScheduleID types.Hash
	Proof                             workarchive.CustodyScheduleProof
}

type migratedPruneBindings struct {
	primary, selected           custodyauthority.Assignment
	primaryEntry, selectedEntry custodyauthority.Entry
	ticket                      types.Hash
}

func (c MigratedPruneContext) bindings() (migratedPruneBindings, error) {
	var b migratedPruneBindings
	id, err := c.Inventory.ID()
	pid, pe := c.Inventory.PolicyID()
	sid, se := c.Proof.ID()
	if err != nil || pe != nil || se != nil || id != c.InventoryID || pid != c.PolicyID || sid != c.ScheduleID || c.InventoryID.IsZero() || c.PolicyID.IsZero() || c.ScheduleID.IsZero() || !c.Inventory.Request.ScheduleID.IsZero() || c.Inventory.Request.StorageID.IsZero() {
		return b, ErrMigratedPrune
	}
	for i, a := range c.Inventory.Policy.Assignments {
		aid, _ := a.ID()
		entry := c.Inventory.Admissions[i]
		if a.Version != custodyauthority.Version0 || entry.Version != custodyauthority.Version0 || !entry.Command.ScheduleID.IsZero() {
			return b, ErrMigratedPrune
		}
		if _, err := custodyauthority.PruneEntryReviewID(a, entry.Command); err != nil {
			return b, err
		}
		if aid == c.Inventory.Request.AssignmentID {
			b.primary, b.primaryEntry = a, entry
		}
		if aid == c.Proof.AssignmentID {
			b.selected, b.selectedEntry = a, entry
			b.ticket, _ = entry.ID()
		}
	}
	if b.ticket.IsZero() {
		return b, custodyauthority.ErrAssignment
	}
	if err := c.Proof.Verify(b.selected, c.Inventory.Policy.CheckpointPolicy); err != nil {
		return b, err
	}
	original, _ := c.Proof.OriginalCheckpoint.Statement.ID()
	want, _ := c.Inventory.Policy.Checkpoint.Statement.ID()
	if original != want {
		return b, ErrMigratedPrune
	}
	return b, nil
}

// SelectedAssignment validates the complete static context before returning the
// original assignment. No owner is opened and no newer position is selected.
func (c MigratedPruneContext) SelectedAssignment() (custodyauthority.Assignment, error) {
	b, e := c.bindings()
	return b.selected, e
}

type MigratedPruneOutcome struct {
	Effect       *workchain.CanonicalPruneEffect
	Cancellation *PruneCancellation
}

func (o MigratedPruneOutcome) EvidenceID(c MigratedPruneContext) (types.Hash, error) {
	b, err := c.bindings()
	if err != nil {
		return types.Hash{}, err
	}
	if (o.Effect == nil) == (o.Cancellation == nil) {
		return types.Hash{}, ErrPruneOutcome
	}
	if o.Effect != nil {
		if !pruneEffectMatches(c.Inventory.Request, b.primaryEntry, *o.Effect) {
			return types.Hash{}, ErrPruneOutcome
		}
		return o.Effect.ID()
	}
	v := *o.Cancellation
	primaryTicket, _ := b.primaryEntry.ID()
	if v.AssignmentID != c.Inventory.Request.AssignmentID || v.RequestID != c.Inventory.Policy.RequestID || v.TicketID != primaryTicket || v.BindingID != c.Inventory.Policy.ExecutorBindingID {
		return types.Hash{}, ErrPruneOutcome
	}
	return v.ID()
}
func (o MigratedPruneOutcome) Artifact() ([]byte, error) {
	if (o.Effect == nil) == (o.Cancellation == nil) {
		return nil, ErrPruneOutcome
	}
	if o.Effect != nil {
		return o.Effect.CanonicalBytes()
	}
	return o.Cancellation.CanonicalBytes()
}
func LoadMigratedPruneOutcome(path, kind string, id types.Hash) (MigratedPruneOutcome, error) {
	var o MigratedPruneOutcome
	if id.IsZero() {
		return o, ErrPruneOutcome
	}
	raw, err := readRegular(path, workchain.MaximumCanonicalPruneEffectBytes)
	if err != nil {
		return o, err
	}
	var actual types.Hash
	switch kind {
	case "effect":
		v, e := workchain.DecodeCanonicalPruneEffect(raw)
		if e != nil {
			return o, e
		}
		actual, err = v.ID()
		o.Effect = &v
	case "cancellation":
		v, e := DecodePruneCancellation(raw)
		if e != nil {
			return o, e
		}
		actual, err = v.ID()
		o.Cancellation = &v
	default:
		return o, ErrPruneOutcome
	}
	if err != nil || actual != id {
		return MigratedPruneOutcome{}, ErrPruneOutcome
	}
	return o, nil
}

// BuildMigratedPruneCompletion uses the unchanged old ticket and outcome ID in
// an explicitly reviewed v2 Complete. Static evidence does not establish a live
// executor result; application must check that result under the original owners.
func BuildMigratedPruneCompletion(c MigratedPruneContext, o MigratedPruneOutcome, pos custodyauthority.Position) (custodyauthority.Command, error) {
	b, err := c.bindings()
	if err != nil {
		return custodyauthority.Command{}, err
	}
	evidence, err := o.EvidenceID(c)
	if err != nil {
		return custodyauthority.Command{}, err
	}
	// The old admission and the one-time migration must both precede completion.
	if pos.Sequence < b.selectedEntry.Command.ExpectedSequence+2 || pos.HeadID == b.ticket {
		return custodyauthority.Command{}, custodyauthority.ErrHead
	}
	draft := custodyauthority.Command{Version: custodyauthority.ScheduleVersion2, AssignmentID: c.Proof.AssignmentID, ScheduleID: c.ScheduleID, ExpectedSequence: pos.Sequence, ExpectedHead: pos.HeadID, Kind: custodyauthority.Complete, TicketID: b.ticket, EvidenceID: evidence, ActorPublicKey: c.Inventory.Request.ConsumerPublicKey}
	if _, err := custodyauthority.ScheduledPruneCommandReviewID(b.selected, draft); err != nil {
		return custodyauthority.Command{}, err
	}
	return draft, nil
}
func migratedPruneRetained(c MigratedPruneContext, s PruneExecution) (MigratedPruneOutcome, error) {
	b, err := c.bindings()
	if err != nil {
		return MigratedPruneOutcome{}, err
	}
	if s.Protection == nil || s.Protection.Pending != nil || s.Protection.BindingID != c.Inventory.Policy.ExecutorBindingID || s.RequestID != c.Inventory.Policy.RequestID || !samePruneRequest(s.Request, c.Inventory.Request) || s.Admission == nil || *s.Admission != b.primaryEntry {
		return MigratedPruneOutcome{}, ErrPruneOutcome
	}
	o := MigratedPruneOutcome{Effect: s.Effect, Cancellation: s.Cancellation}
	if (s.Stage == PruneSucceeded && s.ArchiveInventoryID == c.InventoryID && o.Effect != nil && o.Cancellation == nil) || (s.Stage == PruneCancelled && s.ArchiveInventoryID.IsZero() && o.Cancellation != nil && o.Effect == nil) {
		if _, err := o.EvidenceID(c); err != nil {
			return MigratedPruneOutcome{}, err
		}
		return o, nil
	}
	return MigratedPruneOutcome{}, ErrPruneOutcome
}

func samePruneRequest(a, b PruneRequest) bool {
	x, xe := a.ID()
	y, ye := b.ID()
	return xe == nil && ye == nil && x == y
}
func sameMigratedOutcome(a, b MigratedPruneOutcome) bool {
	x, xe := a.Artifact()
	y, ye := b.Artifact()
	return xe == nil && ye == nil && bytes.Equal(x, y)
}
