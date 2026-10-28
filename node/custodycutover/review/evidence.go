// Package review verifies historical legacy transition material. Its evidence,
// observations and proposals are historical review material, never an import,
// execution grant, source retirement or proof of protected global fencing.
package review

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	a "github.com/outcomemesh/outcomemesh/node/custodyauthority"
	w "github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	s "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const Version1 uint16 = 1
const MaximumCycles = 64
const MaximumHistoryEntries = 5*2*MaximumCycles + 2
const MaximumEvidenceBytes = 32 << 20

var ErrEvidence = errors.New("legacy cutover evidence is incomplete, unretired or inconsistent")
var ErrBlocked = errors.New("legacy cutover remains blocked by an unresolved or unsupported obligation")
var ErrBudget = errors.New("cutover allowance would refund or exceed prior spending limits")
var ErrPreparation = errors.New("invalid disabled cutover preparation")

const domain = "OMESH/custody-cutover-review/v1/"

type Cycle struct {
	Plan     w.Plan
	Begin    a.Entry
	Terminal s.RemoteCustodyTerminal
}

// Evidence includes every authority entry and every accepted source entry.
// A detached Snapshot, opaque completion digest or a prefix is not evidence.
type Evidence struct {
	Version    uint16
	Assignment a.Assignment
	Manifest   workarchive.Manifest
	Initial    workarchive.ReplicaReceipt
	Policy     workarchive.CustodyPolicy
	End        a.Position
	History    []a.Entry
	Cycles     []Cycle
}
type Assessment struct {
	AssignmentID, RetirementID                        types.Hash
	Authority                                         a.Position
	SpentOperations, LegacyLimit, RemainingOperations uint32
	SourceSequence                                    uint64
	SourceHeadID, ReceiptID                           types.Hash
	CurrentReceipt                                    workarchive.ReplicaReceipt
	MinimumRetainUntil                                uint64
}

func (e Evidence) Scope(c Cycle) s.RemoteCustodyScope {
	pid, _ := c.Plan.ID()
	bid, _ := c.Begin.ID()
	return s.RemoteCustodyScope{Worker: w.Config{Assignment: e.Assignment, Plan: c.Plan, PlanID: pid, Begin: c.Begin, BeginID: bid}, Manifest: e.Manifest, InitialReceipt: e.Initial, PreviousReceipt: c.Terminal.Entry.PreviousReceipt, CustodyPolicy: e.Policy, Challenge: c.Terminal.Entry.Record.Challenge}
}
func (e Evidence) CanonicalBytes() ([]byte, error) {
	if e.Version != Version1 || e.Assignment.Version != a.Version1 || len(e.History) > MaximumHistoryEntries || len(e.Cycles) > MaximumCycles || e.End.Sequence != uint64(len(e.History)) || e.End.HeadID.IsZero() || len(e.Policy.TrustedAuditors) > 64 {
		return nil, ErrEvidence
	}
	enc := codec.NewEncoder(4096)
	enc.Fixed([]byte("OMCXEVD1"))
	enc.U16(e.Version)
	add := func(v interface{ CanonicalBytes() ([]byte, error) }) error {
		raw, err := v.CanonicalBytes()
		if err != nil {
			return err
		}
		if enc.Len()+len(raw)+10 > MaximumEvidenceBytes {
			return ErrEvidence
		}
		enc.BytesField(raw)
		return nil
	}
	for _, v := range []interface{ CanonicalBytes() ([]byte, error) }{e.Assignment, e.Manifest, e.Initial} {
		if err := add(v); err != nil {
			return nil, err
		}
	}
	enc.U64(e.Policy.MaximumChallengeLifetime)
	enc.U64(e.Policy.MaximumProofAge)
	enc.U64(e.Policy.MaximumRenewalTerm)
	enc.U16(uint16(len(e.Policy.TrustedAuditors)))
	for _, key := range e.Policy.TrustedAuditors {
		enc.Fixed(key[:])
	}
	enc.U64(e.End.Sequence)
	enc.Fixed(e.End.HeadID[:])
	enc.U16(uint16(len(e.History)))
	for _, entry := range e.History {
		if err := add(entry); err != nil {
			return nil, err
		}
	}
	enc.U16(uint16(len(e.Cycles)))
	for _, c := range e.Cycles {
		for _, v := range []interface{ CanonicalBytes() ([]byte, error) }{c.Plan, c.Begin, c.Terminal} {
			if err := add(v); err != nil {
				return nil, err
			}
		}
	}
	raw := enc.Bytes()
	if len(raw) > MaximumEvidenceBytes {
		return nil, ErrEvidence
	}
	return raw, nil
}
func DecodeEvidence(raw []byte) (Evidence, error) {
	var e Evidence
	if len(raw) > MaximumEvidenceBytes {
		return e, ErrEvidence
	}
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCXEVD1") {
		return e, ErrEvidence
	}
	e.Version, _ = d.U16()
	b, err := d.BytesField(a.MaximumAssignmentBytes)
	if err != nil {
		return e, err
	}
	e.Assignment, err = a.DecodeAssignment(b)
	if err != nil {
		return e, err
	}
	b, err = d.BytesField(workarchive.MaximumManifestBytes)
	if err != nil {
		return e, err
	}
	e.Manifest, err = workarchive.DecodeManifest(b)
	if err != nil {
		return e, err
	}
	b, err = d.BytesField(workarchive.MaximumReplicaReceiptBytes)
	if err != nil {
		return e, err
	}
	e.Initial, err = workarchive.DecodeReplicaReceipt(b)
	if err != nil {
		return e, err
	}
	e.Policy.MaximumChallengeLifetime, _ = d.U64()
	e.Policy.MaximumProofAge, _ = d.U64()
	e.Policy.MaximumRenewalTerm, _ = d.U64()
	n, err := d.U16()
	if err != nil || n > 64 || d.Remaining() < int(n)*32 {
		return e, ErrEvidence
	}
	for i := 0; i < int(n); i++ {
		var key [32]byte
		fixed(d, key[:])
		e.Policy.TrustedAuditors = append(e.Policy.TrustedAuditors, key)
	}
	e.End.Sequence, _ = d.U64()
	fixed(d, e.End.HeadID[:])
	n, err = d.U16()
	if err != nil || n > MaximumHistoryEntries || int(n) > d.Remaining() {
		return e, ErrEvidence
	}
	for i := 0; i < int(n); i++ {
		b, err := d.BytesField(a.MaximumEntryBytes)
		if err != nil {
			return e, err
		}
		v, err := a.DecodeEntry(b)
		if err != nil {
			return e, err
		}
		e.History = append(e.History, v)
	}
	n, err = d.U16()
	if err != nil || n > MaximumCycles || int(n) > d.Remaining() {
		return e, ErrEvidence
	}
	for i := 0; i < int(n); i++ {
		var c Cycle
		b, err := d.BytesField(w.MaximumPlanBytes)
		if err != nil {
			return e, err
		}
		c.Plan, err = w.DecodePlan(b)
		if err != nil {
			return e, err
		}
		b, err = d.BytesField(a.MaximumEntryBytes)
		if err != nil {
			return e, err
		}
		c.Begin, err = a.DecodeEntry(b)
		if err != nil {
			return e, err
		}
		b, err = d.BytesField(s.MaximumRemoteCustodyTerminalBytes)
		if err != nil {
			return e, err
		}
		c.Terminal, err = s.DecodeRemoteCustodyTerminal(b)
		if err != nil {
			return e, err
		}
		e.Cycles = append(e.Cycles, c)
	}
	again, err := e.CanonicalBytes()
	if err != nil || d.Finish() != nil || !bytes.Equal(raw, again) {
		return Evidence{}, ErrEvidence
	}
	return e, nil
}
func (e Evidence) ID() (types.Hash, error) {
	b, err := e.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(domain+"evidence/id", b), nil
}
func (e Evidence) Verify(id types.Hash, end a.Position) (Assessment, error) {
	var result Assessment
	raw, err := e.CanonicalBytes()
	if err != nil {
		return result, err
	}
	e, err = DecodeEvidence(raw)
	if err != nil {
		return result, err
	}
	actual, err := e.Assignment.ID()
	if err != nil || id.IsZero() || actual != id || e.End != end {
		return result, ErrEvidence
	}
	derived, err := workarchive.CreateRemoteCustodyAuthorityAssignment(e.Manifest, e.Initial, e.Policy, e.Assignment.IncarnationID, e.Assignment.AuthorityPublicKey, e.Assignment.Consumers, e.Assignment.MaximumOperations, e.Assignment.MaximumPending, e.Assignment.RemoteControlPublicKey, e.Assignment.RemoteTransportPublicKey)
	if err != nil {
		return result, err
	}
	did, _ := derived.ID()
	if did != id {
		return result, ErrEvidence
	}
	state, err := a.Replay(e.Assignment, id, e.History, end)
	if err != nil {
		return result, err
	}
	snapshot, err := state.Snapshot()
	if err != nil {
		return result, err
	}
	if snapshot.Phase != a.Retired || snapshot.Pending != 0 || snapshot.Remote != nil || snapshot.RetirementID.IsZero() || snapshot.RetirementID != end.HeadID {
		return result, ErrBlocked
	}
	if len(snapshot.Operations) != 2*len(e.Cycles) {
		return result, ErrBlocked
	}
	entriesByID := map[types.Hash]a.Entry{}
	for _, entry := range e.History {
		eid, err := entry.ID()
		if err != nil {
			return result, err
		}
		entriesByID[eid] = entry
	}
	operations := map[types.Hash]a.Operation{}
	for _, op := range snapshot.Operations {
		operations[op.TicketID] = op
	}
	seen := map[types.Hash]bool{}
	retained := func(entry a.Entry) bool {
		seq := entry.Command.ExpectedSequence
		if seq >= uint64(len(e.History)) {
			return false
		}
		return e.History[seq] == entry
	}
	receipt := e.Initial
	head := types.Hash{}
	floor := receipt.RetainUntil
	for i, c := range e.Cycles {
		t := c.Terminal
		if !retained(c.Plan.Admission) || !retained(c.Begin) || !retained(t.AuditAdmission) || !retained(t.Drained) {
			return result, ErrEvidence
		}
		if err := t.Validate(e.Scope(c)); err != nil {
			return result, err
		}
		if err := t.Entry.Verify(e.Manifest, e.Policy, uint64(i)+1, head, receipt); err != nil {
			return result, err
		}
		tid, _ := t.ID()
		aid, _ := t.AuditAdmission.ID()
		sid, _ := c.Plan.Admission.ID()
		bid, _ := c.Begin.ID()
		drain, _ := t.Drained.ID()
		seal, _ := t.Seal.ID()
		pid, _ := c.Plan.ID()
		if aid == sid || seen[aid] || seen[sid] {
			return result, ErrEvidence
		}
		for _, ticket := range []types.Hash{aid, sid} {
			op, ok := operations[ticket]
			if !ok || op.CompletionID.IsZero() || op.EvidenceID != tid {
				return result, ErrBlocked
			}
			if ticket == aid {
				if op.Purpose != a.Audit || !op.RemoteBeginID.IsZero() {
					return result, ErrEvidence
				}
			} else if op.Purpose != a.Serve || op.RemoteBeginID != bid || op.RemoteDrainID != drain || op.RemotePlanID != pid || op.RemoteTombstoneID != seal {
				return result, ErrEvidence
			}
			entry, found := entriesByID[op.CompletionID]
			if !found {
				return result, ErrEvidence
			}
			draft, err := s.BuildRemoteCustodyCompleteCommand(e.Scope(c), t, ticket, a.Position{Sequence: entry.Command.ExpectedSequence, HeadID: entry.Command.ExpectedHead})
			if err != nil {
				return result, err
			}
			draft.Signature = entry.Command.Signature
			if draft != entry.Command {
				return result, ErrEvidence
			}
			seen[ticket] = true
		}
		receipt = t.Entry.Record.RenewedReceipt
		head, _ = t.Entry.ID()
		if receipt.RetainUntil > floor {
			floor = receipt.RetainUntil
		}
	}
	if len(seen) != len(operations) {
		return result, ErrBlocked
	}
	spent := uint32(len(snapshot.Operations))
	if spent > e.Assignment.MaximumOperations {
		return result, ErrBudget
	}
	rid, err := receipt.ID()
	if err != nil {
		return result, err
	}
	return Assessment{AssignmentID: id, RetirementID: snapshot.RetirementID, Authority: end, SpentOperations: spent, LegacyLimit: e.Assignment.MaximumOperations, RemainingOperations: e.Assignment.MaximumOperations - spent, SourceSequence: uint64(len(e.Cycles)), SourceHeadID: head, ReceiptID: rid, CurrentReceipt: receipt, MinimumRetainUntil: floor}, nil
}
func magic(d *codec.Decoder, want string) bool {
	b, e := d.Fixed(8)
	return e == nil && string(b) == want
}
func fixed(d *codec.Decoder, out []byte) {
	b, e := d.Fixed(len(out))
	if e == nil {
		copy(out, b)
	}
}
