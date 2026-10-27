package store

import (
	"bytes"
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const (
	RemoteCustodyTerminalVersion0     uint16 = 0
	MaximumRemoteCustodyTerminalBytes        = workarchive.MaximumCustodyJournalEntryBytes + workarchive.MaximumCustodyAuditIntentBytes +
		2*custodyauthority.MaximumEntryBytes + remoteworker.SealBytes + 128
)

// RemoteCustodyTerminal joins B's signed, sealed journal-entry commitment with
// the SAME response already accepted in A's original local Audit journal. The
// value is historical evidence, never an import path or a fresh proof.
type RemoteCustodyTerminal struct {
	Version         uint16
	PlanID, BeginID types.Hash
	AuditAdmission  custodyauthority.Entry
	Intent          workarchive.CustodyAuditIntent
	Seal            remoteworker.Seal
	Drained         custodyauthority.Entry
	Entry           workarchive.CustodyJournalEntry
}

func (terminal RemoteCustodyTerminal) validateShape() error {
	if terminal.Version != RemoteCustodyTerminalVersion0 || terminal.PlanID.IsZero() || terminal.BeginID.IsZero() ||
		terminal.Seal.PlanID != terminal.PlanID || terminal.Seal.BeginID != terminal.BeginID || terminal.Seal.Disposition != remoteworker.RetainedResult ||
		terminal.Intent.Validate() != nil || terminal.AuditAdmission.Version != custodyauthority.Version1 || terminal.Drained.Version != custodyauthority.Version1 {
		return ErrRemoteCustody
	}
	sealID, err := terminal.Seal.ID()
	if err != nil {
		return errors.Join(ErrRemoteCustody, err)
	}
	entryID, err := terminal.Entry.ID()
	if err != nil || entryID != terminal.Seal.ResultID || terminal.Entry.Sequence != terminal.Intent.PriorSequence+1 ||
		terminal.Entry.PreviousEntryID != terminal.Intent.PriorHeadID || !custodyIntentMatchesChallenge(terminal.Intent, terminal.Entry.Record.Challenge) {
		return errors.Join(ErrRemoteCustody, err)
	}
	previousID, err := terminal.Entry.PreviousReceipt.ID()
	if err != nil || previousID != terminal.Intent.PriorReceiptID {
		return errors.Join(ErrRemoteCustody, err)
	}
	intentID, _ := terminal.Intent.ID()
	a, d := terminal.AuditAdmission.Command, terminal.Drained.Command
	if a.Kind != custodyauthority.Admit || a.Purpose != custodyauthority.Audit || a.Version != custodyauthority.Version1 ||
		a.AssignmentID != terminal.Intent.AssignmentID || a.OperationID != intentID || a.ActorPublicKey != terminal.Intent.ConsumerPublicKey ||
		d.Version != custodyauthority.Version1 || d.AssignmentID != a.AssignmentID || d.Kind != custodyauthority.RemoteDrained ||
		d.OperationID != terminal.BeginID || d.EvidenceID != sealID {
		return ErrRemoteCustody
	}
	return nil
}

func (terminal RemoteCustodyTerminal) CanonicalBytes() ([]byte, error) {
	if err := terminal.validateShape(); err != nil {
		return nil, err
	}
	a, err := terminal.AuditAdmission.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	i, err := terminal.Intent.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	s, err := terminal.Seal.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	d, err := terminal.Drained.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	h, err := terminal.Entry.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	e := codec.NewEncoder(len(a) + len(i) + len(s) + len(d) + len(h) + 128)
	e.Fixed([]byte("OMCRTERM"))
	e.U16(terminal.Version)
	e.Fixed(terminal.PlanID[:])
	e.Fixed(terminal.BeginID[:])
	for _, field := range [][]byte{a, i, s, d, h} {
		e.BytesField(field)
	}
	b := e.Bytes()
	if len(b) > MaximumRemoteCustodyTerminalBytes {
		return nil, ErrRemoteCustody
	}
	return b, nil
}

func DecodeRemoteCustodyTerminal(input []byte) (RemoteCustodyTerminal, error) {
	if len(input) == 0 || len(input) > MaximumRemoteCustodyTerminalBytes {
		return RemoteCustodyTerminal{}, ErrRemoteCustody
	}
	d := codec.NewDecoder(input)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, []byte("OMCRTERM")) {
		return RemoteCustodyTerminal{}, ErrRemoteCustody
	}
	var t RemoteCustodyTerminal
	if t.Version, err = d.U16(); err != nil {
		return RemoteCustodyTerminal{}, ErrRemoteCustody
	}
	for _, id := range []*types.Hash{&t.PlanID, &t.BeginID} {
		b, err := d.Fixed(types.HashSize)
		if err != nil {
			return RemoteCustodyTerminal{}, ErrRemoteCustody
		}
		copy(id[:], b)
	}
	b, err := d.BytesField(custodyauthority.MaximumEntryBytes)
	if err != nil {
		return RemoteCustodyTerminal{}, ErrRemoteCustody
	}
	if t.AuditAdmission, err = custodyauthority.DecodeEntry(b); err != nil {
		return RemoteCustodyTerminal{}, err
	}
	b, err = d.BytesField(workarchive.MaximumCustodyAuditIntentBytes)
	if err != nil {
		return RemoteCustodyTerminal{}, ErrRemoteCustody
	}
	if t.Intent, err = workarchive.DecodeCustodyAuditIntent(b); err != nil {
		return RemoteCustodyTerminal{}, err
	}
	b, err = d.BytesField(remoteworker.SealBytes)
	if err != nil {
		return RemoteCustodyTerminal{}, ErrRemoteCustody
	}
	if t.Seal, err = remoteworker.DecodeSeal(b); err != nil {
		return RemoteCustodyTerminal{}, err
	}
	b, err = d.BytesField(custodyauthority.MaximumEntryBytes)
	if err != nil {
		return RemoteCustodyTerminal{}, ErrRemoteCustody
	}
	if t.Drained, err = custodyauthority.DecodeEntry(b); err != nil {
		return RemoteCustodyTerminal{}, err
	}
	b, err = d.BytesField(workarchive.MaximumCustodyJournalEntryBytes)
	if err != nil {
		return RemoteCustodyTerminal{}, ErrRemoteCustody
	}
	if t.Entry, err = workarchive.DecodeCustodyJournalEntry(b); err != nil {
		return RemoteCustodyTerminal{}, err
	}
	if d.Finish() != nil || t.validateShape() != nil {
		return RemoteCustodyTerminal{}, ErrRemoteCustody
	}
	return t, nil
}

func (terminal RemoteCustodyTerminal) ID() (types.Hash, error) {
	b, err := terminal.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-authority/remote-terminal/id/v0", b), nil
}

// Validate checks historical proof at its original RespondedAt. Only the owned
// runtime methods below establish that A actually accepted this exact entry.
func (terminal RemoteCustodyTerminal) Validate(scope RemoteCustodyScope) error {
	if err := validateRemoteAuditScope(scope, terminal.Intent, terminal.AuditAdmission); err != nil {
		return err
	}
	if _, err := terminal.CanonicalBytes(); err != nil {
		return err
	}
	w := scope.Worker
	if terminal.PlanID != w.PlanID || terminal.BeginID != w.BeginID || terminal.Drained.AuthorityPublicKey != w.Assignment.AuthorityPublicKey {
		return ErrRemoteCustody
	}
	if err := ValidateRemoteCustodyDrain(scope, terminal.Seal, terminal.Drained.Command); err != nil {
		return err
	}
	if err := terminal.Entry.Verify(scope.Manifest, scope.CustodyPolicy, w.Plan.PriorSequence+1, w.Plan.PriorHeadID, scope.PreviousReceipt); err != nil {
		return err
	}
	challengeID, err := terminal.Entry.Record.Challenge.ID()
	if err != nil || challengeID != w.Plan.Admission.Command.OperationID {
		return errors.Join(ErrRemoteCustody, err)
	}
	return nil
}

// checkRemoteTerminalLocked requires this runtime's original owner and source
// decision. It cannot open a caller-selected replacement or a copied B journal.
func (runtime *RemoteCustodyAuditRuntime) checkRemoteTerminalLocked(terminal RemoteCustodyTerminal, decision *workarchive.CustodyJournalDecision, allowPending bool) error {
	if err := runtime.checkSourceIdentity(); err != nil {
		return err
	}
	if err := terminal.Validate(runtime.scope); err != nil {
		return err
	}
	if terminal.Intent != runtime.intent || terminal.AuditAdmission != runtime.admission {
		return ErrRemoteCustody
	}
	current, err := runtime.life.owner.snapshot()
	if err != nil {
		return err
	}
	if current.Pending != nil && !allowPending {
		return ErrPendingAttempt
	}
	if current.Authority.Remote != nil || current.Authority.AssignmentID != runtime.scope.Worker.Plan.AssignmentID {
		return ErrRemoteCustody
	}
	w := runtime.scope.Worker
	serveID, _ := w.Plan.Admission.ID()
	auditID, _ := runtime.admission.ID()
	drainID, _ := terminal.Drained.ID()
	sealID, _ := terminal.Seal.ID()
	tid, _ := terminal.ID()
	audit, serve := false, false
	for _, operation := range current.Authority.Operations {
		if operation.TicketID == auditID {
			audit = operation.Purpose == custodyauthority.Audit && operation.ConsumerPublicKey == runtime.intent.ConsumerPublicKey &&
				operation.OperationID == runtime.session.intentID && operation.RemoteBeginID.IsZero() &&
				(operation.CompletionID.IsZero() || operation.EvidenceID == tid)
		}
		if operation.TicketID == serveID {
			serve = operation.Purpose == custodyauthority.Serve && operation.ConsumerPublicKey == w.Plan.Admission.Command.ActorPublicKey &&
				operation.OperationID == w.Plan.Admission.Command.OperationID && operation.RemoteBeginID == w.BeginID &&
				operation.RemotePlanID == w.PlanID && operation.RemoteDrainID == drainID && operation.RemoteTombstoneID == sealID &&
				(operation.CompletionID.IsZero() || operation.EvidenceID == tid)
		}
	}
	if !audit || !serve {
		return custodyauthority.ErrOperation
	}
	state, err := decision.State()
	if err != nil {
		return err
	}
	head, exists, err := decision.Head()
	if err != nil || !exists {
		return errors.Join(ErrRemoteCustody, err)
	}
	held, _ := head.CanonicalBytes()
	selected, _ := terminal.Entry.CanonicalBytes()
	if state.InitialReceipt != runtime.scope.InitialReceipt || state.Sequence != w.Plan.PriorSequence+1 || !bytes.Equal(held, selected) {
		return ErrRemoteCustody
	}
	return nil
}

// CaptureTerminal can only read this owned runtime's original A journal. Drain
// metadata without a matching locally accepted response cannot produce a value.
func (runtime *RemoteCustodyAuditRuntime) CaptureTerminal(ctx context.Context, response remotewire.Response) (terminal RemoteCustodyTerminal, returnErr error) {
	err := runtime.action(ctx, func(run context.Context) (returnErr error) {
		if _, err := response.CanonicalBytes(); err != nil {
			return err
		}
		if response.Status != remotewire.StatusDrained || response.PlanID != runtime.scope.Worker.PlanID || response.BeginID != runtime.scope.Worker.BeginID {
			return ErrRemoteCustody
		}
		if err := ValidateRemoteCustodyDrain(runtime.scope, response.Seal, response.Drain); err != nil {
			return err
		}
		drained, err := custodyauthority.SignEntry(response.Drain, runtime.authorityKey)
		if err != nil {
			return err
		}
		decision, err := runtime.journal.AcquireDecision()
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, decision.Close()) }()
		head, exists, err := decision.Head()
		if err != nil || !exists {
			return errors.Join(ErrRemoteCustody, err)
		}
		terminal = RemoteCustodyTerminal{Version: RemoteCustodyTerminalVersion0, PlanID: runtime.scope.Worker.PlanID, BeginID: runtime.scope.Worker.BeginID,
			AuditAdmission: runtime.admission, Intent: runtime.intent, Seal: response.Seal, Drained: drained, Entry: head}
		if err := runtime.checkRemoteTerminalLocked(terminal, decision, false); err != nil {
			return err
		}
		return run.Err()
	})
	if err != nil {
		return RemoteCustodyTerminal{}, err
	}
	return terminal, nil
}

// BuildRemoteCustodyCompleteCommand prepares an exact static draft. No signing,
// application or claim of current local acceptance is performed by this helper.
func BuildRemoteCustodyCompleteCommand(scope RemoteCustodyScope, terminal RemoteCustodyTerminal, ticket types.Hash, position custodyauthority.Position) (custodyauthority.Command, error) {
	if err := terminal.Validate(scope); err != nil {
		return custodyauthority.Command{}, err
	}
	auditID, _ := terminal.AuditAdmission.ID()
	serveID, _ := scope.Worker.Plan.Admission.ID()
	var actor [32]byte
	switch ticket {
	case auditID:
		actor = terminal.AuditAdmission.Command.ActorPublicKey
	case serveID:
		actor = scope.Worker.Plan.Admission.Command.ActorPublicKey
	default:
		return custodyauthority.Command{}, custodyauthority.ErrOperation
	}
	drainID, _ := terminal.Drained.ID()
	drainSequence := terminal.Drained.Command.ExpectedSequence + 1
	if position.Sequence < drainSequence || (position.Sequence == drainSequence) != (position.HeadID == drainID) || position.HeadID.IsZero() || position.Sequence >= custodyauthority.MaximumEntries(scope.Worker.Assignment) {
		return custodyauthority.Command{}, custodyauthority.ErrHead
	}
	id, _ := terminal.ID()
	return custodyauthority.Command{Version: custodyauthority.Version1, AssignmentID: scope.Worker.Plan.AssignmentID, ExpectedSequence: position.Sequence,
		ExpectedHead: position.HeadID, Kind: custodyauthority.Complete, TicketID: ticket, EvidenceID: id, ActorPublicKey: actor}, nil
}

func (runtime *RemoteCustodyAuditRuntime) ApplyComplete(ctx context.Context, terminal RemoteCustodyTerminal, entry custodyauthority.Entry) (Commit, error) {
	return runtime.applyRemoteComplete(ctx, terminal, entry, false)
}

// ResumeComplete settles only the retained exact command; Apply never resumes.
func (runtime *RemoteCustodyAuditRuntime) ResumeComplete(ctx context.Context, terminal RemoteCustodyTerminal, entry custodyauthority.Entry) (Commit, error) {
	return runtime.applyRemoteComplete(ctx, terminal, entry, true)
}

func (runtime *RemoteCustodyAuditRuntime) applyRemoteComplete(ctx context.Context, terminal RemoteCustodyTerminal, entry custodyauthority.Entry, resume bool) (commit Commit, returnErr error) {
	// Snapshot the caller's bounded slice-bearing evidence before waiting for
	// the private owner. It cannot be swapped while an action waits for a lock.
	b, err := terminal.CanonicalBytes()
	if err != nil {
		return Commit{}, err
	}
	terminal, err = DecodeRemoteCustodyTerminal(b)
	if err != nil {
		return Commit{}, err
	}
	err = runtime.action(ctx, func(run context.Context) (returnErr error) {
		if _, err := entry.CanonicalBytes(); err != nil {
			return err
		}
		c := entry.Command
		draft, err := BuildRemoteCustodyCompleteCommand(runtime.scope, terminal, c.TicketID, custodyauthority.Position{Sequence: c.ExpectedSequence, HeadID: c.ExpectedHead})
		if err != nil {
			return err
		}
		draft.Signature = c.Signature
		if c != draft || entry.AuthorityPublicKey != runtime.scope.Worker.Assignment.AuthorityPublicKey {
			return ErrRemoteCustody
		}
		current, err := runtime.life.owner.snapshot()
		if err != nil {
			return err
		}
		if resume {
			if current.Pending == nil {
				return ErrNoAttempt
			}
			if *current.Pending != entry {
				return ErrPendingAttempt
			}
		} else if current.Pending != nil {
			return ErrPendingAttempt
		}
		decision, err := runtime.journal.AcquireDecision()
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, decision.Close()) }()
		if err := runtime.checkRemoteTerminalLocked(terminal, decision, resume); err != nil {
			return err
		}
		if err := run.Err(); err != nil {
			return err
		}
		if resume {
			commit, err = runtime.life.owner.resume(run)
		} else {
			commit, err = runtime.life.owner.append(run, entry)
		}
		return err
	})
	return commit, err
}
