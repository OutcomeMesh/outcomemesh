package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type CustodyTerminalCaptureConfig struct {
	Scope         CustodyCommandScope
	Admission     custodyauthority.Entry
	JournalPath   string
	JournalLimits workarchive.CustodyJournalLimits
}

// CaptureCustodyTerminal checks the exact pending ticket in the supplied
// original coordinator and opens only an existing active source journal. This
// first format accepts ONLY the intent's immediate result at the CURRENT head;
// an advanced head is rejected, never searched or promoted into another result.
// It captures a value and does not publish a file or complete either ticket.
func CaptureCustodyTerminal(ctx context.Context, original *Coordinator, config CustodyTerminalCaptureConfig) (terminal CustodyTerminal, returnErr error) {
	if original == nil {
		return CustodyTerminal{}, ErrClosed
	}
	if ctx == nil || config.Scope.AssignmentID != original.assignmentID || config.JournalPath == "" || config.JournalLimits.Validate() != nil {
		return CustodyTerminal{}, ErrCustodyTerminal
	}
	scope, err := freezeCustodyCommandEvidenceScope(config.Scope)
	if err != nil {
		return CustodyTerminal{}, err
	}
	config.Scope = scope
	if _, err := config.Admission.ID(); err != nil {
		return CustodyTerminal{}, err
	}
	binding := custodyAdmissionBinding(config.Scope, config.Admission)
	err = original.WithOperation(ctx, binding, func() (returnErr error) {
		retained, err := readRegular(filepath.Join(original.authority.path, assignmentName), custodyauthority.MaximumAssignmentBytes)
		if err != nil {
			return err
		}
		want, err := config.Scope.Assignment.CanonicalBytes()
		if err != nil || !bytes.Equal(retained, want) {
			return errors.Join(ErrCustodyTerminal, err)
		}
		for _, root := range []string{original.authority.path, original.journal.path} {
			if _, _, err := coordinatorPaths(root, config.JournalPath); err != nil {
				return err
			}
		}
		journal, _, err := openManagedCustodyJournal(ctx, config.JournalPath, config.Scope.Manifest, config.Scope.InitialReceipt, config.Scope.CustodyPolicy, config.JournalLimits, config.Scope.Schedule, config.Scope.Assignment)
		if err != nil {
			return err
		}
		decision, err := journal.AcquireDecision()
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, decision.Close()) }()
		if err := ctx.Err(); err != nil {
			return err
		}
		terminal, err = captureCustodyTerminalLocked(ctx, config.Scope, config.Admission, decision)
		if err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return CustodyTerminal{}, err
	}
	return terminal, nil
}

// Snapshot all slice-bearing static inputs before entering a live owner. No
// caller-owned configuration slice is retained across source locking or I/O.
func freezeCustodyCommandEvidenceScope(scope CustodyCommandScope) (CustodyCommandScope, error) {
	return cloneCustodyCommandScope(scope)
}

// CaptureCustodyTerminalLocked is source-only validation. The caller MUST hold
// the original selected pending-ticket coordinator guard and this active source
// decision through every effect. It never acquires or reenters an owner lock.
func CaptureCustodyTerminalLocked(scope CustodyCommandScope, admission custodyauthority.Entry, decision *workarchive.CustodyJournalDecision) (CustodyTerminal, error) {
	return captureCustodyTerminalLocked(context.Background(), scope, admission, decision)
}

func captureCustodyTerminalLocked(ctx context.Context, scope CustodyCommandScope, admission custodyauthority.Entry, decision *workarchive.CustodyJournalDecision) (CustodyTerminal, error) {
	if decision == nil {
		return CustodyTerminal{}, ErrCustodyTerminal
	}
	head, ok, err := decision.Head()
	if err != nil || !ok {
		return CustodyTerminal{}, errors.Join(ErrCustodyTerminal, err)
	}
	terminal := CustodyTerminal{Version: CustodyTerminalVersion0, AssignmentID: scope.AssignmentID,
		Admission: admission, Intent: scope.Intent, Entry: head}
	if scope.Schedule != nil {
		terminal.Version = CustodyTerminalVersion1
		terminal.ScheduleID = scope.scheduleID()
	}
	if err := validateCustodyTerminalDecision(ctx, scope, terminal, decision); err != nil {
		return CustodyTerminal{}, err
	}
	return terminal, nil
}

// ValidateCustodyTerminalDecision verifies static historical proof and exact
// CURRENT source head under a caller-held active decision. It is not a reusable
// current authority grant. No older-history search is performed.
func ValidateCustodyTerminalDecision(scope CustodyCommandScope, terminal CustodyTerminal, decision *workarchive.CustodyJournalDecision) error {
	return validateCustodyTerminalDecision(context.Background(), scope, terminal, decision)
}

func validateCustodyTerminalDecision(ctx context.Context, scope CustodyCommandScope, terminal CustodyTerminal, decision *workarchive.CustodyJournalDecision) error {
	if decision == nil {
		return ErrCustodyTerminal
	}
	if err := terminal.Validate(scope); err != nil {
		return err
	}
	if scope.Schedule != nil {
		if _, _, err := decision.ScheduleLineage(ctx, scope.Schedule.Proof, scope.Assignment, scope.Schedule.Policy); err != nil {
			return err
		}
	}
	state, err := decision.State()
	if err != nil {
		return err
	}
	head, ok, err := decision.Head()
	if err != nil || !ok || state.InitialReceipt != scope.InitialReceipt || state.Sequence != terminal.Entry.Sequence ||
		state.CurrentReceipt != terminal.Entry.Record.RenewedReceipt {
		return errors.Join(ErrCustodyTerminal, err)
	}
	id, err := terminal.Entry.ID()
	if err != nil || state.HeadEntryID != id {
		return errors.Join(ErrCustodyTerminal, err)
	}
	want, err := terminal.Entry.CanonicalBytes()
	if err != nil {
		return err
	}
	got, err := head.CanonicalBytes()
	if err != nil || !bytes.Equal(want, got) {
		return errors.Join(ErrCustodyTerminal, err)
	}
	return nil
}
