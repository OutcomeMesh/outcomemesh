package store

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// CustodyScheduleContext is explicit, independently reviewed input. A live owner
// never discovers or adopts a schedule from a peer or from an archive filename.
type CustodyScheduleContext struct {
	Proof      workarchive.CustodyScheduleProof
	Policy     workarchive.Policy
	ExpectedID types.Hash
}

func (s *CustodyScheduleContext) detached() (*CustodyScheduleContext, types.Hash, error) {
	if s == nil {
		return nil, types.Hash{}, nil
	}
	if len(s.Policy.TrustedAttestors) > workarchive.MaximumAttestors {
		return nil, types.Hash{}, workarchive.ErrCustodySchedule
	}
	b, err := s.Proof.CanonicalBytes()
	if err != nil {
		return nil, types.Hash{}, err
	}
	p, err := workarchive.DecodeCustodyScheduleProof(b)
	if err != nil {
		return nil, types.Hash{}, err
	}
	id, err := p.ID()
	if err != nil || id != s.ExpectedID {
		return nil, types.Hash{}, workarchive.ErrCustodySchedule
	}
	policy := s.Policy
	policy.TrustedAttestors = append([][32]byte(nil), policy.TrustedAttestors...)
	return &CustodyScheduleContext{Proof: p, Policy: policy, ExpectedID: id}, id, nil
}

func (c *Coordinator) retainedAssignment() (custodyauthority.Assignment, error) {
	b, err := readRegular(filepath.Join(c.authority.path, assignmentName), custodyauthority.MaximumAssignmentBytes)
	if err != nil {
		return custodyauthority.Assignment{}, err
	}
	a, err := custodyauthority.DecodeAssignment(b)
	if err != nil {
		return a, err
	}
	id, err := a.ID()
	if err != nil || id != c.assignmentID {
		return a, custodyauthority.ErrAssignment
	}
	return a, nil
}

// MigrateCustodySchedule appends exactly one replica-signed, authority-cosigned
// transition while holding the original authority and original storage journal.
// It neither reissues admissions nor resets a counter, receipt or pending ticket.
// Unknown outcomes stay held in the original intent journal; Resume only finishes
// that exact retained entry. The caller retains the immutable proof by ExpectedID.
func (c *Coordinator) MigrateCustodySchedule(ctx context.Context, entry custodyauthority.Entry, scope CustodyScheduleContext,
	journalPath string, policy workarchive.CustodyPolicy, limits workarchive.CustodyJournalLimits) (result Commit, returnErr error) {
	if c == nil {
		return result, ErrClosed
	}
	if ctx == nil {
		return result, ErrStore
	}
	s, id, err := scope.detached()
	if err != nil {
		return result, err
	}
	if entry.Command.Kind != custodyauthority.MigrateSchedule || entry.Command.ScheduleID != id || entry.Command.AssignmentID != c.assignmentID {
		return result, custodyauthority.ErrCommand
	}
	if _, err = entry.CanonicalBytes(); err != nil {
		return result, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	current, err := c.snapshot()
	if err != nil {
		return result, err
	}
	a, err := c.retainedAssignment()
	if err != nil {
		return result, err
	}
	if err = s.Proof.Verify(a, s.Policy); err != nil {
		return result, err
	}
	if entry.AuthorityPublicKey != a.AuthorityPublicKey || entry.Command.ActorPublicKey != a.ReplicaPublicKey {
		return result, custodyauthority.ErrAssignment
	}
	// A retained retry is a lookup/recovery, even if later genuine renewals have
	// advanced the journal. Never take a new snapshot as authorization to rewrite it.
	if current.Pending != nil || entry.Command.ExpectedSequence < current.Confirmed.Sequence {
		return c.append(ctx, entry)
	}
	for _, root := range []string{c.authority.path, c.journal.path} {
		if _, _, err = coordinatorPaths(root, journalPath); err != nil {
			return result, err
		}
	}
	journal, _, err := workarchive.OpenScheduledCustodyJournal(ctx, journalPath, s.Proof, a, s.Policy, policy, limits)
	if err != nil {
		return result, err
	}
	decision, err := journal.AcquireDecision()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, decision.Close()) }()
	state, err := decision.State()
	if err != nil {
		return result, err
	}
	if state.Sequence != s.Proof.JournalSequence || state.HeadEntryID != s.Proof.JournalHeadID || state.CurrentReceipt != s.Proof.SelectedReceipt {
		return result, workarchive.ErrCustodySchedule
	}
	if err = decision.CheckAccess(); err != nil {
		return result, err
	}
	return c.append(ctx, entry)
}

func openManagedCustodyJournal(ctx context.Context, path string, manifest workarchive.Manifest, initial workarchive.ReplicaReceipt,
	policy workarchive.CustodyPolicy, limits workarchive.CustodyJournalLimits, schedule *CustodyScheduleContext, assignment custodyauthority.Assignment) (*workarchive.CustodyJournal, workarchive.CustodyJournalState, error) {
	if schedule == nil {
		return workarchive.OpenExistingCustodyJournalWithLimits(ctx, path, manifest, initial, policy, limits)
	}
	id, err := manifest.ID()
	if err != nil || id != assignment.ManifestID || initial != schedule.Proof.InitialReceipt {
		return nil, workarchive.CustodyJournalState{}, workarchive.ErrCustodySchedule
	}
	return workarchive.OpenScheduledCustodyJournal(ctx, path, schedule.Proof, assignment, schedule.Policy, policy, limits)
}
