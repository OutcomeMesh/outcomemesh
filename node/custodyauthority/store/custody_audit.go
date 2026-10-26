package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

var ErrManagedCustodyAudit = errors.New("invalid managed custody audit configuration or peer")

// ManagedCustodyAuditConfig binds an existing unsigned intent and externally
// signed Audit admission. The admission OperationID is IntentID, available before
// challenge signing. A later independent Serve admission binds ChallengeID.
type ManagedCustodyAuditConfig struct {
	AssignmentID      types.Hash
	IntentID          types.Hash
	Admission         custodyauthority.Entry
	IntentPath        string
	JournalPath       string
	ArtifactsPath     string
	Manifest          workarchive.Manifest
	InitialReceipt    workarchive.ReplicaReceipt
	CustodyPolicy     workarchive.CustodyPolicy
	JournalLimits     workarchive.CustodyJournalLimits
	AuditorPrivateKey ed25519.PrivateKey
	SessionConfig     workarchive.CustodySessionConfig
}

// ManagedCustodyAuditSession owns its private cycle, not the original
// coordinator or any transport host. Every effect rechecks that same original
// coordinator and retained intent. No success or error completes its ticket.
// A standalone network Audit cannot recursively call a managed Serve using the
// same coordinator; a joint owned execution boundary is needed for local pairing.
type ManagedCustodyAuditSession struct {
	coordinator   *Coordinator
	binding       OperationBinding
	intentPath    string
	intentID      types.Hash
	journalPath   string
	artifactsPath string
	cycle         *workarchive.CustodyAuditCycle
}

func NewManagedCustodyAuditSession(ctx context.Context, coordinator *Coordinator, config ManagedCustodyAuditConfig) (*ManagedCustodyAuditSession, error) {
	if coordinator == nil {
		return nil, ErrClosed
	}
	if ctx == nil || config.AssignmentID.IsZero() || config.AssignmentID != coordinator.assignmentID || config.IntentID.IsZero() ||
		config.IntentPath == "" || config.JournalPath == "" || config.ArtifactsPath == "" || config.SessionConfig.Validate() != nil || config.JournalLimits.Validate() != nil {
		return nil, ErrManagedCustodyAudit
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	manifestBytes, err := config.Manifest.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	config.Manifest, err = workarchive.DecodeManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	if len(config.CustodyPolicy.TrustedAuditors) == 0 || len(config.CustodyPolicy.TrustedAuditors) > custodyauthority.MaximumMembers {
		return nil, ErrManagedCustodyAudit
	}
	config.CustodyPolicy.TrustedAuditors = append([][32]byte(nil), config.CustodyPolicy.TrustedAuditors...)
	intent, err := workarchive.LoadCustodyAuditIntent(config.IntentPath, config.IntentID)
	if err != nil {
		return nil, err
	}
	ticket, err := config.Admission.ID()
	c := config.Admission.Command
	if err != nil || c.Kind != custodyauthority.Admit || c.Purpose != custodyauthority.Audit || c.AssignmentID != config.AssignmentID ||
		c.OperationID != config.IntentID || intent.AssignmentID != config.AssignmentID || intent.ConsumerPublicKey != c.ActorPublicKey {
		return nil, errors.Join(ErrManagedCustodyAudit, err)
	}
	binding := OperationBinding{AssignmentID: config.AssignmentID, TicketID: ticket, ConsumerPublicKey: c.ActorPublicKey, OperationID: config.IntentID, Purpose: custodyauthority.Audit}
	var session *ManagedCustodyAuditSession
	err = coordinator.WithOperation(ctx, binding, func() error {
		encoded, err := readRegular(filepath.Join(coordinator.authority.path, assignmentName), custodyauthority.MaximumAssignmentBytes)
		if err != nil {
			return err
		}
		retained, err := custodyauthority.DecodeAssignment(encoded)
		if err != nil {
			return err
		}
		assignment, err := workarchive.CreateCustodyAuthorityAssignment(config.Manifest, config.InitialReceipt, config.CustodyPolicy,
			retained.IncarnationID, retained.AuthorityPublicKey, retained.Consumers, retained.MaximumOperations, retained.MaximumPending)
		if err != nil {
			return errors.Join(ErrManagedCustodyAudit, err)
		}
		id, err := assignment.ID()
		retainedID, retainedErr := retained.ID()
		if err != nil || retainedErr != nil || id != config.AssignmentID || retainedID != id || config.Admission.AuthorityPublicKey != assignment.AuthorityPublicKey {
			return errors.Join(ErrManagedCustodyAudit, err, retainedErr)
		}
		if err := managedCustodyAuditorPeer(assignment, intent.ReplicaPeerID); err != nil {
			return errors.Join(ErrManagedCustodyAudit, err)
		}
		if err := managedCustodyAuditRoots(coordinator, config.IntentPath, config.JournalPath, config.ArtifactsPath); err != nil {
			return err
		}
		current, err := workarchive.LoadCustodyAuditIntent(config.IntentPath, config.IntentID)
		if err != nil || current != intent {
			return errors.Join(ErrManagedCustodyAudit, err)
		}
		journal, _, err := workarchive.OpenExistingCustodyJournalWithLimits(ctx, config.JournalPath, config.Manifest, config.InitialReceipt, config.CustodyPolicy, config.JournalLimits)
		if err != nil {
			return err
		}
		cycle, err := workarchive.NewCustodyAuditCycle(ctx, journal, config.ArtifactsPath, intent, config.AuditorPrivateKey, config.SessionConfig)
		if err != nil {
			return err
		}
		intentParent, err := filepath.EvalSymlinks(filepath.Dir(config.IntentPath))
		if err != nil {
			return err
		}
		intentParent, err = filepath.Abs(intentParent)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		session = &ManagedCustodyAuditSession{coordinator: coordinator, binding: binding, intentID: config.IntentID,
			intentPath: filepath.Join(intentParent, filepath.Base(config.IntentPath)), journalPath: journal.Directory(), artifactsPath: cycle.ArtifactsDirectory(), cycle: cycle}
		return session.revalidate()
	})
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (session *ManagedCustodyAuditSession) PrepareChallenge(ctx context.Context) (challenge workarchive.CustodyChallenge, returnErr error) {
	if session == nil || session.coordinator == nil || session.cycle == nil {
		return workarchive.CustodyChallenge{}, ErrManagedCustodyAudit
	}
	err := session.coordinator.WithOperation(ctx, session.binding, func() error {
		if err := session.revalidate(); err != nil {
			return err
		}
		var err error
		challenge, err = session.cycle.PrepareChallenge(ctx)
		return err
	})
	if err != nil {
		return workarchive.CustodyChallenge{}, err
	}
	return challenge, nil
}

func (session *ManagedCustodyAuditSession) Recover(ctx context.Context) (result workarchive.CustodyAuditResult, returnErr error) {
	if session == nil || session.coordinator == nil || session.cycle == nil {
		return workarchive.CustodyAuditResult{}, ErrManagedCustodyAudit
	}
	err := session.coordinator.WithOperation(ctx, session.binding, func() error {
		if err := session.revalidate(); err != nil {
			return err
		}
		var err error
		result, err = session.cycle.Recover(ctx)
		return err
	})
	if err != nil {
		return workarchive.CustodyAuditResult{}, err
	}
	return result, nil
}

func (session *ManagedCustodyAuditSession) Audit(ctx context.Context, authenticatedReplicaID types.Hash, stream workarchive.CustodySessionStream) (workarchive.CustodyAuditResult, error) {
	if stream == nil {
		return workarchive.CustodyAuditResult{}, ErrManagedCustodyAudit
	}
	if session == nil || session.coordinator == nil || session.cycle == nil || ctx == nil || authenticatedReplicaID.IsZero() || authenticatedReplicaID != session.cycle.Intent().ReplicaPeerID {
		return workarchive.CustodyAuditResult{}, errors.Join(ErrManagedCustodyAudit, stream.Close())
	}
	var result workarchive.CustodyAuditResult
	entered := false
	err := session.coordinator.WithOperation(ctx, session.binding, func() error {
		entered = true
		var err error
		result, err = session.auditGuarded(ctx, stream)
		return err
	})
	if !entered {
		err = errors.Join(err, stream.Close())
	}
	if err != nil {
		return workarchive.CustodyAuditResult{}, err
	}
	return result, nil
}

// auditGuarded is private composition for an owned local joint executor. Its
// caller holds the SAME original coordinator once and checks the exact binding.
// It does not expose an already-authorized capability or reenter that owner.
func (session *ManagedCustodyAuditSession) auditGuarded(ctx context.Context, stream workarchive.CustodySessionStream) (result workarchive.CustodyAuditResult, returnErr error) {
	owned := &managedCustodyServeStream{CustodySessionStream: stream}
	var sessionStream workarchive.CustodySessionStream = owned
	if half, ok := stream.(interface{ CloseWrite() error }); ok {
		sessionStream = &managedCustodyAuditDuplexStream{managedCustodyServeStream: owned, half: half}
	}
	drained := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(drained); _ = owned.Close() })
	defer func() {
		closeErr := owned.Close()
		if !stop() {
			<-drained
		}
		returnErr = errors.Join(returnErr, closeErr, ctx.Err())
		if returnErr != nil {
			result = workarchive.CustodyAuditResult{}
		}
	}()
	if err := session.revalidate(); err != nil {
		return workarchive.CustodyAuditResult{}, err
	}
	return session.cycle.Audit(ctx, sessionStream)
}

func (session *ManagedCustodyAuditSession) revalidate() error {
	if err := managedCustodyAuditRoots(session.coordinator, session.intentPath, session.journalPath, session.artifactsPath); err != nil {
		return err
	}
	intent, err := workarchive.LoadCustodyAuditIntent(session.intentPath, session.intentID)
	if err != nil || intent != session.cycle.Intent() {
		return errors.Join(ErrManagedCustodyAudit, err)
	}
	return nil
}

func managedCustodyAuditRoots(coordinator *Coordinator, intentPath, journalPath, artifactsPath string) error {
	roots := []string{coordinator.authority.path, coordinator.journal.path, filepath.Dir(intentPath), journalPath, artifactsPath}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if _, _, err := coordinatorPaths(roots[i], roots[j]); err != nil {
				return err
			}
		}
	}
	return nil
}

type managedCustodyAuditDuplexStream struct {
	*managedCustodyServeStream
	half interface{ CloseWrite() error }
}

func (stream *managedCustodyAuditDuplexStream) CloseWrite() error { return stream.half.CloseWrite() }
