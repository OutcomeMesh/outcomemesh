package store

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"path/filepath"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/transport"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

var ErrManagedCustodyServe = errors.New("invalid managed archive custody serve configuration or peer")

// ManagedCustodyServeConfig selects one already admitted Serve ticket and one
// independently pinned signed challenge. Neither pin is discovered from a peer.
// JournalPath must name the existing active journal for the exact assignment;
// construction never initializes, repairs, signs, admits or completes anything.
// AuditorPeerID is a transport identity, separate from every control/evidence key.
type ManagedCustodyServeConfig struct {
	Schedule          *CustodyScheduleContext
	AssignmentID      types.Hash
	Admission         custodyauthority.Entry
	ChallengeID       types.Hash
	AuditorPeerID     types.Hash
	JournalPath       string
	Manifest          workarchive.Manifest
	InitialReceipt    workarchive.ReplicaReceipt
	CustodyPolicy     workarchive.CustodyPolicy
	JournalLimits     workarchive.CustodyJournalLimits
	ReplicaPrivateKey ed25519.PrivateKey
	SessionConfig     workarchive.CustodySessionConfig
	Objects           *workarchive.ObjectStore
}

// ManagedCustodyServeSession keeps its journal-backed custody session private.
// The caller retains the ORIGINAL coordinator and object-store owners for the
// adapter's entire lifetime and supplies the authenticated transport peer on
// every Serve. This library adapter creates no listener and owns no network
// service. Paths and the object store must remain owner-controlled; copying a
// root or signing key is not fenced by this same-process boundary.
type ManagedCustodyServeSession struct {
	coordinator *Coordinator
	binding     OperationBinding
	challengeID types.Hash
	auditorPeer types.Hash
	journalPath string
	objects     *workarchive.ObjectStore
	session     *workarchive.CustodySession
}

// NewManagedCustodyServeSession validates the exact retained admission under
// coordinator's current operation guard, opens only the existing journal and
// constructs a private replica session. The caller keeps both original owners.
func NewManagedCustodyServeSession(ctx context.Context, coordinator *Coordinator, config ManagedCustodyServeConfig) (*ManagedCustodyServeSession, error) {
	if coordinator == nil {
		return nil, ErrClosed
	}
	if ctx == nil || config.AssignmentID.IsZero() || config.AssignmentID != coordinator.assignmentID ||
		config.ChallengeID.IsZero() || config.AuditorPeerID.IsZero() || config.Objects == nil || config.JournalPath == "" {
		return nil, ErrManagedCustodyServe
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := config.SessionConfig.Validate(); err != nil {
		return nil, errors.Join(ErrManagedCustodyServe, err)
	}
	if err := config.JournalLimits.Validate(); err != nil {
		return nil, errors.Join(ErrManagedCustodyServe, err)
	}
	// Detach bounded caller-owned scope before waiting for the original owner.
	// Canonical decoding also rejects an invalid or excessively large manifest.
	manifestBytes, err := config.Manifest.CanonicalBytes()
	if err != nil {
		return nil, errors.Join(ErrManagedCustodyServe, err)
	}
	config.Manifest, err = workarchive.DecodeManifest(manifestBytes)
	if err != nil || len(config.CustodyPolicy.TrustedAuditors) == 0 ||
		len(config.CustodyPolicy.TrustedAuditors) > custodyauthority.MaximumMembers {
		return nil, errors.Join(ErrManagedCustodyServe, err)
	}
	config.CustodyPolicy.TrustedAuditors = append([][ed25519.PublicKeySize]byte(nil), config.CustodyPolicy.TrustedAuditors...)
	key, err := managedCustodyReplicaKey(config.ReplicaPrivateKey, config.InitialReceipt.ReplicaPublicKey)
	if err != nil {
		return nil, err
	}
	ticket, err := config.Admission.ID() // verifies both exact signatures
	c := config.Admission.Command
	if err != nil || c.Kind != custodyauthority.Admit || c.Purpose != custodyauthority.Serve ||
		c.AssignmentID != config.AssignmentID || c.OperationID != config.ChallengeID {
		return nil, errors.Join(ErrManagedCustodyServe, err)
	}
	schedule, scheduleID, err := config.Schedule.detached()
	if err != nil {
		return nil, err
	}
	binding := OperationBinding{ScheduleID: scheduleID, AssignmentID: config.AssignmentID, TicketID: ticket, ConsumerPublicKey: c.ActorPublicKey,
		OperationID: config.ChallengeID, Purpose: custodyauthority.Serve}
	var result *ManagedCustodyServeSession
	err = coordinator.WithOperation(ctx, binding, func() error {
		// Read the original owner's retained bootstrap scope only after its
		// live checks. A caller-supplied assignment cannot relabel this owner.
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
			return errors.Join(ErrManagedCustodyServe, err)
		}
		retainedID, err := retained.ID()
		if err != nil || retainedID != config.AssignmentID {
			return errors.Join(ErrManagedCustodyServe, err)
		}
		assignmentID, err := assignment.ID()
		if err != nil || assignmentID != config.AssignmentID || config.Admission.AuthorityPublicKey != assignment.AuthorityPublicKey {
			return errors.Join(ErrManagedCustodyServe, err)
		}
		if err := managedCustodyAuditorPeer(assignment, config.AuditorPeerID); err != nil {
			return err
		}
		if err := managedCustodyServeRoots(coordinator, config.JournalPath, config.Objects); err != nil {
			return err
		}
		journal, _, err := openManagedCustodyJournal(ctx, config.JournalPath,
			config.Manifest, config.InitialReceipt, config.CustodyPolicy, config.JournalLimits, schedule, retained)
		if err != nil {
			return err
		}
		if err := managedCustodyServeRoots(coordinator, journal.Directory(), config.Objects); err != nil {
			return err
		}
		private, err := workarchive.NewJournalCustodyReplicaSession(journal, config.Objects, key, config.SessionConfig)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		result = &ManagedCustodyServeSession{coordinator: coordinator, binding: binding, challengeID: config.ChallengeID,
			auditorPeer: config.AuditorPeerID, journalPath: journal.Directory(), objects: config.Objects, session: private}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Serve accepts one exact challenge only while the original pending ticket is
// live. Its guard covers fresh signing, journal publication, cached/recovered
// delivery, the auditor's final EOF, stream closure and cancellation drain.
// No successful or failed exchange implicitly completes the authority ticket.
// The supplied stream must support concurrent Close to interrupt blocked I/O.
func (session *ManagedCustodyServeSession) Serve(ctx context.Context, authenticatedPeerID types.Hash,
	stream workarchive.CustodySessionStream,
) (workarchive.CustodyServeReport, error) {
	if stream == nil {
		return workarchive.CustodyServeReport{}, ErrManagedCustodyServe
	}
	owned := &managedCustodyServeStream{CustodySessionStream: stream}
	if session == nil || session.coordinator == nil || session.session == nil || ctx == nil ||
		authenticatedPeerID.IsZero() || authenticatedPeerID != session.auditorPeer {
		return workarchive.CustodyServeReport{}, errors.Join(ErrManagedCustodyServe, owned.Close())
	}
	var report workarchive.CustodyServeReport
	entered := false
	err := session.coordinator.WithOperation(ctx, session.binding, func() (err error) {
		entered = true
		drained := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			defer close(drained)
			_ = owned.Close()
		})
		defer func() {
			closeErr := owned.Close()
			if !stop() {
				<-drained
			}
			err = errors.Join(err, closeErr, ctx.Err())
		}()
		if err := managedCustodyServeRoots(session.coordinator, session.journalPath, session.objects); err != nil {
			return err
		}
		report, err = session.session.ServeExpected(ctx, owned, session.challengeID)
		return err
	})
	if !entered {
		err = errors.Join(err, owned.Close())
	}
	return report, err
}

func managedCustodyReplicaKey(key ed25519.PrivateKey, expected [ed25519.PublicKeySize]byte) (ed25519.PrivateKey, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrManagedCustodyServe
	}
	canonical := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(canonical, key) != 1 ||
		!ed25519.PublicKey(expected[:]).Equal(canonical.Public().(ed25519.PublicKey)) {
		return nil, ErrManagedCustodyServe
	}
	return canonical, nil
}

func managedCustodyAuditorPeer(assignment custodyauthority.Assignment, peer types.Hash) error {
	keys := [][ed25519.PublicKeySize]byte{assignment.AuthorityPublicKey, assignment.ReplicaPublicKey}
	keys = append(keys, assignment.Auditors...)
	for _, consumer := range assignment.Consumers {
		keys = append(keys, consumer.PublicKey)
	}
	for _, key := range keys {
		id, err := transport.PeerIDFromPublicKey(key[:])
		if err != nil || id == peer {
			return errors.Join(ErrManagedCustodyServe, err)
		}
	}
	return nil
}

// The caller already holds the original coordinator guard. Check the actual
// configured object root and opened journal root, never a caller's substitute.
func managedCustodyServeRoots(coordinator *Coordinator, journalPath string, objects *workarchive.ObjectStore) error {
	roots := []string{coordinator.authority.path, coordinator.journal.path, journalPath, objects.Directory()}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if _, _, err := coordinatorPaths(roots[i], roots[j]); err != nil {
				return err
			}
		}
	}
	return nil
}

// CustodySession closes finite streams itself. Retain its first cleanup result
// and make cancellation and normal cleanup share that same synchronous close.
type managedCustodyServeStream struct {
	workarchive.CustodySessionStream
	once sync.Once
	err  error
}

func (stream *managedCustodyServeStream) Close() error {
	stream.once.Do(func() { stream.err = stream.CustodySessionStream.Close() })
	return stream.err
}
