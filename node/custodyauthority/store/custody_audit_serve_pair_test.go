package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func newManagedCustodyPair(t testing.TB) (*managedAuditFixture, *ManagedCustodyAuditServePair) {
	t.Helper()
	f := newManagedAuditFixture(t, func(intent *workarchive.CustodyAuditIntent) { intent.ReplicaPeerID = runtimePeer(45) })
	return f, openManagedCustodyPair(t, f)
}

func openManagedCustodyPair(t testing.TB, f *managedAuditFixture) *ManagedCustodyAuditServePair {
	t.Helper()
	audit := f.open(t)
	challenge, err := audit.PrepareChallenge(t.Context())
	if err != nil || !reflect.DeepEqual(challenge, f.serve.challenge) {
		t.Fatal("prepared intent changed the admitted Serve challenge", err)
	}
	serve := f.serve.open(t)
	pair, err := NewManagedCustodyAuditServePair(audit, serve)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func TestManagedCustodyAuditServePairRejectsSameTransportIdentity(t *testing.T) {
	f := newManagedAuditFixture(t, func(intent *workarchive.CustodyAuditIntent) { intent.ReplicaPeerID = runtimePeer(46) })
	audit, serve := f.open(t), f.serve.open(t)
	if pair, err := NewManagedCustodyAuditServePair(audit, serve); !errors.Is(err, ErrManagedCustodyPair) || pair != nil {
		t.Fatal("pair reused one authenticated identity for both participants", err)
	}
	for _, participants := range []struct {
		audit *ManagedCustodyAuditSession
		serve *ManagedCustodyServeSession
	}{{nil, serve}, {audit, nil}} {
		if pair, err := NewManagedCustodyAuditServePair(participants.audit, participants.serve); !errors.Is(err, ErrManagedCustodyPair) || pair != nil {
			t.Fatal("pair accepted a missing participant", err)
		}
	}
}

func exchangeManagedCustodyPair(t testing.TB, f *managedAuditFixture, pair *ManagedCustodyAuditServePair) ManagedCustodyAuditServeResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	auditor, replica := net.Pipe()
	defer auditor.Close()
	defer replica.Close()
	result, err := pair.Exchange(ctx, f.intent.ReplicaPeerID, f.serve.config.AuditorPeerID, auditor, replica)
	if err != nil {
		t.Fatal("paired exchange failed", err)
	}
	if result.Audit.JournalSequence != 1 || result.Serve.JournalSequence != 1 ||
		result.Audit.Report.ChallengeID != result.Serve.ChallengeID || result.Audit.Report.ProofID != result.Serve.ProofID ||
		result.Audit.Report.RenewedReceiptID != result.Serve.RenewedReceiptID {
		t.Fatal("paired participants did not accept one exact response", result)
	}
	auditHead, exists, err := f.journal.Head()
	if err != nil || !exists || auditHead.Sequence != 1 {
		t.Fatal("audit journal missing accepted response", err)
	}
	serveHead, exists, err := f.serve.journal.Head()
	if err != nil || !exists || serveHead.Sequence != 1 {
		t.Fatal("replica journal missing published response", err)
	}
	want, _ := result.Audit.Record.CanonicalBytes()
	for _, record := range []workarchive.CustodyRecord{auditHead.Record, serveHead.Record} {
		encoded, err := record.CanonicalBytes()
		if err != nil || !bytes.Equal(want, encoded) {
			t.Fatal("paired journals retained different signed responses", err)
		}
	}
	return result
}

func TestManagedCustodyAuditServePairFreshCachedReopenedAndStopping(t *testing.T) {
	f, pair := newManagedCustodyPair(t)
	lifetime := t
	var first ManagedCustodyAuditServeResult
	for _, phase := range []string{"fresh", "cached", "reopened", "stopping"} {
		t.Run(phase, func(t *testing.T) {
			coordinator := f.serve.archive.f.coordinator
			if phase == "reopened" {
				if err := coordinator.Close(); err != nil {
					t.Fatal(err)
				}
				var err error
				coordinator, err = OpenCoordinator(f.serve.archive.f.authorityPath, f.serve.archive.f.pinsPath,
					f.serve.archive.policy.Assignments[0], f.config.AssignmentID)
				if err != nil {
					t.Fatal(err)
				}
				f.serve.archive.f.coordinator = coordinator
				lifetime.Cleanup(func() { _ = coordinator.Close() })
				pair = openManagedCustodyPair(t, f)
			}
			if phase == "stopping" {
				stop := testEntry(t, testCoordination(t, coordinator).Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(229))
				appendCoordinated(t, coordinator, stop)
			}
			before := testCoordination(t, coordinator)
			result := exchangeManagedCustodyPair(t, f, pair)
			if phase == "fresh" {
				first = result
				if result.Audit.Recovered {
					t.Fatal("fresh paired audit reported a recovered result")
				}
			} else {
				want, _ := first.Audit.Record.CanonicalBytes()
				got, _ := result.Audit.Record.CanonicalBytes()
				if !result.Audit.Recovered || !bytes.Equal(want, got) || first.Audit.Report != result.Audit.Report || first.Serve != result.Serve {
					t.Fatal("paired retry refreshed or changed its signed result")
				}
			}
			if !reflect.DeepEqual(before, testCoordination(t, coordinator)) {
				t.Fatal("paired exchange changed or completed authority")
			}
		})
	}
}

func TestManagedCustodyAuditServePairCompletedTicketRejectsBeforeEitherInput(t *testing.T) {
	for _, completed := range []string{"audit", "serve"} {
		t.Run(completed, func(t *testing.T) {
			f, pair := newManagedCustodyPair(t)
			result := exchangeManagedCustodyPair(t, f, pair)
			coordinator := f.serve.archive.f.coordinator
			ticket := pair.audit.binding.TicketID
			if completed == "serve" {
				ticket = pair.serve.binding.TicketID
			}
			entry := testEntry(t, testCoordination(t, coordinator).Authority, custodyauthority.Complete, types.Hash{}, ticket, result.Audit.Report.RenewedReceiptID)
			appendCoordinated(t, coordinator, entry)
			before := testCoordination(t, coordinator)
			auditor, replica := newManagedServeStream(t, f.serve.challenge), newManagedServeStream(t, f.serve.challenge)
			if _, err := pair.Exchange(t.Context(), f.intent.ReplicaPeerID, f.serve.config.AuditorPeerID, auditor, replica); !errors.Is(err, custodyauthority.ErrOperation) {
				t.Fatal("completed pair entered live exchange", err)
			}
			assertManagedPairNoInput(t, auditor, replica)
			if !reflect.DeepEqual(before, testCoordination(t, coordinator)) {
				t.Fatal("rejected paired exchange changed authority")
			}
		})
	}
}

func assertManagedPairNoInput(t testing.TB, streams ...*managedServeStream) {
	t.Helper()
	for _, stream := range streams {
		if stream.reads.Load() != 0 || stream.writes.Load() != 0 || stream.closes.Load() != 1 {
			t.Fatalf("rejected pair touched I/O or repeated cleanup: read=%d write=%d close=%d", stream.reads.Load(), stream.writes.Load(), stream.closes.Load())
		}
	}
}

func TestManagedCustodyAuditServePairRejectsPeersAndCrossParticipantRoots(t *testing.T) {
	for _, mode := range []string{"replica-peer", "auditor-peer", "shared-journal", "objects-as-audit-artifacts"} {
		t.Run(mode, func(t *testing.T) {
			f, pair := newManagedCustodyPair(t)
			replicaPeer, auditorPeer := f.intent.ReplicaPeerID, f.serve.config.AuditorPeerID
			want := ErrManagedCustodyPair
			switch mode {
			case "replica-peer":
				replicaPeer = runtimePeer(48)
			case "auditor-peer":
				auditorPeer = runtimePeer(48)
			case "shared-journal", "objects-as-audit-artifacts":
				config := f.config
				if mode == "shared-journal" {
					config.JournalPath = f.serve.config.JournalPath
				} else {
					config.ArtifactsPath = f.serve.config.Objects.Directory()
					lock, err := workarchive.AcquireCustodyArtifacts(config.ArtifactsPath)
					if err != nil {
						t.Fatal(err)
					}
					if err := lock.Close(); err != nil {
						t.Fatal(err)
					}
				}
				audit, err := NewManagedCustodyAuditSession(t.Context(), f.serve.archive.f.coordinator, config)
				if err != nil {
					t.Fatal("individually valid participant could not open", err)
				}
				pair, err = NewManagedCustodyAuditServePair(audit, pair.serve)
				if err != nil {
					t.Fatal(err)
				}
				want = ErrRootOverlap
			}
			auditor, replica := newManagedServeStream(t, f.serve.challenge), newManagedServeStream(t, f.serve.challenge)
			if _, err := pair.Exchange(t.Context(), replicaPeer, auditorPeer, auditor, replica); !errors.Is(err, want) {
				t.Fatal("invalid paired scope accepted", mode, err)
			}
			assertManagedPairNoInput(t, auditor, replica)
		})
	}
}

func TestManagedCustodyAuditServePairRejectsDifferentAdmittedChallengeBeforeIO(t *testing.T) {
	f := newManagedAuditFixture(t, func(intent *workarchive.CustodyAuditIntent) {
		intent.ReplicaPeerID = runtimePeer(45)
		intent.Nonce = testHash(231)
	})
	pair, err := NewManagedCustodyAuditServePair(f.open(t), f.serve.open(t))
	if err != nil {
		t.Fatal(err)
	}
	before := testCoordination(t, f.serve.archive.f.coordinator)
	auditor, replica := newManagedServeStream(t, f.serve.challenge), newManagedServeStream(t, f.serve.challenge)
	if _, err := pair.Exchange(t.Context(), f.intent.ReplicaPeerID, f.serve.config.AuditorPeerID, auditor, replica); !errors.Is(err, ErrManagedCustodyPair) {
		t.Fatal("pair delivered another admission's challenge", err)
	}
	assertManagedPairNoInput(t, auditor, replica)
	for _, journal := range []*workarchive.CustodyJournal{f.journal, f.serve.journal} {
		if state, err := journal.State(); err != nil || state.Sequence != 0 {
			t.Fatal("challenge mismatch appended a response", err)
		}
	}
	if !reflect.DeepEqual(before, testCoordination(t, f.serve.archive.f.coordinator)) {
		t.Fatal("challenge mismatch changed authority")
	}
}

type managedPairBlockedStream struct {
	readEntered   chan struct{}
	closeEntered  chan struct{}
	closeReturned chan struct{}
	closed        chan struct{}
	release       chan struct{}
	readOnce      sync.Once
	closes        atomic.Int32
}

func newManagedPairBlockedStream() *managedPairBlockedStream {
	return &managedPairBlockedStream{readEntered: make(chan struct{}), closeEntered: make(chan struct{}), closeReturned: make(chan struct{}),
		closed: make(chan struct{}), release: make(chan struct{})}
}

func (stream *managedPairBlockedStream) Read([]byte) (int, error) {
	stream.readOnce.Do(func() { close(stream.readEntered) })
	<-stream.closed
	return 0, io.ErrClosedPipe
}
func (*managedPairBlockedStream) Write(in []byte) (int, error) { return len(in), nil }
func (*managedPairBlockedStream) SetDeadline(time.Time) error  { return nil }
func (stream *managedPairBlockedStream) Close() error {
	stream.closes.Add(1)
	close(stream.closeEntered)
	close(stream.closed)
	<-stream.release
	close(stream.closeReturned)
	return nil
}

func waitManagedPairCheckpoint(t testing.TB, checkpoint <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-checkpoint:
	case <-time.After(5 * time.Second):
		t.Fatal("paired checkpoint not reached", name)
	}
}

func TestManagedCustodyAuditServePairCancellationClosesBothAndDrainsOriginalGuard(t *testing.T) {
	f, pair := newManagedCustodyPair(t)
	coordinator := f.serve.archive.f.coordinator
	before := testCoordination(t, coordinator)
	stop := testEntry(t, before.Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(230))
	auditor, replica := newManagedPairBlockedStream(), newManagedPairBlockedStream()
	var auditorOnce, replicaOnce sync.Once
	t.Cleanup(func() {
		auditorOnce.Do(func() { close(auditor.release) })
		replicaOnce.Do(func() { close(replica.release) })
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	exchanged := make(chan error, 1)
	go func() {
		_, err := pair.Exchange(ctx, f.intent.ReplicaPeerID, f.serve.config.AuditorPeerID, auditor, replica)
		exchanged <- err
	}()
	waitManagedPairCheckpoint(t, auditor.readEntered, "auditor blocked input")
	waitManagedPairCheckpoint(t, replica.readEntered, "replica blocked input")
	if coordinator.mu.TryLock() {
		coordinator.mu.Unlock()
		t.Fatal("pair did not hold its original coordinator through active I/O")
	}
	operationEntered, operationStarted := make(chan struct{}), make(chan struct{})
	operationDone := make(chan error, 1)
	go func() {
		close(operationStarted)
		operationDone <- coordinator.WithOperation(t.Context(), pair.audit.binding, func() error { close(operationEntered); return nil })
	}()
	stopStarted, stopDone := make(chan struct{}), make(chan error, 1)
	go func() { close(stopStarted); _, err := coordinator.Append(t.Context(), stop); stopDone <- err }()
	waitManagedPairCheckpoint(t, operationStarted, "waiting original operation")
	waitManagedPairCheckpoint(t, stopStarted, "waiting Stop")
	cancel()
	// Both must enter Close while neither release barrier is open. A single
	// synchronous closer cannot strand the second participant behind the first.
	waitManagedPairCheckpoint(t, auditor.closeEntered, "auditor actual close")
	waitManagedPairCheckpoint(t, replica.closeEntered, "replica actual close")
	assertGuardHeld := func() {
		t.Helper()
		if coordinator.mu.TryLock() {
			coordinator.mu.Unlock()
			t.Fatal("pair released original guard before both closes drained")
		}
		select {
		case <-operationEntered:
			t.Fatal("another original operation entered before pair drained")
		case err := <-stopDone:
			t.Fatal("Stop committed before pair drained", err)
		case err := <-exchanged:
			t.Fatal("pair returned before both closes drained", err)
		default:
		}
	}
	assertGuardHeld()
	auditorOnce.Do(func() { close(auditor.release) })
	waitManagedPairCheckpoint(t, auditor.closeReturned, "first close returned")
	assertGuardHeld()
	replicaOnce.Do(func() { close(replica.release) })
	select {
	case err := <-exchanged:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("paired cancellation error lost", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pair failed to drain after both closes returned")
	}
	if err := <-operationDone; err != nil {
		t.Fatal("original pending operation failed after drain", err)
	}
	if err := <-stopDone; err != nil {
		t.Fatal("Stop failed after pair drained", err)
	}
	if auditor.closes.Load() != 1 || replica.closes.Load() != 1 {
		t.Fatal("pair repeated actual stream cleanup")
	}
	after := testCoordination(t, coordinator)
	if after.Authority.Phase != custodyauthority.Stopping || after.Authority.Pending != before.Authority.Pending || after.Pending != nil {
		t.Fatal("paired cancellation completed or lost a ticket")
	}
	for _, journal := range []*workarchive.CustodyJournal{f.journal, f.serve.journal} {
		if state, err := journal.State(); err != nil || state.Sequence != 0 {
			t.Fatal("cancelled empty exchange published a response", err)
		}
	}
}
