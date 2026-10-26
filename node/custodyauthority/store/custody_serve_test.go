package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type managedServeFixture struct {
	archive   *archivePruneFixture
	config    ManagedCustodyServeConfig
	challenge workarchive.CustodyChallenge
	journal   *workarchive.CustodyJournal
	now       uint64
}

func newManagedServeFixture(t testing.TB) *managedServeFixture {
	t.Helper()
	a := newArchivePruneFixture(t)
	replica := a.replicas[0]
	manifest, err := workarchive.VerifyArchiveDirectory(replica.Directory, a.policy.Checkpoint,
		a.policy.CheckpointPolicy, a.f.base, a.f.parameters, workarchive.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	objects, err := workarchive.OpenObjectStore(filepath.Join(t.TempDir(), "custody-objects"), workarchive.DefaultObjectStorePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objects.ImportArchiveDirectory(replica.Directory, a.policy.Checkpoint, a.policy.CheckpointPolicy,
		a.f.base, a.f.parameters, workarchive.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	policy := workarchive.CustodyPolicy{TrustedAuditors: append([][32]byte(nil), a.policy.Assignments[0].Auditors...),
		MaximumChallengeLifetime: 60, MaximumProofAge: 100, MaximumRenewalTerm: 20_000}
	now := replica.Receipt.StoredAt + 11
	challenge, err := workarchive.CreateCustodyChallenge(manifest, replica.Receipt, testKey(3), now-1, 60, 1, replica.Receipt.RetainUntil+1)
	if err != nil {
		t.Fatal(err)
	}
	id, err := challenge.ID()
	if err != nil {
		t.Fatal(err)
	}
	coordinator := a.f.coordinator
	snapshot := testCoordination(t, coordinator).Authority
	command, err := (custodyauthority.Command{AssignmentID: snapshot.AssignmentID, ExpectedSequence: snapshot.Sequence,
		ExpectedHead: snapshot.HeadID, Kind: custodyauthority.Admit, Purpose: custodyauthority.Serve, OperationID: id}).Sign(testKey(4))
	if err != nil {
		t.Fatal(err)
	}
	admission, err := custodyauthority.SignEntry(command, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	appendCoordinated(t, coordinator, admission)
	journalPath := filepath.Join(t.TempDir(), "custody-journal")
	journal, _, err := workarchive.OpenOrCreateCustodyJournal(journalPath, manifest, replica.Receipt, policy)
	if err != nil {
		t.Fatal(err)
	}
	var replicaKey ed25519.PrivateKey
	for _, seed := range []byte{61, 62} {
		if replica.Receipt.ReplicaPublicKey == testPublic(seed) {
			replicaKey = testKey(seed)
		}
	}
	if len(replicaKey) != ed25519.PrivateKeySize {
		t.Fatal("fixture has no matching replica signing key")
	}
	sessionConfig := workarchive.DefaultCustodySessionConfig()
	sessionConfig.Now = func() uint64 { return now }
	return &managedServeFixture{archive: a, journal: journal, challenge: challenge, now: now,
		config: ManagedCustodyServeConfig{AssignmentID: snapshot.AssignmentID, Admission: admission, ChallengeID: id,
			AuditorPeerID: runtimePeer(46), JournalPath: journalPath, Manifest: manifest, InitialReceipt: replica.Receipt,
			CustodyPolicy: policy, JournalLimits: workarchive.DefaultCustodyJournalLimits(), ReplicaPrivateKey: replicaKey,
			SessionConfig: sessionConfig, Objects: objects}}
}

func (f *managedServeFixture) open(t testing.TB) *ManagedCustodyServeSession {
	t.Helper()
	session, err := NewManagedCustodyServeSession(context.Background(), f.archive.f.coordinator, f.config)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func (f *managedServeFixture) state(t testing.TB, sequence uint64) workarchive.CustodyJournalState {
	t.Helper()
	state, err := f.journal.State()
	if err != nil || state.Sequence != sequence {
		t.Fatalf("journal sequence=%d want=%d error=%v", state.Sequence, sequence, err)
	}
	return state
}

func (f *managedServeFixture) verifiedRecord(t testing.TB, output []byte) workarchive.CustodyRecord {
	t.Helper()
	r := bytes.NewReader(output)
	readFrame := func() []byte {
		var prefix [4]byte
		if _, err := io.ReadFull(r, prefix[:]); err != nil {
			t.Fatal(err)
		}
		size := binary.BigEndian.Uint32(prefix[:])
		if uint64(size) > uint64(r.Len()) {
			t.Fatal("response frame exceeds remaining bytes")
		}
		value := make([]byte, size)
		if _, err := io.ReadFull(r, value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	batch, err := workarchive.DecodeChunkBatch(readFrame())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := workarchive.DecodeCustodyProof(readFrame())
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := workarchive.DecodeReplicaReceipt(readFrame())
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 0 {
		t.Fatal("unexpected bytes after renewal")
	}
	if err := workarchive.VerifyReplicaRenewal(f.config.Manifest, f.config.InitialReceipt, renewed, f.challenge,
		batch, proof, f.config.CustodyPolicy, f.now); err != nil {
		t.Fatal("unverifiable served renewal", err)
	}
	return workarchive.CustodyRecord{Version: workarchive.CustodyRecordVersion0, Challenge: f.challenge,
		Batch: batch, Proof: proof, RenewedReceipt: renewed}
}

type managedServeStream struct {
	input        *bytes.Reader
	output       bytes.Buffer
	reads        atomic.Int32
	writes       atomic.Int32
	closes       atomic.Int32
	failWrite    bool
	eofEntered   chan struct{}
	releaseEOF   <-chan struct{}
	closeEntered chan struct{}
	releaseClose <-chan struct{}
	eofOnce      sync.Once
	closeOnce    sync.Once
}

func newManagedServeStream(t testing.TB, challenge workarchive.CustodyChallenge) *managedServeStream {
	t.Helper()
	encoded, err := challenge.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 4+len(encoded))
	binary.BigEndian.PutUint32(frame, uint32(len(encoded)))
	copy(frame[4:], encoded)
	return &managedServeStream{input: bytes.NewReader(frame)}
}

func (s *managedServeStream) Read(p []byte) (int, error) {
	s.reads.Add(1)
	n, err := s.input.Read(p)
	if errors.Is(err, io.EOF) && s.eofEntered != nil {
		s.eofOnce.Do(func() { close(s.eofEntered); <-s.releaseEOF })
	}
	return n, err
}

func (s *managedServeStream) Write(p []byte) (int, error) {
	s.writes.Add(1)
	if s.failWrite {
		return 0, io.ErrClosedPipe
	}
	return s.output.Write(p)
}

func (s *managedServeStream) Close() error {
	s.closes.Add(1)
	if s.closeEntered != nil {
		s.closeOnce.Do(func() { close(s.closeEntered); <-s.releaseClose })
	}
	return nil
}

func (s *managedServeStream) SetDeadline(time.Time) error { return nil }

func TestManagedCustodyServeFreshCachedAndRestarted(t *testing.T) {
	f := newManagedServeFixture(t)
	session := f.open(t)
	before := testCoordination(t, f.archive.f.coordinator)
	var first []byte
	var firstReport workarchive.CustodyServeReport
	for _, mode := range []string{"fresh", "cached", "restarted"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "restarted" {
				// The already signed proof remains fresh after the challenge expired.
				f.config.SessionConfig.Now = func() uint64 { return f.now + 70 }
				session = f.open(t)
			}
			stream := newManagedServeStream(t, f.challenge)
			report, err := session.Serve(t.Context(), f.config.AuditorPeerID, stream)
			if err != nil || report.JournalSequence != 1 || report.ChallengeID != f.config.ChallengeID || stream.closes.Load() == 0 {
				t.Fatalf("serve report=%+v closed=%d error=%v", report, stream.closes.Load(), err)
			}
			f.verifiedRecord(t, stream.output.Bytes())
			if first == nil {
				first, firstReport = bytes.Clone(stream.output.Bytes()), report
			} else if !bytes.Equal(first, stream.output.Bytes()) || report != firstReport {
				t.Fatal("retry changed the exact persisted response")
			}
			f.state(t, 1)
			if after := testCoordination(t, f.archive.f.coordinator); !reflect.DeepEqual(before, after) {
				t.Fatal("serving implicitly changed or completed authority")
			}
		})
	}
}

func TestManagedCustodyServeRejectsDifferentChallengeBeforeEffect(t *testing.T) {
	f := newManagedServeFixture(t)
	session := f.open(t)
	other, err := workarchive.CreateCustodyChallenge(f.config.Manifest, f.config.InitialReceipt, testKey(3), f.now-1, 60, 1,
		f.config.InitialReceipt.RetainUntil+1)
	if err != nil {
		t.Fatal(err)
	}
	for _, cached := range []bool{false, true} {
		if cached {
			if _, err := session.Serve(t.Context(), f.config.AuditorPeerID, newManagedServeStream(t, f.challenge)); err != nil {
				t.Fatal(err)
			}
		}
		stream := newManagedServeStream(t, other)
		if _, err := session.Serve(t.Context(), f.config.AuditorPeerID, stream); err == nil || stream.writes.Load() != 0 || stream.closes.Load() == 0 {
			t.Fatal("different signed challenge reached response effects", err)
		}
		f.state(t, uint64(map[bool]int{false: 0, true: 1}[cached]))
	}
}

func TestManagedCustodyServeAuthorityCheckedBeforeStreamInput(t *testing.T) {
	for _, mode := range []string{"wrong-peer", "completed", "retired", "pending", "cancelled", "closed"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedServeFixture(t)
			session := f.open(t)
			coordinator := f.archive.f.coordinator
			peer := f.config.AuditorPeerID
			ctx := t.Context()
			ticket, _ := f.config.Admission.ID()
			snapshot := testCoordination(t, coordinator).Authority
			switch mode {
			case "wrong-peer":
				peer = runtimePeer(47)
			case "completed":
				appendCoordinated(t, coordinator, testEntry(t, snapshot, custodyauthority.Complete, types.Hash{}, ticket, testHash(171)))
			case "retired":
				appendCoordinated(t, coordinator, testEntry(t, snapshot, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(172)))
				for _, entry := range []custodyauthority.Entry{f.config.Admission, f.archive.f.admission} {
					id, _ := entry.ID()
					appendCoordinated(t, coordinator, testEntry(t, testCoordination(t, coordinator).Authority, custodyauthority.Complete, types.Hash{}, id, testHash(173)))
				}
				snapshot = testCoordination(t, coordinator).Authority
				appendCoordinated(t, coordinator, testEntry(t, snapshot, custodyauthority.Retire, types.Hash{}, types.Hash{}, snapshot.StopID))
			case "pending":
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				coordinator.journal.hooks.at = func(stage string) error {
					if stage == "intent-after-apply" {
						cancel()
					}
					return nil
				}
				if _, err := coordinator.Append(ctx, testEntry(t, snapshot, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(174))); !errors.Is(err, ErrPendingAttempt) {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed":
				if err := coordinator.Close(); err != nil {
					t.Fatal(err)
				}
			}
			stream := newManagedServeStream(t, f.challenge)
			if _, err := session.Serve(ctx, peer, stream); err == nil || stream.reads.Load() != 0 || stream.writes.Load() != 0 || stream.closes.Load() == 0 {
				t.Fatalf("denied serve touched stream: reads=%d writes=%d closed=%d error=%v", stream.reads.Load(), stream.writes.Load(), stream.closes.Load(), err)
			}
			if mode != "wrong-peer" {
				if _, err := NewManagedCustodyServeSession(ctx, coordinator, f.config); err == nil {
					t.Fatal("reopening turned denied authority into current permission")
				}
			}
			f.state(t, 0)
		})
	}
}

func TestManagedCustodyServeGuardDrainsEOFAndClose(t *testing.T) {
	for _, mode := range []string{"fresh-stop", "cached-complete", "restarted-stop"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedServeFixture(t)
			session := f.open(t)
			if mode != "fresh-stop" {
				if _, err := session.Serve(t.Context(), f.config.AuditorPeerID, newManagedServeStream(t, f.challenge)); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "restarted-stop" {
				session = f.open(t)
			}
			coordinator := f.archive.f.coordinator
			snapshot := testCoordination(t, coordinator).Authority
			kind, ticket := custodyauthority.Stop, types.Hash{}
			if mode == "cached-complete" {
				kind = custodyauthority.Complete
				ticket, _ = f.config.Admission.ID()
			}
			entry := testEntry(t, snapshot, kind, types.Hash{}, ticket, testHash(181))
			stream := newManagedServeStream(t, f.challenge)
			stream.eofEntered, stream.closeEntered = make(chan struct{}), make(chan struct{})
			releaseEOF, releaseClose := make(chan struct{}), make(chan struct{})
			stream.releaseEOF, stream.releaseClose = releaseEOF, releaseClose
			var eofOnce, closeOnce sync.Once
			t.Cleanup(func() { eofOnce.Do(func() { close(releaseEOF) }); closeOnce.Do(func() { close(releaseClose) }) })
			served := make(chan error, 1)
			go func() { _, err := session.Serve(t.Context(), f.config.AuditorPeerID, stream); served <- err }()
			select {
			case <-stream.eofEntered:
			case err := <-served:
				t.Fatal("serve ended before EOF barrier", err)
			case <-time.After(5 * time.Second):
				t.Fatal("serve did not reach EOF barrier")
			}
			if coordinator.mu.TryLock() {
				coordinator.mu.Unlock()
				t.Fatal("authority guard escaped live reply")
			}
			changed := make(chan error, 1)
			go func() { _, err := coordinator.Append(t.Context(), entry); changed <- err }()
			select {
			case err := <-changed:
				t.Fatal("authority changed before EOF", err)
			default:
			}
			eofOnce.Do(func() { close(releaseEOF) })
			select {
			case <-stream.closeEntered:
			case <-time.After(5 * time.Second):
				t.Fatal("stream did not reach close barrier")
			}
			if coordinator.mu.TryLock() {
				coordinator.mu.Unlock()
				t.Fatal("authority guard escaped stream cleanup")
			}
			select {
			case err := <-changed:
				t.Fatal("authority changed before stream close", err)
			default:
			}
			closeOnce.Do(func() { close(releaseClose) })
			if err := <-served; err != nil {
				t.Fatal(err)
			}
			if err := <-changed; err != nil {
				t.Fatal(err)
			}
			retry := newManagedServeStream(t, f.challenge)
			_, err := session.Serve(t.Context(), f.config.AuditorPeerID, retry)
			if kind == custodyauthority.Stop {
				if err != nil || retry.output.Len() == 0 {
					t.Fatal("stopping blocked the originally admitted response", err)
				}
			} else if err == nil || retry.reads.Load() != 0 || retry.writes.Load() != 0 {
				t.Fatal("completed cached response reused history as permission", err)
			}
		})
	}
}

func TestManagedCustodyServeLostWriteRecoversExactRecord(t *testing.T) {
	f := newManagedServeFixture(t)
	session := f.open(t)
	stream := newManagedServeStream(t, f.challenge)
	stream.failWrite = true
	if _, err := session.Serve(t.Context(), f.config.AuditorPeerID, stream); err == nil || stream.output.Len() != 0 {
		t.Fatal("failed transport asserted success", err)
	}
	f.state(t, 1)
	head, exists, err := f.journal.Head()
	if err != nil || !exists {
		t.Fatal("response was not persisted before write", err)
	}
	f.config.SessionConfig.Now = func() uint64 { return f.now + 70 }
	session = f.open(t)
	retry := newManagedServeStream(t, f.challenge)
	if _, err := session.Serve(t.Context(), f.config.AuditorPeerID, retry); err != nil {
		t.Fatal(err)
	}
	recovered := f.verifiedRecord(t, retry.output.Bytes())
	want, _ := head.Record.CanonicalBytes()
	got, _ := recovered.CanonicalBytes()
	if !bytes.Equal(want, got) {
		t.Fatal("restart regenerated the persisted signed record")
	}
	f.state(t, 1)
}

type managedServeCancellationStream struct {
	*managedServeStream
	blockRequest bool
	blocked      chan struct{}
	closed       chan struct{}
	closeStarted chan struct{}
	release      <-chan struct{}
	closeError   error
	blockedOnce  sync.Once
}

func (s *managedServeCancellationStream) Read(p []byte) (int, error) {
	if !s.blockRequest && s.input.Len() != 0 {
		return s.managedServeStream.Read(p)
	}
	s.reads.Add(1)
	s.blockedOnce.Do(func() { close(s.blocked) })
	<-s.closed
	return 0, io.ErrClosedPipe
}

func (s *managedServeCancellationStream) Close() error {
	s.closes.Add(1)
	close(s.closeStarted)
	close(s.closed)
	<-s.release
	return s.closeError
}

func TestManagedCustodyServeCancellationDrainsCloseAndPreservesErrors(t *testing.T) {
	for _, blockRequest := range []bool{true, false} {
		t.Run(map[bool]string{true: "request", false: "auditor-eof"}[blockRequest], func(t *testing.T) {
			f := newManagedServeFixture(t)
			session := f.open(t)
			release := make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			closeFailure := errors.New("custody stream cleanup failed")
			stream := &managedServeCancellationStream{managedServeStream: newManagedServeStream(t, f.challenge),
				blockRequest: blockRequest, blocked: make(chan struct{}), closed: make(chan struct{}),
				closeStarted: make(chan struct{}), release: release, closeError: closeFailure}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			served := make(chan error, 1)
			go func() { _, err := session.Serve(ctx, f.config.AuditorPeerID, stream); served <- err }()
			select {
			case <-stream.blocked:
			case err := <-served:
				t.Fatal("serve ended before blocked input", err)
			case <-time.After(5 * time.Second):
				t.Fatal("serve did not reach blocked input")
			}
			cancel()
			select {
			case <-stream.closeStarted:
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation did not interrupt the stream")
			}
			if f.archive.f.coordinator.mu.TryLock() {
				f.archive.f.coordinator.mu.Unlock()
				t.Fatal("cancellation released authority before cleanup drained")
			}
			select {
			case err := <-served:
				t.Fatal("serve returned before cancellation cleanup", err)
			default:
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case err := <-served:
				if !errors.Is(err, context.Canceled) || !errors.Is(err, closeFailure) || stream.closes.Load() != 1 {
					t.Fatalf("cancellation lost result or repeated cleanup: closes=%d error=%v", stream.closes.Load(), err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation did not finish after cleanup")
			}
			sequence := uint64(1)
			if blockRequest {
				sequence = 0
			}
			f.state(t, sequence)
			if current := testCoordination(t, f.archive.f.coordinator); current.Authority.Pending != 2 || current.Pending != nil {
				t.Fatal("cancelled exchange implicitly resolved the retained Serve ticket")
			}
		})
	}
}

func TestManagedCustodyServeRejectsAdvancedJournalHead(t *testing.T) {
	f := newManagedServeFixture(t)
	session := f.open(t)
	if _, err := session.Serve(t.Context(), f.config.AuditorPeerID, newManagedServeStream(t, f.challenge)); err != nil {
		t.Fatal(err)
	}
	previous := f.state(t, 1).CurrentReceipt
	challenge, err := workarchive.CreateCustodyChallenge(f.config.Manifest, previous, testKey(3), f.now+1, 60, 1, previous.RetainUntil+1)
	if err != nil {
		t.Fatal(err)
	}
	batch, proof, err := workarchive.AnswerCustodyChallenge(f.config.Objects, f.config.Manifest, previous, challenge,
		f.config.CustodyPolicy, f.config.ReplicaPrivateKey, f.now+2)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := workarchive.RenewReplicaReceipt(f.config.Manifest, previous, challenge, batch, proof,
		f.config.CustodyPolicy, f.config.ReplicaPrivateKey, f.now+2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.journal.Append(workarchive.CustodyRecord{Version: workarchive.CustodyRecordVersion0,
		Challenge: challenge, Batch: batch, Proof: proof, RenewedReceipt: renewed}); err != nil {
		t.Fatal(err)
	}
	stream := newManagedServeStream(t, f.challenge)
	if _, err := session.Serve(t.Context(), f.config.AuditorPeerID, stream); err == nil || stream.writes.Load() != 0 {
		t.Fatal("cached response ignored advanced journal head", err)
	}
	f.state(t, 2)
}

func TestManagedCustodyServeRejectsMissingRetiredHistoricalAndAliasedRoots(t *testing.T) {
	f := newManagedServeFixture(t)
	for _, mode := range []string{"missing", "retired", "historical", "authority", "authority-pins", "authority-child", "objects-child", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			config := f.config
			root := filepath.Join(t.TempDir(), "journal")
			if mode == "retired" || mode == "historical" {
				if err := os.CopyFS(root, os.DirFS(f.config.JournalPath)); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "retired":
				// A named retirement marker cannot be downgraded because its bytes are invalid.
				if err := os.WriteFile(filepath.Join(root, "retirement.omcrt"), []byte("retained retirement"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "historical":
				path := filepath.Join(root, "header.omcj")
				encoded, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				header, err := workarchive.DecodeCustodyJournalHeader(encoded)
				if err != nil {
					t.Fatal(err)
				}
				header.Version, header.HistoricalTransferID = workarchive.CustodyJournalHeaderHistoricalVersion1, testHash(191)
				encoded, err = header.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			case "authority":
				root = f.archive.f.authorityPath
			case "authority-pins":
				root = f.archive.f.pinsPath
			case "authority-child":
				root = filepath.Join(f.archive.f.authorityPath, "uncreated-journal")
			case "objects-child":
				root = filepath.Join(f.config.Objects.Directory(), "uncreated-journal")
			case "symlink":
				if err := os.Symlink(f.config.JournalPath, root); err != nil {
					t.Fatal(err)
				}
			}
			config.JournalPath = root
			if _, err := NewManagedCustodyServeSession(t.Context(), f.archive.f.coordinator, config); err == nil {
				t.Fatal("invalid journal source became a managed service")
			}
			if mode == "missing" || mode == "authority-child" || mode == "objects-child" {
				if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("opening silently initialized missing evidence", err)
				}
			}
		})
	}
	if _, err := f.journal.State(); err != nil {
		t.Fatal("failed constructor damaged source evidence", err)
	}
}

func TestManagedCustodyServeRejectsWrongSignedBindingsAndDetachesConfig(t *testing.T) {
	f := newManagedServeFixture(t)
	for _, mode := range []string{"assignment", "challenge", "admission", "unadmitted", "wrong-consumer", "prune-ticket", "replica-key", "malformed-key", "peer", "authority-peer", "replica-peer", "auditor-peer", "consumer-peer", "policy", "receipt"} {
		t.Run(mode, func(t *testing.T) {
			config := f.config
			switch mode {
			case "assignment":
				config.AssignmentID = testHash(201)
			case "challenge":
				config.ChallengeID = testHash(202)
			case "admission":
				config.Admission.Signature[0] ^= 1
			case "unadmitted", "wrong-consumer":
				command := config.Admission.Command
				actor := byte(4)
				if mode == "wrong-consumer" {
					actor = 5
					command.ActorPublicKey = [32]byte{}
				} else {
					command.ExpectedSequence++
				}
				command, err := command.Sign(testKey(actor))
				if err != nil {
					t.Fatal(err)
				}
				config.Admission, err = custodyauthority.SignEntry(command, testKey(1))
				if err != nil {
					t.Fatal(err)
				}
			case "prune-ticket":
				config.Admission = f.archive.f.admission
			case "replica-key":
				config.ReplicaPrivateKey = testKey(89)
			case "malformed-key":
				config.ReplicaPrivateKey = bytes.Clone(config.ReplicaPrivateKey)
				config.ReplicaPrivateKey[0] ^= 1
			case "peer":
				config.AuditorPeerID = types.Hash{}
			case "authority-peer":
				config.AuditorPeerID = runtimePeer(1)
			case "replica-peer":
				seed := byte(61)
				if config.InitialReceipt.ReplicaPublicKey != testPublic(seed) {
					seed = 62
				}
				config.AuditorPeerID = runtimePeer(seed)
			case "auditor-peer":
				config.AuditorPeerID = runtimePeer(3)
			case "consumer-peer":
				config.AuditorPeerID = runtimePeer(4)
			case "policy":
				config.CustodyPolicy.MaximumProofAge++
			case "receipt":
				config.InitialReceipt = f.archive.replicas[1].Receipt
			}
			if _, err := NewManagedCustodyServeSession(t.Context(), f.archive.f.coordinator, config); err == nil {
				t.Fatal("unrelated or invalid binding accepted")
			}
			f.state(t, 0)
		})
	}
	// Detach the caller-owned copy from the independent verification fixture.
	config := f.config
	manifestBytes, _ := config.Manifest.CanonicalBytes()
	config.Manifest, _ = workarchive.DecodeManifest(manifestBytes)
	config.CustodyPolicy.TrustedAuditors = append([][32]byte(nil), config.CustodyPolicy.TrustedAuditors...)
	config.ReplicaPrivateKey = bytes.Clone(config.ReplicaPrivateKey)
	session, err := NewManagedCustodyServeSession(t.Context(), f.archive.f.coordinator, config)
	if err != nil {
		t.Fatal(err)
	}
	config.Manifest.Chunks[0].ID[0] ^= 1
	config.CustodyPolicy.TrustedAuditors[0][0] ^= 1
	config.ReplicaPrivateKey[0] ^= 1
	stream := newManagedServeStream(t, f.challenge)
	if _, err := session.Serve(t.Context(), f.config.AuditorPeerID, stream); err != nil {
		t.Fatal("caller mutation changed the live service", err)
	}
	f.verifiedRecord(t, stream.output.Bytes())
	f.state(t, 1)
}
