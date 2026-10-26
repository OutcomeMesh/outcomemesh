package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
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

type managedAuditFixture struct {
	serve   *managedServeFixture
	config  ManagedCustodyAuditConfig
	intent  workarchive.CustodyAuditIntent
	journal *workarchive.CustodyJournal
}

func newManagedAuditFixture(t testing.TB, mutations ...func(*workarchive.CustodyAuditIntent)) *managedAuditFixture {
	t.Helper()
	f := newManagedServeFixture(t)
	journalPath := filepath.Join(t.TempDir(), "auditor-journal")
	journal, _, err := workarchive.OpenOrCreateCustodyJournal(journalPath, f.config.Manifest, f.config.InitialReceipt, f.config.CustodyPolicy)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := filepath.Join(t.TempDir(), "auditor-artifacts")
	lock, err := workarchive.AcquireCustodyArtifacts(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	receiptID, _ := f.config.InitialReceipt.ID()
	intent := workarchive.CustodyAuditIntent{Version: workarchive.CustodyAuditIntentVersion0, AssignmentID: f.config.AssignmentID,
		ConsumerPublicKey: testPublic(4), AuditorPublicKey: f.challenge.AuditorPublicKey, ReplicaPeerID: runtimePeer(47), PriorReceiptID: receiptID,
		IssuedAt: f.challenge.IssuedAt, ExpiresAt: f.challenge.ExpiresAt, RenewUntil: f.challenge.RenewUntil, RequestedSamples: f.challenge.RequestedSamples, Nonce: f.challenge.Nonce}
	for _, mutate := range mutations {
		mutate(&intent)
	}
	intentPath := filepath.Join(t.TempDir(), "intent.omcai")
	if err := workarchive.PublishCustodyAuditIntent(t.Context(), intentPath, intent); err != nil {
		t.Fatal(err)
	}
	intentID, _ := intent.ID()
	coordinator := f.archive.f.coordinator
	snapshot := testCoordination(t, coordinator).Authority
	command, err := (custodyauthority.Command{AssignmentID: snapshot.AssignmentID, ExpectedSequence: snapshot.Sequence, ExpectedHead: snapshot.HeadID,
		Kind: custodyauthority.Admit, Purpose: custodyauthority.Audit, OperationID: intentID}).Sign(testKey(4))
	if err != nil {
		t.Fatal(err)
	}
	admission, err := custodyauthority.SignEntry(command, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	appendCoordinated(t, coordinator, admission)
	return &managedAuditFixture{serve: f, journal: journal, intent: intent, config: ManagedCustodyAuditConfig{AssignmentID: f.config.AssignmentID, IntentID: intentID, Admission: admission,
		IntentPath: intentPath, JournalPath: journalPath, ArtifactsPath: artifacts, Manifest: f.config.Manifest, InitialReceipt: f.config.InitialReceipt,
		CustodyPolicy: f.config.CustodyPolicy, JournalLimits: f.config.JournalLimits, AuditorPrivateKey: testKey(3), SessionConfig: f.config.SessionConfig}}
}

func (f *managedAuditFixture) open(t testing.TB) *ManagedCustodyAuditSession {
	t.Helper()
	session, err := NewManagedCustodyAuditSession(t.Context(), f.serve.archive.f.coordinator, f.config)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func (f *managedAuditFixture) exchange(t testing.TB, session *ManagedCustodyAuditSession, replica *workarchive.CustodySession) workarchive.CustodyAuditResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	served := make(chan error, 1)
	go func() { _, err := replica.Serve(ctx, server); served <- err }()
	result, err := session.Audit(ctx, f.intent.ReplicaPeerID, client)
	if err != nil {
		_ = server.Close()
		<-served
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	return result
}

func (f *managedAuditFixture) rawReplica(t testing.TB) *workarchive.CustodySession {
	t.Helper()
	s, err := workarchive.NewJournalCustodyReplicaSession(f.serve.journal, f.serve.config.Objects, f.serve.config.ReplicaPrivateKey, f.serve.config.SessionConfig)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *managedAuditFixture) answer(t testing.TB) workarchive.CustodyRecord {
	t.Helper()
	batch, proof, err := workarchive.AnswerCustodyChallenge(f.serve.config.Objects, f.config.Manifest, f.config.InitialReceipt, f.serve.challenge, f.config.CustodyPolicy, f.serve.config.ReplicaPrivateKey, f.serve.now)
	if err != nil {
		t.Fatal(err)
	}
	renewal, err := workarchive.RenewReplicaReceipt(f.config.Manifest, f.config.InitialReceipt, f.serve.challenge, batch, proof, f.config.CustodyPolicy, f.serve.config.ReplicaPrivateKey, f.serve.now)
	if err != nil {
		t.Fatal(err)
	}
	return workarchive.CustodyRecord{Version: workarchive.CustodyRecordVersion0, Challenge: f.serve.challenge, Batch: batch, Proof: proof, RenewedReceipt: renewal}
}

func TestManagedCustodyAuditPrepareExchangeRetryRecoverAndRestart(t *testing.T) {
	f := newManagedAuditFixture(t)
	session := f.open(t)
	coordinator := f.serve.archive.f.coordinator
	before := testCoordination(t, coordinator)
	if entries, err := os.ReadDir(f.config.ArtifactsPath); err != nil || len(entries) != 1 {
		t.Fatal("constructor published artifacts", entries, err)
	}
	challenge, err := session.PrepareChallenge(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want, _ := f.serve.challenge.CanonicalBytes()
	got, _ := challenge.CanonicalBytes()
	if !bytes.Equal(got, want) {
		t.Fatal("intent signing changed exact challenge")
	}
	if state, err := f.journal.State(); err != nil || state.Sequence != 0 {
		t.Fatal(state, err)
	}
	replica := f.rawReplica(t)
	first := f.exchange(t, session, replica)
	if first.JournalSequence != 1 || first.Recovered {
		t.Fatal(first.JournalSequence, first.Recovered)
	}
	firstBytes, _ := first.Record.CanonicalBytes()
	for range 2 {
		session = f.open(t)
		retry := f.exchange(t, session, replica)
		b, _ := retry.Record.CanonicalBytes()
		if !retry.Recovered || retry.JournalSequence != 1 || !bytes.Equal(firstBytes, b) {
			t.Fatal("retry minted another response")
		}
	}
	cyclePath := filepath.Join(f.config.ArtifactsPath, "cycle-00000000000000000001")
	for _, name := range []string{"challenge.omcc", "record.omcr", "receipt.omrr"} {
		if err := os.Remove(filepath.Join(cyclePath, name)); err != nil {
			t.Fatal(err)
		}
	}
	stateBefore, _ := f.journal.State()
	recovered, err := session.Recover(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := recovered.Record.CanonicalBytes()
	if !recovered.Recovered || !bytes.Equal(b, firstBytes) {
		t.Fatal("recovery changed committed record")
	}
	if state, err := f.journal.State(); err != nil || state != stateBefore {
		t.Fatal("recovery advanced journal", err)
	}
	if !reflect.DeepEqual(before, testCoordination(t, coordinator)) {
		t.Fatal("audit completed or changed authority")
	}
	if err := os.WriteFile(filepath.Join(cyclePath, "receipt.omrr"), []byte("conflict"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Recover(t.Context()); err == nil {
		t.Fatal("recovery replaced conflicting artifact")
	}
}

func TestManagedCustodyAuditDeniedBeforeSigningPublicationAndStreamIO(t *testing.T) {
	for _, mode := range []string{"wrong-peer", "completed", "pending", "cancelled", "closed", "changed-intent"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedAuditFixture(t)
			session := f.open(t)
			coordinator := f.serve.archive.f.coordinator
			ctx := t.Context()
			peer := f.intent.ReplicaPeerID
			snapshot := testCoordination(t, coordinator).Authority
			switch mode {
			case "wrong-peer":
				peer = runtimePeer(48)
			case "completed":
				ticket, _ := f.config.Admission.ID()
				appendCoordinated(t, coordinator, testEntry(t, snapshot, custodyauthority.Complete, types.Hash{}, ticket, testHash(221)))
			case "pending":
				pendingCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				coordinator.journal.hooks.at = func(stage string) error {
					if stage == "intent-after-apply" {
						cancel()
					}
					return nil
				}
				if _, err := coordinator.Append(pendingCtx, testEntry(t, snapshot, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(222))); !errors.Is(err, ErrPendingAttempt) {
					t.Fatal(err)
				}
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "closed":
				if err := coordinator.Close(); err != nil {
					t.Fatal(err)
				}
			case "changed-intent":
				if err := os.WriteFile(f.config.IntentPath, []byte("corrupt"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			stream := newManagedServeStream(t, f.serve.challenge)
			if _, err := session.Audit(ctx, peer, stream); err == nil || stream.reads.Load() != 0 || stream.writes.Load() != 0 || stream.closes.Load() != 1 {
				t.Fatalf("denied audit touched IO: reads=%d writes=%d closes=%d err=%v", stream.reads.Load(), stream.writes.Load(), stream.closes.Load(), err)
			}
			if mode != "wrong-peer" {
				if _, err := session.PrepareChallenge(ctx); err == nil {
					t.Fatal("denied audit signed a challenge")
				}
				if _, err := session.Recover(ctx); err == nil {
					t.Fatal("denied audit recovered outputs")
				}
			}
			if entries, err := os.ReadDir(f.config.ArtifactsPath); err != nil || len(entries) != 1 {
				t.Fatal("denial published artifacts", entries, err)
			}
			if state, err := f.journal.State(); err != nil || state.Sequence != 0 {
				t.Fatal(state, err)
			}
		})
	}
}

func TestManagedCustodyAuditRejectsMissingWrongScopeAndRolePins(t *testing.T) {
	for _, mode := range []string{"missing-journal", "missing-artifacts", "missing-lock", "overlap", "wrong-policy", "wrong-ticket", "noncanonical-key", "replica-role-peer"} {
		t.Run(mode, func(t *testing.T) {
			var f *managedAuditFixture
			if mode == "replica-role-peer" {
				f = newManagedAuditFixture(t, func(i *workarchive.CustodyAuditIntent) { i.ReplicaPeerID = runtimePeer(3) })
			} else {
				f = newManagedAuditFixture(t)
			}
			c := f.config
			switch mode {
			case "missing-journal":
				c.JournalPath = filepath.Join(t.TempDir(), "missing")
			case "missing-artifacts":
				c.ArtifactsPath = filepath.Join(t.TempDir(), "missing")
			case "missing-lock":
				if err := os.Remove(filepath.Join(c.ArtifactsPath, "custody.lock")); err != nil {
					t.Fatal(err)
				}
			case "overlap":
				c.ArtifactsPath = c.JournalPath
			case "wrong-policy":
				c.CustodyPolicy.MaximumProofAge++
			case "wrong-ticket":
				c.Admission = f.serve.config.Admission
			case "noncanonical-key":
				c.AuditorPrivateKey = append([]byte(nil), c.AuditorPrivateKey...)
				c.AuditorPrivateKey[63] ^= 1
			}
			if _, err := NewManagedCustodyAuditSession(t.Context(), f.serve.archive.f.coordinator, c); err == nil {
				t.Fatal("accepted bad audit scope")
			}
			if mode == "missing-journal" {
				if _, err := os.Stat(c.JournalPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("initialized journal", err)
				}
			}
			if mode == "missing-artifacts" {
				if _, err := os.Stat(c.ArtifactsPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("initialized artifacts", err)
				}
			}
		})
	}
}

type managedAuditResponseStream struct {
	input        *bytes.Reader
	written      bytes.Buffer
	closeEntered chan struct{}
	releaseClose <-chan struct{}
	closeErr     error
	once         sync.Once
	closes       atomic.Int32
}

func newManagedAuditResponseStream(t testing.TB, record workarchive.CustodyRecord) *managedAuditResponseStream {
	t.Helper()
	var data []byte
	for _, body := range []interface{ CanonicalBytes() ([]byte, error) }{record.Batch, record.Proof, record.RenewedReceipt} {
		b, err := body.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		data = binary.BigEndian.AppendUint32(data, uint32(len(b)))
		data = append(data, b...)
	}
	return &managedAuditResponseStream{input: bytes.NewReader(data)}
}
func (s *managedAuditResponseStream) Read(b []byte) (int, error)  { return s.input.Read(b) }
func (s *managedAuditResponseStream) Write(b []byte) (int, error) { return s.written.Write(b) }
func (s *managedAuditResponseStream) SetDeadline(time.Time) error { return nil }
func (s *managedAuditResponseStream) Close() error {
	s.closes.Add(1)
	s.once.Do(func() {
		if s.closeEntered != nil {
			close(s.closeEntered)
			<-s.releaseClose
		}
	})
	return s.closeErr
}

func TestManagedCustodyAuditGuardDrainsCloseBeforeStopAndAcceptance(t *testing.T) {
	f := newManagedAuditFixture(t)
	session := f.open(t)
	coordinator := f.serve.archive.f.coordinator
	snapshot := testCoordination(t, coordinator).Authority
	stream := newManagedAuditResponseStream(t, f.answer(t))
	stream.closeEntered = make(chan struct{})
	release := make(chan struct{})
	stream.releaseClose = release
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	done := make(chan error, 1)
	go func() { _, err := session.Audit(t.Context(), f.intent.ReplicaPeerID, stream); done <- err }()
	select {
	case <-stream.closeEntered:
	case err := <-done:
		t.Fatal("audit missed close barrier", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no close barrier")
	}
	if coordinator.mu.TryLock() {
		coordinator.mu.Unlock()
		t.Fatal("authority released before actual close")
	}
	stop := testEntry(t, snapshot, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(223))
	stopped := make(chan error, 1)
	go func() { _, err := coordinator.Append(t.Context(), stop); stopped <- err }()
	select {
	case err := <-stopped:
		t.Fatal("stop overtook close", err)
	default:
	}
	once.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if stream.closes.Load() != 1 {
		t.Fatal("underlying close repeated", stream.closes.Load())
	}
	if state, err := f.journal.State(); err != nil || state.Sequence != 1 {
		t.Fatal(state, err)
	}
	if _, err := session.PrepareChallenge(t.Context()); err != nil {
		t.Fatal("Stopping blocked admitted audit", err)
	}
}

func TestManagedCustodyAuditCloseFailureDoesNotAcceptVerifiedResponse(t *testing.T) {
	f := newManagedAuditFixture(t)
	session := f.open(t)
	stream := newManagedAuditResponseStream(t, f.answer(t))
	injected := errors.New("close failed")
	stream.closeErr = injected
	if _, err := session.Audit(t.Context(), f.intent.ReplicaPeerID, stream); !errors.Is(err, injected) {
		t.Fatal(err)
	}
	if stream.closes.Load() != 1 {
		t.Fatal(stream.closes.Load())
	}
	if state, err := f.journal.State(); err != nil || state.Sequence != 0 {
		t.Fatal("accepted before successful close", state, err)
	}
}

func TestManagedCustodyAuditDoesNotSignExpiredMissingChallengeOrRecoverAbsentCommit(t *testing.T) {
	f := newManagedAuditFixture(t)
	session := f.open(t)
	if _, err := session.Recover(t.Context()); err == nil {
		t.Fatal("recovered absent result")
	}
	if entries, err := os.ReadDir(f.config.ArtifactsPath); err != nil || len(entries) != 1 {
		t.Fatal("recovery signed/published challenge", entries, err)
	}
	f.config.SessionConfig.Now = func() uint64 { return f.intent.ExpiresAt + 1 }
	session = f.open(t)
	if _, err := session.PrepareChallenge(t.Context()); err == nil {
		t.Fatal("signed expired missing challenge")
	}
	if entries, err := os.ReadDir(f.config.ArtifactsPath); err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
}

var _ io.ReadWriteCloser = (*managedAuditResponseStream)(nil)

func TestManagedCustodyAuditRejectsForeignAdvancedAndStaleJournalHeads(t *testing.T) {
	for _, mode := range []string{"foreign", "advanced", "stale-proof"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedAuditFixture(t)
			first := f.answer(t)
			answer := func(previous workarchive.ReplicaReceipt, issued, responded uint64) workarchive.CustodyRecord {
				challenge, err := workarchive.CreateCustodyChallenge(f.config.Manifest, previous, f.config.AuditorPrivateKey, issued, 60, 1, previous.RetainUntil+1)
				if err != nil {
					t.Fatal(err)
				}
				batch, proof, err := workarchive.AnswerCustodyChallenge(f.serve.config.Objects, f.config.Manifest, previous, challenge, f.config.CustodyPolicy, f.serve.config.ReplicaPrivateKey, responded)
				if err != nil {
					t.Fatal(err)
				}
				renewal, err := workarchive.RenewReplicaReceipt(f.config.Manifest, previous, challenge, batch, proof, f.config.CustodyPolicy, f.serve.config.ReplicaPrivateKey, responded)
				if err != nil {
					t.Fatal(err)
				}
				return workarchive.CustodyRecord{Version: workarchive.CustodyRecordVersion0, Challenge: challenge, Batch: batch, Proof: proof, RenewedReceipt: renewal}
			}
			if mode == "foreign" {
				first = answer(f.config.InitialReceipt, f.intent.IssuedAt, f.serve.now)
			}
			if _, _, err := f.journal.Append(first); err != nil {
				t.Fatal(err)
			}
			if mode == "advanced" {
				second := answer(first.RenewedReceipt, f.serve.now+1, f.serve.now+2)
				if _, _, err := f.journal.Append(second); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "stale-proof" {
				f.config.SessionConfig.Now = func() uint64 { return f.serve.now + f.config.CustodyPolicy.MaximumProofAge + 1 }
			}
			session := f.open(t)
			before, _ := f.journal.State()
			if _, err := session.PrepareChallenge(t.Context()); err == nil {
				t.Fatal("prepared against wrong/currently stale head")
			}
			if _, err := session.Recover(t.Context()); err == nil {
				t.Fatal("promoted foreign/advanced/stale head")
			}
			if entries, err := os.ReadDir(f.config.ArtifactsPath); err != nil || len(entries) != 1 {
				t.Fatal("invalid recovery changed artifacts", entries, err)
			}
			if after, err := f.journal.State(); err != nil || after != before {
				t.Fatal("invalid recovery changed journal", after, err)
			}
		})
	}
}

type managedAuditCancellationStream struct {
	readEntered  chan struct{}
	closeEntered chan struct{}
	releaseClose <-chan struct{}
	closed       chan struct{}
	readOnce     sync.Once
	closeOnce    sync.Once
	closes       atomic.Int32
	err          error
}

func (s *managedAuditCancellationStream) Read([]byte) (int, error) {
	s.readOnce.Do(func() { close(s.readEntered) })
	<-s.closed
	return 0, io.ErrClosedPipe
}
func (s *managedAuditCancellationStream) Write(b []byte) (int, error) { return len(b), nil }
func (s *managedAuditCancellationStream) SetDeadline(time.Time) error { return nil }
func (s *managedAuditCancellationStream) Close() error {
	s.closes.Add(1)
	s.closeOnce.Do(func() { close(s.closeEntered); <-s.releaseClose; close(s.closed) })
	return s.err
}

func TestManagedCustodyAuditCancellationDrainsCloseWithoutAcceptance(t *testing.T) {
	f := newManagedAuditFixture(t)
	session := f.open(t)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	injected := errors.New("cancel close failed")
	stream := &managedAuditCancellationStream{readEntered: make(chan struct{}), closeEntered: make(chan struct{}), releaseClose: release, closed: make(chan struct{}), err: injected}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := session.Audit(ctx, f.intent.ReplicaPeerID, stream); done <- err }()
	select {
	case <-stream.readEntered:
	case err := <-done:
		t.Fatal("audit missed blocked read", err)
	case <-time.After(5 * time.Second):
		t.Fatal("audit did not read")
	}
	cancel()
	select {
	case <-stream.closeEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not close stream")
	}
	coordinator := f.serve.archive.f.coordinator
	if coordinator.mu.TryLock() {
		coordinator.mu.Unlock()
		t.Fatal("authority released before cancellation cleanup")
	}
	select {
	case err := <-done:
		t.Fatal("cancellation escaped blocked Close", err)
	default:
	}
	once.Do(func() { close(release) })
	if err := <-done; !errors.Is(err, context.Canceled) || !errors.Is(err, injected) {
		t.Fatal(err)
	}
	if stream.closes.Load() != 1 {
		t.Fatal("cancel repeated underlying close", stream.closes.Load())
	}
	if state, err := f.journal.State(); err != nil || state.Sequence != 0 {
		t.Fatal("cancel accepted response", state, err)
	}
}
