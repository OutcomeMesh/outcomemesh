package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func runtimePeer(seed byte) types.Hash {
	id, _ := transport.PeerIDFromPublicKey(testKey(seed).Public().(ed25519.PublicKey))
	return id
}

func TestPruneCommandRuntimeZeroAndNilLifecycle(t *testing.T) {
	for _, service := range []*PruneCommandService{nil, {}} {
		if err := service.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if len(service.Addresses()) != 0 {
			t.Fatal("unopened runtime has addresses")
		}
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func testPruneServiceConfig(t testing.TB, f *pruneFixture) PruneCommandServiceConfig {
	t.Helper()
	return PruneCommandServiceConfig{AuthorityPath: f.authorityPath, AuthorityPinsPath: f.pinsPath,
		ExecutorPath: f.executorPath, ExecutorPinsPath: f.executorPinsPath,
		Assignment: testAssignment(), AssignmentID: testAssignmentID(t), RequestID: f.id,
		ServerPeerID: runtimePeer(45), ClientPeerID: runtimePeer(46), Timeout: 2 * time.Second}
}

func openTestPruneService(t testing.TB, f *pruneFixture) *PruneCommandService {
	t.Helper()
	_ = f.executor.Close()
	_ = f.coordinator.Close()
	s, err := OpenPruneCommandService(testPruneServiceConfig(t, f))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func startTestPruneService(t testing.TB, s *PruneCommandService) string {
	t.Helper()
	if err := s.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	addresses := s.Addresses()
	if len(addresses) != 1 {
		t.Fatal(addresses)
	}
	return addresses[0]
}

func runtimeFixture(f *pruneFixture, s *PruneCommandService) *pruneFixture {
	copy := *f
	copy.executor, copy.coordinator = s.executor, s.coordinator
	return &copy
}

func runtimeDeliveryConfig(path string, id types.Hash, address string) PruneDeliveryConfig {
	return PruneDeliveryConfig{Path: path, Assignment: testAssignment(), IntentID: id, Address: address,
		Timeout: 2 * time.Second, Transport: libp2ptransport.DefaultConfig()}
}

func retainedRuntimeAdmit(t testing.TB, f *pruneFixture, address string) PruneDeliveryConfig {
	t.Helper()
	intent := AdmissionIntent{ClientPeerID: runtimePeer(46), ServerPeerID: runtimePeer(45), Entry: f.admission}
	outbox, path, id := newTestAdmissionOutbox(t, intent)
	_ = outbox.Close()
	return runtimeDeliveryConfig(path, id, address)
}

func assertRuntimeOwnersBusy(t testing.TB, f *pruneFixture) {
	t.Helper()
	if other, err := OpenPinnedPruneExecutor(f.executorPath, f.executorPinsPath, testAssignment(), f.id); !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("runtime released executor owner", err)
	}
	if other, err := OpenCoordinator(f.authorityPath, f.pinsPath, testAssignment(), testAssignmentID(t)); !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("runtime released coordinator owner", err)
	}
}

func waitPruneRuntimeDone(t testing.TB, s *PruneCommandService) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("runtime did not close")
	}
}

func TestPruneCommandRuntimeLifecycleAndOfflineHistory(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admission = pruneAdmissionEntry(t, f)
			s := openTestPruneService(t, f)
			assertRuntimeOwnersBusy(t, f)
			if len(s.Addresses()) != 0 || testCoordination(t, s.coordinator).Authority.Sequence != 0 ||
				pruneSnapshot(t, s.executor).Stage != PrunePrepared {
				t.Fatal("open listened or advanced")
			}
			delivery := retainedRuntimeAdmit(t, f, startTestPruneService(t, s))
			ack, err := DeliverPruneAdmission(t.Context(), testKey(46), delivery)
			if err != nil {
				t.Fatal(err)
			}
			assertPruneAdmissionConfirmed(t, runtimeFixture(f, s))
			outbox := openTestAdmissionOutbox(t, delivery.Path, delivery.IntentID)
			if *testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != ack {
				t.Fatal("runtime returned before local durability")
			}
			_ = outbox.Close()
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			waitPruneRuntimeDone(t, s)
			f.reopen(t)
			// No raw writer escapes the service. Work requires closing it and an
			// explicit local handoff to the existing live-guarded executor API.
			if outcome == "succeeded" {
				if result, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil }); err != nil || !result.Applied {
					t.Fatal(err)
				}
			} else if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); err != nil {
				t.Fatal(err)
			}
			entry := pruneCompletionEntry(t, f)
			terminal := pruneSnapshot(t, f.executor)
			completeIntent := CompletionIntent{ClientPeerID: runtimePeer(46), ServerPeerID: runtimePeer(45), Entry: entry}
			completeOutbox, path, id := newTestOutbox(t, completeIntent)
			_ = completeOutbox.Close()
			s = openTestPruneService(t, f)
			completion := runtimeDeliveryConfig(path, id, startTestPruneService(t, s))
			completed, err := DeliverPruneCompletion(t.Context(), testKey(46), completion)
			if err != nil {
				t.Fatal(err)
			}
			if c := testCoordination(t, s.coordinator); c.Authority.Sequence != 2 || c.Authority.Pending != 0 || c.Pending != nil {
				t.Fatal("completion did not drain")
			}
			if !reflect.DeepEqual(terminal, pruneSnapshot(t, s.executor)) {
				t.Fatal("completion runtime repeated effect")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			stop := f.stop(t)
			appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop))
			// Invalid transport configuration cannot mask a network attempt: a
			// retained ACK returns with no socket or server, but still needs the key.
			delivery.Address, completion.Address = "offline", "offline"
			delivery.Transport, completion.Transport = libp2ptransport.Config{}, libp2ptransport.Config{}
			if got, err := DeliverPruneAdmission(t.Context(), testKey(46), delivery); err != nil || got != ack {
				t.Fatal("cached admission contacted network", err)
			}
			if got, err := DeliverPruneCompletion(t.Context(), testKey(46), completion); err != nil || got != completed {
				t.Fatal("cached completion contacted network", err)
			}
			if got, err := DeliverPruneAdmission(t.Context(), testKey(47), delivery); !errors.Is(err, ErrPruneRuntime) || got != (admissionwire.Acknowledgement{}) {
				t.Fatal("cached receipt bypassed client identity", err)
			}
			// Preserve lost receipt evidence aside; the original intents remain.
			for _, item := range []struct{ root, received, receipt string }{
				{delivery.Path, admissionReceivedName, admissionReceiptName}, {completion.Path, completionReceivedName, completionReceiptName},
			} {
				if err := os.Rename(filepath.Join(item.root, item.received, item.receipt), filepath.Join(t.TempDir(), "old-ack")); err != nil {
					t.Fatal(err)
				}
			}
			before := testCoordination(t, f.coordinator)
			s = openTestPruneService(t, f)
			address := startTestPruneService(t, s)
			delivery = runtimeDeliveryConfig(delivery.Path, delivery.IntentID, address)
			completion = runtimeDeliveryConfig(completion.Path, completion.IntentID, address)
			retry, err := DeliverPruneAdmission(t.Context(), testKey(46), delivery)
			if err != nil || retry.EntryID != ack.EntryID || retry.Nonce == ack.Nonce {
				t.Fatal("historical retry changed command", err)
			}
			retriedCompletion, err := DeliverPruneCompletion(t.Context(), testKey(46), completion)
			if err != nil || retriedCompletion.EntryID != completed.EntryID || retriedCompletion.Nonce == completed.Nonce {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, testCoordination(t, s.coordinator)) || !reflect.DeepEqual(terminal, pruneSnapshot(t, s.executor)) {
				t.Fatal("historical runtime changed lifecycle")
			}
		})
	}
}

func TestPruneCommandRuntimeOpenFailuresReleaseOwnedLocks(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	config := testPruneServiceConfig(t, f)
	_ = f.executor.Close()
	// Failure after acquiring the executor must not close the OTHER coordinator.
	if s, err := OpenPruneCommandService(config); !errors.Is(err, ErrBusy) || s != nil {
		t.Fatal("busy coordinator accepted", err)
	}
	f.executor, _ = OpenPinnedPruneExecutor(f.executorPath, f.executorPinsPath, testAssignment(), f.id)
	if f.executor == nil {
		t.Fatal("partial open leaked executor lock")
	}
	_ = f.executor.Close()
	_ = f.coordinator.Close()
	for _, field := range []string{"assignment", "request", "zero-peer", "equal-peer", "role-peer", "timeout", "overlap", "nested", "symlink", "missing"} {
		t.Run(field, func(t *testing.T) {
			bad := config
			switch field {
			case "assignment":
				bad.AssignmentID = testHash(99)
			case "request":
				bad.RequestID = testHash(99)
			case "zero-peer":
				bad.ClientPeerID = types.Hash{}
			case "equal-peer":
				bad.ClientPeerID = bad.ServerPeerID
			case "role-peer":
				bad.ServerPeerID = runtimePeer(1)
			case "timeout":
				bad.Timeout = 0
			case "overlap":
				bad.AuthorityPath = bad.ExecutorPinsPath
			case "nested":
				bad.AuthorityPath = filepath.Join(bad.ExecutorPath, "nested")
			case "symlink":
				bad.ExecutorPath = filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(config.ExecutorPath, bad.ExecutorPath); err != nil {
					t.Fatal(err)
				}
			case "missing":
				bad.ExecutorPath = filepath.Join(t.TempDir(), "missing")
			}
			if s, err := OpenPruneCommandService(bad); err == nil {
				_ = s.Close()
				t.Fatal("invalid runtime opened")
			}
			if field == "missing" {
				if _, err := os.Lstat(bad.ExecutorPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("open recreated executor")
				}
			}
			s, err := OpenPruneCommandService(config)
			if err != nil {
				t.Fatal("failed open leaked an owner", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPruneCommandRuntimeStartupKeysAndCancellation(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	s := openTestPruneService(t, f)
	config := libp2ptransport.DefaultConfig()
	badKey := bytes.Clone(testKey(45))
	badKey[len(badKey)-1] ^= 1
	for _, key := range []ed25519.PrivateKey{nil, testKey(47), badKey} {
		if err := s.Start(t.Context(), key, config); !errors.Is(err, ErrPruneRuntime) {
			t.Fatal(err)
		}
		if len(s.Addresses()) != 0 {
			t.Fatal("invalid identity opened listener")
		}
		assertRuntimeOwnersBusy(t, f)
	}
	if err := s.Start(nil, testKey(45), config); !errors.Is(err, ErrPruneRuntime) {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.Start(cancelled, testKey(45), config); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	badConfig := config
	badConfig.Listen = []string{"not-a-listener"}
	if err := s.Start(t.Context(), testKey(45), badConfig); err == nil {
		t.Fatal("invalid listener accepted")
	}
	assertRuntimeOwnersBusy(t, f)
	ctx, stop := context.WithCancel(t.Context())
	if err := s.Start(ctx, testKey(45), config); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx, testKey(45), config); !errors.Is(err, ErrPruneServiceStarted) {
		t.Fatal(err)
	}
	stop()
	waitPruneRuntimeDone(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(t.Context(), testKey(45), config); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if len(s.Addresses()) != 0 {
		t.Fatal("closed service advertised routes")
	}
	f.reopen(t)
	if testCoordination(t, f.coordinator).Authority.Sequence != 0 || pruneSnapshot(t, f.executor).Stage != PrunePrepared {
		t.Fatal("startup or shutdown advanced work")
	}
	for _, key := range []byte{1, 2, 3, 4} {
		if err := validatePruneRuntimePeers(testAssignment(), runtimePeer(key), runtimePeer(46)); !errors.Is(err, ErrPruneRuntime) {
			t.Fatal("server reused control/evidence key")
		}
		if err := validatePruneRuntimePeers(testAssignment(), runtimePeer(45), runtimePeer(key)); !errors.Is(err, ErrPruneRuntime) {
			t.Fatal("client reused control/evidence key")
		}
	}
}

func TestPruneCommandRuntimeCloseDrainsBeforeUnlock(t *testing.T) {
	for _, stage := range []string{"confirm-before-publish", "pins-admission-confirm-before-publish"} {
		for _, mode := range []string{"close", "cancel"} {
			t.Run(stage+"/"+mode, func(t *testing.T) {
				f := newPruneFixtureWithStorageID(t, testHash(91))
				f.admission = pruneAdmissionEntry(t, f)
				s := openTestPruneService(t, f)
				reached, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				t.Cleanup(unblock)
				hook := func(at string) error {
					if at == stage {
						close(reached)
						<-release
					}
					return nil
				}
				setCoordinatorHooks(s.coordinator, storeHooks{at: hook})
				s.executor.pins.hooks.at = hook
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if err := s.Start(ctx, testKey(45), libp2ptransport.DefaultConfig()); err != nil {
					t.Fatal(err)
				}
				delivery := retainedRuntimeAdmit(t, f, s.Addresses()[0])
				result := make(chan error, 1)
				go func() {
					ack, err := DeliverPruneAdmission(t.Context(), testKey(46), delivery)
					if ack != (admissionwire.Acknowledgement{}) {
						t.Error("shutdown before reply asserted client success")
					}
					result <- err
				}()
				select {
				case <-reached:
				case <-time.After(5 * time.Second):
					t.Fatal("server missed barrier")
				}
				// The one-shot driver retains its process lock across network I/O.
				if _, err := DeliverPruneAdmission(t.Context(), testKey(46), delivery); !errors.Is(err, ErrBusy) {
					t.Fatal("concurrent driver shared journal", err)
				}
				if mode == "cancel" {
					cancel()
				}
				closed := make(chan error, 2)
				go func() { closed <- s.Close() }()
				go func() { closed <- s.Close() }()
				select {
				case <-s.Done():
					t.Fatal("shutdown escaped active handler")
				case <-time.After(20 * time.Millisecond):
				}
				assertRuntimeOwnersBusy(t, f)
				unblock()
				first, second := <-closed, <-closed
				if (first == nil) != (second == nil) || first != second {
					t.Fatal("concurrent close lost final error", first, second)
				}
				waitPruneRuntimeDone(t, s)
				if err := <-result; !errors.Is(err, admissionwire.ErrUnconfirmed) {
					t.Fatal("lost reply resolved client", err)
				}
				s = openTestPruneService(t, f)
				delivery.Address = startTestPruneService(t, s)
				if _, err := DeliverPruneAdmission(t.Context(), testKey(46), delivery); err != nil {
					t.Fatal("explicit recovery failed", err)
				}
				assertPruneAdmissionConfirmed(t, runtimeFixture(f, s))
			})
		}
	}
}

func TestPruneCommandRuntimeUncertaintyStopsWithoutAutoRecovery(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admission = pruneAdmissionEntry(t, f)
	s := openTestPruneService(t, f)
	fault := errors.New("independent confirmation unavailable")
	setCoordinatorHooks(s.coordinator, storeHooks{at: func(at string) error {
		if at == "confirm-before-publish" {
			return fault
		}
		return nil
	}})
	delivery := retainedRuntimeAdmit(t, f, startTestPruneService(t, s))
	if ack, err := DeliverPruneAdmission(t.Context(), testKey(46), delivery); !errors.Is(err, admissionwire.ErrUnconfirmed) || ack != (admissionwire.Acknowledgement{}) {
		t.Fatal(err)
	}
	waitPruneRuntimeDone(t, s)
	if err := s.Close(); !errors.Is(err, fault) || !errors.Is(err, ErrUncertain) {
		t.Fatal("fatal storage error hidden", err)
	}
	s = openTestPruneService(t, f)
	before := testCoordination(t, s.coordinator)
	if before.Pending == nil || *before.Pending != f.admission {
		t.Fatal("runtime open silently confirmed attempt")
	}
	delivery.Address = startTestPruneService(t, s)
	if !reflect.DeepEqual(before, testCoordination(t, s.coordinator)) {
		t.Fatal("start submitted recovery")
	}
	if _, err := DeliverPruneAdmission(t.Context(), testKey(46), delivery); err != nil {
		t.Fatal(err)
	}
	assertPruneAdmissionConfirmed(t, runtimeFixture(f, s))
}

func TestPruneCommandRuntimeCloseInterruptsIncompleteStreams(t *testing.T) {
	for _, kind := range []custodyauthority.Kind{custodyauthority.Admit, custodyauthority.Complete} {
		t.Run(string(rune('0'+kind)), func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			s := openTestPruneService(t, f)
			entered := make(chan struct{})
			s.hooks.at = func(stage string) error {
				if stage == "runtime-handler-entered" {
					close(entered)
				}
				return nil
			}
			address := startTestPruneService(t, s)
			client, err := libp2ptransport.New(t.Context(), testKey(46), libp2ptransport.DefaultConfig(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var stream interface {
				Write([]byte) (int, error)
				Close() error
			}
			if kind == custodyauthority.Admit {
				stream, _, err = client.OpenPruneAdmissionStream(t.Context(), address, runtimePeer(45))
			} else {
				stream, _, err = client.OpenPruneCompletionStream(t.Context(), address, runtimePeer(45))
			}
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if _, err := stream.Write([]byte{'O'}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("handler did not enter")
			}
			closed := make(chan error, 1)
			go func() { closed <- s.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("incomplete frame blocked shutdown")
			}
			waitPruneRuntimeDone(t, s)
			f.reopen(t)
			if testCoordination(t, f.coordinator).Authority.Sequence != 0 || pruneSnapshot(t, f.executor).Stage != PrunePrepared {
				t.Fatal("partial frame advanced state")
			}
		})
	}
}

func TestPruneCommandRuntimeConcurrentStartAndClose(t *testing.T) {
	for range 8 {
		f := newPruneFixtureWithStorageID(t, testHash(91))
		s := openTestPruneService(t, f)
		barrier := make(chan struct{})
		started, closed := make(chan error, 1), make(chan error, 1)
		go func() { <-barrier; started <- s.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()) }()
		go func() { <-barrier; closed <- s.Close() }()
		close(barrier)
		if err := <-started; err != nil && !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		waitPruneRuntimeDone(t, s)
		f.reopen(t)
		if testCoordination(t, f.coordinator).Authority.Sequence != 0 {
			t.Fatal("lifecycle race changed authority")
		}
		_ = f.executor.Close()
		_ = f.coordinator.Close()
		_ = f.chain.Close()
	}
}

func TestPruneCommandRuntimeRejectedCommandKeepsServiceAvailable(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admission = pruneAdmissionEntry(t, f)
	s := openTestPruneService(t, f)
	address := startTestPruneService(t, s)
	c := f.admission.Command
	c.ExpectedHead = testHash(99)
	c, err := c.Sign(testKey(4))
	if err != nil {
		t.Fatal(err)
	}
	bad, err := custodyauthority.SignEntry(c, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	intent := AdmissionIntent{ClientPeerID: runtimePeer(46), ServerPeerID: runtimePeer(45), Entry: bad}
	outbox, path, id := newTestAdmissionOutbox(t, intent)
	_ = outbox.Close()
	if ack, err := DeliverPruneAdmission(t.Context(), testKey(46), runtimeDeliveryConfig(path, id, address)); !errors.Is(err, admissionwire.ErrUnconfirmed) || ack != (admissionwire.Acknowledgement{}) {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
		t.Fatal("invalid command shut down service")
	default:
	}
	if _, err := DeliverPruneAdmission(t.Context(), testKey(46), retainedRuntimeAdmit(t, f, address)); err != nil {
		t.Fatal(err)
	}
	assertPruneAdmissionConfirmed(t, runtimeFixture(f, s))
}

func TestPruneRuntimeDeliveryValidationAndFailedStartup(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admission = pruneAdmissionEntry(t, f)
	delivery := retainedRuntimeAdmit(t, f, "unused")
	badKey := bytes.Clone(testKey(46))
	badKey[63] ^= 1
	for _, key := range []ed25519.PrivateKey{nil, testKey(47), badKey} {
		if ack, err := DeliverPruneAdmission(t.Context(), key, delivery); !errors.Is(err, ErrPruneRuntime) || ack != (admissionwire.Acknowledgement{}) {
			t.Fatal(err)
		}
		outbox := openTestAdmissionOutbox(t, delivery.Path, delivery.IntentID)
		if testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != nil {
			t.Fatal("invalid identity recorded receipt")
		}
		_ = outbox.Close()
	}
	bad := delivery
	bad.Transport = libp2ptransport.Config{}
	if _, err := DeliverPruneAdmission(t.Context(), testKey(46), bad); err == nil {
		t.Fatal("invalid host accepted")
	}
	outbox := openTestAdmissionOutbox(t, delivery.Path, delivery.IntentID)
	_ = outbox.Close()
	if ack, err := DeliverPruneCompletion(t.Context(), testKey(46), delivery); err == nil || ack != (completionwire.Acknowledgement{}) {
		t.Fatal("wrong journal kind accepted")
	}
	missing := delivery
	missing.Path = filepath.Join(t.TempDir(), "missing")
	if _, err := DeliverPruneAdmission(t.Context(), testKey(46), missing); err == nil {
		t.Fatal("missing journal accepted")
	}
	if _, err := os.Lstat(missing.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("driver created journal")
	}
	if _, err := DeliverPruneAdmission(nil, testKey(46), delivery); !errors.Is(err, ErrPruneRuntime) {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := DeliverPruneAdmission(cancelled, testKey(46), delivery); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	bad = delivery
	bad.Timeout = 0
	if _, err := DeliverPruneAdmission(t.Context(), testKey(46), bad); !errors.Is(err, ErrPruneRuntime) {
		t.Fatal(err)
	}
	if testCoordination(t, f.coordinator).Authority.Sequence != 0 {
		t.Fatal("failed driver mutated authority")
	}
}
