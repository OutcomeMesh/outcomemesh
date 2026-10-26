package store

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func managedPairRuntimeConfig(f *managedAuditFixture) ManagedCustodyPairRuntimeConfig {
	serve := f.serve.config
	serve.Objects = nil
	return ManagedCustodyPairRuntimeConfig{AuthorityPath: f.serve.archive.f.authorityPath, AuthorityPinsPath: f.serve.archive.f.pinsPath,
		Assignment: f.serve.archive.policy.Assignments[0], Audit: f.config, Serve: serve, ObjectPath: f.serve.config.Objects.Directory(),
		ObjectPolicy: workarchive.DefaultObjectStorePolicy(), AuditorPeerID: f.serve.config.AuditorPeerID, ReplicaPeerID: f.intent.ReplicaPeerID}
}

func openManagedPairRuntime(t testing.TB, f *managedAuditFixture) (*ManagedCustodyPairRuntime, ManagedCustodyPairRuntimeConfig) {
	t.Helper()
	config := managedPairRuntimeConfig(f)
	if err := f.serve.archive.f.coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenManagedCustodyPairRuntime(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime, config
}

func TestManagedCustodyPairRuntimeReviewFreshRetryAndReopen(t *testing.T) {
	f := newManagedAuditFixture(t)
	before := testCoordination(t, f.serve.archive.f.coordinator)
	runtime, config := openManagedPairRuntime(t, f)
	if entries, err := os.ReadDir(f.config.ArtifactsPath); err != nil || len(entries) != 1 {
		t.Fatal("Open created an audit challenge", err)
	}
	if other, err := OpenManagedCustodyPairRuntime(t.Context(), config); !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("duplicate original owner", err)
	}
	review, err := runtime.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, err := review.ID()
	if err != nil || review.ReplicaJournalSequence != 0 || review.Audit.JournalSequence != 0 || id.IsZero() {
		t.Fatal("invalid initial review", review, err)
	}
	first, err := runtime.ExchangeQUICReviewed(t.Context(), id, testKey(46), testKey(47), libp2ptransport.DefaultConfig())
	if err != nil || first.Audit.JournalSequence != 1 || first.Serve.JournalSequence != 1 {
		t.Fatal("owned paired exchange", err)
	}
	if !reflect.DeepEqual(before, testCoordination(t, runtime.audit.life.owner)) {
		t.Fatal("pair completed authority")
	}
	if _, err := runtime.ExchangeQUICReviewed(t.Context(), id, testKey(46), testKey(47), libp2ptransport.DefaultConfig()); !errors.Is(err, ErrManagedCustodyReview) {
		t.Fatal("old review survived changed journal positions", err)
	}
	review, err = runtime.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ = review.ID()
	second, err := runtime.ExchangeQUICReviewed(t.Context(), id, testKey(46), testKey(47), libp2ptransport.DefaultConfig())
	if err != nil || !second.Audit.Recovered || !reflect.DeepEqual(first.Audit.Record, second.Audit.Record) || first.Serve != second.Serve {
		t.Fatal("paired retry minted another response", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenManagedCustodyPairRuntime(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	review, err = reopened.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ = review.ID()
	third, err := reopened.ExchangeQUICReviewed(t.Context(), id, testKey(46), testKey(47), libp2ptransport.DefaultConfig())
	if err != nil || !reflect.DeepEqual(first.Audit.Record, third.Audit.Record) || !reflect.DeepEqual(before, testCoordination(t, reopened.audit.life.owner)) {
		t.Fatal("reopen changed the original result or authority", err)
	}
}

func TestManagedCustodyPairRuntimeAtomicReviewAfterTransportSetup(t *testing.T) {
	f := newManagedAuditFixture(t)
	runtime, _ := openManagedPairRuntime(t, f)
	review, err := runtime.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := review.ID()
	runtime.hooks.at = func(stage string) error {
		if stage == "pair-runtime-streams-ready" {
			_, _, err := f.journal.Append(f.answer(t))
			return err
		}
		return nil
	}
	if _, err := runtime.ExchangeQUICReviewed(t.Context(), id, testKey(46), testKey(47), libp2ptransport.DefaultConfig()); !errors.Is(err, ErrManagedCustodyReview) {
		t.Fatal("state changed after early review but before app I/O", err)
	}
	if state, err := f.serve.journal.State(); err != nil || state.Sequence != 0 {
		t.Fatal("stale reviewed pair served/signed a response", err)
	}
	if entries, err := os.ReadDir(f.config.ArtifactsPath); err != nil || len(entries) != 1 {
		t.Fatal("stale comparison published a challenge", entries, err)
	}
}

func TestManagedCustodyPairRuntimeCloseDrainsAcceptedCallbacks(t *testing.T) {
	f := newManagedAuditFixture(t)
	runtime, _ := openManagedPairRuntime(t, f)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	runtime.hooks.at = func(stage string) error {
		if stage == "pair-runtime-handler-before-return" {
			close(entered)
			<-release
		}
		return nil
	}
	action := make(chan error, 1)
	go func() {
		_, err := runtime.ExchangeQUIC(t.Context(), testKey(46), testKey(47), libp2ptransport.DefaultConfig())
		action <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("paired callback did not enter retirement")
	}
	closed := make(chan error, 1)
	go func() { closed <- runtime.Close() }()
	select {
	case <-closed:
		t.Fatal("owner released before callback drain")
	case <-time.After(30 * time.Millisecond):
	}
	assertCustodyRuntimeOwnerBusy(t, managedAuditRuntimeConfig(f))
	once.Do(func() { close(release) })
	select {
	case <-action:
	case <-time.After(3 * time.Second):
		t.Fatal("pair did not drain after callback release")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestManagedCustodyPairRuntimeRetainsCleanupFailure(t *testing.T) {
	f := newManagedAuditFixture(t)
	runtime, _ := openManagedPairRuntime(t, f)
	injected := errors.New("paired callback cleanup failed")
	runtime.hooks.at = func(stage string) error {
		if stage == "pair-runtime-handler-before-return" {
			return injected
		}
		return nil
	}
	if _, err := runtime.ExchangeQUIC(t.Context(), testKey(46), testKey(47), libp2ptransport.DefaultConfig()); !errors.Is(err, injected) {
		t.Fatal("paired result hid callback cleanup error", err)
	}
	for range 2 {
		if err := runtime.Close(); !errors.Is(err, injected) {
			t.Fatal("Close lost cleanup failure", err)
		}
	}
}

func TestManagedCustodyPairRuntimeFailureReleasesOnlyAcquiredOwners(t *testing.T) {
	f := newManagedAuditFixture(t)
	config := managedPairRuntimeConfig(f)
	if err := f.serve.archive.f.coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	bad := config
	bad.ReplicaPeerID = runtimePeer(48)
	if other, err := OpenManagedCustodyPairRuntime(t.Context(), bad); err == nil {
		_ = other.Close()
		t.Fatal("mismatched selected peer accepted")
	}
	runtime, err := OpenManagedCustodyPairRuntime(t.Context(), config)
	if err != nil {
		t.Fatal("failed Open leaked owner", err)
	}
	defer runtime.Close()
	review, err := runtime.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := review.ID()
	if _, err := runtime.ExchangeQUICReviewed(t.Context(), id, testKey(3), testKey(47), libp2ptransport.DefaultConfig()); err == nil {
		t.Fatal("evidence key used as transport")
	}
	assertCustodyRuntimeOwnerBusy(t, managedAuditRuntimeConfig(f))
	if state, err := f.journal.State(); err != nil || state.Sequence != 0 {
		t.Fatal("failed key check accepted a response", err)
	}
}

func TestManagedCustodyPairCallbackGateRejectsLateHandlers(t *testing.T) {
	callbacks := newCustodyPairCallbacks()
	callbacks.stop()
	f := newManagedServeFixture(t)
	raw := newManagedServeStream(t, f.challenge)
	stream := &managedServeServiceStream{CustodySessionStream: raw}
	callbacks.handle(context.Background(), types.Hash{}, stream)
	callbacks.wait.Wait()
	if stream.resets.Load() != 1 || raw.reads.Load()+raw.writes.Load()+raw.closes.Load() != 0 {
		t.Fatal("late handler entered callback ownership")
	}
}
