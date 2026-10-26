package store

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func managedAuditRuntimeConfig(f *managedAuditFixture) ManagedCustodyAuditRuntimeConfig {
	return ManagedCustodyAuditRuntimeConfig{AuthorityPath: f.serve.archive.f.authorityPath, AuthorityPinsPath: f.serve.archive.f.pinsPath,
		Assignment: f.serve.archive.policy.Assignments[0], Audit: f.config, AuditorPeerID: f.serve.config.AuditorPeerID}
}

func openManagedAuditRuntime(t testing.TB, f *managedAuditFixture) (*ManagedCustodyAuditRuntime, ManagedCustodyAuditRuntimeConfig) {
	t.Helper()
	config := managedAuditRuntimeConfig(f)
	if err := f.serve.archive.f.coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenManagedCustodyAuditRuntime(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime, config
}

func assertCustodyRuntimeOwnerBusy(t testing.TB, config ManagedCustodyAuditRuntimeConfig) {
	t.Helper()
	owner, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, config.Assignment, config.Audit.AssignmentID)
	if owner != nil {
		_ = owner.Close()
	}
	if !errors.Is(err, ErrBusy) {
		t.Fatal("runtime released the original owner", err)
	}
}

func TestManagedCustodyAuditRuntimeReadOnlyReviewAndExactPreparedRetry(t *testing.T) {
	f := newManagedAuditFixture(t)
	config := managedAuditRuntimeConfig(f)
	if other, err := OpenManagedCustodyAuditRuntime(t.Context(), config); !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("duplicate original owner", err)
	}
	before := testCoordination(t, f.serve.archive.f.coordinator)
	runtime, config := openManagedAuditRuntime(t, f)
	assertCustodyRuntimeOwnerBusy(t, config)
	review, err := runtime.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, err := review.ID()
	if err != nil || id.IsZero() || review.IntentID != f.config.IntentID || review.JournalSequence != 0 ||
		review.AuditorPeerID != config.AuditorPeerID || review.ReplicaPeerID != f.intent.ReplicaPeerID {
		t.Fatal("review lost scope", review, err)
	}
	if entries, err := os.ReadDir(f.config.ArtifactsPath); err != nil || len(entries) != 1 {
		t.Fatal("Open/Review created challenge or output", entries, err)
	}
	first, err := runtime.PrepareChallengeReviewed(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runtime.PrepareChallengeReviewed(t.Context(), id)
	a, _ := first.CanonicalBytes()
	b, _ := second.CanonicalBytes()
	if err != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("reviewed retry changed challenge", err)
	}
	if state, err := f.journal.State(); err != nil || state.Sequence != 0 {
		t.Fatal("Prepare accepted an audit response", err)
	}
	if !reflect.DeepEqual(before, testCoordination(t, runtime.life.owner)) {
		t.Fatal("runtime automatically changed authority")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Review(t.Context()); !errors.Is(err, ErrClosed) {
		t.Fatal("closed runtime reviewed", err)
	}
	reopened, err := OpenManagedCustodyAuditRuntime(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reflect.DeepEqual(before, testCoordination(t, reopened.life.owner)) {
		t.Fatal("reopen advanced authority")
	}
	newReview, err := reopened.Review(t.Context())
	newID, hashErr := newReview.ID()
	if err != nil || hashErr != nil || newID != id {
		t.Fatal("equivalent reopened scope changed local comparison", err, hashErr)
	}
}

func TestManagedCustodyAuditRuntimeReviewChangesRefuseBeforeSigning(t *testing.T) {
	f := newManagedAuditFixture(t)
	runtime, config := openManagedAuditRuntime(t, f)
	review, err := runtime.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := review.ID()
	stop := testEntry(t, testCoordination(t, runtime.life.owner).Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(231))
	appendCoordinated(t, runtime.life.owner, stop)
	if _, err := runtime.PrepareChallengeReviewed(t.Context(), id); !errors.Is(err, ErrManagedCustodyReview) {
		t.Fatal("changed original position authorized signing", err)
	}
	if entries, err := os.ReadDir(f.config.ArtifactsPath); err != nil || len(entries) != 1 {
		t.Fatal("stale comparison signed a challenge", entries, err)
	}
	review, err = runtime.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	stoppedID, _ := review.ID()
	if stoppedID == id {
		t.Fatal("authority position omitted from comparison")
	}
	if _, err := runtime.PrepareChallengeReviewed(t.Context(), stoppedID); err != nil {
		t.Fatal("Stopping refused pending drain", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	config.Audit.JournalLimits.MaximumPaths--
	reopened, err := OpenManagedCustodyAuditRuntime(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	changed, err := reopened.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	changedID, _ := changed.ID()
	if changedID == stoppedID {
		t.Fatal("local caps omitted from comparison")
	}
	if _, err := reopened.PrepareChallengeReviewed(t.Context(), stoppedID); !errors.Is(err, ErrManagedCustodyReview) {
		t.Fatal("review crossed changed local limits", err)
	}
}

func TestManagedCustodyAuditRuntimePinnedQUICAndOfflineRecovery(t *testing.T) {
	f := newManagedAuditFixture(t)
	runtime, _ := openManagedAuditRuntime(t, f)
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	cfg := libp2ptransport.DefaultConfig()
	cfg.MaxArchiveCustodyStreamsPerMinute = 2
	server, err := libp2ptransport.New(ctx, testKey(47), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	replica := f.rawReplica(t)
	served := make(chan error, 2)
	if err := server.SetArchiveCustodyHandler([]types.Hash{runtime.auditorPeer}, func(ctx context.Context, _ types.Hash, stream network.Stream) {
		_, err := replica.Serve(ctx, stream)
		served <- err
	}); err != nil {
		t.Fatal(err)
	}
	review, err := runtime.Review(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := review.ID()
	first, err := runtime.AuditQUICReviewed(ctx, id, testKey(46), libp2ptransport.DefaultConfig(), server.Addresses()[0])
	if err != nil || first.JournalSequence != 1 || first.Recovered {
		t.Fatal("owned network audit", err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.AuditQUICReviewed(ctx, id, testKey(46), libp2ptransport.DefaultConfig(), server.Addresses()[0]); !errors.Is(err, ErrManagedCustodyReview) {
		t.Fatal("stale journal position replayed as current review", err)
	}
	review, err = runtime.Review(ctx)
	if err != nil {
		t.Fatal(err)
	}
	currentID, _ := review.ID()
	retry, err := runtime.AuditQUICReviewed(ctx, currentID, testKey(46), libp2ptransport.DefaultConfig(), server.Addresses()[0])
	if err != nil || !retry.Recovered || !reflect.DeepEqual(first.Record, retry.Record) {
		t.Fatal("network retry changed signed record", err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	recovered, err := runtime.RecoverReviewed(ctx, currentID)
	if err != nil || !reflect.DeepEqual(first.Record, recovered.Record) {
		t.Fatal("offline exact recovery", err)
	}
	if _, err := runtime.AuditQUICReviewed(ctx, currentID, testKey(3), libp2ptransport.DefaultConfig(), server.Addresses()[0]); err == nil {
		t.Fatal("evidence key was accepted as transport key")
	}
}

func TestManagedCustodyAuditRuntimeCloseCancelsNetworkAndRetainsOwnerUntilDrain(t *testing.T) {
	f := newManagedAuditFixture(t)
	runtime, config := openManagedAuditRuntime(t, f)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	server, err := libp2ptransport.New(ctx, testKey(47), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	entered, drained := make(chan struct{}), make(chan struct{})
	if err := server.SetArchiveCustodyHandler([]types.Hash{runtime.auditorPeer}, func(_ context.Context, _ types.Hash, stream network.Stream) {
		defer close(drained)
		defer stream.Close()
		var prefix [4]byte
		if _, err := io.ReadFull(stream, prefix[:]); err != nil {
			return
		}
		close(entered)
		_, _ = io.Copy(io.Discard, stream)
	}); err != nil {
		t.Fatal(err)
	}
	audited := make(chan error, 1)
	go func() {
		_, err := runtime.AuditQUIC(ctx, testKey(46), libp2ptransport.DefaultConfig(), server.Addresses()[0])
		audited <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("audit did not enter blocked network read")
	}
	assertCustodyRuntimeOwnerBusy(t, config)
	if _, err := runtime.Review(ctx); !errors.Is(err, ErrManagedCustodyRuntimeBusy) {
		t.Fatal("parallel action bypassed lifecycle gate", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-audited:
		if err == nil {
			t.Fatal("cancelled audit accepted a result")
		}
	case <-ctx.Done():
		t.Fatal("Close did not cancel the active network action")
	}
	select {
	case <-drained:
	case <-ctx.Done():
		t.Fatal("remote test handler did not drain")
	}
	if state, err := f.journal.State(); err != nil || state.Sequence != 0 {
		t.Fatal("cancellation accepted a response", err)
	}
}

func TestManagedCustodyAuditRuntimeCloseWaitsForAcceptedAction(t *testing.T) {
	f := newManagedAuditFixture(t)
	runtime, config := openManagedAuditRuntime(t, f)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	runtime.hooks.at = func(stage string) error {
		if stage == "audit-runtime-action-entered" {
			close(entered)
			<-release
		}
		return nil
	}
	action := make(chan error, 1)
	go func() { _, err := runtime.PrepareChallenge(t.Context()); action <- err }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- runtime.Close() }()
	select {
	case <-closed:
		t.Fatal("owner closed before accepted action drain")
	case <-time.After(30 * time.Millisecond):
	}
	assertCustodyRuntimeOwnerBusy(t, config)
	once.Do(func() { close(release) })
	if err := <-action; !errors.Is(err, context.Canceled) {
		t.Fatal("Close lost cancellation", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}
