package main

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/discovery"
)

func TestWorkDiscoveryPublicationAdvancesSignedActivationSequence(t *testing.T) {
	t.Parallel()

	key := testAutomaticWorkKey("publication")
	identity, err := discovery.Sign(key, 91, 1, 1_800_000_600, []string{"127.0.0.1:9844"})
	if err != nil {
		t.Fatal(err)
	}
	self, err := identity.PeerID()
	if err != nil {
		t.Fatal(err)
	}
	book, err := discovery.NewBook(91, 8)
	if err != nil {
		t.Fatal(err)
	}
	const now uint64 = 1_800_000_000
	sequence, err := publishWorkDiscoveryRecord(
		book, key, self, 91, 5, []string{"127.0.0.1:9845"}, now, 100,
	)
	if err != nil || sequence != 100 {
		t.Fatalf("first publication sequence=%d error=%v", sequence, err)
	}
	sequence, err = publishWorkDiscoveryRecord(
		book, key, self, 91, 5, []string{"127.0.0.1:9846"}, now+1, 50,
	)
	if err != nil || sequence != 101 {
		t.Fatalf("second publication sequence=%d error=%v", sequence, err)
	}
	records := book.List(now+1, 8)
	if len(records) != 1 || records[0].Sequence != 101 || records[0].Addresses[0] != "127.0.0.1:9846" ||
		!records[0].Supports(workDiscoveryFeatures, 5) {
		t.Fatalf("published record=%+v", records)
	}
}

func TestWorkDiscoveryRenewalPersistsHigherSequence(t *testing.T) {
	t.Parallel()

	key := testAutomaticWorkKey("renewal")
	identity, err := discovery.Sign(key, 92, 1, unixNow()+600, []string{"127.0.0.1:9844"})
	if err != nil {
		t.Fatal(err)
	}
	self, _ := identity.PeerID()
	book, _ := discovery.NewBook(92, 8)
	now := unixNow()
	first, err := publishWorkDiscoveryRecord(
		book, key, self, 92, 6, []string{"127.0.0.1:9845"}, now, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errorsFound := renewWorkDiscoveryRecordsAt(
		ctx, t.TempDir(), book, key, self, 92, 6, []string{"127.0.0.1:9845"}, 5*time.Millisecond,
	)
	deadline := time.After(time.Second)
	for {
		records := book.List(unixNow(), 1)
		if len(records) == 1 && records[0].Sequence > first {
			break
		}
		select {
		case renewalErr, ok := <-errorsFound:
			if ok {
				t.Fatal(renewalErr)
			}
			t.Fatal("renewal stopped before publishing")
		case <-deadline:
			t.Fatal("renewal did not advance the signed sequence")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	for renewalErr := range errorsFound {
		if renewalErr != nil {
			t.Fatal(renewalErr)
		}
	}
}

func TestWorkDiscoveryRotationAvoidsFixedCandidatePrefix(t *testing.T) {
	t.Parallel()

	self := types.DomainHash("test/omd/work-discovery-rotation/self")
	ids := make([]types.Hash, 12)
	for index := range ids {
		ids[index] = types.DomainHash("test/omd/work-discovery-rotation/candidate", []byte{byte(index)})
	}
	orderedAt := func(now uint64) []types.Hash {
		candidates := make([]workDiscoveryCandidate, len(ids))
		for index, id := range ids {
			candidates[index] = workDiscoveryCandidate{
				id: id, bootstrap: index < 3, rotation: workDiscoveryRotation(self, id, now),
			}
		}
		orderWorkDiscoveryCandidates(candidates)
		result := make([]types.Hash, len(candidates))
		for index, candidate := range candidates {
			result[index] = candidate.id
			if (index < 3) != candidate.bootstrap {
				t.Fatalf("selected bootstrap tier changed at index %d", index)
			}
		}
		return result
	}
	period := uint64(workDiscoveryRefreshInterval / time.Second)
	first := orderedAt(period * 100)
	if sameEpoch := orderedAt(period*100 + period - 1); !slices.Equal(first, sameEpoch) {
		t.Fatal("candidate order changed inside one refresh epoch")
	}
	if nextEpoch := orderedAt(period * 101); slices.Equal(first, nextEpoch) {
		t.Fatal("candidate order remained a fixed prefix across refresh epochs")
	}
	seen := make(map[types.Hash]struct{}, len(ids)-3)
	for epoch := uint64(100); epoch < 228; epoch++ {
		ordered := orderedAt(period * epoch)
		for _, id := range ordered[3:6] {
			seen[id] = struct{}{}
		}
	}
	if len(seen) != len(ids)-3 {
		t.Fatalf("rotating three-candidate budget reached %d/%d signed candidates", len(seen), len(ids)-3)
	}
}

func TestPeriodicWorkDiscoveryRefreshStopsAndSurfacesFailure(t *testing.T) {
	t.Parallel()

	want := errors.New("persist peerbook")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	observed := 0
	failures := repeatWorkDiscoveryRefresh(
		ctx, time.Millisecond,
		func(context.Context) ([]workDiscoveryRefreshResult, error) {
			calls++
			if calls == 3 {
				return nil, want
			}
			return []workDiscoveryRefreshResult{{PeerID: types.DomainHash("test/periodic-refresh")}}, nil
		},
		func(results []workDiscoveryRefreshResult) { observed += len(results) },
	)
	select {
	case err, ok := <-failures:
		if !ok || !errors.Is(err, want) {
			t.Fatalf("periodic refresh error=%v open=%t", err, ok)
		}
	case <-time.After(time.Second):
		t.Fatal("periodic refresh did not surface its fatal error")
	}
	if calls != 3 || observed != 2 {
		t.Fatalf("periodic refresh calls=%d observed=%d", calls, observed)
	}
}

func TestConcurrentWorkDiscoverySavesRetainEveryAdmittedRecord(t *testing.T) {
	t.Parallel()

	const networkID uint32 = 93
	now := unixNow()
	book, err := discovery.NewBookWithPolicy(networkID, discovery.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	errorsFound := make(chan error, 16)
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			key := testAutomaticWorkKey("save-" + strconv.Itoa(index))
			record, err := discovery.SignActivation(
				key, networkID, 1, now+600, 7,
				discovery.FeatureVersionedChainV1|discovery.FeaturePeerExchangeV1,
				[]string{"127.0.0.1:9845"},
			)
			if err == nil {
				err = book.Add(record, now)
			}
			if err == nil {
				err = savePeerBook(data, book, now)
			}
			if err != nil {
				errorsFound <- err
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
	restored, err := openPeerBook(data, networkID, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := restored.Len(now); got != 16 {
		t.Fatalf("concurrent peerbook saves retained %d/16 records", got)
	}
}
