package main

import (
	"context"
	"testing"
	"time"

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
