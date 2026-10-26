package workarchive

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func auditIntentGolden() CustodyAuditIntent {
	var i CustodyAuditIntent
	i.Version = CustodyAuditIntentVersion0
	for _, part := range []struct {
		dst  []byte
		fill byte
	}{{i.AssignmentID[:], 1}, {i.ConsumerPublicKey[:], 2}, {i.AuditorPublicKey[:], 3}, {i.ReplicaPeerID[:], 4}, {i.PriorHeadID[:], 5}, {i.PriorReceiptID[:], 6}, {i.Nonce[:], 7}} {
		for n := range part.dst {
			part.dst[n] = part.fill
		}
	}
	i.PriorSequence = 3
	i.IssuedAt = 1001
	i.ExpiresAt = 1061
	i.RenewUntil = 25000
	i.RequestedSamples = 2
	return i
}

func TestCustodyAuditIntentCanonicalGoldenAndBounds(t *testing.T) {
	i := auditIntentGolden()
	b, err := i.CanonicalBytes()
	if err != nil || len(b) != 268 {
		t.Fatal(len(b), err)
	}
	id, err := i.ID()
	if err != nil || id.String() != "4916f1d3fdb11272b9f4c1a826975f946b1519569f70281844e86ba7ab314113" {
		t.Fatal(id, err)
	}
	decoded, err := DecodeCustodyAuditIntent(b)
	if err != nil || decoded != i {
		t.Fatal(decoded, err)
	}
	for n := 0; n < len(b); n++ {
		if _, err := DecodeCustodyAuditIntent(b[:n]); err == nil {
			t.Fatalf("accepted prefix %d", n)
		}
	}
	for _, bad := range [][]byte{append(bytes.Clone(b), 0), bytes.Repeat([]byte{1}, MaximumCustodyAuditIntentBytes+1)} {
		if _, err := DecodeCustodyAuditIntent(bad); err == nil {
			t.Fatal("accepted invalid envelope")
		}
	}
	for _, mutate := range []func(*CustodyAuditIntent){
		func(x *CustodyAuditIntent) { x.Version++ }, func(x *CustodyAuditIntent) { x.AssignmentID = types.Hash{} },
		func(x *CustodyAuditIntent) { x.PriorSequence = 0 }, func(x *CustodyAuditIntent) { x.PriorSequence = ^uint64(0) },
		func(x *CustodyAuditIntent) { x.PriorReceiptID = types.Hash{} }, func(x *CustodyAuditIntent) { x.Nonce = types.Hash{} },
		func(x *CustodyAuditIntent) { x.ExpiresAt = x.IssuedAt }, func(x *CustodyAuditIntent) { x.RenewUntil = x.ExpiresAt },
		func(x *CustodyAuditIntent) { x.RequestedSamples = 0 }, func(x *CustodyAuditIntent) { x.RequestedSamples = MaximumCustodySamples + 1 },
	} {
		bad := i
		mutate(&bad)
		if _, err := bad.CanonicalBytes(); err == nil {
			t.Fatalf("accepted bad intent %+v", bad)
		}
	}
}

func TestCustodyAuditIntentExactPublicationAndPinnedLoad(t *testing.T) {
	i := auditIntentGolden()
	id, _ := i.ID()
	root := t.TempDir()
	path := filepath.Join(root, "intent.omcai")
	if err := PublishCustodyAuditIntent(t.Context(), path, i); err != nil {
		t.Fatal(err)
	}
	before := snapshotExistingCustodyTree(t, root)
	if got, err := LoadCustodyAuditIntent(path, id); err != nil || got != i {
		t.Fatal(got, err)
	}
	if err := PublishCustodyAuditIntent(t.Context(), path, i); err != nil {
		t.Fatal(err)
	}
	assertExistingCustodyTreeUnchanged(t, root, before)
	other := i
	other.Nonce[0]++
	if err := PublishCustodyAuditIntent(t.Context(), path, other); !errors.Is(err, ErrCustodyAuditIntent) {
		t.Fatal(err)
	}
	if _, err := LoadCustodyAuditIntent(path, types.DomainHash("wrong-intent")); !errors.Is(err, ErrCustodyAuditIntent) {
		t.Fatal(err)
	}
	assertExistingCustodyTreeUnchanged(t, root, before)
	missing := filepath.Join(root, "missing", "intent.omcai")
	if err := PublishCustodyAuditIntent(t.Context(), missing, i); err == nil {
		t.Fatal("created missing preparation root")
	}
	if _, err := os.Stat(filepath.Dir(missing)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := PublishCustodyAuditIntent(cancelled, filepath.Join(root, "cancelled"), i); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCustodyAuditIntent(link, id); err == nil {
		t.Fatal("followed intent symlink")
	}
}

func FuzzDecodeCustodyAuditIntent(f *testing.F) {
	b, _ := auditIntentGolden().CanonicalBytes()
	f.Add(b)
	f.Add([]byte{})
	f.Add(append(bytes.Clone(b), 0))
	f.Fuzz(func(t *testing.T, input []byte) {
		i, err := DecodeCustodyAuditIntent(input)
		if err != nil {
			return
		}
		canonical, err := i.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, input) {
			t.Fatal("accepted noncanonical intent")
		}
		if _, err := i.ID(); err != nil {
			t.Fatal(err)
		}
	})
}
