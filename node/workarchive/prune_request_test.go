package workarchive

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestCanonicalPruneRequestMatchesBeforePublicationAndChecksLiveTime(t *testing.T) {
	f, replicas, policy := prepareAvailabilityPrune(t)
	bundle, err := VerifyReplicaSet(replicas, f.checkpoint, f.policy, policy, f.base, f.parameters, DefaultLimits(), 1_001)
	if err != nil {
		t.Fatal(err)
	}
	bundleID, _ := bundle.ID()
	boundary := workchain.CanonicalFloor{Pruned: true, BaseID: f.binding.BaseID, Anchor: f.manifest.Anchor,
		AncestryNodes: f.manifest.AncestryNodes, AncestryRoot: f.manifest.AncestryRoot, StatementID: bundle.StatementID,
		ManifestID: bundle.ManifestID, AvailabilityID: bundleID, VerifiedAt: 1_000, RetainUntil: 20_000}
	for _, change := range []func(*workchain.CanonicalFloor){
		func(b *workchain.CanonicalFloor) { b.AvailabilityID[0] ^= 1 }, func(b *workchain.CanonicalFloor) { b.ManifestID[0] ^= 1 },
		func(b *workchain.CanonicalFloor) { b.StatementID[0] ^= 1 }, func(b *workchain.CanonicalFloor) { b.AncestryRoot[0] ^= 1 },
		func(b *workchain.CanonicalFloor) { b.RetainUntil++ }, func(b *workchain.CanonicalFloor) { b.VerifiedAt = 1_002 },
		func(b *workchain.CanonicalFloor) { b.PruneTicketID = types.DomainHash("test/existing-ticket") },
	} {
		bad := boundary
		change(&bad)
		path := filepath.Join(t.TempDir(), "mismatch.omav")
		if got, err := prepareCanonicalPrune(t.Context(), f.source, replicas, path, f.checkpoint, f.policy, policy,
			f.base, f.parameters, DefaultLimits(), func() time.Time { return time.Unix(1_001, 0) }, &bad); got != nil || !errors.Is(err, ErrAvailability) {
			t.Fatal("changed request accepted", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("mismatch published evidence")
		}
	}
	for _, next := range []int64{1_002, 1_101, 999} {
		now := int64(1_001)
		path := filepath.Join(t.TempDir(), "verified.omav")
		verified, err := prepareCanonicalPrune(t.Context(), f.source, replicas, path, f.checkpoint, f.policy, policy,
			f.base, f.parameters, DefaultLimits(), func() time.Time { return time.Unix(now, 0) }, &boundary)
		if err != nil || verified.boundary.VerifiedAt != 1_000 {
			t.Fatal("request observation changed", err)
		}
		now = next
		at, err := verified.Authorize()
		if next == 1_002 {
			if err != nil || at != 1_002 {
				t.Fatal(err)
			}
		} else if err == nil {
			t.Fatal("historical verification became live permission")
		}
		floor, err := f.source.CanonicalFloor()
		if err != nil || floor.Pruned {
			t.Fatal("verification executed deletion", err)
		}
	}
	if _, err := (*CanonicalPruneVerification)(nil).Authorize(); !errors.Is(err, ErrAvailability) {
		t.Fatal(err)
	}
	// The public boundary uses real time, so these historical receipts fail.
	if got, err := VerifyCanonicalPruneRequest(t.Context(), f.source, replicas, filepath.Join(t.TempDir(), "live.omav"), f.checkpoint,
		f.policy, policy, f.base, f.parameters, DefaultLimits(), boundary); got != nil || !errors.Is(err, ErrAvailability) {
		t.Fatal("public API accepted historical time", err)
	}
}

func TestPrunePolicyIDCommitsTrustAndTiming(t *testing.T) {
	f, _, replicaPolicy := prepareAvailabilityPrune(t)
	id, err := PrunePolicyID(f.checkpoint, f.policy, replicaPolicy)
	if err != nil || id.IsZero() {
		t.Fatal(err)
	}
	if again, err := PrunePolicyID(f.checkpoint, f.policy, replicaPolicy); err != nil || again != id {
		t.Fatal("unstable policy digest", err)
	}
	for _, change := range []func(*Checkpoint, *Policy, *ReplicaPolicy){
		func(c *Checkpoint, p *Policy, r *ReplicaPolicy) { c.Statement.Sequence++ },
		func(c *Checkpoint, p *Policy, r *ReplicaPolicy) { p.Binding.GenesisID[0] ^= 1 },
		func(c *Checkpoint, p *Policy, r *ReplicaPolicy) { p.RequiredAttestations++ },
		func(c *Checkpoint, p *Policy, r *ReplicaPolicy) { r.RequiredReplicas++ },
		func(c *Checkpoint, p *Policy, r *ReplicaPolicy) { r.MaximumReceiptAge++ },
		func(c *Checkpoint, p *Policy, r *ReplicaPolicy) { r.MinimumRemainingTerm++ },
		func(c *Checkpoint, p *Policy, r *ReplicaPolicy) { p.TrustedAttestors = nil },
		func(c *Checkpoint, p *Policy, r *ReplicaPolicy) { r.TrustedReplicas = nil },
	} {
		c, p, r := f.checkpoint, f.policy, replicaPolicy
		change(&c, &p, &r)
		if got, err := PrunePolicyID(c, p, r); err == nil && got == id {
			t.Fatal("policy field omitted")
		}
	}
}
