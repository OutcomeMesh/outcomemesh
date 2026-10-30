package workarchive

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestScheduledPruneLiveRetentionAndClock(t *testing.T) {
	f, replicas, policy := prepareAvailabilityPrune(t)
	next, statement, err := PrepareRadixArchiveMigration(f.archivePath, f.checkpoint, f.policy, f.base, f.parameters, f.manifest.Anchor.Height+10, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	cp := signedCheckpoint(t, statement, f.keys)
	parameters := f.parameters
	parameters.RadixActivationHeight = next.Binding.RadixActivationHeight
	chain, err := workchain.New(f.base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	var blocks []workblock.Block
	tip, _ := f.source.Tip()
	for id := tip.ID; id != f.base.Tip.ID; {
		block, err := f.source.BlockByID(id)
		if err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, block)
		id = block.Header.Seal.AnchorParent
	}
	for i := len(blocks) - 1; i >= 0; i-- {
		if _, _, err := chain.Commit(blocks[i], blocks[i].Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
	}
	original, _ := f.manifest.CanonicalBytes()
	target, _ := next.CanonicalBytes()
	custody := CustodyPolicy{TrustedAuditors: [][32]byte{[32]byte(custodyTestKey(3).Public().(ed25519.PublicKey))}, MaximumChallengeLifetime: 60, MaximumProofAge: 100, MaximumRenewalTerm: 20000}
	var assignments []custodyauthority.Assignment
	var evidence []ScheduledReplicaEvidence
	var receipts []ScheduledReplicaReceipt
	var directories []string
	for i, replica := range replicas {
		a, err := CreateCustodyAuthorityAssignment(f.manifest, replica.Receipt, custody, types.Hash{byte(i + 1)}, [32]byte(custodyTestKey(1).Public().(ed25519.PublicKey)), []custodyauthority.Consumer{{PublicKey: [32]byte(custodyTestKey(4).Public().(ed25519.PublicKey)), Purposes: custodyauthority.AllPurposes}}, 16, 4)
		if err != nil {
			t.Fatal(err)
		}
		aid, _ := a.ID()
		proof := CustodyScheduleProof{AssignmentID: aid, OriginalManifest: original, TargetManifest: target, OriginalCheckpoint: f.checkpoint, TargetCheckpoint: cp, InitialReceipt: replica.Receipt, SelectedReceipt: replica.Receipt}
		lineage := CustodyReceiptLineage{AssignmentID: aid, Manifest: original, InitialReceipt: replica.Receipt, Policy: custody}
		r, err := CreateScheduledReplicaReceipt(t.Context(), proof, a, f.policy, lineage, replica.Receipt, custodyTestKey(byte(61+i)))
		if err != nil {
			t.Fatal(err)
		}
		assignments = append(assignments, a)
		evidence = append(evidence, ScheduledReplicaEvidence{Proof: proof, Lineage: lineage})
		receipts = append(receipts, r)
		directory := filepath.Join(t.TempDir(), "target")
		if _, _, err := MigrateRadixArchiveDirectory(replica.Directory, directory, f.checkpoint, cp, f.policy, f.base, f.parameters, DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		directories = append(directories, directory)
	}
	bundle, err := CreateScheduledAvailabilityBundle(t.Context(), cp, f.policy, policy, assignments, evidence, receipts, 1001)
	if err != nil {
		t.Fatal(err)
	}
	bid, _ := bundle.ID()
	sid, _ := cp.Statement.ID()
	floor := workchain.CanonicalFloor{Pruned: true, RadixActivationHeight: parameters.RadixActivationHeight, BaseID: statement.BaseID, Anchor: statement.Anchor, AncestryNodes: statement.AncestryNodes, AncestryRoot: statement.AncestryRoot, ManifestID: statement.ArchiveManifestID, StatementID: sid, AvailabilityID: bid, VerifiedAt: 1001, RetainUntil: 20000}
	for _, tc := range []struct {
		name   string
		step   int
		at     time.Time
		cancel bool
		want   error
	}{
		{"fresh", 3, time.Unix(1002, 0), false, nil},
		{"age-inclusive", 3, time.Unix(1100, 0), false, nil},
		{"expired-after-replay", 2, time.Unix(1101, 0), false, ErrAvailability},
		{"expired-at-mutation", 3, time.Unix(1101, 0), false, ErrAvailability},
		{"backwards-after-replay", 2, time.Unix(1000, 0), false, ErrAvailabilityClock},
		{"subsecond-backwards-at-mutation", 3, time.Unix(1001, 400000000), false, ErrAvailabilityClock},
		{"zero-clock", 1, time.Unix(0, 0), false, ErrAvailabilityClock},
		{"cancel-at-mutation", 3, time.Time{}, true, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			clock := func() time.Time {
				calls++
				if calls == tc.step {
					if tc.cancel {
						cancel()
					} else {
						return tc.at
					}
				}
				return time.Unix(1001, 500000000)
			}
			verified, err := verifyScheduledCanonicalPruneRequest(ctx, chain, directories, bundle, cp, f.policy, policy, assignments, evidence, f.base, parameters, DefaultLimits(), floor, clock)
			if err == nil {
				_, err = verified.Authorize()
			}
			if !errors.Is(err, tc.want) || calls != tc.step {
				t.Fatal("live gate", err, calls, tc.want)
			}
		})
	}
}
