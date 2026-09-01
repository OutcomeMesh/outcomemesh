package workarchive

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestReplicaAvailabilityAuthorizesCanonicalPrune(t *testing.T) {
	fixture := newArchiveFixture(t)
	replicas, replicaPolicy := archiveReplicaFixture(t, fixture, 1_000, 20_000)
	bundle, err := VerifyReplicaSet(
		replicas, fixture.checkpoint, fixture.policy, replicaPolicy,
		fixture.base, fixture.parameters, DefaultLimits(), 1_001,
	)
	if err != nil {
		t.Fatal(err)
	}
	if bundleID, err := bundle.ID(); err != nil {
		t.Fatal(err)
	} else if bundleID.String() != "d1c16895c3d74a2b82debbf2fa7e46d6cadf13292ce214a1697e7af32deca897" {
		t.Fatalf("availability bundle ID=%s", bundleID)
	}
	encoded, err := bundle.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAvailabilityBundle(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decodedID, err := decoded.ID(); err != nil {
		t.Fatal(err)
	} else if bundleID, _ := bundle.ID(); decodedID != bundleID {
		t.Fatalf("availability bundle ID=%s want=%s", decodedID, bundleID)
	}

	parent := fixture.manifest.Anchor
	for index := 0; index < 2; index++ {
		block, _ := mineArchiveChild(
			t, fixture.source, parent.ID,
			parent.Timestamp+fixture.parameters.TargetSpacing,
			"availability-extension-"+string(rune('a'+index)),
		)
		if _, _, err := fixture.source.Commit(block, block.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
		parent, err = fixture.source.TipByID(mustArchiveBlockID(t, block))
		if err != nil {
			t.Fatal(err)
		}
	}
	if report, err := fixture.source.PruneStaleForks(); err != nil || report.RemovedNodes == 0 {
		t.Fatalf("stale branch preparation report=%+v err=%v", report, err)
	}
	blockedParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PruneCanonicalPrefix(
		fixture.source, replicas, filepath.Join(blockedParent, "availability.omav"),
		fixture.checkpoint, fixture.policy, replicaPolicy,
		fixture.base, fixture.parameters, DefaultLimits(), 1_001,
	); err == nil {
		t.Fatal("canonical prune ignored availability publication failure")
	}
	if floor, err := fixture.source.CanonicalFloor(); err != nil || floor.Pruned {
		t.Fatalf("availability publication failure changed floor=%+v err=%v", floor, err)
	}
	result, err := PruneCanonicalPrefix(
		fixture.source, replicas, filepath.Join(t.TempDir(), "availability.omav"),
		fixture.checkpoint, fixture.policy, replicaPolicy,
		fixture.base, fixture.parameters, DefaultLimits(), 1_001,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.FloorID != fixture.manifest.Anchor.ID || result.Report.RemovedNodes != 3 ||
		result.Report.ArchivedHeaders != 2 || result.Report.ReleasedHistoryBytes == 0 {
		t.Fatalf("availability prune report=%+v", result.Report)
	}
	floor, err := fixture.source.CanonicalFloor()
	if err != nil || !floor.Pruned || floor.Anchor.ID != fixture.manifest.Anchor.ID ||
		floor.ManifestID != fixture.manifestID || floor.RetainUntil != 20_000 {
		t.Fatalf("availability floor=%+v err=%v", floor, err)
	}
	if bundleID, _ := result.Bundle.ID(); floor.AvailabilityID != bundleID {
		t.Fatalf("floor availability=%s want=%s", floor.AvailabilityID, bundleID)
	}
	firstChunk, err := DecodeChunk(mustReadArchiveFile(
		t, filepath.Join(fixture.archivePath, chunkFileName(0)),
	))
	if err != nil {
		t.Fatal(err)
	}
	activationID, _ := firstChunk.Blocks[0].Header.ID()
	if _, err := fixture.source.BlockByID(activationID); !errors.Is(err, workchain.ErrHistoryPruned) {
		t.Fatalf("availability-pruned block error=%v", err)
	}
	tip, err := fixture.source.Tip()
	if err != nil {
		t.Fatal(err)
	}
	extension, _ := mineArchiveChild(
		t, fixture.source, tip.ID, tip.Timestamp+fixture.parameters.TargetSpacing,
		"availability-post-prune-extension",
	)
	if _, _, err := fixture.source.Commit(extension, extension.Header.Seal.Timestamp); err != nil {
		t.Fatalf("extend availability-pruned chain: %v", err)
	}
}

func TestReplicaAvailabilityRejectsDuplicateStaleAndMissingBytes(t *testing.T) {
	fixture := newArchiveFixture(t)
	replicas, replicaPolicy := archiveReplicaFixture(t, fixture, 1_000, 20_000)
	duplicate := []Replica{replicas[0], replicas[0]}
	duplicate[1].Receipt = replicas[1].Receipt
	if _, err := VerifyReplicaSet(
		duplicate, fixture.checkpoint, fixture.policy, replicaPolicy,
		fixture.base, fixture.parameters, DefaultLimits(), 1_001,
	); !errors.Is(err, ErrAvailability) {
		t.Fatalf("duplicate replica directory error=%v", err)
	}
	if _, err := VerifyReplicaSet(
		replicas, fixture.checkpoint, fixture.policy, replicaPolicy,
		fixture.base, fixture.parameters, DefaultLimits(), 20_000,
	); !errors.Is(err, ErrAvailability) {
		t.Fatalf("expired replica receipts error=%v", err)
	}
	if _, err := PruneCanonicalPrefix(
		fixture.source, replicas, filepath.Join(replicas[0].Directory, "availability.omav"),
		fixture.checkpoint, fixture.policy, replicaPolicy,
		fixture.base, fixture.parameters, DefaultLimits(), 1_001,
	); !errors.Is(err, ErrAvailability) {
		t.Fatalf("availability evidence inside replica error=%v", err)
	}
	replicaAlias := filepath.Join(t.TempDir(), "replica-alias")
	if err := os.Symlink(replicas[0].Directory, replicaAlias); err != nil {
		t.Fatal(err)
	}
	if _, err := PruneCanonicalPrefix(
		fixture.source, replicas, filepath.Join(replicaAlias, "availability.omav"),
		fixture.checkpoint, fixture.policy, replicaPolicy,
		fixture.base, fixture.parameters, DefaultLimits(), 1_001,
	); !errors.Is(err, ErrAvailability) {
		t.Fatalf("availability evidence through replica symlink error=%v", err)
	}
	if err := os.Remove(filepath.Join(replicas[1].Directory, chunkFileName(0))); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReplicaSet(
		replicas, fixture.checkpoint, fixture.policy, replicaPolicy,
		fixture.base, fixture.parameters, DefaultLimits(), 1_001,
	); err == nil {
		t.Fatal("missing replica bytes authorized pruning")
	}
}

func TestReplicaAvailabilityCodecsRejectMutationAndTrailingBytes(t *testing.T) {
	fixture := newArchiveFixture(t)
	replicas, policy := archiveReplicaFixture(t, fixture, 1_000, 20_000)
	bundle, err := VerifyReplicaSet(
		replicas, fixture.checkpoint, fixture.policy, policy,
		fixture.base, fixture.parameters, DefaultLimits(), 1_001,
	)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, _ := replicas[0].Receipt.CanonicalBytes()
	if _, err := DecodeReplicaReceipt(append(receiptBytes, 0)); !errors.Is(err, ErrReplicaReceipt) {
		t.Fatalf("trailing receipt error=%v", err)
	}
	mutated := append([]byte(nil), receiptBytes...)
	mutated[len(mutated)-1] ^= 1
	if receipt, err := DecodeReplicaReceipt(mutated); err == nil && receipt.verifySignature() == nil {
		t.Fatal("mutated replica receipt verified")
	}
	bundleBytes, _ := bundle.CanonicalBytes()
	if _, err := DecodeAvailabilityBundle(append(bundleBytes, 0)); !errors.Is(err, ErrAvailability) {
		t.Fatalf("trailing availability bundle error=%v", err)
	}
	if _, err := DecodeAvailabilityBundle(make([]byte, MaximumAvailabilityBundleBytes+1)); !errors.Is(err, ErrAvailability) {
		t.Fatalf("oversize availability bundle error=%v", err)
	}
	bundleID, _ := bundle.ID()
	path := filepath.Join(t.TempDir(), "availability.omav")
	if err := SaveAvailabilityBundleFile(
		path, bundle, fixture.checkpoint, fixture.policy, policy, 1_001, bundleID,
	); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadAvailabilityBundleFile(
		path, fixture.checkpoint, fixture.policy, policy, 1_001, bundleID,
	); err != nil {
		t.Fatal(err)
	} else if loadedID, _ := loaded.ID(); loadedID != bundleID {
		t.Fatalf("loaded availability ID=%s want=%s", loadedID, bundleID)
	}
}

func FuzzDecodeReplicaReceiptNeverPanics(f *testing.F) {
	receiptBytes, _ := availabilityCodecSeeds()
	f.Add(receiptBytes)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = DecodeReplicaReceipt(input) })
}

func FuzzDecodeAvailabilityBundleNeverPanics(f *testing.F) {
	_, bundleBytes := availabilityCodecSeeds()
	f.Add(bundleBytes)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = DecodeAvailabilityBundle(input) })
}

func availabilityCodecSeeds() ([]byte, []byte) {
	binding := Binding{
		NetworkID: 909, GenesisID: types.DomainHash("test/workarchive/availability-codec-genesis"),
		ActivationHeight: 1, BaseID: types.DomainHash("test/workarchive/availability-codec-base"),
	}
	receipts := make([]ReplicaReceipt, 2)
	for index := range receipts {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(71 + index)}, ed25519.SeedSize))
		receipts[index] = ReplicaReceipt{
			Version: ReplicaReceiptVersion0, Binding: binding,
			StatementID: types.DomainHash("test/workarchive/availability-codec-statement"),
			ManifestID:  types.DomainHash("test/workarchive/availability-codec-manifest"),
			AnchorID:    types.DomainHash("test/workarchive/availability-codec-anchor"),
			LocationID:  types.DomainHash("test/workarchive/availability-codec-location", []byte{byte(index)}),
			StoredAt:    1_000, RetainUntil: 20_000,
		}
		copy(receipts[index].ReplicaPublicKey[:], key.Public().(ed25519.PublicKey))
		message, _ := receipts[index].signatureMessage()
		copy(receipts[index].Signature[:], ed25519.Sign(key, message))
	}
	if bytes.Compare(receipts[0].ReplicaPublicKey[:], receipts[1].ReplicaPublicKey[:]) > 0 {
		receipts[0], receipts[1] = receipts[1], receipts[0]
	}
	receiptBytes, _ := receipts[0].CanonicalBytes()
	bundle := AvailabilityBundle{
		Version: AvailabilityBundleVersion0, StatementID: receipts[0].StatementID,
		ManifestID: receipts[0].ManifestID, AnchorID: receipts[0].AnchorID, Receipts: receipts,
	}
	bundleBytes, _ := bundle.CanonicalBytes()
	return receiptBytes, bundleBytes
}

func archiveReplicaFixture(
	t testing.TB,
	fixture archiveFixture,
	storedAt uint64,
	retainUntil uint64,
) ([]Replica, ReplicaPolicy) {
	t.Helper()
	keys := []ed25519.PrivateKey{
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, ed25519.SeedSize)),
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{62}, ed25519.SeedSize)),
	}
	replicas := make([]Replica, len(keys))
	for index, key := range keys {
		directory := filepath.Join(t.TempDir(), "replica")
		copyArchiveDirectory(t, fixture.archivePath, directory)
		receipt, err := CreateReplicaReceipt(
			directory, fixture.checkpoint, fixture.policy, fixture.base, fixture.parameters,
			DefaultLimits(), key,
			types.DomainHash("test/workarchive/replica-location", []byte{byte(index)}),
			storedAt, retainUntil,
		)
		if err != nil {
			t.Fatal(err)
		}
		replicas[index] = Replica{Directory: directory, Receipt: receipt}
	}
	return replicas, ReplicaPolicy{
		TrustedReplicas: sortedPublicKeys(keys), RequiredReplicas: 2,
		MaximumReceiptAge: 100, MinimumRemainingTerm: 1_000,
	}
}

func mustArchiveBlockID(t testing.TB, block workblock.Block) types.Hash {
	t.Helper()
	id, err := block.Header.ID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustReadArchiveFile(t testing.TB, path string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
