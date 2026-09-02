package workarchive

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestCustodyChallengeRenewsReplicaReceiptChain(t *testing.T) {
	fixture := newArchiveFixture(t)
	replicas, replicaPolicy := archiveReplicaFixture(t, fixture, 1_000, 20_000)
	replicaKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, ed25519.SeedSize))
	auditorKey := custodyTestKey(81)
	policy := custodyTestPolicy(auditorKey)
	store, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "custody-objects"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportArchiveDirectory(
		replicas[0].Directory, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}

	challenge, err := createCustodyChallenge(
		fixture.manifest, replicas[0].Receipt, auditorKey, 1_001, 60, 2, 25_000,
		bytes.NewReader(bytes.Repeat([]byte{91}, types.HashSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := challenge.Verify(
		fixture.manifest, replicas[0].Receipt, policy, 1_002,
	); err != nil {
		t.Fatal(err)
	}
	challengeBytes, err := challenge.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decodedChallenge, err := DecodeCustodyChallenge(challengeBytes)
	if err != nil {
		t.Fatal(err)
	}
	challengeID, err := decodedChallenge.ID()
	if err != nil {
		t.Fatal(err)
	}
	batch, proof, err := AnswerCustodyChallenge(
		store, fixture.manifest, replicas[0].Receipt, decodedChallenge,
		policy, replicaKey, 1_002,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Objects) != 2 || proof.ChallengeID != challengeID {
		t.Fatalf("custody batch/proof=%d/%+v", len(batch.Objects), proof)
	}
	proofBytes, err := proof.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decodedProof, err := DecodeCustodyProof(proofBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCustodyResponse(
		fixture.manifest, replicas[0].Receipt, decodedChallenge, batch,
		decodedProof, policy, 1_003,
	); err != nil {
		t.Fatal(err)
	}
	renewed, err := RenewReplicaReceipt(
		fixture.manifest, replicas[0].Receipt, decodedChallenge, batch,
		decodedProof, policy, replicaKey, 1_003,
	)
	if err != nil {
		t.Fatal(err)
	}
	previousID, _ := replicas[0].Receipt.ID()
	proofID, _ := decodedProof.ID()
	renewedID, _ := renewed.ID()
	const expectedChallengeID = "416d0cddeb186b623a453e334e22b384fd5e3efd6d19bf88adfb8a7e41f941f1"
	const expectedProofID = "d24f2a42db0cd2249ee99f62fb0e2a6245bc71aebe186f962b91793f958a101c"
	const expectedRenewalID = "c5a7ebd40c7dc96e4aa97b55a57645a9334a721fa041aaa1344563f2531f1a83"
	if challengeID.String() != expectedChallengeID || proofID.String() != expectedProofID ||
		renewedID.String() != expectedRenewalID {
		t.Fatalf(
			"custody IDs challenge=%s proof=%s renewal=%s",
			challengeID, proofID, renewedID,
		)
	}
	if renewed.Version != ReplicaReceiptVersion1 || renewed.PreviousReceiptID != previousID ||
		renewed.CustodyProofID != proofID || renewed.StoredAt != decodedProof.RespondedAt ||
		renewed.RetainUntil != 25_000 {
		t.Fatalf("renewed receipt=%+v", renewed)
	}
	renewedBytes, err := renewed.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decodedRenewed, err := DecodeReplicaReceipt(renewedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if decodedRenewedID, err := decodedRenewed.ID(); err != nil {
		t.Fatal(err)
	} else if renewedID, _ := renewed.ID(); decodedRenewedID != renewedID {
		t.Fatalf("decoded renewal ID=%s want=%s", decodedRenewedID, renewedID)
	}
	if err := VerifyReplicaRenewal(
		fixture.manifest, replicas[0].Receipt, decodedRenewed, decodedChallenge,
		batch, decodedProof, policy, 1_003,
	); err != nil {
		t.Fatal(err)
	}
	tamperedTerm := decodedRenewed
	tamperedTerm.RetainUntil++
	tamperedMessage, err := tamperedTerm.signatureMessage()
	if err != nil {
		t.Fatal(err)
	}
	copy(tamperedTerm.Signature[:], ed25519.Sign(replicaKey, tamperedMessage))
	if err := VerifyReplicaRenewal(
		fixture.manifest, replicas[0].Receipt, tamperedTerm, decodedChallenge,
		batch, decodedProof, policy, 1_003,
	); !errors.Is(err, ErrReplicaReceipt) {
		t.Fatalf("proof reused for a different renewal term error=%v", err)
	}

	receipts := []ReplicaReceipt{decodedRenewed, replicas[1].Receipt}
	sort.Slice(receipts, func(left, right int) bool {
		return bytes.Compare(receipts[left].ReplicaPublicKey[:], receipts[right].ReplicaPublicKey[:]) < 0
	})
	statementID, _ := fixture.checkpoint.Statement.ID()
	bundle := AvailabilityBundle{
		Version: AvailabilityBundleVersion0, StatementID: statementID,
		ManifestID: fixture.manifestID, AnchorID: fixture.manifest.Anchor.ID,
		Receipts: receipts,
	}
	if err := bundle.Verify(
		fixture.checkpoint, fixture.policy, replicaPolicy, 1_003,
	); err != nil {
		t.Fatalf("mixed v0/v1 availability bundle: %v", err)
	}

	secondChallenge, err := createCustodyChallenge(
		fixture.manifest, decodedRenewed, auditorKey, 1_004, 60, 1, 30_000,
		bytes.NewReader(bytes.Repeat([]byte{92}, types.HashSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	secondBatch, secondProof, err := AnswerCustodyChallenge(
		store, fixture.manifest, decodedRenewed, secondChallenge,
		policy, replicaKey, 1_005,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondRenewal, err := RenewReplicaReceipt(
		fixture.manifest, decodedRenewed, secondChallenge, secondBatch,
		secondProof, policy, replicaKey, 1_006,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstRenewalID, _ := decodedRenewed.ID()
	if secondRenewal.PreviousReceiptID != firstRenewalID ||
		secondRenewal.CustodyProofID == decodedRenewed.CustodyProofID {
		t.Fatalf("second renewal linkage=%+v", secondRenewal)
	}
}

func TestCustodyChallengeRejectsBiasedReplayStaleAndCorruptEvidence(t *testing.T) {
	fixture := newArchiveFixture(t)
	replicas, _ := archiveReplicaFixture(t, fixture, 1_000, 20_000)
	receipt := replicas[0].Receipt
	replicaKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, ed25519.SeedSize))
	auditorKey := custodyTestKey(81)
	policy := custodyTestPolicy(auditorKey)
	store, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "negative-custody-objects"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportArchiveDirectory(
		replicas[0].Directory, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}
	challenge, err := createCustodyChallenge(
		fixture.manifest, receipt, auditorKey, 1_001, 60, 1, 21_000,
		bytes.NewReader(bytes.Repeat([]byte{101}, types.HashSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	batch, proof, err := AnswerCustodyChallenge(
		store, fixture.manifest, receipt, challenge, policy, replicaKey, 1_002,
	)
	if err != nil {
		t.Fatal(err)
	}

	biased := challenge
	for _, descriptor := range fixture.manifest.Chunks {
		if descriptor.ID != biased.IDs[0] {
			biased.IDs = []types.Hash{descriptor.ID}
			break
		}
	}
	message, err := biased.signatureMessage()
	if err != nil {
		t.Fatal(err)
	}
	copy(biased.Signature[:], ed25519.Sign(auditorKey, message))
	if err := biased.Verify(fixture.manifest, receipt, policy, 1_002); !errors.Is(err, ErrCustodyChallenge) {
		t.Fatalf("biased custody sample error=%v", err)
	}

	secondChallenge, err := createCustodyChallenge(
		fixture.manifest, receipt, auditorKey, 1_003, 60, 1, 21_000,
		bytes.NewReader(bytes.Repeat([]byte{102}, types.HashSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCustodyResponse(
		fixture.manifest, receipt, secondChallenge, batch, proof, policy, 1_004,
	); !errors.Is(err, ErrCustodyProof) {
		t.Fatalf("replayed custody proof error=%v", err)
	}
	stalePolicy := policy
	stalePolicy.MaximumProofAge = 1
	if err := VerifyCustodyResponse(
		fixture.manifest, receipt, challenge, batch, proof, stalePolicy, 1_004,
	); !errors.Is(err, ErrCustodyProof) {
		t.Fatalf("stale custody proof error=%v", err)
	}
	mutatedBatch := batch
	mutatedBatch.Objects = append([]ChunkObject(nil), batch.Objects...)
	mutatedBatch.Objects[0].Encoded = append([]byte(nil), batch.Objects[0].Encoded...)
	mutatedBatch.Objects[0].Encoded[len(mutatedBatch.Objects[0].Encoded)-1] ^= 1
	if err := VerifyCustodyResponse(
		fixture.manifest, receipt, challenge, mutatedBatch, proof, policy, 1_003,
	); !errors.Is(err, ErrCustodyProof) {
		t.Fatalf("corrupt custody batch error=%v", err)
	}
	wrongReplica := custodyTestKey(82)
	if _, _, err := AnswerCustodyChallenge(
		store, fixture.manifest, receipt, challenge, policy, wrongReplica, 1_002,
	); !errors.Is(err, ErrCustodyProof) {
		t.Fatalf("wrong replica key error=%v", err)
	}
	shortPolicy := policy
	shortPolicy.MaximumRenewalTerm = 100
	if _, err := RenewReplicaReceipt(
		fixture.manifest, receipt, challenge, batch, proof, shortPolicy,
		replicaKey, 1_003,
	); !errors.Is(err, ErrReplicaReceipt) {
		t.Fatalf("excessive renewal error=%v", err)
	}
	if _, err := createCustodyChallenge(
		fixture.manifest, receipt, auditorKey, 19_998, 2, 1, 21_000,
		bytes.NewReader(bytes.Repeat([]byte{103}, types.HashSize)),
	); !errors.Is(err, ErrCustodyChallenge) {
		t.Fatalf("challenge reaching receipt expiry error=%v", err)
	}
	if _, err := createCustodyChallenge(
		fixture.manifest, receipt, auditorKey, 1_001, 60, 1, 21_000,
		bytes.NewReader(nil),
	); !errors.Is(err, ErrCustodyChallenge) {
		t.Fatalf("failed custody entropy error=%v", err)
	}
	if _, err := createCustodyChallenge(
		fixture.manifest, receipt, auditorKey, 1_001, 60, 1, 21_000,
		bytes.NewReader(make([]byte, types.HashSize)),
	); !errors.Is(err, ErrCustodyChallenge) {
		t.Fatalf("zero custody nonce error=%v", err)
	}
	untrustedPolicy := custodyTestPolicy(custodyTestKey(89))
	if err := challenge.Verify(
		fixture.manifest, receipt, untrustedPolicy, 1_002,
	); !errors.Is(err, ErrCustodyChallenge) {
		t.Fatalf("untrusted auditor error=%v", err)
	}
}

func TestCustodyCodecsRejectMutationAndTrailingBytes(t *testing.T) {
	challengeBytes, proofBytes := custodyCodecSeeds(t)
	challenge, err := DecodeCustodyChallenge(challengeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if canonical, err := challenge.CanonicalBytes(); err != nil || !bytes.Equal(canonical, challengeBytes) {
		t.Fatalf("challenge canonical mismatch err=%v", err)
	}
	proof, err := DecodeCustodyProof(proofBytes)
	if err != nil {
		t.Fatal(err)
	}
	if canonical, err := proof.CanonicalBytes(); err != nil || !bytes.Equal(canonical, proofBytes) {
		t.Fatalf("proof canonical mismatch err=%v", err)
	}
	if _, err := DecodeCustodyChallenge(append(challengeBytes, 0)); !errors.Is(err, ErrCustodyChallenge) {
		t.Fatalf("trailing challenge error=%v", err)
	}
	if _, err := DecodeCustodyProof(append(proofBytes, 0)); !errors.Is(err, ErrCustodyProof) {
		t.Fatalf("trailing proof error=%v", err)
	}
	mutated := append([]byte(nil), proofBytes...)
	mutated[len(mutated)-1] ^= 1
	if _, err := DecodeCustodyProof(mutated); !errors.Is(err, ErrCustodyProof) {
		t.Fatalf("mutated proof error=%v", err)
	}
}

func FuzzDecodeCustodyChallengeNeverPanics(f *testing.F) {
	challengeBytes, _ := custodyCodecSeeds(f)
	f.Add(challengeBytes)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = DecodeCustodyChallenge(input) })
}

func FuzzDecodeCustodyProofNeverPanics(f *testing.F) {
	_, proofBytes := custodyCodecSeeds(f)
	f.Add(proofBytes)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = DecodeCustodyProof(input) })
}

func custodyCodecSeeds(t testing.TB) ([]byte, []byte) {
	t.Helper()
	manifestBytes, chunkBytes := archiveCodecSeedsForVersion(t, ManifestVersion1)
	manifest, err := DecodeManifest(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifestID, _ := manifest.ID()
	replicaKey := custodyTestKey(83)
	receipt := ReplicaReceipt{
		Version: ReplicaReceiptVersion0, Binding: manifest.Binding,
		StatementID: types.DomainHash("test/workarchive/custody-codec-statement"),
		ManifestID:  manifestID, AnchorID: manifest.Anchor.ID,
		LocationID: types.DomainHash("test/workarchive/custody-codec-location"),
		StoredAt:   1_000, RetainUntil: 20_000,
	}
	copy(receipt.ReplicaPublicKey[:], replicaKey.Public().(ed25519.PublicKey))
	message, _ := receipt.signatureMessage()
	copy(receipt.Signature[:], ed25519.Sign(replicaKey, message))
	auditorKey := custodyTestKey(84)
	challenge, err := createCustodyChallenge(
		manifest, receipt, auditorKey, 1_001, 60, 1, 21_000,
		bytes.NewReader(bytes.Repeat([]byte{111}, types.HashSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	challengeBytes, _ := challenge.CanonicalBytes()
	batch := ChunkBatch{
		Version: ObjectExchangeVersion0, ManifestID: manifestID,
		Objects: []ChunkObject{{ID: manifest.Chunks[0].ID, Encoded: chunkBytes}},
	}
	digest, err := custodyBatchDigest(batch)
	if err != nil {
		t.Fatal(err)
	}
	challengeID, _ := challenge.ID()
	receiptID, _ := receipt.ID()
	proof := CustodyProof{
		Version: CustodyProofVersion0, ChallengeID: challengeID,
		ReceiptID: receiptID, ManifestID: manifestID, RespondedAt: 1_002,
		BatchDigest: digest, ReplicaPublicKey: receipt.ReplicaPublicKey,
	}
	message, _ = proof.signatureMessage()
	copy(proof.Signature[:], ed25519.Sign(replicaKey, message))
	proofBytes, _ := proof.CanonicalBytes()
	return challengeBytes, proofBytes
}

func custodyTestKey(value byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{value}, ed25519.SeedSize))
}

func custodyTestPolicy(auditorKey ed25519.PrivateKey) CustodyPolicy {
	var publicKey [ed25519.PublicKeySize]byte
	copy(publicKey[:], auditorKey.Public().(ed25519.PublicKey))
	return CustodyPolicy{
		TrustedAuditors:          [][ed25519.PublicKeySize]byte{publicKey},
		MaximumChallengeLifetime: 120, MaximumProofAge: 120,
		MaximumRenewalTerm: 40_000,
	}
}
