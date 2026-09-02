package workarchive

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	CustodyChallengeVersion0        uint16 = 0
	CustodyProofVersion0            uint16 = 0
	MinimumCustodySamples                  = 1
	MaximumCustodySamples                  = 8
	MaximumCustodyChallengeBytes           = 1_024
	MaximumCustodyProofBytes               = 512
	MaximumCustodyChallengeLifetime uint64 = 10 * 60
	MaximumCustodyProofAge          uint64 = 30 * 24 * 60 * 60
)

const (
	custodyChallengeSignatureDomain = "OMESH/workgraph/archive/custody-challenge/signature/v0"
	custodyChallengeIDDomain        = "OMESH/workgraph/archive/custody-challenge/id/v0"
	custodySampleDomain             = "OMESH/workgraph/archive/custody-challenge/sample/v0"
	custodyBatchDomain              = "OMESH/workgraph/archive/custody-batch/v0"
	custodyProofSignatureDomain     = "OMESH/workgraph/archive/custody-proof/signature/v0"
	custodyProofIDDomain            = "OMESH/workgraph/archive/custody-proof/id/v0"
)

var (
	ErrCustodyChallenge = errors.New("invalid WorkGraph archive custody challenge")
	ErrCustodyProof     = errors.New("invalid WorkGraph archive custody proof")
	ErrCustodyPolicy    = errors.New("invalid WorkGraph archive custody policy")
)

var (
	custodyChallengeMagic = [8]byte{'O', 'M', 'W', 'A', 'C', 'H', 'A', 'L'}
	custodyProofMagic     = [8]byte{'O', 'M', 'W', 'A', 'C', 'P', 'R', 'F'}
)

type CustodyPolicy struct {
	TrustedAuditors          [][ed25519.PublicKeySize]byte
	MaximumChallengeLifetime uint64
	MaximumProofAge          uint64
	MaximumRenewalTerm       uint64
}

type CustodyChallenge struct {
	Version          uint16
	StatementID      types.Hash
	ManifestID       types.Hash
	ReceiptID        types.Hash
	IssuedAt         uint64
	ExpiresAt        uint64
	RenewUntil       uint64
	Nonce            types.Hash
	RequestedSamples uint16
	IDs              []types.Hash
	AuditorPublicKey [ed25519.PublicKeySize]byte
	Signature        [ed25519.SignatureSize]byte
}

type CustodyProof struct {
	Version          uint16
	ChallengeID      types.Hash
	ReceiptID        types.Hash
	ManifestID       types.Hash
	RespondedAt      uint64
	BatchDigest      types.Hash
	ReplicaPublicKey [ed25519.PublicKeySize]byte
	Signature        [ed25519.SignatureSize]byte
}

func CreateCustodyChallenge(
	manifest Manifest,
	receipt ReplicaReceipt,
	auditorPrivateKey ed25519.PrivateKey,
	issuedAt uint64,
	lifetime uint64,
	requestedSamples uint16,
	renewUntil uint64,
) (CustodyChallenge, error) {
	return createCustodyChallenge(
		manifest, receipt, auditorPrivateKey, issuedAt, lifetime,
		requestedSamples, renewUntil, rand.Reader,
	)
}

func createCustodyChallenge(
	manifest Manifest,
	receipt ReplicaReceipt,
	auditorPrivateKey ed25519.PrivateKey,
	issuedAt uint64,
	lifetime uint64,
	requestedSamples uint16,
	renewUntil uint64,
	entropy io.Reader,
) (CustodyChallenge, error) {
	if manifest.Validate() != nil || receipt.verifySignature() != nil ||
		len(auditorPrivateKey) != ed25519.PrivateKeySize || entropy == nil || issuedAt == 0 ||
		lifetime == 0 || lifetime > MaximumCustodyChallengeLifetime ||
		requestedSamples < MinimumCustodySamples || requestedSamples > MaximumCustodySamples ||
		issuedAt > ^uint64(0)-lifetime || renewUntil <= issuedAt ||
		renewUntil-issuedAt > MaximumReplicaTermSeconds {
		return CustodyChallenge{}, ErrCustodyChallenge
	}
	manifestID, err := manifest.ID()
	if err != nil {
		return CustodyChallenge{}, err
	}
	receiptID, err := receipt.ID()
	if err != nil {
		return CustodyChallenge{}, err
	}
	if receipt.ManifestID != manifestID || receipt.Binding != manifest.Binding ||
		receipt.AnchorID != manifest.Anchor.ID || issuedAt < receipt.StoredAt ||
		issuedAt+lifetime >= receipt.RetainUntil || renewUntil <= receipt.RetainUntil {
		return CustodyChallenge{}, ErrCustodyChallenge
	}
	statementID := receipt.StatementID
	challenge := CustodyChallenge{
		Version: CustodyChallengeVersion0, StatementID: statementID,
		ManifestID: manifestID, ReceiptID: receiptID, IssuedAt: issuedAt,
		ExpiresAt: issuedAt + lifetime, RenewUntil: renewUntil,
		RequestedSamples: requestedSamples,
	}
	if _, err := io.ReadFull(entropy, challenge.Nonce[:]); err != nil || challenge.Nonce.IsZero() {
		return CustodyChallenge{}, errors.Join(ErrCustodyChallenge, err)
	}
	challenge.IDs, err = custodySampleIDs(
		manifest, receiptID, challenge.Nonce, requestedSamples,
	)
	if err != nil {
		return CustodyChallenge{}, err
	}
	copy(challenge.AuditorPublicKey[:], auditorPrivateKey.Public().(ed25519.PublicKey))
	message, err := challenge.signatureMessage()
	if err != nil {
		return CustodyChallenge{}, err
	}
	copy(challenge.Signature[:], ed25519.Sign(auditorPrivateKey, message))
	return challenge, nil
}

func (challenge CustodyChallenge) Verify(
	manifest Manifest,
	receipt ReplicaReceipt,
	policy CustodyPolicy,
	at uint64,
) error {
	if policy.validate() != nil || challenge.verifySignature() != nil ||
		manifest.Validate() != nil || receipt.verifySignature() != nil || at == 0 ||
		at < challenge.IssuedAt || at > challenge.ExpiresAt ||
		challenge.ExpiresAt-challenge.IssuedAt > policy.MaximumChallengeLifetime {
		return ErrCustodyChallenge
	}
	trusted := false
	for _, key := range policy.TrustedAuditors {
		if key == challenge.AuditorPublicKey {
			trusted = true
			break
		}
	}
	manifestID, err := manifest.ID()
	if err != nil {
		return err
	}
	receiptID, err := receipt.ID()
	if err != nil {
		return err
	}
	if !trusted || challenge.StatementID != receipt.StatementID ||
		challenge.ManifestID != manifestID || challenge.ReceiptID != receiptID ||
		receipt.ManifestID != manifestID || receipt.Binding != manifest.Binding ||
		receipt.AnchorID != manifest.Anchor.ID || challenge.IssuedAt < receipt.StoredAt ||
		challenge.ExpiresAt >= receipt.RetainUntil ||
		challenge.RenewUntil <= receipt.RetainUntil ||
		challenge.RenewUntil-challenge.IssuedAt > policy.MaximumRenewalTerm {
		return ErrCustodyChallenge
	}
	expected, err := custodySampleIDs(
		manifest, receiptID, challenge.Nonce, challenge.RequestedSamples,
	)
	if err != nil || !equalCustodyIDs(expected, challenge.IDs) {
		return ErrCustodyChallenge
	}
	return nil
}

func AnswerCustodyChallenge(
	store *ObjectStore,
	manifest Manifest,
	receipt ReplicaReceipt,
	challenge CustodyChallenge,
	policy CustodyPolicy,
	replicaPrivateKey ed25519.PrivateKey,
	respondedAt uint64,
) (ChunkBatch, CustodyProof, error) {
	if store == nil || len(replicaPrivateKey) != ed25519.PrivateKeySize ||
		challenge.Verify(manifest, receipt, policy, respondedAt) != nil ||
		!bytes.Equal(
			replicaPrivateKey.Public().(ed25519.PublicKey), receipt.ReplicaPublicKey[:],
		) {
		return ChunkBatch{}, CustodyProof{}, ErrCustodyProof
	}
	request := ChunkRequest{
		Version: ObjectExchangeVersion0, ManifestID: challenge.ManifestID,
		IDs: append([]types.Hash(nil), challenge.IDs...),
	}
	batch, err := ServeChunkRequest(store, manifest, request)
	if err != nil {
		return ChunkBatch{}, CustodyProof{}, err
	}
	batchDigest, err := custodyBatchDigest(batch)
	if err != nil {
		return ChunkBatch{}, CustodyProof{}, err
	}
	challengeID, err := challenge.ID()
	if err != nil {
		return ChunkBatch{}, CustodyProof{}, err
	}
	proof := CustodyProof{
		Version: CustodyProofVersion0, ChallengeID: challengeID,
		ReceiptID: challenge.ReceiptID, ManifestID: challenge.ManifestID,
		RespondedAt: respondedAt, BatchDigest: batchDigest,
		ReplicaPublicKey: receipt.ReplicaPublicKey,
	}
	message, err := proof.signatureMessage()
	if err != nil {
		return ChunkBatch{}, CustodyProof{}, err
	}
	copy(proof.Signature[:], ed25519.Sign(replicaPrivateKey, message))
	return batch, proof, nil
}

func VerifyCustodyResponse(
	manifest Manifest,
	receipt ReplicaReceipt,
	challenge CustodyChallenge,
	batch ChunkBatch,
	proof CustodyProof,
	policy CustodyPolicy,
	now uint64,
) error {
	if now == 0 || proof.verifySignature() != nil ||
		challenge.Verify(manifest, receipt, policy, proof.RespondedAt) != nil ||
		now < proof.RespondedAt || now-proof.RespondedAt > policy.MaximumProofAge {
		return ErrCustodyProof
	}
	challengeID, err := challenge.ID()
	if err != nil {
		return err
	}
	receiptID, err := receipt.ID()
	if err != nil {
		return err
	}
	if proof.ChallengeID != challengeID || proof.ReceiptID != receiptID ||
		proof.ManifestID != challenge.ManifestID ||
		proof.ReplicaPublicKey != receipt.ReplicaPublicKey ||
		!objectBatchAnswersRequest(batch, ChunkRequest{
			Version: ObjectExchangeVersion0, ManifestID: challenge.ManifestID,
			IDs: challenge.IDs,
		}) {
		return ErrCustodyProof
	}
	for _, object := range batch.Objects {
		descriptor, exists := manifestDescriptor(manifest, object.ID)
		if !exists || validateChunkObject(manifest, descriptor, object.Encoded) != nil {
			return ErrCustodyProof
		}
	}
	digest, err := custodyBatchDigest(batch)
	if err != nil || digest != proof.BatchDigest {
		return ErrCustodyProof
	}
	return nil
}

func RenewReplicaReceipt(
	manifest Manifest,
	receipt ReplicaReceipt,
	challenge CustodyChallenge,
	batch ChunkBatch,
	proof CustodyProof,
	policy CustodyPolicy,
	replicaPrivateKey ed25519.PrivateKey,
	now uint64,
) (ReplicaReceipt, error) {
	if len(replicaPrivateKey) != ed25519.PrivateKeySize ||
		VerifyCustodyResponse(
			manifest, receipt, challenge, batch, proof, policy, now,
		) != nil || now >= receipt.RetainUntil || challenge.RenewUntil <= now ||
		challenge.RenewUntil-proof.RespondedAt > policy.MaximumRenewalTerm ||
		challenge.RenewUntil-proof.RespondedAt > MaximumReplicaTermSeconds ||
		!bytes.Equal(
			replicaPrivateKey.Public().(ed25519.PublicKey), receipt.ReplicaPublicKey[:],
		) {
		return ReplicaReceipt{}, ErrReplicaReceipt
	}
	previousID, err := receipt.ID()
	if err != nil {
		return ReplicaReceipt{}, err
	}
	proofID, err := proof.ID()
	if err != nil {
		return ReplicaReceipt{}, err
	}
	renewed := ReplicaReceipt{
		Version: ReplicaReceiptVersion1, Binding: receipt.Binding,
		StatementID: receipt.StatementID, ManifestID: receipt.ManifestID,
		AnchorID: receipt.AnchorID, LocationID: receipt.LocationID,
		PreviousReceiptID: previousID, CustodyProofID: proofID,
		StoredAt: proof.RespondedAt, RetainUntil: challenge.RenewUntil,
		ReplicaPublicKey: receipt.ReplicaPublicKey,
	}
	message, err := renewed.signatureMessage()
	if err != nil {
		return ReplicaReceipt{}, err
	}
	copy(renewed.Signature[:], ed25519.Sign(replicaPrivateKey, message))
	if err := VerifyReplicaRenewal(
		manifest, receipt, renewed, challenge, batch, proof, policy, now,
	); err != nil {
		return ReplicaReceipt{}, err
	}
	return renewed, nil
}

func VerifyReplicaRenewal(
	manifest Manifest,
	previous ReplicaReceipt,
	renewed ReplicaReceipt,
	challenge CustodyChallenge,
	batch ChunkBatch,
	proof CustodyProof,
	policy CustodyPolicy,
	now uint64,
) error {
	if renewed.verifySignature() != nil || renewed.Version != ReplicaReceiptVersion1 ||
		VerifyCustodyResponse(
			manifest, previous, challenge, batch, proof, policy, now,
		) != nil || renewed.Binding != previous.Binding ||
		renewed.StatementID != previous.StatementID || renewed.ManifestID != previous.ManifestID ||
		renewed.AnchorID != previous.AnchorID || renewed.LocationID != previous.LocationID ||
		renewed.ReplicaPublicKey != previous.ReplicaPublicKey ||
		renewed.StoredAt != proof.RespondedAt ||
		renewed.RetainUntil != challenge.RenewUntil ||
		renewed.RetainUntil <= previous.RetainUntil {
		return ErrReplicaReceipt
	}
	previousID, err := previous.ID()
	if err != nil {
		return err
	}
	proofID, err := proof.ID()
	if err != nil {
		return err
	}
	if renewed.PreviousReceiptID != previousID || renewed.CustodyProofID != proofID {
		return ErrReplicaReceipt
	}
	return nil
}

func (challenge CustodyChallenge) CanonicalBytes() ([]byte, error) {
	if challenge.verifySignature() != nil {
		return nil, ErrCustodyChallenge
	}
	unsigned, err := challenge.unsignedBytes()
	if err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(len(unsigned) + ed25519.SignatureSize)
	encoder.Fixed(unsigned)
	encoder.Fixed(challenge.Signature[:])
	encoded := encoder.Bytes()
	if len(encoded) > MaximumCustodyChallengeBytes {
		return nil, ErrCustodyChallenge
	}
	return encoded, nil
}

func DecodeCustodyChallenge(input []byte) (CustodyChallenge, error) {
	if len(input) == 0 || len(input) > MaximumCustodyChallengeBytes {
		return CustodyChallenge{}, ErrCustodyChallenge
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(custodyChallengeMagic))
	if err != nil || !bytes.Equal(magic, custodyChallengeMagic[:]) {
		return CustodyChallenge{}, ErrCustodyChallenge
	}
	var challenge CustodyChallenge
	if challenge.Version, err = decoder.U16(); err != nil {
		return CustodyChallenge{}, err
	}
	for _, destination := range []*types.Hash{
		&challenge.StatementID, &challenge.ManifestID, &challenge.ReceiptID,
	} {
		value, decodeErr := decoder.Fixed(types.HashSize)
		if decodeErr != nil {
			return CustodyChallenge{}, decodeErr
		}
		copy(destination[:], value)
	}
	if challenge.IssuedAt, err = decoder.U64(); err != nil {
		return CustodyChallenge{}, err
	}
	if challenge.ExpiresAt, err = decoder.U64(); err != nil {
		return CustodyChallenge{}, err
	}
	if challenge.RenewUntil, err = decoder.U64(); err != nil {
		return CustodyChallenge{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return CustodyChallenge{}, decodeErr
	} else {
		copy(challenge.Nonce[:], value)
	}
	if challenge.RequestedSamples, err = decoder.U16(); err != nil {
		return CustodyChallenge{}, err
	}
	count, err := decoder.ListLength(MaximumCustodySamples)
	if err != nil || count < MinimumCustodySamples {
		return CustodyChallenge{}, ErrCustodyChallenge
	}
	challenge.IDs = make([]types.Hash, count)
	for index := range challenge.IDs {
		value, decodeErr := decoder.Fixed(types.HashSize)
		if decodeErr != nil {
			return CustodyChallenge{}, decodeErr
		}
		copy(challenge.IDs[index][:], value)
	}
	if value, decodeErr := decoder.Fixed(ed25519.PublicKeySize); decodeErr != nil {
		return CustodyChallenge{}, decodeErr
	} else {
		copy(challenge.AuditorPublicKey[:], value)
	}
	if value, decodeErr := decoder.Fixed(ed25519.SignatureSize); decodeErr != nil {
		return CustodyChallenge{}, decodeErr
	} else {
		copy(challenge.Signature[:], value)
	}
	if err := decoder.Finish(); err != nil || challenge.verifySignature() != nil {
		return CustodyChallenge{}, ErrCustodyChallenge
	}
	return challenge, nil
}

func (challenge CustodyChallenge) ID() (types.Hash, error) {
	encoded, err := challenge.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(custodyChallengeIDDomain, encoded), nil
}

func (proof CustodyProof) CanonicalBytes() ([]byte, error) {
	if proof.verifySignature() != nil {
		return nil, ErrCustodyProof
	}
	unsigned, err := proof.unsignedBytes()
	if err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(len(unsigned) + ed25519.SignatureSize)
	encoder.Fixed(unsigned)
	encoder.Fixed(proof.Signature[:])
	encoded := encoder.Bytes()
	if len(encoded) > MaximumCustodyProofBytes {
		return nil, ErrCustodyProof
	}
	return encoded, nil
}

func DecodeCustodyProof(input []byte) (CustodyProof, error) {
	if len(input) == 0 || len(input) > MaximumCustodyProofBytes {
		return CustodyProof{}, ErrCustodyProof
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(custodyProofMagic))
	if err != nil || !bytes.Equal(magic, custodyProofMagic[:]) {
		return CustodyProof{}, ErrCustodyProof
	}
	var proof CustodyProof
	if proof.Version, err = decoder.U16(); err != nil {
		return CustodyProof{}, err
	}
	for _, destination := range []*types.Hash{
		&proof.ChallengeID, &proof.ReceiptID, &proof.ManifestID,
	} {
		value, decodeErr := decoder.Fixed(types.HashSize)
		if decodeErr != nil {
			return CustodyProof{}, decodeErr
		}
		copy(destination[:], value)
	}
	if proof.RespondedAt, err = decoder.U64(); err != nil {
		return CustodyProof{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return CustodyProof{}, decodeErr
	} else {
		copy(proof.BatchDigest[:], value)
	}
	if value, decodeErr := decoder.Fixed(ed25519.PublicKeySize); decodeErr != nil {
		return CustodyProof{}, decodeErr
	} else {
		copy(proof.ReplicaPublicKey[:], value)
	}
	if value, decodeErr := decoder.Fixed(ed25519.SignatureSize); decodeErr != nil {
		return CustodyProof{}, decodeErr
	} else {
		copy(proof.Signature[:], value)
	}
	if err := decoder.Finish(); err != nil || proof.verifySignature() != nil {
		return CustodyProof{}, ErrCustodyProof
	}
	return proof, nil
}

func (proof CustodyProof) ID() (types.Hash, error) {
	encoded, err := proof.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(custodyProofIDDomain, encoded), nil
}

func custodySampleIDs(
	manifest Manifest,
	receiptID types.Hash,
	nonce types.Hash,
	requested uint16,
) ([]types.Hash, error) {
	if manifest.Validate() != nil || receiptID.IsZero() || nonce.IsZero() ||
		requested < MinimumCustodySamples || requested > MaximumCustodySamples {
		return nil, ErrCustodyChallenge
	}
	type candidate struct {
		id    types.Hash
		score types.Hash
		bytes uint32
	}
	candidates := make([]candidate, len(manifest.Chunks))
	manifestID, err := manifest.ID()
	if err != nil {
		return nil, err
	}
	for index, descriptor := range manifest.Chunks {
		candidates[index] = candidate{
			id: descriptor.ID, bytes: descriptor.EncodedBytes,
			score: types.DomainHash(
				custodySampleDomain, manifestID[:], receiptID[:], nonce[:], descriptor.ID[:],
			),
		}
	}
	sort.Slice(candidates, func(left, right int) bool {
		comparison := types.CompareHash(candidates[left].score, candidates[right].score)
		if comparison == 0 {
			return types.CompareHash(candidates[left].id, candidates[right].id) < 0
		}
		return comparison < 0
	})
	ids := make([]types.Hash, 0, min(int(requested), len(candidates)))
	var totalBytes uint64
	for _, candidate := range candidates {
		if len(ids) == int(requested) {
			break
		}
		if uint64(candidate.bytes) > MaximumChunkBytes-totalBytes {
			continue
		}
		ids = append(ids, candidate.id)
		totalBytes += uint64(candidate.bytes)
	}
	if len(ids) == 0 {
		return nil, ErrCustodyChallenge
	}
	sort.Slice(ids, func(left, right int) bool {
		return types.CompareHash(ids[left], ids[right]) < 0
	})
	return ids, nil
}

func custodyBatchDigest(batch ChunkBatch) (types.Hash, error) {
	encoded, err := batch.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(custodyBatchDomain, encoded), nil
}

func equalCustodyIDs(left, right []types.Hash) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (challenge CustodyChallenge) unsignedBytes() ([]byte, error) {
	if challenge.verifyShape() != nil {
		return nil, ErrCustodyChallenge
	}
	encoder := codec.NewEncoder(MaximumCustodyChallengeBytes)
	encoder.Fixed(custodyChallengeMagic[:])
	encoder.U16(challenge.Version)
	encoder.Fixed(challenge.StatementID[:])
	encoder.Fixed(challenge.ManifestID[:])
	encoder.Fixed(challenge.ReceiptID[:])
	encoder.U64(challenge.IssuedAt)
	encoder.U64(challenge.ExpiresAt)
	encoder.U64(challenge.RenewUntil)
	encoder.Fixed(challenge.Nonce[:])
	encoder.U16(challenge.RequestedSamples)
	encoder.Uvarint(uint64(len(challenge.IDs)))
	for _, id := range challenge.IDs {
		encoder.Fixed(id[:])
	}
	encoder.Fixed(challenge.AuditorPublicKey[:])
	return encoder.Bytes(), nil
}

func (challenge CustodyChallenge) signatureMessage() ([]byte, error) {
	unsigned, err := challenge.unsignedBytes()
	if err != nil {
		return nil, err
	}
	hash := types.DomainHash(custodyChallengeSignatureDomain, unsigned)
	return hash[:], nil
}

func (challenge CustodyChallenge) verifyShape() error {
	if challenge.Version != CustodyChallengeVersion0 || challenge.StatementID.IsZero() ||
		challenge.ManifestID.IsZero() || challenge.ReceiptID.IsZero() || challenge.IssuedAt == 0 ||
		challenge.ExpiresAt <= challenge.IssuedAt ||
		challenge.ExpiresAt-challenge.IssuedAt > MaximumCustodyChallengeLifetime ||
		challenge.RenewUntil <= challenge.ExpiresAt ||
		challenge.RenewUntil-challenge.IssuedAt > MaximumReplicaTermSeconds ||
		challenge.Nonce.IsZero() || challenge.RequestedSamples < MinimumCustodySamples ||
		challenge.RequestedSamples > MaximumCustodySamples || len(challenge.IDs) == 0 ||
		len(challenge.IDs) > int(challenge.RequestedSamples) ||
		types.Hash(challenge.AuditorPublicKey).IsZero() {
		return ErrCustodyChallenge
	}
	for index, id := range challenge.IDs {
		if id.IsZero() || (index > 0 && types.CompareHash(challenge.IDs[index-1], id) >= 0) {
			return ErrCustodyChallenge
		}
	}
	return nil
}

func (challenge CustodyChallenge) verifySignature() error {
	message, err := challenge.signatureMessage()
	if err != nil || !ed25519.Verify(
		ed25519.PublicKey(challenge.AuditorPublicKey[:]), message, challenge.Signature[:],
	) {
		return ErrCustodyChallenge
	}
	return nil
}

func (proof CustodyProof) unsignedBytes() ([]byte, error) {
	if proof.verifyShape() != nil {
		return nil, ErrCustodyProof
	}
	encoder := codec.NewEncoder(MaximumCustodyProofBytes)
	encoder.Fixed(custodyProofMagic[:])
	encoder.U16(proof.Version)
	encoder.Fixed(proof.ChallengeID[:])
	encoder.Fixed(proof.ReceiptID[:])
	encoder.Fixed(proof.ManifestID[:])
	encoder.U64(proof.RespondedAt)
	encoder.Fixed(proof.BatchDigest[:])
	encoder.Fixed(proof.ReplicaPublicKey[:])
	return encoder.Bytes(), nil
}

func (proof CustodyProof) signatureMessage() ([]byte, error) {
	unsigned, err := proof.unsignedBytes()
	if err != nil {
		return nil, err
	}
	hash := types.DomainHash(custodyProofSignatureDomain, unsigned)
	return hash[:], nil
}

func (proof CustodyProof) verifyShape() error {
	if proof.Version != CustodyProofVersion0 || proof.ChallengeID.IsZero() ||
		proof.ReceiptID.IsZero() || proof.ManifestID.IsZero() || proof.RespondedAt == 0 ||
		proof.BatchDigest.IsZero() || types.Hash(proof.ReplicaPublicKey).IsZero() {
		return ErrCustodyProof
	}
	return nil
}

func (proof CustodyProof) verifySignature() error {
	message, err := proof.signatureMessage()
	if err != nil || !ed25519.Verify(
		ed25519.PublicKey(proof.ReplicaPublicKey[:]), message, proof.Signature[:],
	) {
		return ErrCustodyProof
	}
	return nil
}

func (policy CustodyPolicy) validate() error {
	if len(policy.TrustedAuditors) == 0 || len(policy.TrustedAuditors) > MaximumReplicas ||
		policy.MaximumChallengeLifetime == 0 ||
		policy.MaximumChallengeLifetime > MaximumCustodyChallengeLifetime ||
		policy.MaximumProofAge == 0 || policy.MaximumProofAge > MaximumCustodyProofAge ||
		policy.MaximumRenewalTerm == 0 || policy.MaximumRenewalTerm > MaximumReplicaTermSeconds {
		return ErrCustodyPolicy
	}
	for index, key := range policy.TrustedAuditors {
		if types.Hash(key).IsZero() ||
			(index > 0 && bytes.Compare(policy.TrustedAuditors[index-1][:], key[:]) >= 0) {
			return ErrCustodyPolicy
		}
	}
	return nil
}
