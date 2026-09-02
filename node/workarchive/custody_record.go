package workarchive

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
)

const (
	CustodyRecordVersion0     uint16 = 0
	MaximumCustodyRecordBytes        = MaximumCustodyChallengeBytes +
		MaximumObjectBatchBytes + MaximumCustodyProofBytes + MaximumReplicaReceiptBytes + 128
)

var ErrCustodyRecord = errors.New("invalid WorkGraph archive custody record")

var custodyRecordMagic = [8]byte{'O', 'M', 'W', 'A', 'C', 'R', 'E', 'C'}

// CustodyRecord is the durable, self-contained response committed before a
// replica writes any custody bytes to the network. The first valid record for
// one predecessor is immutable; its challenge may be retried idempotently.
type CustodyRecord struct {
	Version        uint16
	Challenge      CustodyChallenge
	Batch          ChunkBatch
	Proof          CustodyProof
	RenewedReceipt ReplicaReceipt
}

func (record CustodyRecord) CanonicalBytes() ([]byte, error) {
	if record.verifyShape() != nil {
		return nil, ErrCustodyRecord
	}
	challenge, err := record.Challenge.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	batch, err := record.Batch.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	proof, err := record.Proof.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	renewal, err := record.RenewedReceipt.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(len(challenge) + len(batch) + len(proof) + len(renewal) + 64)
	encoder.Fixed(custodyRecordMagic[:])
	encoder.U16(record.Version)
	encoder.BytesField(challenge)
	encoder.BytesField(batch)
	encoder.BytesField(proof)
	encoder.BytesField(renewal)
	encoded := encoder.Bytes()
	if len(encoded) > MaximumCustodyRecordBytes {
		return nil, ErrCustodyRecord
	}
	return encoded, nil
}

func DecodeCustodyRecord(input []byte) (CustodyRecord, error) {
	if len(input) == 0 || len(input) > MaximumCustodyRecordBytes {
		return CustodyRecord{}, ErrCustodyRecord
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(custodyRecordMagic))
	if err != nil || !bytes.Equal(magic, custodyRecordMagic[:]) {
		return CustodyRecord{}, ErrCustodyRecord
	}
	var record CustodyRecord
	if record.Version, err = decoder.U16(); err != nil {
		return CustodyRecord{}, errors.Join(ErrCustodyRecord, err)
	}
	challenge, err := decoder.BytesField(MaximumCustodyChallengeBytes)
	if err != nil {
		return CustodyRecord{}, errors.Join(ErrCustodyRecord, err)
	}
	record.Challenge, err = DecodeCustodyChallenge(challenge)
	if err != nil {
		return CustodyRecord{}, errors.Join(ErrCustodyRecord, err)
	}
	batch, err := decoder.BytesField(MaximumObjectBatchBytes)
	if err != nil {
		return CustodyRecord{}, errors.Join(ErrCustodyRecord, err)
	}
	record.Batch, err = DecodeChunkBatch(batch)
	if err != nil {
		return CustodyRecord{}, errors.Join(ErrCustodyRecord, err)
	}
	proof, err := decoder.BytesField(MaximumCustodyProofBytes)
	if err != nil {
		return CustodyRecord{}, errors.Join(ErrCustodyRecord, err)
	}
	record.Proof, err = DecodeCustodyProof(proof)
	if err != nil {
		return CustodyRecord{}, errors.Join(ErrCustodyRecord, err)
	}
	renewal, err := decoder.BytesField(MaximumReplicaReceiptBytes)
	if err != nil {
		return CustodyRecord{}, errors.Join(ErrCustodyRecord, err)
	}
	record.RenewedReceipt, err = DecodeReplicaReceipt(renewal)
	if err != nil {
		return CustodyRecord{}, errors.Join(ErrCustodyRecord, err)
	}
	if err := decoder.Finish(); err != nil || record.verifyShape() != nil {
		return CustodyRecord{}, ErrCustodyRecord
	}
	return record, nil
}

func (record CustodyRecord) Verify(
	manifest Manifest,
	previous ReplicaReceipt,
	policy CustodyPolicy,
) error {
	if record.verifyShape() != nil || VerifyReplicaRenewal(
		manifest, previous, record.RenewedReceipt, record.Challenge,
		record.Batch, record.Proof, policy, record.Proof.RespondedAt,
	) != nil {
		return ErrCustodyRecord
	}
	return nil
}

func (record CustodyRecord) verifyShape() error {
	if record.Version != CustodyRecordVersion0 ||
		record.Challenge.verifySignature() != nil || record.Batch.Validate() != nil ||
		record.Proof.verifySignature() != nil || record.RenewedReceipt.verifySignature() != nil {
		return ErrCustodyRecord
	}
	return nil
}

// PublishCustodyRecordFile installs the first valid record without replacing an
// existing predecessor decision. A concurrent identical challenge returns the
// already durable winner; a different challenge fails closed.
func PublishCustodyRecordFile(
	path string,
	proposed CustodyRecord,
	manifest Manifest,
	previous ReplicaReceipt,
	policy CustodyPolicy,
) (CustodyRecord, bool, error) {
	return publishCustodyRecordFile(
		path, proposed, manifest, previous, policy, custodyRecordHooks{},
	)
}

type custodyRecordHooks struct {
	beforePublish func()
	afterPublish  func()
}

func publishCustodyRecordFile(
	path string,
	proposed CustodyRecord,
	manifest Manifest,
	previous ReplicaReceipt,
	policy CustodyPolicy,
	hooks custodyRecordHooks,
) (CustodyRecord, bool, error) {
	if path == "" || proposed.Verify(manifest, previous, policy) != nil {
		return CustodyRecord{}, false, ErrCustodyRecord
	}
	if current, err := LoadCustodyRecordFile(path, manifest, previous, policy); err == nil {
		return resolveCustodyRecord(current, proposed)
	} else if !errors.Is(err, os.ErrNotExist) {
		return CustodyRecord{}, false, err
	}
	encoded, err := proposed.CanonicalBytes()
	if err != nil {
		return CustodyRecord{}, false, err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return CustodyRecord{}, false, err
	}
	temporary, err := os.CreateTemp(directory, ".outcomemesh-work-custody-record-*")
	if err != nil {
		return CustodyRecord{}, false, err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return CustodyRecord{}, false, err
	}
	written, err := temporary.Write(encoded)
	if err != nil {
		return CustodyRecord{}, false, err
	}
	if written != len(encoded) {
		return CustodyRecord{}, false, io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return CustodyRecord{}, false, err
	}
	if err := temporary.Close(); err != nil {
		return CustodyRecord{}, false, err
	}
	if hooks.beforePublish != nil {
		hooks.beforePublish()
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return CustodyRecord{}, false, err
		}
		current, loadErr := LoadCustodyRecordFile(path, manifest, previous, policy)
		if loadErr != nil {
			return CustodyRecord{}, false, loadErr
		}
		return resolveCustodyRecord(current, proposed)
	}
	if err := syncDirectory(directory); err != nil {
		return CustodyRecord{}, false, err
	}
	if hooks.afterPublish != nil {
		hooks.afterPublish()
	}
	return proposed, true, nil
}

func LoadCustodyRecordFile(
	path string,
	manifest Manifest,
	previous ReplicaReceipt,
	policy CustodyPolicy,
) (CustodyRecord, error) {
	if path == "" {
		return CustodyRecord{}, ErrCustodyRecord
	}
	encoded, err := readRegularArchiveFile(path, MaximumCustodyRecordBytes)
	if err != nil {
		return CustodyRecord{}, errors.Join(ErrCustodyRecord, err)
	}
	record, err := DecodeCustodyRecord(encoded)
	if err != nil || record.Verify(manifest, previous, policy) != nil {
		return CustodyRecord{}, errors.Join(ErrCustodyRecord, err)
	}
	return record, nil
}

func resolveCustodyRecord(
	current CustodyRecord,
	proposed CustodyRecord,
) (CustodyRecord, bool, error) {
	currentChallengeID, err := current.Challenge.ID()
	if err != nil {
		return CustodyRecord{}, false, err
	}
	proposedChallengeID, err := proposed.Challenge.ID()
	if err != nil {
		return CustodyRecord{}, false, err
	}
	if currentChallengeID != proposedChallengeID {
		return CustodyRecord{}, false, ErrCustodyRecord
	}
	return current, false, nil
}
