package workarchive

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	MinimumCustodySessionTimeout = 100 * time.Millisecond
	MaximumCustodySessionTimeout = 10 * time.Minute
)

var ErrCustodySession = errors.New("invalid WorkGraph archive custody session")

type CustodySessionStream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

type CustodySessionConfig struct {
	RequestTimeout time.Duration
	Now            func() uint64
}

func DefaultCustodySessionConfig() CustodySessionConfig {
	return CustodySessionConfig{
		RequestTimeout: 2 * time.Minute,
		Now: func() uint64 {
			current := time.Now().Unix()
			if current <= 0 {
				return 0
			}
			return uint64(current)
		},
	}
}

func (config CustodySessionConfig) Validate() error {
	if config.RequestTimeout < MinimumCustodySessionTimeout ||
		config.RequestTimeout > MaximumCustodySessionTimeout || config.Now == nil {
		return ErrCustodySession
	}
	return nil
}

type CustodyResponse struct {
	Batch          ChunkBatch
	Proof          CustodyProof
	RenewedReceipt ReplicaReceipt
}

type CustodyAuditReport struct {
	ChallengeID      types.Hash
	ProofID          types.Hash
	RenewedReceiptID types.Hash
	Objects          uint16
	ReceivedBytes    uint64
	RespondedAt      uint64
}

type CustodyServeReport struct {
	ChallengeID      types.Hash
	ProofID          types.Hash
	RenewedReceiptID types.Hash
	Objects          uint16
	SentBytes        uint64
	RespondedAt      uint64
}

type CustodySession struct {
	manifest          Manifest
	receipt           ReplicaReceipt
	policy            CustodyPolicy
	store             *ObjectStore
	replicaPrivateKey ed25519.PrivateKey
	config            CustodySessionConfig
	serveMu           sync.Mutex
	cachedResponse    *cachedCustodyResponse
	recordPath        string
}

type cachedCustodyResponse struct {
	challengeID types.Hash
	batch       []byte
	proof       []byte
	renewal     []byte
	report      CustodyServeReport
}

func NewCustodyAuditorSession(
	manifest Manifest,
	receipt ReplicaReceipt,
	policy CustodyPolicy,
	config CustodySessionConfig,
) (*CustodySession, error) {
	if err := validateCustodySessionInputs(manifest, receipt, policy, config); err != nil {
		return nil, err
	}
	return &CustodySession{
		manifest: manifest, receipt: receipt, policy: policy, config: config,
	}, nil
}

func NewCustodyReplicaSession(
	manifest Manifest,
	receipt ReplicaReceipt,
	store *ObjectStore,
	policy CustodyPolicy,
	replicaPrivateKey ed25519.PrivateKey,
	config CustodySessionConfig,
) (*CustodySession, error) {
	if err := validateCustodySessionInputs(manifest, receipt, policy, config); err != nil ||
		store == nil || len(replicaPrivateKey) != ed25519.PrivateKeySize ||
		!ed25519.PublicKey(replicaPrivateKey.Public().(ed25519.PublicKey)).Equal(
			ed25519.PublicKey(receipt.ReplicaPublicKey[:]),
		) {
		return nil, ErrCustodySession
	}
	return &CustodySession{
		manifest: manifest, receipt: receipt, policy: policy, store: store,
		replicaPrivateKey: append(ed25519.PrivateKey(nil), replicaPrivateKey...), config: config,
	}, nil
}

// NewDurableCustodyReplicaSession restores the immutable first renewal for one
// predecessor, or publishes it atomically before the first network response.
func NewDurableCustodyReplicaSession(
	manifest Manifest,
	receipt ReplicaReceipt,
	store *ObjectStore,
	policy CustodyPolicy,
	replicaPrivateKey ed25519.PrivateKey,
	recordPath string,
	config CustodySessionConfig,
) (*CustodySession, error) {
	if recordPath == "" {
		return nil, ErrCustodySession
	}
	session, err := NewCustodyReplicaSession(
		manifest, receipt, store, policy, replicaPrivateKey, config,
	)
	if err != nil {
		return nil, err
	}
	session.recordPath = recordPath
	record, err := LoadCustodyRecordFile(recordPath, manifest, receipt, policy)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return session, nil
		}
		return nil, err
	}
	session.cachedResponse, err = cachedCustodyResponseFromRecord(record)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// Audit runs exactly one challenge exchange on a stream whose replica
// transport identity was already authenticated and pinned by the caller.
func (session *CustodySession) Audit(
	ctx context.Context,
	stream CustodySessionStream,
	challenge CustodyChallenge,
) (CustodyResponse, CustodyAuditReport, error) {
	if session == nil || ctx == nil || stream == nil || session.config.Validate() != nil {
		if stream != nil {
			_ = stream.Close()
		}
		return CustodyResponse{}, CustodyAuditReport{}, ErrCustodySession
	}
	defer stream.Close()
	if err := challenge.Verify(
		session.manifest, session.receipt, session.policy, session.config.Now(),
	); err != nil {
		return CustodyResponse{}, CustodyAuditReport{}, errors.Join(ErrCustodySession, err)
	}
	encodedChallenge, err := challenge.CanonicalBytes()
	if err != nil {
		return CustodyResponse{}, CustodyAuditReport{}, err
	}
	if err := session.writeFrame(ctx, stream, encodedChallenge, MaximumCustodyChallengeBytes); err != nil {
		return CustodyResponse{}, CustodyAuditReport{}, err
	}
	encodedBatch, err := session.readFrame(ctx, stream, MaximumObjectBatchBytes)
	if err != nil {
		return CustodyResponse{}, CustodyAuditReport{}, err
	}
	batch, err := DecodeChunkBatch(encodedBatch)
	if err != nil {
		return CustodyResponse{}, CustodyAuditReport{}, errors.Join(ErrCustodySession, err)
	}
	encodedProof, err := session.readFrame(ctx, stream, MaximumCustodyProofBytes)
	if err != nil {
		return CustodyResponse{}, CustodyAuditReport{}, err
	}
	proof, err := DecodeCustodyProof(encodedProof)
	if err != nil {
		return CustodyResponse{}, CustodyAuditReport{}, errors.Join(ErrCustodySession, err)
	}
	encodedRenewal, err := session.readFrame(ctx, stream, MaximumReplicaReceiptBytes)
	if err != nil {
		return CustodyResponse{}, CustodyAuditReport{}, err
	}
	renewed, err := DecodeReplicaReceipt(encodedRenewal)
	if err != nil {
		return CustodyResponse{}, CustodyAuditReport{}, errors.Join(ErrCustodySession, err)
	}
	now := session.config.Now()
	if err := VerifyReplicaRenewal(
		session.manifest, session.receipt, renewed, challenge, batch, proof,
		session.policy, now,
	); err != nil {
		return CustodyResponse{}, CustodyAuditReport{}, errors.Join(ErrCustodySession, err)
	}
	challengeID, err := challenge.ID()
	if err != nil {
		return CustodyResponse{}, CustodyAuditReport{}, err
	}
	proofID, err := proof.ID()
	if err != nil {
		return CustodyResponse{}, CustodyAuditReport{}, err
	}
	renewedID, err := renewed.ID()
	if err != nil {
		return CustodyResponse{}, CustodyAuditReport{}, err
	}
	report := CustodyAuditReport{
		ChallengeID: challengeID, ProofID: proofID, RenewedReceiptID: renewedID,
		Objects: uint16(len(batch.Objects)), RespondedAt: proof.RespondedAt,
	}
	for _, object := range batch.Objects {
		report.ReceivedBytes += uint64(len(object.Encoded))
	}
	return CustodyResponse{Batch: batch, Proof: proof, RenewedReceipt: renewed}, report, nil
}

// Serve accepts one signed challenge, returns the exact sampled objects and
// proof, then signs the linked receipt renewal and closes the finite stream.
func (session *CustodySession) Serve(
	ctx context.Context,
	stream CustodySessionStream,
) (CustodyServeReport, error) {
	if session == nil || ctx == nil || stream == nil || session.store == nil ||
		len(session.replicaPrivateKey) != ed25519.PrivateKeySize ||
		session.config.Validate() != nil {
		if stream != nil {
			_ = stream.Close()
		}
		return CustodyServeReport{}, ErrCustodySession
	}
	defer stream.Close()
	encodedChallenge, err := session.readFrame(ctx, stream, MaximumCustodyChallengeBytes)
	if err != nil {
		return CustodyServeReport{}, err
	}
	challenge, err := DecodeCustodyChallenge(encodedChallenge)
	if err != nil {
		return CustodyServeReport{}, errors.Join(ErrCustodySession, err)
	}
	respondedAt := session.config.Now()
	if err := challenge.Verify(
		session.manifest, session.receipt, session.policy, respondedAt,
	); err != nil {
		return CustodyServeReport{}, errors.Join(ErrCustodySession, err)
	}
	challengeID, err := challenge.ID()
	if err != nil {
		return CustodyServeReport{}, err
	}
	session.serveMu.Lock()
	defer session.serveMu.Unlock()
	if session.cachedResponse != nil {
		if session.cachedResponse.challengeID != challengeID {
			return CustodyServeReport{}, ErrCustodySession
		}
		if err := session.writeResponse(ctx, stream, session.cachedResponse); err != nil {
			return CustodyServeReport{}, err
		}
		if err := session.awaitAuditorClose(ctx, stream); err != nil {
			return CustodyServeReport{}, err
		}
		return session.cachedResponse.report, nil
	}
	batch, proof, err := AnswerCustodyChallenge(
		session.store, session.manifest, session.receipt, challenge, session.policy,
		session.replicaPrivateKey, respondedAt,
	)
	if err != nil {
		return CustodyServeReport{}, errors.Join(ErrCustodySession, err)
	}
	renewed, err := RenewReplicaReceipt(
		session.manifest, session.receipt, challenge, batch, proof, session.policy,
		session.replicaPrivateKey, respondedAt,
	)
	if err != nil {
		return CustodyServeReport{}, errors.Join(ErrCustodySession, err)
	}
	record := CustodyRecord{
		Version: CustodyRecordVersion0, Challenge: challenge, Batch: batch,
		Proof: proof, RenewedReceipt: renewed,
	}
	if session.recordPath != "" {
		record, _, err = PublishCustodyRecordFile(
			session.recordPath, record, session.manifest, session.receipt, session.policy,
		)
		if err != nil {
			return CustodyServeReport{}, errors.Join(ErrCustodySession, err)
		}
	}
	cached, err := cachedCustodyResponseFromRecord(record)
	if err != nil {
		return CustodyServeReport{}, err
	}
	// Cache before the first write. A transport failure can then retry only this
	// exact signed result instead of creating a sibling renewal.
	session.cachedResponse = cached
	if err := session.writeResponse(ctx, stream, cached); err != nil {
		return CustodyServeReport{}, err
	}
	if err := session.awaitAuditorClose(ctx, stream); err != nil {
		return CustodyServeReport{}, err
	}
	return cached.report, nil
}

func cachedCustodyResponseFromRecord(record CustodyRecord) (*cachedCustodyResponse, error) {
	challengeID, err := record.Challenge.ID()
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
	proofID, err := record.Proof.ID()
	if err != nil {
		return nil, err
	}
	renewedID, err := record.RenewedReceipt.ID()
	if err != nil {
		return nil, err
	}
	report := CustodyServeReport{
		ChallengeID: challengeID, ProofID: proofID, RenewedReceiptID: renewedID,
		Objects: uint16(len(record.Batch.Objects)), RespondedAt: record.Proof.RespondedAt,
	}
	for _, object := range record.Batch.Objects {
		report.SentBytes += uint64(len(object.Encoded))
	}
	return &cachedCustodyResponse{
		challengeID: challengeID, batch: batch, proof: proof, renewal: renewal,
		report: report,
	}, nil
}

func (session *CustodySession) writeResponse(
	ctx context.Context,
	stream CustodySessionStream,
	cached *cachedCustodyResponse,
) error {
	if cached == nil {
		return ErrCustodySession
	}
	for _, frame := range []struct {
		encoded []byte
		maximum int
	}{
		{cached.batch, MaximumObjectBatchBytes},
		{cached.proof, MaximumCustodyProofBytes},
		{cached.renewal, MaximumReplicaReceiptBytes},
	} {
		if err := session.writeFrame(ctx, stream, frame.encoded, frame.maximum); err != nil {
			return err
		}
	}
	return nil
}

// awaitAuditorClose is the transport-level completion acknowledgement. It adds
// no fifth protocol message: after validating all three response frames, Audit
// closes its stream and Serve observes EOF before a one-shot host may exit.
func (session *CustodySession) awaitAuditorClose(
	ctx context.Context,
	stream CustodySessionStream,
) error {
	if err := session.setDeadline(ctx, stream); err != nil {
		return err
	}
	var unexpected [1]byte
	read, err := stream.Read(unexpected[:])
	if read == 0 && errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		err = errors.New("auditor sent data after custody response")
	}
	return errors.Join(ErrCustodySession, err)
}

func validateCustodySessionInputs(
	manifest Manifest,
	receipt ReplicaReceipt,
	policy CustodyPolicy,
	config CustodySessionConfig,
) error {
	if manifest.Validate() != nil || receipt.verifySignature() != nil ||
		policy.validate() != nil || config.Validate() != nil {
		return ErrCustodySession
	}
	manifestID, err := manifest.ID()
	if err != nil || receipt.ManifestID != manifestID || receipt.Binding != manifest.Binding ||
		receipt.AnchorID != manifest.Anchor.ID {
		return ErrCustodySession
	}
	return nil
}

func (session *CustodySession) readFrame(
	ctx context.Context,
	stream CustodySessionStream,
	maximum int,
) ([]byte, error) {
	if err := session.setDeadline(ctx, stream); err != nil {
		return nil, err
	}
	return readCustodySessionFrame(stream, maximum)
}

func readCustodySessionFrame(reader io.Reader, maximum int) ([]byte, error) {
	if reader == nil || maximum <= 0 || maximum > MaximumObjectBatchBytes {
		return nil, ErrCustodySession
	}
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, errors.Join(ErrCustodySession, err)
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size == 0 || uint64(size) > uint64(maximum) {
		return nil, ErrCustodySession
	}
	encoded := make([]byte, int(size))
	if _, err := io.ReadFull(reader, encoded); err != nil {
		return nil, errors.Join(ErrCustodySession, err)
	}
	return encoded, nil
}

func (session *CustodySession) writeFrame(
	ctx context.Context,
	stream CustodySessionStream,
	encoded []byte,
	maximum int,
) error {
	if err := session.setDeadline(ctx, stream); err != nil {
		return err
	}
	if len(encoded) == 0 || len(encoded) > maximum || maximum > MaximumObjectBatchBytes {
		return ErrCustodySession
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(encoded)))
	if err := writeCustodySessionBytes(stream, prefix[:]); err != nil {
		return err
	}
	return writeCustodySessionBytes(stream, encoded)
}

func (session *CustodySession) setDeadline(ctx context.Context, stream CustodySessionStream) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(session.config.RequestTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return stream.SetDeadline(deadline)
}

func writeCustodySessionBytes(writer io.Writer, encoded []byte) error {
	for len(encoded) > 0 {
		written, err := writer.Write(encoded)
		if err != nil {
			return errors.Join(ErrCustodySession, err)
		}
		if written <= 0 || written > len(encoded) {
			return errors.Join(ErrCustodySession, io.ErrShortWrite)
		}
		encoded = encoded[written:]
	}
	return nil
}
