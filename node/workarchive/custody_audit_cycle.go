package workarchive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var ErrCustodyAuditCycle = errors.New("invalid custody audit cycle or predecessor")

// CustodyAuditCycle is a trusted local effect primitive, not an admission proof.
// Managed callers hold their original authority guard around EVERY method.
// The artifact root/lock and journal must already exist. Construction never
// signs, publishes, initializes, repairs, or recovers missing artifacts.
type CustodyAuditCycle struct {
	journal   *CustodyJournal
	artifacts string
	intent    CustodyAuditIntent
	manifest  Manifest
	policy    CustodyPolicy
	key       ed25519.PrivateKey
	config    CustodySessionConfig
}

type CustodyAuditResult struct {
	Challenge       CustodyChallenge
	Record          CustodyRecord
	Report          CustodyAuditReport
	JournalSequence uint64
	Recovered       bool
}

func NewCustodyAuditCycle(ctx context.Context, journal *CustodyJournal, artifacts string,
	intent CustodyAuditIntent, auditorKey ed25519.PrivateKey, config CustodySessionConfig,
) (cycle *CustodyAuditCycle, returnErr error) {
	if ctx == nil || journal == nil || artifacts == "" || intent.Validate() != nil || config.Validate() != nil ||
		journal.header.Version != CustodyJournalHeaderVersion0 || len(auditorKey) != ed25519.PrivateKeySize {
		return nil, ErrCustodyAuditCycle
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := ed25519.NewKeyFromSeed(auditorKey[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(key, auditorKey) != 1 || !key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(intent.AuditorPublicKey[:])) {
		return nil, ErrCustodyAuditCycle
	}
	trusted := false
	for _, auditor := range journal.policy.TrustedAuditors {
		if auditor == intent.AuditorPublicKey {
			trusted = true
		}
	}
	if !trusted || intent.ExpiresAt-intent.IssuedAt > journal.policy.MaximumChallengeLifetime ||
		intent.RenewUntil-intent.IssuedAt > journal.policy.MaximumRenewalTerm || CustodyEvidencePathsOverlap(journal.path, artifacts) {
		return nil, ErrCustodyAuditCycle
	}
	if err := requireCustodyJournalDirectory(artifacts); err != nil {
		return nil, err
	}
	artifacts, err := filepath.EvalSymlinks(artifacts)
	if err != nil {
		return nil, err
	}
	artifacts, err = filepath.Abs(artifacts)
	if err != nil {
		return nil, err
	}
	lock, err := acquireCustodyEvidenceLockContext(ctx, artifacts, custodyArtifactsLockName, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := lock.Close(); err != nil {
			cycle = nil
			returnErr = errors.Join(returnErr, err)
		}
	}()
	manifestBytes, err := journal.manifest.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	manifest, err := DecodeManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	policy := journal.policy
	policy.TrustedAuditors = append([][32]byte(nil), policy.TrustedAuditors...)
	return &CustodyAuditCycle{journal: journal, artifacts: artifacts, intent: intent, manifest: manifest, policy: policy, key: key, config: config}, nil
}

func (cycle *CustodyAuditCycle) Intent() CustodyAuditIntent {
	if cycle == nil {
		return CustodyAuditIntent{}
	}
	return cycle.intent
}

// ArtifactsDirectory is the immutable resolved root actually opened by this
// cycle. Placement information is not a live permission or physical fence.
func (cycle *CustodyAuditCycle) ArtifactsDirectory() string {
	if cycle == nil {
		return ""
	}
	return cycle.artifacts
}

// PrepareChallenge deterministically publishes the exact selected challenge
// under an artifact->journal decision. Already retained challenges never obtain
// a fresh nonce/time. A committed exact result may restore its missing challenge.
func (cycle *CustodyAuditCycle) PrepareChallenge(ctx context.Context) (challenge CustodyChallenge, returnErr error) {
	return cycle.prepareChallengeChecked(ctx, nil)
}

// PrepareChallengeChecked is a trusted local primitive. The managed caller
// retains its original authority while check validates the SAME source decision
// before signing and after publication, under artifact->journal locks. check
// must not escape the decision or reacquire either lock. This grants no authority.
func (cycle *CustodyAuditCycle) PrepareChallengeChecked(ctx context.Context, check func(*CustodyJournalDecision) error) (CustodyChallenge, error) {
	if check == nil {
		return CustodyChallenge{}, ErrCustodyAuditCycle
	}
	return cycle.prepareChallengeChecked(ctx, check)
}

func (cycle *CustodyAuditCycle) prepareChallengeChecked(ctx context.Context, check func(*CustodyJournalDecision) error) (challenge CustodyChallenge, returnErr error) {
	err := cycle.withDecision(ctx, func(decision *CustodyJournalDecision) error {
		if check != nil {
			if err := check(decision); err != nil {
				return err
			}
		}
		var err error
		challenge, _, _, err = cycle.prepareLocked(ctx, decision)
		if err == nil && check != nil {
			err = check(decision)
		}
		return err
	})
	if err != nil {
		return CustodyChallenge{}, err
	}
	return challenge, nil
}

// Recover only promotes the exact prior+1 entry selected by this intent. It does
// not search a newer head, refresh evidence time, or accept a pending record as
// proof of a journal commit. Its caller must still hold current authority.
func (cycle *CustodyAuditCycle) Recover(ctx context.Context) (result CustodyAuditResult, returnErr error) {
	err := cycle.withDecision(ctx, func(decision *CustodyJournalDecision) error {
		state, err := decision.State()
		if err != nil || state.Sequence != cycle.intent.PriorSequence+1 {
			return errors.Join(ErrCustodyAuditCycle, err)
		}
		challenge, previous, head, err := cycle.prepareLocked(ctx, decision)
		if err != nil {
			return err
		}
		if head == nil {
			return ErrCustodyAuditCycle
		}
		result, err = cycle.publishResult(ctx, challenge, previous, *head, true)
		return err
	})
	if err != nil {
		return CustodyAuditResult{}, err
	}
	return result, nil
}

// Audit exchanges exactly this intent's challenge, even on retry. A retained
// local result requires the same exact returned record. A response is verified and its
// stream closed before journal acceptance; the journal commits the complete
// response before record/receipt outputs, making interrupted output repair exact.
func (cycle *CustodyAuditCycle) Audit(ctx context.Context, stream CustodySessionStream) (result CustodyAuditResult, returnErr error) {
	if stream == nil {
		return CustodyAuditResult{}, ErrCustodyAuditCycle
	}
	owned := &custodyAuditCycleStream{CustodySessionStream: stream}
	var sessionStream CustodySessionStream = owned
	if half, ok := stream.(interface{ CloseWrite() error }); ok {
		sessionStream = &custodyAuditCycleDuplexStream{custodyAuditCycleStream: owned, half: half}
	}
	defer func() { returnErr = errors.Join(returnErr, owned.Close()) }()
	err := cycle.withDecision(ctx, func(decision *CustodyJournalDecision) error {
		challenge, previous, head, err := cycle.prepareLocked(ctx, decision)
		if err != nil {
			return err
		}
		auditor, err := NewCustodyAuditorSession(cycle.manifest, previous, cycle.policy, cycle.config)
		if err != nil {
			return err
		}
		response, _, auditErr := auditor.Audit(ctx, sessionStream, challenge)
		if err := errors.Join(auditErr, owned.Close(), ctx.Err()); err != nil {
			return err
		}
		record := CustodyRecord{Version: CustodyRecordVersion0, Challenge: challenge, Batch: response.Batch, Proof: response.Proof, RenewedReceipt: response.RenewedReceipt}
		if err := VerifyReplicaRenewal(cycle.manifest, previous, record.RenewedReceipt, challenge, record.Batch, record.Proof, cycle.policy, cycle.config.Now()); err != nil {
			return err
		}
		if head != nil {
			retained, err := head.Record.CanonicalBytes()
			if err != nil {
				return err
			}
			received, err := record.CanonicalBytes()
			if err != nil || !bytes.Equal(retained, received) {
				return errors.Join(ErrCustodyAuditCycle, err)
			}
			result, err = cycle.publishResult(ctx, challenge, previous, *head, true)
			return err
		}
		entry, _, err := decision.Append(record)
		if err != nil {
			return err
		}
		result, err = cycle.publishResult(ctx, challenge, previous, entry, false)
		return err
	})
	if err != nil {
		return CustodyAuditResult{}, err
	}
	return result, nil
}

func (cycle *CustodyAuditCycle) withDecision(ctx context.Context, action func(*CustodyJournalDecision) error) (returnErr error) {
	if cycle == nil || ctx == nil || action == nil {
		return ErrCustodyAuditCycle
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	lock, err := acquireCustodyEvidenceLockContext(ctx, cycle.artifacts, custodyArtifactsLockName, false)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	decision, err := cycle.journal.AcquireDecision()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, decision.Close()) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	return action(decision)
}

func (cycle *CustodyAuditCycle) prepareLocked(ctx context.Context, decision *CustodyJournalDecision) (CustodyChallenge, ReplicaReceipt, *CustodyJournalEntry, error) {
	state, err := decision.State()
	if err != nil {
		return CustodyChallenge{}, ReplicaReceipt{}, nil, err
	}
	intent := cycle.intent
	previous := state.CurrentReceipt
	var completed *CustodyJournalEntry
	if state.Sequence == intent.PriorSequence && state.HeadEntryID == intent.PriorHeadID {
		id, err := previous.ID()
		if err != nil || id != intent.PriorReceiptID {
			return CustodyChallenge{}, ReplicaReceipt{}, nil, ErrCustodyAuditCycle
		}
	} else if state.Sequence == intent.PriorSequence+1 {
		head, exists, err := decision.Head()
		if err != nil || !exists || head.Sequence != state.Sequence || head.PreviousEntryID != intent.PriorHeadID {
			return CustodyChallenge{}, ReplicaReceipt{}, nil, errors.Join(ErrCustodyAuditCycle, err)
		}
		previous = head.PreviousReceipt
		id, err := previous.ID()
		if err != nil || id != intent.PriorReceiptID || !cycle.matchesChallenge(head.Record.Challenge) {
			return CustodyChallenge{}, ReplicaReceipt{}, nil, ErrCustodyAuditCycle
		}
		if err := VerifyReplicaRenewal(cycle.manifest, previous, head.Record.RenewedReceipt, head.Record.Challenge, head.Record.Batch, head.Record.Proof, cycle.policy, cycle.config.Now()); err != nil {
			return CustodyChallenge{}, ReplicaReceipt{}, nil, err
		}
		completed = &head
	} else {
		return CustodyChallenge{}, ReplicaReceipt{}, nil, ErrCustodyAuditCycle
	}
	challengePath, recordPath, receiptPath := cycle.paths()
	var challenge CustodyChallenge
	if encoded, err := readRegularArchiveFile(challengePath, MaximumCustodyChallengeBytes); err == nil {
		challenge, err = DecodeCustodyChallenge(encoded)
		if err != nil || !cycle.matchesChallenge(challenge) || challenge.Verify(cycle.manifest, previous, cycle.policy, intent.ExpiresAt) != nil {
			return CustodyChallenge{}, ReplicaReceipt{}, nil, errors.Join(ErrCustodyAuditCycle, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return CustodyChallenge{}, ReplicaReceipt{}, nil, err
	} else if completed != nil {
		challenge = completed.Record.Challenge
	} else {
		now := cycle.config.Now()
		if now < intent.IssuedAt || now > intent.ExpiresAt {
			return CustodyChallenge{}, ReplicaReceipt{}, nil, ErrCustodyAuditCycle
		}
		challenge, err = createCustodyChallenge(cycle.manifest, previous, cycle.key, intent.IssuedAt, intent.ExpiresAt-intent.IssuedAt, intent.RequestedSamples, intent.RenewUntil, bytes.NewReader(intent.Nonce[:]))
		if err != nil || challenge.Verify(cycle.manifest, previous, cycle.policy, now) != nil {
			return CustodyChallenge{}, ReplicaReceipt{}, nil, errors.Join(ErrCustodyAuditCycle, err)
		}
	}
	if completed == nil {
		for _, path := range []string{recordPath, receiptPath} {
			if _, err := os.Lstat(path); err == nil {
				return CustodyChallenge{}, ReplicaReceipt{}, nil, ErrCustodyAuditCycle
			} else if !errors.Is(err, os.ErrNotExist) {
				return CustodyChallenge{}, ReplicaReceipt{}, nil, err
			}
		}
		now := cycle.config.Now()
		if now < intent.IssuedAt || (now > intent.ExpiresAt && now-intent.ExpiresAt > cycle.policy.MaximumProofAge) {
			return CustodyChallenge{}, ReplicaReceipt{}, nil, ErrCustodyAuditCycle
		}
	} else {
		id, _ := challenge.ID()
		retainedID, _ := completed.Record.Challenge.ID()
		if id != retainedID {
			return CustodyChallenge{}, ReplicaReceipt{}, nil, ErrCustodyAuditCycle
		}
	}
	if err := cycle.ensureCycleDirectory(ctx); err != nil {
		return CustodyChallenge{}, ReplicaReceipt{}, nil, err
	}
	encoded, err := challenge.CanonicalBytes()
	if err != nil {
		return CustodyChallenge{}, ReplicaReceipt{}, nil, err
	}
	if err := publishCustodyAuditBytes(ctx, challengePath, encoded); err != nil {
		return CustodyChallenge{}, ReplicaReceipt{}, nil, err
	}
	return challenge, previous, completed, nil
}

func (cycle *CustodyAuditCycle) matchesChallenge(challenge CustodyChallenge) bool {
	i := cycle.intent
	return challenge.ReceiptID == i.PriorReceiptID && challenge.AuditorPublicKey == i.AuditorPublicKey &&
		challenge.IssuedAt == i.IssuedAt && challenge.ExpiresAt == i.ExpiresAt && challenge.RenewUntil == i.RenewUntil &&
		challenge.RequestedSamples == i.RequestedSamples && challenge.Nonce == i.Nonce
}

func (cycle *CustodyAuditCycle) paths() (string, string, string) {
	dir := filepath.Join(cycle.artifacts, fmt.Sprintf("cycle-%020d", cycle.intent.PriorSequence+1))
	return filepath.Join(dir, "challenge.omcc"), filepath.Join(dir, "record.omcr"), filepath.Join(dir, "receipt.omrr")
}

func (cycle *CustodyAuditCycle) ensureCycleDirectory(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	challenge, _, _ := cycle.paths()
	dir := filepath.Dir(challenge)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := requireCustodyJournalDirectory(dir); err != nil {
		return err
	}
	return syncDirectory(cycle.artifacts)
}

func (cycle *CustodyAuditCycle) publishResult(ctx context.Context, challenge CustodyChallenge, previous ReplicaReceipt, head CustodyJournalEntry, recovered bool) (CustodyAuditResult, error) {
	if err := VerifyReplicaRenewal(cycle.manifest, previous, head.Record.RenewedReceipt, challenge, head.Record.Batch, head.Record.Proof, cycle.policy, cycle.config.Now()); err != nil {
		return CustodyAuditResult{}, err
	}
	challengeID, _ := challenge.ID()
	headChallengeID, _ := head.Record.Challenge.ID()
	previousID, _ := previous.ID()
	if head.Sequence != cycle.intent.PriorSequence+1 || head.PreviousEntryID != cycle.intent.PriorHeadID || previousID != cycle.intent.PriorReceiptID || headChallengeID != challengeID {
		return CustodyAuditResult{}, ErrCustodyAuditCycle
	}
	_, recordPath, receiptPath := cycle.paths()
	for _, output := range []struct {
		path string
		body interface{ CanonicalBytes() ([]byte, error) }
	}{{recordPath, head.Record}, {receiptPath, head.Record.RenewedReceipt}} {
		encoded, err := output.body.CanonicalBytes()
		if err != nil {
			return CustodyAuditResult{}, err
		}
		if err := publishCustodyAuditBytes(ctx, output.path, encoded); err != nil {
			return CustodyAuditResult{}, err
		}
	}
	proofID, _ := head.Record.Proof.ID()
	renewalID, _ := head.Record.RenewedReceipt.ID()
	report := CustodyAuditReport{ChallengeID: challengeID, ProofID: proofID, RenewedReceiptID: renewalID, Objects: uint16(len(head.Record.Batch.Objects)), RespondedAt: head.Record.Proof.RespondedAt}
	for _, object := range head.Record.Batch.Objects {
		report.ReceivedBytes += uint64(len(object.Encoded))
	}
	return CustodyAuditResult{Challenge: challenge, Record: head.Record, Report: report, JournalSequence: head.Sequence, Recovered: recovered}, nil
}

type custodyAuditCycleStream struct {
	CustodySessionStream
	once sync.Once
	err  error
}

func (stream *custodyAuditCycleStream) Close() error {
	stream.once.Do(func() { stream.err = stream.CustodySessionStream.Close() })
	return stream.err
}

type custodyAuditCycleDuplexStream struct {
	*custodyAuditCycleStream
	half interface{ CloseWrite() error }
}

func (stream *custodyAuditCycleDuplexStream) CloseWrite() error { return stream.half.CloseWrite() }
