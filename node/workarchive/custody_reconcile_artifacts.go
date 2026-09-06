package workarchive

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Only the established canonical filenames are interpreted. Every unknown,
// future-cycle, or temporary entry remains inventoried by the checkpoint and
// requires review; it is never ignored as permission to start a fresh cycle.
func inspectCustodyReconciliationArtifacts(root string, journal custodyReconciliationJournal, report *CustodyReconciliationReport) ([3][]byte, error) {
	var pending [3][]byte
	var paths, committedCycles uint64
	err := visitCustodyReconciliationDirectory(root, &paths, func(name string, directory bool) error {
		if name == custodyArtifactsLockName && !directory {
			return nil
		}
		sequence, ok := custodyReconciliationCycleSequence(name)
		if !ok || !directory || sequence > report.Pending.Sequence {
			report.UnclassifiedArtifacts++
			return nil
		}
		var artifacts [3][]byte
		err := visitCustodyReconciliationDirectory(filepath.Join(root, name), &paths, func(file string, directory bool) error {
			index, limit := -1, 0
			switch file {
			case "challenge.omcc":
				index, limit = 0, MaximumCustodyChallengeBytes
			case "record.omcr":
				index, limit = 1, MaximumCustodyRecordBytes
			case "receipt.omrr":
				index, limit = 2, MaximumReplicaReceiptBytes
			}
			if index == -1 {
				report.UnclassifiedArtifacts++
				return nil
			}
			if directory {
				return ErrCustodyReconciliation
			}
			encoded, err := readRegularArchiveFile(filepath.Join(root, name, file), limit)
			if err != nil {
				return errors.Join(ErrCustodyReconciliation, err)
			}
			artifacts[index] = encoded
			return nil
		})
		if err != nil {
			return err
		}
		if sequence == report.Pending.Sequence {
			pending = artifacts
			return nil
		}
		committedCycles++
		entry, err := journal.entry(sequence)
		if err != nil {
			return err
		}
		challenge, _ := entry.Record.Challenge.CanonicalBytes()
		record, _ := entry.Record.CanonicalBytes()
		receipt, _ := entry.Record.RenewedReceipt.CanonicalBytes()
		for index, expected := range [3][]byte{challenge, record, receipt} {
			if artifacts[index] == nil {
				report.MissingCommittedArtifacts++
			} else if !bytes.Equal(artifacts[index], expected) {
				report.ConflictingArtifacts++
			}
		}
		return nil
	})
	if err != nil {
		return pending, err
	}
	report.MissingCommittedArtifacts += (report.AuditorSequence - committedCycles) * 3
	return pending, nil
}

func inspectCustodyReconciliationPending(artifacts [3][]byte, peer *CustodyRecord, manifest Manifest, previous ReplicaReceipt, policy CustodyPolicy, report *CustodyReconciliationReport) error {
	var challenge *CustodyChallenge
	var local *CustodyRecord
	if artifacts[0] != nil {
		decoded, err := DecodeCustodyChallenge(artifacts[0])
		if err != nil || decoded.Verify(manifest, previous, policy, decoded.IssuedAt) != nil {
			return errors.Join(ErrCustodyReconciliation, err)
		}
		challenge = &decoded
	}
	if artifacts[1] != nil {
		decoded, err := DecodeCustodyRecord(artifacts[1])
		if err != nil || decoded.Verify(manifest, previous, policy) != nil {
			return errors.Join(ErrCustodyReconciliation, err)
		}
		local = &decoded
		if challenge == nil {
			challenge = &decoded.Challenge
		} else {
			encoded, _ := decoded.Challenge.CanonicalBytes()
			if !bytes.Equal(artifacts[0], encoded) {
				report.Pending.State = "conflict"
			}
		}
	}
	if challenge == nil {
		if artifacts[2] != nil {
			report.ConflictingArtifacts++
			report.Pending.State = "conflict"
		}
		return nil
	}
	report.Pending.ChallengeID, _ = challenge.ID()
	report.Pending.ExpiresAt = challenge.ExpiresAt
	report.ClockBeforeEvidence = report.ClockBeforeEvidence || report.AssessedAt < challenge.IssuedAt
	response := local
	if local != nil {
		report.Pending.RecordSource = "auditor-artifact"
	}
	if peer != nil {
		peerID, _ := peer.Challenge.ID()
		if peerID != report.Pending.ChallengeID {
			report.Pending.State = "conflict"
		} else if local == nil {
			response, report.Pending.RecordSource = peer, "replica-slot"
		} else {
			left, _ := local.CanonicalBytes()
			right, _ := peer.CanonicalBytes()
			if !bytes.Equal(left, right) {
				report.Pending.State = "conflict"
			} else {
				report.Pending.RecordSource = "both"
			}
		}
	}
	if artifacts[2] != nil {
		if response == nil {
			report.Pending.State = "conflict"
		} else {
			expected, _ := response.RenewedReceipt.CanonicalBytes()
			if !bytes.Equal(artifacts[2], expected) {
				report.Pending.State = "conflict"
			}
		}
	}
	if response != nil {
		report.Pending.RespondedAt, report.Pending.RetainUntil = response.Proof.RespondedAt, response.RenewedReceipt.RetainUntil
		report.ClockBeforeEvidence = report.ClockBeforeEvidence || report.AssessedAt < response.Proof.RespondedAt
		// Historical verification above deliberately used the signed response
		// time. These separate bounds must never reinterpret stale evidence as
		// a new live response or backdate a fresh availability claim.
		report.Pending.ProofWithinAge = report.AssessedAt >= response.Proof.RespondedAt && report.AssessedAt-response.Proof.RespondedAt <= policy.MaximumProofAge
		report.Pending.ReceiptUnexpired = report.AssessedAt >= response.RenewedReceipt.StoredAt && report.AssessedAt < response.RenewedReceipt.RetainUntil
	}
	if report.Pending.State == "conflict" {
		return nil
	}
	switch {
	case response != nil:
		report.Pending.State = "historical-response"
	case report.AssessedAt < challenge.IssuedAt:
		report.Pending.State = "future-request"
	case report.AssessedAt > challenge.ExpiresAt:
		report.Pending.State = "unanswered-expired"
	default:
		report.Pending.State = "unanswered-open"
	}
	return nil
}

func custodyReconciliationCycleSequence(name string) (uint64, bool) {
	sequence, err := strconv.ParseUint(strings.TrimPrefix(name, "cycle-"), 10, 64)
	return sequence, err == nil && sequence != 0 && fmt.Sprintf("cycle-%020d", sequence) == name
}

func visitCustodyReconciliationDirectory(path string, paths *uint64, visit func(string, bool) error) error {
	if err := requireCustodyJournalDirectory(path); err != nil {
		return err
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	for {
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			(*paths)++
			if *paths > MaximumCustodyJournalPaths || entry.Type()&os.ModeSymlink != 0 {
				return ErrCustodyReconciliation
			}
			if err := visit(entry.Name(), entry.IsDir()); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}
