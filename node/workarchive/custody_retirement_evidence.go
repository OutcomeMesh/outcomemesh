package workarchive

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/types"
)

type CustodyLocalParticipants struct {
	AuditorJournal, AuditorArtifacts, ReplicaJournal string
}

func loadCustodyRetirement(root string) (CustodyParticipantRetirement, bool, error) {
	encoded, err := readRegularArchiveFile(filepath.Join(root, custodyRetirementFileName), MaximumCustodyParticipantRetirementBytes)
	if errors.Is(err, os.ErrNotExist) {
		return CustodyParticipantRetirement{}, false, nil
	}
	if err != nil {
		return CustodyParticipantRetirement{}, false, errors.Join(ErrCustodyRetirement, err)
	}
	retirement, err := DecodeCustodyParticipantRetirement(encoded)
	return retirement, err == nil, err
}

func verifyCustodyRetirementJournal(root string, header CustodyJournalHeader, headerBytes []byte, state CustodyJournalState) error {
	retirement, exists, err := loadCustodyRetirement(root)
	if err != nil || !exists {
		return err
	}
	receiptID, err := state.CurrentReceipt.ID()
	if err != nil || header.Version != CustodyJournalHeaderVersion0 ||
		retirement.Before.HeaderID != types.DomainHash(custodyCheckpointHeaderDomain, headerBytes) ||
		retirement.Before.Sequence != state.Sequence || retirement.Before.HeadEntryID != state.HeadEntryID || retirement.Before.ReceiptID != receiptID {
		return ErrCustodyRetirement
	}
	tree, err := walkCustodyEvidenceTreeExceptRetirement(context.Background(), root, "", MaximumCustodyJournalBytes, MaximumCustodyJournalPaths, true)
	if err != nil || tree != retirement.Before.Journal {
		return errors.Join(ErrCustodyRetirement, err)
	}
	return nil
}

func validateCustodyLocalParticipantPaths(local CustodyLocalParticipants, evidence CustodyRebaselineEvidence, archive CustodyRebaselineArchive) error {
	targets := []string{local.AuditorJournal, local.AuditorArtifacts, local.ReplicaJournal}
	for index, path := range targets {
		if path == "" {
			return ErrCustodyRetirement
		}
		for _, previous := range targets[:index] {
			if CustodyEvidencePathsOverlap(path, previous) {
				return ErrCustodyRetirement
			}
		}
		for _, source := range []string{evidence.Recovery, evidence.TransferPackage, evidence.AuditorBackup, evidence.ReplicaBackup, archive.Directory} {
			if CustodyEvidencePathsOverlap(path, source) {
				return ErrCustodyRetirement
			}
		}
	}
	return nil
}

// Existing locks only, artifact first and journal roots in canonical order.
// No journal initializer is called, including on crash retries.
func lockCustodyLocalParticipants(local CustodyLocalParticipants) (func(), error) {
	artifacts, err := acquireCustodyEvidenceLock(local.AuditorArtifacts, custodyArtifactsLockName, false)
	if err != nil {
		return nil, err
	}
	locks := []*os.File{artifacts}
	release := func() {
		for i := len(locks) - 1; i >= 0; i-- {
			_ = locks[i].Close()
		}
	}
	var roots []string
	for _, path := range []string{local.AuditorJournal, local.ReplicaJournal} {
		root, err := resolveCustodyEvidencePath(path)
		if err != nil {
			release()
			return nil, err
		}
		roots = append(roots, root)
	}
	sort.Strings(roots)
	for _, root := range roots {
		lock, err := acquireCustodyEvidenceLock(root, custodyJournalLockName, false)
		if err != nil {
			release()
			return nil, err
		}
		locks = append(locks, lock)
	}
	return release, nil
}

func verifyCustodyRetirementBefore(root, artifacts string, before CustodyCheckpoint, manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy) error {
	current, err := captureCustodyCheckpointLocked(root, artifacts, manifest, initial, policy)
	if err != nil {
		return err
	}
	current.Journal, err = walkCustodyEvidenceTreeExceptRetirement(context.Background(), root, "", MaximumCustodyJournalBytes, MaximumCustodyJournalPaths, true)
	if err != nil || current != before {
		return errors.Join(ErrCustodyCheckpointMismatch, err)
	}
	return nil
}
