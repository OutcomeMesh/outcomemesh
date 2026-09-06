package workarchive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func buildCustodyHistoricalApplication(ctx context.Context, destination, auditorPath string, transfer CustodyHistoricalTransfer,
	header CustodyJournalHeader, manifest Manifest, policy CustodyPolicy, limits CustodyJournalLimits, hooks custodyApplicationHooks,
) error {
	sourceJournal, sourceArtifacts := custodyBackupEvidencePaths(auditorPath, true)
	journalPath, artifactsPath := custodyBackupEvidencePaths(destination, true)
	// Copy artifacts first, then take the established artifact -> journal lock
	// order. No journal exists yet, so no live v0 header is ever copied.
	tree, err := walkCustodyEvidenceTree(ctx, sourceArtifacts, artifactsPath, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
	if err != nil || tree != transfer.AuditorCheckpoint.Artifacts {
		return errors.Join(ErrCustodyHistoricalApplication, err)
	}
	artifactLock, err := acquireCustodyEvidenceLock(artifactsPath, custodyArtifactsLockName, false)
	if err != nil {
		return err
	}
	defer artifactLock.Close()
	if err := os.Mkdir(journalPath, 0o700); err != nil {
		return err
	}
	if err := syncDirectory(destination); err != nil {
		return err
	}
	journalLock, err := acquireCustodyEvidenceLock(journalPath, custodyJournalLockName, true)
	if err != nil {
		return err
	}
	defer journalLock.Close()
	headerBytes, err := header.CanonicalBytes()
	if err != nil {
		return err
	}
	if err := publishCustodyApplicationBytes(ctx, destination, filepath.Join(journalPath, custodyJournalHeaderName), headerBytes); err != nil {
		return err
	}
	if err := runCustodyApplicationHook(hooks.afterHeader); err != nil {
		return err
	}
	copiedBytes, copiedPaths := uint64(len(headerBytes)), uint64(3) // root, lock, header
	for _, name := range []string{custodyJournalObjectsName, custodyJournalSlotsName, custodyJournalPendingName} {
		tree, err := walkCustodyEvidenceTree(ctx, filepath.Join(sourceJournal, name), filepath.Join(journalPath, name),
			MaximumCustodyJournalBytes-copiedBytes, MaximumCustodyJournalPaths-copiedPaths)
		if err != nil {
			return err
		}
		copiedBytes += tree.Bytes
		copiedPaths += tree.Paths
	}
	// v1 adds exactly one fixed hash to the unchanged v0 header encoding.
	if copiedBytes != transfer.AuditorCheckpoint.Journal.Bytes+types.HashSize || copiedPaths != transfer.AuditorCheckpoint.Journal.Paths {
		return ErrCustodyHistoricalApplication
	}
	journal := &CustodyJournal{path: journalPath, header: header, manifest: manifest, policy: policy, limits: limits}
	state, err := journal.scan()
	if err != nil || state.Sequence != transfer.AuditorCheckpoint.Sequence || state.HeadEntryID != transfer.AuditorCheckpoint.HeadEntryID || state.CurrentReceipt != transfer.Entry.PreviousReceipt {
		return errors.Join(ErrCustodyHistoricalApplication, err)
	}
	if err := runCustodyApplicationHook(hooks.afterCopy); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// This is not a generic writable historical handle. Only this private
	// constructor, under both destination locks, installs the exact reviewed
	// next entry. Public Append and Rotate reject this header unconditionally.
	entry := transfer.Entry
	transferID, _ := transfer.ID()
	if header.Version != CustodyJournalHeaderHistoricalVersion1 || header.HistoricalTransferID != transferID ||
		entry.Verify(manifest, policy, state.Sequence+1, state.HeadEntryID, state.CurrentReceipt) != nil {
		return ErrCustodyHistoricalApplication
	}
	body, _ := entry.CanonicalBytes()
	entryID, _ := entry.ID()
	slot := custodyJournalSlot{Version: custodyJournalSlotVersion0, Sequence: entry.Sequence, EntryID: entryID}
	if err := journal.admitAppend(false, uint64(len(body)), slot); err != nil {
		return err
	}
	if err := journal.publishBody(entryID, body); err != nil {
		return err
	}
	if err := runCustodyApplicationHook(hooks.afterBody); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	created, err := journal.publishSlot(slot)
	if err != nil || !created {
		return errors.Join(ErrCustodyHistoricalApplication, err)
	}
	if err := runCustodyApplicationHook(hooks.afterSlot); err != nil {
		return err
	}
	_, artifactDelta := custodyApplicationDelta(transfer, header)
	for _, name := range []string{"challenge.omcc", "record.omcr", "receipt.omrr"} {
		relative := filepath.Join(fmt.Sprintf("cycle-%020d", entry.Sequence), name)
		if err := publishCustodyApplicationBytes(ctx, filepath.Dir(filepath.Join(artifactsPath, relative)), filepath.Join(artifactsPath, relative), artifactDelta[relative]); err != nil {
			return err
		}
	}
	if err := runCustodyApplicationHook(hooks.afterArtifacts); err != nil {
		return err
	}
	return ctx.Err()
}

func custodyApplicationDelta(transfer CustodyHistoricalTransfer, header CustodyJournalHeader) (map[string][]byte, map[string][]byte) {
	headerBytes, _ := header.CanonicalBytes()
	entry := transfer.Entry
	body, _ := entry.CanonicalBytes()
	entryID, _ := entry.ID()
	slot, _ := (custodyJournalSlot{Version: custodyJournalSlotVersion0, Sequence: entry.Sequence, EntryID: entryID}).canonicalBytes()
	journal := &CustodyJournal{}
	journalDelta := map[string][]byte{
		custodyJournalHeaderName: headerBytes,
		filepath.Join(custodyJournalObjectsName, custodyJournalActiveName, custodyJournalBodyName(entryID)): body,
		filepath.Join(journal.slotBucketPath(entry.Sequence), custodyJournalSlotName(entry.Sequence)):       slot,
	}
	challenge, _ := entry.Record.Challenge.CanonicalBytes()
	record, _ := entry.Record.CanonicalBytes()
	receipt, _ := entry.Record.RenewedReceipt.CanonicalBytes()
	cycle := fmt.Sprintf("cycle-%020d", entry.Sequence)
	return journalDelta, map[string][]byte{
		filepath.Join(cycle, "challenge.omcc"): challenge,
		filepath.Join(cycle, "record.omcr"):    record,
		filepath.Join(cycle, "receipt.omrr"):   receipt,
	}
}

func verifyCustodyApplicationEvidence(destination string, application CustodyHistoricalApplication, transfer CustodyHistoricalTransfer,
	header CustodyJournalHeader, auditorPath string, manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) error {
	transferID, _ := transfer.ID()
	headerBytes, _ := header.CanonicalBytes()
	if application.validate() != nil || application.TransferID != transferID ||
		header.HistoricalTransferID != transferID || header.Version != CustodyJournalHeaderHistoricalVersion1 ||
		application.Result.HeaderID != types.DomainHash(custodyCheckpointHeaderDomain, headerBytes) ||
		application.Result.Sequence != transfer.ReplicaCheckpoint.Sequence ||
		application.Result.HeadEntryID != transfer.ReplicaCheckpoint.HeadEntryID || application.Result.ReceiptID != transfer.ReplicaCheckpoint.ReceiptID {
		return ErrCustodyHistoricalApplication
	}
	encodedTransfer, _ := transfer.CanonicalBytes()
	storedTransfer, err := readRegularArchiveFile(filepath.Join(destination, custodyTransferFileName), MaximumCustodyHistoricalTransferBytes)
	if err != nil || !bytes.Equal(storedTransfer, encodedTransfer) {
		return errors.Join(ErrCustodyHistoricalApplication, err)
	}
	journalPath, artifactsPath := custodyBackupEvidencePaths(destination, true)
	release, err := lockCustodyEvidencePair(journalPath, artifactsPath, false)
	if err != nil {
		return err
	}
	defer release()
	actual, err := captureCustodyCheckpointLocked(journalPath, artifactsPath, manifest, initial, policy)
	if err != nil || actual != application.Result {
		return errors.Join(ErrCustodyHistoricalApplication, err)
	}
	// Exact overlays, not only a shared head or an inclusion check: no extra
	// directories, duplicate body locations, or silently replaced old files.
	// This also makes a lost-result retry deterministic without trusting a
	// self-reported result checkpoint in the destination.
	journalDelta, artifactDelta := custodyApplicationDelta(transfer, header)
	sourceJournal, sourceArtifacts := custodyBackupEvidencePaths(auditorPath, true)
	if err := verifyCustodyApplicationDelta(sourceJournal, journalPath, journalDelta); err != nil {
		return err
	}
	return verifyCustodyApplicationDelta(sourceArtifacts, artifactsPath, artifactDelta)
}
