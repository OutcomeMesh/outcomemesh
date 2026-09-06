package workarchive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	custodyApplicationLockName = "recovery.lock"
	custodyApplicationFileName = "application.omcap"
)

type custodyApplicationHooks struct {
	afterHeader, afterCopy, afterBody, afterSlot, afterArtifacts, beforeCommit, afterCommit func() error
}

// CreateCustodyHistoricalApplication applies one reviewed handoff only to a
// new, historical-only auditor reconstruction. It never opens a source writer,
// changes a pin, or authorizes cutover. Every journal byte is written behind a
// v1 quarantine header; live open/append/rotate/session APIs reject that header.
// Incomplete destinations are preserved, not resumed. Exact completed retries
// reverify the sources, handoff, copied prefix, and complete result inventory.
func CreateCustodyHistoricalApplication(ctx context.Context, destination, transferPackage string, transferID types.Hash,
	auditorPath, replicaPath string, auditorID, replicaID types.Hash,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy, limits CustodyJournalLimits,
) (CustodyHistoricalApplication, bool, error) {
	return createCustodyHistoricalApplication(ctx, destination, transferPackage, transferID, auditorPath, replicaPath, auditorID, replicaID, manifest, initial, policy, limits, custodyApplicationHooks{})
}

func createCustodyHistoricalApplication(ctx context.Context, destination, transferPackage string, transferID types.Hash,
	auditorPath, replicaPath string, auditorID, replicaID types.Hash,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy, limits CustodyJournalLimits, hooks custodyApplicationHooks,
) (CustodyHistoricalApplication, bool, error) {
	if ctx == nil || limits.Validate() != nil {
		return CustodyHistoricalApplication{}, false, ErrCustodyHistoricalApplication
	}
	if err := ctx.Err(); err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	transfer, header, release, err := lockCustodyApplicationInputs(destination, transferPackage, transferID, auditorPath, replicaPath, auditorID, replicaID, manifest, initial, policy)
	if err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	if _, err := os.Lstat(destination); err == nil {
		result, err := verifyCustodyApplicationLockedInputs(destination, types.Hash{}, transfer, header, auditorPath, manifest, initial, policy)
		return result, false, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return CustodyHistoricalApplication{}, false, err
	}
	if err := makeCustodyJournalRoot(filepath.Dir(destination)); err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	lock, err := acquireCustodyEvidenceLock(destination, custodyApplicationLockName, true)
	if err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	defer lock.Close()
	encodedTransfer, _ := transfer.CanonicalBytes()
	if err := publishCustodyApplicationBytes(ctx, destination, filepath.Join(destination, custodyTransferFileName), encodedTransfer); err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	if err := buildCustodyHistoricalApplication(ctx, destination, auditorPath, transfer, header, manifest, policy, limits, hooks); err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	journalPath, artifactsPath := custodyBackupEvidencePaths(destination, true)
	checkpoint, err := captureCustodyCheckpoint(journalPath, artifactsPath, manifest, initial, policy, false)
	if err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	application := CustodyHistoricalApplication{Version: CustodyHistoricalApplicationVersion0, TransferID: transferID, Result: checkpoint}
	if err := verifyCustodyApplicationEvidence(destination, application, transfer, header, auditorPath, manifest, initial, policy); err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	if err := runCustodyApplicationHook(hooks.beforeCommit); err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	encoded, _ := application.CanonicalBytes()
	if err := validateCustodyApplicationLayout(destination, nil); err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	if err := publishCustodyApplicationBytes(ctx, destination, filepath.Join(destination, custodyApplicationFileName), encoded); err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	if err := validateCustodyApplicationLayout(destination, encoded); err != nil {
		return CustodyHistoricalApplication{}, false, err
	}
	if err := runCustodyApplicationHook(hooks.afterCommit); err != nil {
		return application, true, err
	}
	return application, true, nil
}

// VerifyCustodyHistoricalApplication requires an independently retained result
// ID, the reviewed transfer ID, and both pinned source bundles. No repair or
// ordinary journal open occurs. A valid result is still forbidden to run.
func VerifyCustodyHistoricalApplication(destination string, expectedID types.Hash, transferPackage string, transferID types.Hash,
	auditorPath, replicaPath string, auditorID, replicaID types.Hash,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) (CustodyHistoricalApplication, error) {
	if expectedID.IsZero() {
		return CustodyHistoricalApplication{}, ErrCustodyHistoricalApplication
	}
	transfer, header, release, err := lockCustodyApplicationInputs(destination, transferPackage, transferID, auditorPath, replicaPath, auditorID, replicaID, manifest, initial, policy)
	if err != nil {
		return CustodyHistoricalApplication{}, err
	}
	defer release()
	return verifyCustodyApplicationLockedInputs(destination, expectedID, transfer, header, auditorPath, manifest, initial, policy)
}

func lockCustodyApplicationInputs(destination, transferPackage string, transferID types.Hash,
	auditorPath, replicaPath string, auditorID, replicaID types.Hash,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) (CustodyHistoricalTransfer, CustodyJournalHeader, func(), error) {
	fail := func(err error) (CustodyHistoricalTransfer, CustodyJournalHeader, func(), error) {
		return CustodyHistoricalTransfer{}, CustodyJournalHeader{}, nil, errors.Join(ErrCustodyHistoricalApplication, err)
	}
	paths := []string{destination, transferPackage, auditorPath, replicaPath}
	if transferID.IsZero() || auditorID.IsZero() || replicaID.IsZero() {
		return fail(nil)
	}
	for index, path := range paths {
		if path == "" {
			return fail(nil)
		}
		for _, previous := range paths[:index] {
			if CustodyEvidencePathsOverlap(previous, path) {
				return fail(nil)
			}
		}
	}
	releaseSources, err := lockCustodyPinBackups(auditorPath, replicaPath)
	if err != nil {
		return fail(err)
	}
	transfer, err := prepareCustodyHistoricalTransferLocked(auditorPath, replicaPath, auditorID, replicaID, manifest, initial, policy)
	if err != nil {
		releaseSources()
		return fail(err)
	}
	id, _ := transfer.ID()
	if id != transferID {
		releaseSources()
		return fail(nil)
	}
	headerBytes, err := readRegularArchiveFile(filepath.Join(auditorPath, custodyBackupJournalName, custodyJournalHeaderName), MaximumCustodyJournalHeaderBytes)
	if err != nil {
		releaseSources()
		return fail(err)
	}
	header, err := DecodeCustodyJournalHeader(headerBytes)
	if err != nil || header.Version != CustodyJournalHeaderVersion0 {
		releaseSources()
		return fail(err)
	}
	header.Version, header.HistoricalTransferID = CustodyJournalHeaderHistoricalVersion1, transferID
	lock, err := acquireCustodyEvidenceLock(transferPackage, custodyTransferLockName, false)
	if err != nil {
		releaseSources()
		return fail(err)
	}
	release := func() { _ = lock.Close(); releaseSources() }
	if _, err := readCustodyTransferPackageLocked(transferPackage, transferID); err != nil {
		release()
		return fail(err)
	}
	return transfer, header, release, nil
}

func verifyCustodyApplicationLockedInputs(destination string, expectedID types.Hash, transfer CustodyHistoricalTransfer, header CustodyJournalHeader,
	auditorPath string, manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) (CustodyHistoricalApplication, error) {
	lock, err := acquireCustodyEvidenceLock(destination, custodyApplicationLockName, false)
	if err != nil {
		return CustodyHistoricalApplication{}, errors.Join(ErrCustodyApplicationIncomplete, err)
	}
	defer lock.Close()
	encoded, err := readRegularArchiveFile(filepath.Join(destination, custodyApplicationFileName), MaximumCustodyHistoricalApplicationBytes)
	if err != nil {
		return CustodyHistoricalApplication{}, errors.Join(ErrCustodyApplicationIncomplete, err)
	}
	application, err := DecodeCustodyHistoricalApplication(encoded)
	if err != nil {
		return CustodyHistoricalApplication{}, err
	}
	id, _ := application.ID()
	if !expectedID.IsZero() && id != expectedID {
		return CustodyHistoricalApplication{}, ErrCustodyHistoricalApplication
	}
	if err := validateCustodyApplicationLayout(destination, encoded); err != nil {
		return CustodyHistoricalApplication{}, err
	}
	if err := verifyCustodyApplicationEvidence(destination, application, transfer, header, auditorPath, manifest, initial, policy); err != nil {
		return CustodyHistoricalApplication{}, err
	}
	return application, nil
}

// Only the caller's private construction path writes these no-replace files.
// Existing bytes must match in full, not merely share a challenge ID.
func publishCustodyApplicationBytes(ctx context.Context, temporaryDirectory, path string, encoded []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if current, err := readRegularArchiveFile(path, len(encoded)); err == nil {
		if !bytes.Equal(current, encoded) {
			return ErrCustodyHistoricalApplication
		}
		return syncDirectory(filepath.Dir(path))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := writeCustodyTransferTemporary(ctx, temporaryDirectory, encoded)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	committed, err := readRegularArchiveFile(path, len(encoded))
	if err != nil || !bytes.Equal(committed, encoded) {
		return errors.Join(ErrCustodyHistoricalApplication, err)
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	return syncDirectory(temporaryDirectory)
}

func validateCustodyApplicationLayout(root string, committed []byte) error {
	expected := map[string]bool{custodyApplicationLockName: false, custodyApplicationFileName: false, custodyTransferFileName: false, custodyBackupJournalName: true, custodyBackupArtifactsName: true}
	if committed == nil {
		delete(expected, custodyApplicationFileName)
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(7)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > 6 {
		return ErrCustodyHistoricalApplication
	}
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(root, entry.Name()))
		if err != nil {
			return err
		}
		if isDirectory, known := expected[entry.Name()]; known {
			if info.IsDir() != isDirectory || (!isDirectory && !info.Mode().IsRegular()) {
				return ErrCustodyHistoricalApplication
			}
			delete(expected, entry.Name())
		} else {
			if committed == nil || !strings.HasPrefix(entry.Name(), ".outcomemesh-custody-journal-") {
				return ErrCustodyHistoricalApplication
			}
			temporary, err := readRegularArchiveFile(filepath.Join(root, entry.Name()), MaximumCustodyHistoricalApplicationBytes)
			if err != nil || !bytes.Equal(temporary, committed) {
				return ErrCustodyHistoricalApplication
			}
		}
	}
	if len(expected) != 0 {
		return ErrCustodyHistoricalApplication
	}
	return nil
}

func runCustodyApplicationHook(hook func() error) error {
	if hook != nil {
		return hook()
	}
	return nil
}
