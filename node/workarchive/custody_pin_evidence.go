package workarchive

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

func lockCustodyPinBackups(current, previous string) (func(), error) {
	paths := []string{current}
	if previous != "" {
		if CustodyEvidencePathsOverlap(current, previous) {
			return nil, ErrCustodyBackupPinConflict
		}
		paths = append(paths, previous)
	}
	for index, path := range paths {
		resolved, err := resolveCustodyEvidencePath(path)
		if err != nil {
			return nil, err
		}
		// Reject a symlink root as the regular backup verifier does.
		if err := requireCustodyJournalDirectory(path); err != nil {
			return nil, err
		}
		paths[index] = resolved
	}
	sort.Strings(paths)
	var locks []*os.File
	release := func() {
		for index := len(locks) - 1; index >= 0; index-- {
			_ = locks[index].Close()
		}
	}
	for _, path := range paths {
		lock, err := acquireCustodyEvidenceLock(path, custodyBackupLockName, false)
		if err != nil {
			release()
			return nil, err
		}
		locks = append(locks, lock)
	}
	return release, nil
}

// Both bundles have already passed complete replay and inventory verification;
// their permanent backup locks remain held throughout this comparison. Backups
// must remain immutable, not be used as live journal directories.
func custodyBackupPreservesEvidence(previousPath, currentPath string, previous, current CustodyCheckpoint) error {
	if current.HeaderID != previous.HeaderID || current.Sequence < previous.Sequence ||
		(current.Artifacts == (CustodyCheckpointTree{})) != (previous.Artifacts == (CustodyCheckpointTree{})) {
		return ErrCustodyBackupPinConflict
	}
	oldJournalPath, oldArtifacts := custodyBackupEvidencePaths(previousPath, !previous.Artifacts.ID.IsZero())
	newJournalPath, newArtifacts := custodyBackupEvidencePaths(currentPath, !current.Artifacts.ID.IsZero())
	oldJournal, newJournal := &CustodyJournal{path: oldJournalPath}, &CustodyJournal{path: newJournalPath}
	if previous.Sequence != 0 {
		entry, err := newJournal.loadSequence(previous.Sequence)
		if err != nil {
			return errors.Join(ErrCustodyBackupPinConflict, err)
		}
		entryID, _ := entry.ID()
		receiptID, _ := entry.Record.RenewedReceipt.ID()
		if entryID != previous.HeadEntryID || receiptID != previous.ReceiptID {
			return ErrCustodyBackupPinConflict
		}
	}
	oldBodies, err := oldJournal.scanBodyPaths()
	if err != nil {
		return err
	}
	newBodies, err := newJournal.scanBodyPaths()
	if err != nil {
		return err
	}
	// Rotation can move bodies. Compare verified content IDs, not active/segment
	// paths, including orphan evidence that has not committed a sequence slot.
	for id := range oldBodies {
		if _, found := newBodies[id]; !found {
			return fmt.Errorf("%w: missing historical body %s", ErrCustodyBackupPinConflict, id)
		}
	}
	if err := custodyPinnedTreePreserved(filepath.Join(oldJournalPath, custodyJournalPendingName), filepath.Join(newJournalPath, custodyJournalPendingName)); err != nil {
		return err
	}
	if oldArtifacts != "" {
		return custodyPinnedTreePreserved(oldArtifacts, newArtifacts)
	}
	return nil
}

// Require every old relative path and regular-file byte to remain present.
// New paths may be added. Timestamps, modes, and inode numbers are not compared
// across backups; the same checkpoint ceilings bound this extra traversal.
func custodyPinnedTreePreserved(previous, current string) error {
	var paths, totalBytes uint64
	leftBuffer, rightBuffer := make([]byte, 32*1024), make([]byte, 32*1024)
	var visit func(string, string, int) error
	visit = func(left, right string, depth int) error {
		paths++
		if paths > MaximumCustodyJournalPaths {
			return ErrCustodyBackupPinConflict
		}
		leftInfo, err := os.Lstat(left)
		if err != nil {
			return err
		}
		rightInfo, err := os.Lstat(right)
		if err != nil {
			return errors.Join(ErrCustodyBackupPinConflict, err)
		}
		if leftInfo.IsDir() {
			if !rightInfo.IsDir() || depth > 3 {
				return ErrCustodyBackupPinConflict
			}
			directory, err := os.Open(left)
			if err != nil {
				return err
			}
			defer directory.Close()
			opened, err := directory.Stat()
			if err != nil || !sameCustodyEvidenceFile(leftInfo, opened) {
				return errors.Join(ErrCustodyBackupPinConflict, err)
			}
			for {
				entries, readErr := directory.ReadDir(128)
				for _, entry := range entries {
					if err := visit(filepath.Join(left, entry.Name()), filepath.Join(right, entry.Name()), depth+1); err != nil {
						return err
					}
				}
				if errors.Is(readErr, io.EOF) {
					for _, check := range []struct {
						path string
						info os.FileInfo
					}{{left, leftInfo}, {right, rightInfo}} {
						info, err := os.Lstat(check.path)
						if err != nil || !sameCustodyEvidenceFile(check.info, info) {
							return errors.Join(ErrCustodyBackupPinConflict, err)
						}
					}
					return nil
				}
				if readErr != nil {
					return readErr
				}
			}
		}
		if !leftInfo.Mode().IsRegular() || !rightInfo.Mode().IsRegular() || leftInfo.Size() < 0 || leftInfo.Size() != rightInfo.Size() || uint64(leftInfo.Size()) > MaximumCustodyJournalBytes-totalBytes {
			return ErrCustodyBackupPinConflict
		}
		totalBytes += uint64(leftInfo.Size())
		leftFile, err := os.Open(left)
		if err != nil {
			return err
		}
		defer leftFile.Close()
		rightFile, err := os.Open(right)
		if err != nil {
			return err
		}
		defer rightFile.Close()
		for _, check := range []struct {
			file *os.File
			info os.FileInfo
		}{{leftFile, leftInfo}, {rightFile, rightInfo}} {
			opened, err := check.file.Stat()
			if err != nil || !sameCustodyEvidenceFile(check.info, opened) {
				return errors.Join(ErrCustodyBackupPinConflict, err)
			}
		}
		for remaining := leftInfo.Size(); remaining > 0; {
			size := int64(len(leftBuffer))
			if remaining < size {
				size = remaining
			}
			if _, err := io.ReadFull(leftFile, leftBuffer[:size]); err != nil {
				return err
			}
			if _, err := io.ReadFull(rightFile, rightBuffer[:size]); err != nil {
				return err
			}
			if !bytes.Equal(leftBuffer[:size], rightBuffer[:size]) {
				return fmt.Errorf("%w: changed retained artifact", ErrCustodyBackupPinConflict)
			}
			remaining -= size
		}
		for _, check := range []struct {
			path string
			file *os.File
			info os.FileInfo
		}{{left, leftFile, leftInfo}, {right, rightFile, rightInfo}} {
			if n, err := check.file.Read(leftBuffer[:1]); n != 0 || !errors.Is(err, io.EOF) {
				return ErrCustodyBackupPinConflict
			}
			info, err := os.Lstat(check.path)
			if err != nil || !sameCustodyEvidenceFile(check.info, info) {
				return errors.Join(ErrCustodyBackupPinConflict, err)
			}
		}
		return nil
	}
	return visit(previous, current, 0)
}
