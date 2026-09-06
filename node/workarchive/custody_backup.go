package workarchive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	custodyBackupLockName       = "backup.lock"
	custodyBackupCheckpointName = "checkpoint.omccp"
	custodyBackupJournalName    = "journal"
	custodyBackupArtifactsName  = "artifacts"
)

var (
	ErrCustodyBackup           = errors.New("invalid custody backup")
	ErrCustodyBackupIncomplete = errors.New("custody backup is incomplete; preserve it and use a new destination")
)

type custodyBackupHooks struct {
	afterJournalCopy func() error
	afterCopy        func() error
	beforeCommit     func() error
	afterCommit      func() error
}

// CreateCustodyBackup copies a stable, replay-verified evidence pair into a new
// directory. The final checkpoint file commits the bundle only after the copied
// files and directories are synced and independently replayed. No source inode
// is shared with the copy. Source locks remain held until publication finishes.
//
// A complete, identical destination is an idempotent retry (created=false).
// Incomplete or different destinations are never resumed, replaced, or deleted.
// Cancellation is checked during copying and before commit; journal replay and
// the existing bounded lock waits may delay observing it. Keep the returned ID
// independently, and never run the backup as a second decision authority.
func CreateCustodyBackup(
	ctx context.Context, destination, journalPath, artifactsPath string,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) (checkpoint CustodyCheckpoint, created bool, err error) {
	return createCustodyBackup(ctx, destination, journalPath, artifactsPath, manifest, initial, policy, custodyBackupHooks{})
}

func createCustodyBackup(
	ctx context.Context, destination, journalPath, artifactsPath string,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy, hooks custodyBackupHooks,
) (CustodyCheckpoint, bool, error) {
	if ctx == nil || destination == "" || journalPath == "" || manifest.Validate() != nil ||
		initial.verifySignature() != nil || policy.validate() != nil {
		return CustodyCheckpoint{}, false, ErrCustodyBackup
	}
	if err := ctx.Err(); err != nil {
		return CustodyCheckpoint{}, false, err
	}
	if CustodyEvidencePathsOverlap(destination, journalPath) ||
		(artifactsPath != "" && CustodyEvidencePathsOverlap(destination, artifactsPath)) {
		return CustodyCheckpoint{}, false, fmt.Errorf("%w: destination must be outside both evidence trees", ErrCustodyBackup)
	}
	// Do not initialize locks or repair source evidence while backing it up.
	release, err := lockCustodyEvidencePair(journalPath, artifactsPath, false)
	if err != nil {
		return CustodyCheckpoint{}, false, err
	}
	defer release()
	checkpoint, err := custodyCheckpointStateLocked(journalPath, manifest, initial, policy)
	if err != nil {
		return CustodyCheckpoint{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return CustodyCheckpoint{}, false, err
	}
	if _, err := os.Lstat(destination); err == nil {
		return retryCustodyBackup(destination, journalPath, artifactsPath, manifest, initial, policy)
	} else if !errors.Is(err, os.ErrNotExist) {
		return CustodyCheckpoint{}, false, err
	}
	if err := makeCustodyJournalRoot(filepath.Dir(destination)); err != nil {
		return CustodyCheckpoint{}, false, err
	}
	// Mkdir reserves the exact destination atomically. Never rename over an
	// existing directory, even an empty one, and never remove a failed attempt.
	if err := os.Mkdir(destination, 0o700); err != nil {
		return CustodyCheckpoint{}, false, errors.Join(ErrCustodyBackup, err)
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return CustodyCheckpoint{}, false, err
	}
	lock, err := acquireCustodyEvidenceLock(destination, custodyBackupLockName, true)
	if err != nil {
		return CustodyCheckpoint{}, false, err
	}
	defer lock.Close()
	copyJournal, copyArtifacts := custodyBackupEvidencePaths(destination, artifactsPath != "")
	checkpoint.Journal, err = walkCustodyEvidenceTree(ctx, journalPath, copyJournal, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
	if err != nil {
		return CustodyCheckpoint{}, false, err
	}
	if hooks.afterJournalCopy != nil {
		if err := hooks.afterJournalCopy(); err != nil {
			return CustodyCheckpoint{}, false, err
		}
	}
	if copyArtifacts != "" {
		checkpoint.Artifacts, err = walkCustodyEvidenceTree(ctx, artifactsPath, copyArtifacts, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
		if err != nil {
			return CustodyCheckpoint{}, false, err
		}
	}
	if hooks.afterCopy != nil {
		if err := hooks.afterCopy(); err != nil {
			return CustodyCheckpoint{}, false, err
		}
	}
	id, err := checkpoint.ID()
	if err != nil {
		return CustodyCheckpoint{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return CustodyCheckpoint{}, false, err
	}
	// Reopen independent destination inodes. A copy or disk error cannot become
	// a completed backup merely because the source inventory was valid.
	if err := VerifyCustodyCheckpoint(checkpoint, id, copyJournal, copyArtifacts, manifest, initial, policy); err != nil {
		return CustodyCheckpoint{}, false, err
	}
	if hooks.beforeCommit != nil {
		if err := hooks.beforeCommit(); err != nil {
			return CustodyCheckpoint{}, false, err
		}
	}
	if err := ctx.Err(); err != nil {
		return CustodyCheckpoint{}, false, err
	}
	encoded, _ := checkpoint.CanonicalBytes()
	if _, err := publishCustodyJournalBytes(destination, filepath.Join(destination, custodyBackupCheckpointName), encoded); err != nil {
		return CustodyCheckpoint{}, false, err
	}
	committed, err := readRegularArchiveFile(filepath.Join(destination, custodyBackupCheckpointName), MaximumCustodyCheckpointBytes)
	if err != nil || !bytes.Equal(committed, encoded) {
		return CustodyCheckpoint{}, false, errors.Join(ErrCustodyCheckpointMismatch, err)
	}
	if hooks.afterCommit != nil {
		if err := hooks.afterCommit(); err != nil {
			return checkpoint, true, err
		}
	}
	return checkpoint, true, nil
}

// The caller already holds the source locks. Comparing its complete current
// inventory prevents an old destination from being reported as a fresh backup.
func retryCustodyBackup(destination, journalPath, artifactsPath string, manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy) (CustodyCheckpoint, bool, error) {
	if err := requireCustodyJournalDirectory(destination); err != nil {
		return CustodyCheckpoint{}, false, errors.Join(ErrCustodyBackup, err)
	}
	if _, err := os.Lstat(filepath.Join(destination, custodyBackupCheckpointName)); err != nil {
		return CustodyCheckpoint{}, false, errors.Join(ErrCustodyBackupIncomplete, err)
	}
	checkpoint, err := captureCustodyCheckpointLocked(journalPath, artifactsPath, manifest, initial, policy)
	if err != nil {
		return CustodyCheckpoint{}, false, err
	}
	id, _ := checkpoint.ID()
	verified, err := VerifyCustodyBackup(destination, id, manifest, initial, policy)
	return verified, false, err
}

// VerifyCustodyBackup requires a separately retained checkpoint ID. It never
// repairs or initializes the bundle, and needs no access to the original paths.
// Successful verification establishes an exact historical copy, not freshness
// relative to later decisions, durability on every filesystem, or safe cutover.
func VerifyCustodyBackup(destination string, expectedID types.Hash, manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy) (CustodyCheckpoint, error) {
	if destination == "" || expectedID.IsZero() {
		return CustodyCheckpoint{}, ErrCustodyBackup
	}
	if err := requireCustodyJournalDirectory(destination); err != nil {
		return CustodyCheckpoint{}, errors.Join(ErrCustodyBackup, err)
	}
	lock, err := acquireCustodyEvidenceLock(destination, custodyBackupLockName, false)
	if err != nil {
		return CustodyCheckpoint{}, errors.Join(ErrCustodyBackupIncomplete, err)
	}
	defer lock.Close()
	return verifyCustodyBackupLocked(destination, expectedID, manifest, initial, policy)
}

// The caller holds the existing bundle lock and supplies a nonzero independent
// checkpoint ID. Keeping this lock outside the verifier lets pin promotion
// compare two verified immutable bundles without releasing either bundle lock.
func verifyCustodyBackupLocked(destination string, expectedID types.Hash, manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy) (CustodyCheckpoint, error) {
	encoded, err := readRegularArchiveFile(filepath.Join(destination, custodyBackupCheckpointName), MaximumCustodyCheckpointBytes)
	if err != nil {
		return CustodyCheckpoint{}, errors.Join(ErrCustodyBackupIncomplete, err)
	}
	checkpoint, err := DecodeCustodyCheckpoint(encoded)
	if err != nil {
		return CustodyCheckpoint{}, errors.Join(ErrCustodyBackup, err)
	}
	id, _ := checkpoint.ID()
	if id != expectedID {
		return CustodyCheckpoint{}, ErrCustodyCheckpointMismatch
	}
	hasArtifacts := checkpoint.Artifacts != (CustodyCheckpointTree{})
	if err := validateCustodyBackupLayout(destination, hasArtifacts); err != nil {
		return CustodyCheckpoint{}, err
	}
	j, a := custodyBackupEvidencePaths(destination, hasArtifacts)
	if err := VerifyCustodyCheckpoint(checkpoint, expectedID, j, a, manifest, initial, policy); err != nil {
		return CustodyCheckpoint{}, err
	}
	return checkpoint, nil
}

func custodyBackupEvidencePaths(root string, hasArtifacts bool) (string, string) {
	j, a := filepath.Join(root, custodyBackupJournalName), ""
	if hasArtifacts {
		a = filepath.Join(root, custodyBackupArtifactsName)
	}
	return j, a
}

func validateCustodyBackupLayout(root string, hasArtifacts bool) error {
	expected := map[string]bool{custodyBackupLockName: false, custodyBackupCheckpointName: false, custodyBackupJournalName: true}
	if hasArtifacts {
		expected[custodyBackupArtifactsName] = true
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	defer directory.Close()
	// Four permanent entries and at most one abandoned checkpoint temp link.
	entries, err := directory.ReadDir(6)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > 5 {
		return errors.Join(ErrCustodyBackup, err)
	}
	temporary := false
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(root, entry.Name()))
		if err != nil {
			return err
		}
		wantDirectory, known := expected[entry.Name()]
		if known {
			if info.IsDir() != wantDirectory || (!info.IsDir() && !info.Mode().IsRegular()) {
				return ErrCustodyBackup
			}
			delete(expected, entry.Name())
		} else {
			if temporary || !strings.HasPrefix(entry.Name(), ".outcomemesh-custody-journal-") ||
				!info.Mode().IsRegular() || info.Size() < 0 || info.Size() > MaximumCustodyCheckpointBytes {
				return ErrCustodyBackup
			}
			temporary = true
		}
	}
	if len(expected) != 0 {
		return ErrCustodyBackup
	}
	return nil
}
