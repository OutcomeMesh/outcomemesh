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
	custodyTransferLockName = "transfer.lock"
	custodyTransferFileName = "historical.omcht"
)

var ErrCustodyTransferIncomplete = errors.New("custody transfer package is incomplete; preserve it and use a new destination")

type custodyTransferHooks struct {
	afterWrite  func() error
	afterCommit func() error
}

// CreateCustodyHistoricalTransferPackage exports the reviewed ID into a new,
// no-replace directory. It holds both immutable source bundle locks through
// publication, replays their evidence, and never writes in either source tree.
// Exact completed retries succeed; incomplete attempts are retained, not resumed.
// No key, network session, journal writer, or pin update is involved. Cancellation
// is checked before creation and publication; bounded lock waits/replay may delay it.
func CreateCustodyHistoricalTransferPackage(ctx context.Context, destination string, expectedID types.Hash,
	auditorPath, replicaPath string, auditorID, replicaID types.Hash,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) (CustodyHistoricalTransfer, bool, error) {
	return createCustodyHistoricalTransferPackage(ctx, destination, expectedID, auditorPath, replicaPath, auditorID, replicaID, manifest, initial, policy, custodyTransferHooks{})
}

func createCustodyHistoricalTransferPackage(ctx context.Context, destination string, expectedID types.Hash,
	auditorPath, replicaPath string, auditorID, replicaID types.Hash,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy, hooks custodyTransferHooks,
) (CustodyHistoricalTransfer, bool, error) {
	if ctx == nil || validateCustodyTransferPaths(destination, expectedID, auditorPath, replicaPath, auditorID, replicaID) != nil {
		return CustodyHistoricalTransfer{}, false, ErrCustodyHistoricalTransfer
	}
	if err := ctx.Err(); err != nil {
		return CustodyHistoricalTransfer{}, false, err
	}
	release, err := lockCustodyPinBackups(auditorPath, replicaPath)
	if err != nil {
		return CustodyHistoricalTransfer{}, false, err
	}
	defer release()
	transfer, err := prepareCustodyHistoricalTransferLocked(auditorPath, replicaPath, auditorID, replicaID, manifest, initial, policy)
	if err != nil {
		return CustodyHistoricalTransfer{}, false, err
	}
	id, _ := transfer.ID()
	if id != expectedID {
		return CustodyHistoricalTransfer{}, false, ErrCustodyHistoricalTransfer
	}
	if err := ctx.Err(); err != nil {
		return CustodyHistoricalTransfer{}, false, err
	}
	if _, err := os.Lstat(destination); err == nil {
		got, err := verifyCustodyTransferPackageLockedSources(destination, expectedID)
		return got, false, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return CustodyHistoricalTransfer{}, false, err
	}
	if err := makeCustodyJournalRoot(filepath.Dir(destination)); err != nil {
		return CustodyHistoricalTransfer{}, false, err
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return CustodyHistoricalTransfer{}, false, err
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return CustodyHistoricalTransfer{}, false, err
	}
	lock, err := acquireCustodyEvidenceLock(destination, custodyTransferLockName, true)
	if err != nil {
		return CustodyHistoricalTransfer{}, false, err
	}
	defer lock.Close()
	encoded, _ := transfer.CanonicalBytes()
	temporary, err := writeCustodyTransferTemporary(ctx, destination, encoded)
	if err != nil {
		return CustodyHistoricalTransfer{}, false, err
	}
	// Keep failed attempts, including the fully written uncommitted envelope.
	if hooks.afterWrite != nil {
		if err := hooks.afterWrite(); err != nil {
			return CustodyHistoricalTransfer{}, false, err
		}
	}
	if err := ctx.Err(); err != nil {
		return CustodyHistoricalTransfer{}, false, err
	}
	path := filepath.Join(destination, custodyTransferFileName)
	if err := os.Link(temporary, path); err != nil {
		return CustodyHistoricalTransfer{}, false, err
	}
	if err := syncDirectory(destination); err != nil {
		return CustodyHistoricalTransfer{}, false, err
	}
	// Independently reread and decode after the durability boundary.
	got, err := readCustodyTransferPackageLocked(destination, expectedID)
	if err != nil {
		return CustodyHistoricalTransfer{}, false, err
	}
	if hooks.afterCommit != nil {
		if err := hooks.afterCommit(); err != nil {
			return got, true, err
		}
	}
	// Only the successfully committed temporary link is disposable; neither
	// evidence nor an incomplete attempt is cleaned up by a later retry.
	if err := os.Remove(temporary); err != nil {
		return got, true, err
	}
	return got, true, syncDirectory(destination)
}

func writeCustodyTransferTemporary(ctx context.Context, directory string, encoded []byte) (string, error) {
	file, err := os.CreateTemp(directory, ".outcomemesh-custody-journal-*")
	if err != nil {
		return "", err
	}
	defer file.Close()
	// Unlike live journal scratch space, this quarantine package retains even
	// partial failed writes. A retry must use a new directory, never clean it up.
	reader := custodyEvidenceContextReader{ctx: ctx, reader: bytes.NewReader(encoded)}
	written, err := io.CopyBuffer(file, reader, make([]byte, 32*1024))
	if err != nil {
		return "", err
	}
	if written != int64(len(encoded)) {
		return "", io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := syncDirectory(directory); err != nil {
		return "", err
	}
	return file.Name(), nil
}

// VerifyCustodyHistoricalTransferPackage needs all three independent IDs and
// both complete source bundles. The envelope alone cannot prove retained local
// intent or the full common prefix. Recompute selection rather than trusting a
// plan file's claims. Verification grants no import/cutover authority.
func VerifyCustodyHistoricalTransferPackage(destination string, expectedID types.Hash,
	auditorPath, replicaPath string, auditorID, replicaID types.Hash,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) (CustodyHistoricalTransfer, error) {
	if err := validateCustodyTransferPaths(destination, expectedID, auditorPath, replicaPath, auditorID, replicaID); err != nil {
		return CustodyHistoricalTransfer{}, err
	}
	release, err := lockCustodyPinBackups(auditorPath, replicaPath)
	if err != nil {
		return CustodyHistoricalTransfer{}, err
	}
	defer release()
	transfer, err := prepareCustodyHistoricalTransferLocked(auditorPath, replicaPath, auditorID, replicaID, manifest, initial, policy)
	if err != nil {
		return CustodyHistoricalTransfer{}, err
	}
	id, _ := transfer.ID()
	if id != expectedID {
		return CustodyHistoricalTransfer{}, ErrCustodyHistoricalTransfer
	}
	return verifyCustodyTransferPackageLockedSources(destination, expectedID)
}

func validateCustodyTransferPaths(destination string, expectedID types.Hash, auditorPath, replicaPath string, auditorID, replicaID types.Hash) error {
	if destination == "" || expectedID.IsZero() || auditorID.IsZero() || replicaID.IsZero() ||
		CustodyEvidencePathsOverlap(auditorPath, replicaPath) ||
		CustodyEvidencePathsOverlap(destination, auditorPath) || CustodyEvidencePathsOverlap(destination, replicaPath) {
		return ErrCustodyHistoricalTransfer
	}
	return nil
}

// Source locks are already held in canonical order, and the package is disjoint.
func verifyCustodyTransferPackageLockedSources(destination string, expectedID types.Hash) (CustodyHistoricalTransfer, error) {
	lock, err := acquireCustodyEvidenceLock(destination, custodyTransferLockName, false)
	if err != nil {
		return CustodyHistoricalTransfer{}, errors.Join(ErrCustodyTransferIncomplete, err)
	}
	defer lock.Close()
	return readCustodyTransferPackageLocked(destination, expectedID)
}

func readCustodyTransferPackageLocked(destination string, expectedID types.Hash) (CustodyHistoricalTransfer, error) {
	encoded, err := readRegularArchiveFile(filepath.Join(destination, custodyTransferFileName), MaximumCustodyHistoricalTransferBytes)
	if err != nil {
		return CustodyHistoricalTransfer{}, errors.Join(ErrCustodyTransferIncomplete, err)
	}
	transfer, err := DecodeCustodyHistoricalTransfer(encoded)
	if err != nil {
		return CustodyHistoricalTransfer{}, err
	}
	id, _ := transfer.ID()
	if expectedID.IsZero() || id != expectedID {
		return CustodyHistoricalTransfer{}, ErrCustodyHistoricalTransfer
	}
	directory, err := os.Open(destination)
	if err != nil {
		return CustodyHistoricalTransfer{}, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(4)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) < 2 || len(entries) > 3 {
		return CustodyHistoricalTransfer{}, ErrCustodyHistoricalTransfer
	}
	for _, entry := range entries {
		if entry.Name() == custodyTransferLockName || entry.Name() == custodyTransferFileName {
			continue // Existing lock and bounded envelope reads checked their types.
		}
		// A kill just after commit may retain the exact temporary envelope. No
		// arbitrary extra file, symlink, or partial temp is accepted as complete.
		if !strings.HasPrefix(entry.Name(), ".outcomemesh-custody-journal-") {
			return CustodyHistoricalTransfer{}, ErrCustodyHistoricalTransfer
		}
		pending, err := readRegularArchiveFile(filepath.Join(destination, entry.Name()), MaximumCustodyHistoricalTransferBytes)
		if err != nil || !bytes.Equal(pending, encoded) {
			return CustodyHistoricalTransfer{}, errors.Join(ErrCustodyHistoricalTransfer, err)
		}
	}
	return transfer, nil
}
