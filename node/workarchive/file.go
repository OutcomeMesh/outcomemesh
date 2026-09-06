package workarchive

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// SaveCheckpointFile atomically replaces a public checkpoint bundle and
// fsyncs both file and containing directory. The expected statement ID keeps a
// caller from publishing signatures over an unintended anchor.
func SaveCheckpointFile(
	path string,
	checkpoint Checkpoint,
	policy Policy,
	expectedStatementID types.Hash,
) error {
	if path == "" || expectedStatementID.IsZero() || checkpoint.Verify(policy) != nil {
		return ErrCheckpoint
	}
	statementID, err := checkpoint.Statement.ID()
	if err != nil || statementID != expectedStatementID {
		return ErrCheckpoint
	}
	encoded, err := checkpoint.CanonicalBytes()
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".outcomemesh-work-archive-checkpoint-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	written, err := temporary.Write(encoded)
	if err != nil {
		return err
	}
	if written != len(encoded) {
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}

func LoadCheckpointFile(
	path string,
	policy Policy,
	expectedStatementID types.Hash,
) (Checkpoint, error) {
	if path == "" || expectedStatementID.IsZero() {
		return Checkpoint{}, ErrCheckpoint
	}
	file, err := os.Open(path)
	if err != nil {
		return Checkpoint{}, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, MaximumCheckpointBytes+1))
	if err != nil {
		return Checkpoint{}, err
	}
	if len(encoded) == 0 || len(encoded) > MaximumCheckpointBytes {
		return Checkpoint{}, ErrCheckpoint
	}
	checkpoint, err := DecodeCheckpoint(encoded)
	if err != nil {
		return Checkpoint{}, err
	}
	if err := checkpoint.Verify(policy); err != nil {
		return Checkpoint{}, err
	}
	statementID, err := checkpoint.Statement.ID()
	if err != nil || statementID != expectedStatementID {
		return Checkpoint{}, errors.Join(ErrCheckpoint, err)
	}
	return checkpoint, nil
}

// SaveAvailabilityBundleFile durably publishes the exact replica evidence ID
// later embedded in a canonical retained floor, without replacing an existing
// path. Identical retries verify and fsync the existing file and directory;
// another bundle, a symlink, or damaged evidence fails closed. A published
// bundle is evidence, not a reusable live authorization to delete history.
func SaveAvailabilityBundleFile(
	path string,
	bundle AvailabilityBundle,
	checkpoint Checkpoint,
	checkpointPolicy Policy,
	replicaPolicy ReplicaPolicy,
	now uint64,
	expectedBundleID types.Hash,
) error {
	if path == "" || expectedBundleID.IsZero() ||
		bundle.Verify(checkpoint, checkpointPolicy, replicaPolicy, now) != nil {
		return ErrAvailability
	}
	bundleID, err := bundle.ID()
	if err != nil || bundleID != expectedBundleID {
		return ErrAvailability
	}
	encoded, err := bundle.CanonicalBytes()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return syncAvailabilityBundleFile(path, encoded)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".outcomemesh-work-archive-availability-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	written, err := temporary.Write(encoded)
	if err != nil {
		return err
	}
	if written != len(encoded) {
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	return syncAvailabilityBundleFile(path, encoded)
}

// The directory is operator-controlled. The inode and exact bytes are checked
// on the same open handle we sync, including when another publisher won a race.
func syncAvailabilityBundleFile(path string, encoded []byte) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(encoded)) {
		return errors.Join(ErrAvailability, err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return errors.Join(ErrAvailability, err)
	}
	current, err := io.ReadAll(io.LimitReader(file, MaximumAvailabilityBundleBytes+1))
	if err != nil || !bytes.Equal(current, encoded) {
		return errors.Join(ErrAvailability, err)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func LoadAvailabilityBundleFile(
	path string,
	checkpoint Checkpoint,
	checkpointPolicy Policy,
	replicaPolicy ReplicaPolicy,
	now uint64,
	expectedBundleID types.Hash,
) (AvailabilityBundle, error) {
	if path == "" || expectedBundleID.IsZero() {
		return AvailabilityBundle{}, ErrAvailability
	}
	encoded, err := readRegularArchiveFile(path, MaximumAvailabilityBundleBytes)
	if err != nil {
		return AvailabilityBundle{}, errors.Join(ErrAvailability, err)
	}
	bundle, err := DecodeAvailabilityBundle(encoded)
	if err != nil || bundle.Verify(checkpoint, checkpointPolicy, replicaPolicy, now) != nil {
		return AvailabilityBundle{}, errors.Join(ErrAvailability, err)
	}
	bundleID, err := bundle.ID()
	if err != nil || bundleID != expectedBundleID {
		return AvailabilityBundle{}, errors.Join(ErrAvailability, err)
	}
	return bundle, nil
}
