package workarchive

import (
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
