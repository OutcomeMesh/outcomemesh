package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// SaveArchivePruneLineageEvidenceFile streams an immutable prepared value to a
// no-replace file. The existing dedicated parent must remain operator-controlled.
// Exact retries recheck the external evidence ID and sync the same verified file
// and parent. Failure/cancellation after publication may leave a complete file;
// preserve the pins and retry exactly. No owner, key or live journal is accessed.
func SaveArchivePruneLineageEvidenceFile(ctx context.Context, path string, evidence ArchivePruneLineageEvidence, expectedID types.Hash) error {
	return saveArchivePruneLineageEvidenceFile(ctx, path, evidence, expectedID, storeHooks{})
}

func saveArchivePruneLineageEvidenceFile(ctx context.Context, path string, evidence ArchivePruneLineageEvidence, expectedID types.Hash, hooks storeHooks) error {
	if ctx == nil || expectedID.IsZero() || evidence.id != expectedID {
		return ErrPruneLineageEvidence
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := storePath(path)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return syncLineageEvidenceFile(ctx, path, expectedID, hooks)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".outcomemesh-prune-lineage-*")
	if err != nil {
		return err
	}
	defer file.Close()
	defer func() { _ = os.Remove(file.Name()) }()
	for _, part := range evidence.parts {
		if err := writeLineageEvidencePart(ctx, file, part); err != nil {
			return err
		}
	}
	if err := hooks.reach("before-file-sync"); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := hooks.reach("file-synced"); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Link(file.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := hooks.reach("lineage-evidence-published"); err != nil {
		return err
	}
	return syncLineageEvidenceFile(ctx, path, expectedID, hooks)
}

type lineageEvidenceFile struct {
	file            *os.File
	path            string
	info, directory os.FileInfo
}

func openLineageEvidenceFile(path string, flags int) (*lineageEvidenceFile, error) {
	directory, err := os.Lstat(filepath.Dir(path))
	if err != nil || !directory.IsDir() {
		return nil, errors.Join(ErrPruneLineageEvidence, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 76 || info.Size() > MaximumArchivePruneLineageEvidenceBytes {
		return nil, errors.Join(ErrPruneLineageEvidence, err)
	}
	file, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || info.Size() != opened.Size() {
		_ = file.Close()
		return nil, errors.Join(ErrPruneLineageEvidence, err)
	}
	return &lineageEvidenceFile{file: file, path: path, info: info, directory: directory}, nil
}

func (input *lineageEvidenceFile) checkNames() error {
	current, err := os.Lstat(input.path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(input.info, current) || current.Size() != input.info.Size() {
		return errors.Join(ErrPruneLineageEvidence, err)
	}
	directory, err := os.Lstat(filepath.Dir(input.path))
	if err != nil || !directory.IsDir() || !os.SameFile(input.directory, directory) {
		return errors.Join(ErrPruneLineageEvidence, err)
	}
	return nil
}

func (input *lineageEvidenceFile) verifyHash(ctx context.Context, expectedID types.Hash) error {
	hash := sha256.New()
	_, _ = hash.Write([]byte(archivePruneLineageEvidenceDomain))
	buffer := make([]byte, 64<<10)
	reader := io.LimitReader(input.file, input.info.Size()+1)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := reader.Read(buffer)
		total += int64(n)
		_, _ = hash.Write(buffer[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	if total != input.info.Size() || types.Hash(hash.Sum(nil)) != expectedID {
		return ErrPruneLineageEvidence
	}
	return input.checkNames()
}

func syncLineageEvidenceFile(ctx context.Context, path string, expectedID types.Hash, hooks storeHooks) (err error) {
	input, err := openLineageEvidenceFile(path, os.O_RDWR)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.file.Close()) }()
	if err := input.verifyHash(ctx, expectedID); err != nil {
		return err
	}
	if err := input.file.Sync(); err != nil {
		return err
	}
	if err := hooks.reach("lineage-evidence-before-directory-sync"); err != nil {
		return err
	}
	if err := input.checkNames(); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, directory.Close()) }()
	opened, err := directory.Stat()
	if err != nil || !os.SameFile(input.directory, opened) {
		return errors.Join(ErrPruneLineageEvidence, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	if err := hooks.reach("lineage-evidence-directory-synced"); err != nil {
		return err
	}
	return ctx.Err()
}

// LoadArchivePruneLineageEvidenceFile is read-only and requires three separately
// retained pins plus the exact inventory. It authenticates the bounded file
// before allocating bodies, then decodes and fully verifies all prefixes. It
// neither discovers/activates a journal nor attests to present live authority.
// Concurrent mutation of the file/parent or caller inventory is unsupported.
func LoadArchivePruneLineageEvidenceFile(ctx context.Context, path string, inventory ArchivePruneInventory,
	expectedInventoryID, expectedPolicyID, expectedEvidenceID types.Hash,
) (evidence ArchivePruneLineageEvidence, err error) {
	if err := checkLineageEvidenceInventory(ctx, inventory, expectedInventoryID, expectedPolicyID); err != nil {
		return ArchivePruneLineageEvidence{}, err
	}
	if expectedEvidenceID.IsZero() {
		return ArchivePruneLineageEvidence{}, ErrPruneLineageEvidence
	}
	path, err = storePath(path)
	if err != nil {
		return ArchivePruneLineageEvidence{}, err
	}
	input, err := openLineageEvidenceFile(path, os.O_RDONLY)
	if err != nil {
		return ArchivePruneLineageEvidence{}, err
	}
	defer func() {
		err = errors.Join(err, input.file.Close())
		if err != nil {
			evidence = ArchivePruneLineageEvidence{}
		}
	}()
	if err := input.verifyHash(ctx, expectedEvidenceID); err != nil {
		return ArchivePruneLineageEvidence{}, err
	}
	if _, err := input.file.Seek(0, io.SeekStart); err != nil {
		return ArchivePruneLineageEvidence{}, err
	}
	evidence, err = decodeLineageEvidence(ctx, input.file, input.info.Size(), inventory, expectedInventoryID, expectedPolicyID, expectedEvidenceID)
	if err != nil {
		return ArchivePruneLineageEvidence{}, err
	}
	if err := input.checkNames(); err != nil {
		return ArchivePruneLineageEvidence{}, err
	}
	return evidence, ctx.Err()
}
