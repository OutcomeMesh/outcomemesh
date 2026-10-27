package workarchive

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

func createCustodySourceRoot(ctx context.Context, path string) (string, os.FileInfo, error) {
	if ctx == nil || path == "" {
		return "", nil, ErrCustodyJournal
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", nil, err
	}
	if err := requireCustodyJournalDirectory(parent); err != nil {
		return "", nil, err
	}
	path = filepath.Join(parent, filepath.Base(abs))
	if err := os.Mkdir(path, 0o700); err != nil {
		return "", nil, err
	}
	// Retain every uncertain initialization. No cleanup removes this claim.
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, errors.Join(ErrCustodyJournal, err)
	}
	if err := syncDirectory(parent); err != nil {
		return "", nil, err
	}
	return path, info, nil
}

// CreateCustodyArtifacts creates only a NEW artifact root and its permanent
// lock. It signs/publishes no challenge and never repairs a retained root.
func CreateCustodyArtifacts(ctx context.Context, path string) (*os.File, error) {
	path, root, err := createCustodySourceRoot(ctx, path)
	if err != nil {
		return nil, err
	}
	lock, err := acquireCustodyEvidenceLockContext(ctx, path, custodyArtifactsLockName, true)
	if err != nil {
		return nil, err
	}
	err = checkCreatedCustodySource(path, root, lock, custodyArtifactsLockName)
	if err != nil || ctx.Err() != nil {
		return nil, errors.Join(ErrCustodyJournal, err, ctx.Err(), lock.Close())
	}
	return lock, nil
}

func checkCreatedCustodySource(path string, original os.FileInfo, lock *os.File, lockName string) error {
	root, rootErr := os.Lstat(path)
	current, pathErr := os.Lstat(filepath.Join(path, lockName))
	opened, openErr := lock.Stat()
	if rootErr != nil || pathErr != nil || openErr != nil || !root.IsDir() || !os.SameFile(root, original) || !current.Mode().IsRegular() || current.Size() != 0 || !os.SameFile(current, opened) {
		return errors.Join(ErrCustodyJournal, rootErr, pathErr, openErr)
	}
	return nil
}

// OpenExistingCustodyArtifacts acquires only the retained permanent lock. It
// never creates a missing root/lock or changes the challenge/result branch.
func OpenExistingCustodyArtifacts(ctx context.Context, path string) (*os.File, error) {
	return acquireCustodyEvidenceLockContext(ctx, path, custodyArtifactsLockName, false)
}
