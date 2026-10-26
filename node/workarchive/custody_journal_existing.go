package workarchive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
)

// OpenExistingCustodyJournalWithLimits replays an active journal under its
// original permanent lock. It never creates or repairs a root, lock, header,
// directory, or evidence file. The returned state is a local observation, not
// permission to perform a live operation without its own decision guard.
func OpenExistingCustodyJournalWithLimits(
	ctx context.Context,
	path string,
	manifest Manifest,
	initialReceipt ReplicaReceipt,
	policy CustodyPolicy,
	limits CustodyJournalLimits,
) (openedJournal *CustodyJournal, openedState CustodyJournalState, returnErr error) {
	if ctx == nil || path == "" {
		return nil, CustodyJournalState{}, ErrCustodyJournal
	}
	if err := ctx.Err(); err != nil {
		return nil, CustodyJournalState{}, err
	}
	if err := limits.Validate(); err != nil {
		return nil, CustodyJournalState{}, err
	}
	if policy.validate() != nil || manifest.Validate() != nil || initialReceipt.verifySignature() != nil {
		return nil, CustodyJournalState{}, ErrCustodyJournal
	}
	manifestID, err := manifest.ID()
	if err != nil || initialReceipt.ManifestID != manifestID ||
		initialReceipt.Binding != manifest.Binding || initialReceipt.AnchorID != manifest.Anchor.ID {
		return nil, CustodyJournalState{}, ErrCustodyJournal
	}
	policyID, err := custodyJournalPolicyID(policy)
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	expected := CustodyJournalHeader{
		Version: CustodyJournalHeaderVersion0, ManifestID: manifestID,
		PolicyID: policyID, InitialReceipt: initialReceipt,
	}
	expectedBytes, err := expected.CanonicalBytes()
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	// Detach caller-owned slices before retaining this immutable configuration.
	manifestBytes, err := manifest.CanonicalBytes()
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	manifest, err = DecodeManifest(manifestBytes)
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	policy.TrustedAuditors = append([][ed25519.PublicKeySize]byte(nil), policy.TrustedAuditors...)
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	// Reject a symlink root before resolving ancestor aliases for stable placement.
	if err := requireCustodyJournalDirectory(path); err != nil {
		return nil, CustodyJournalState{}, err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	rootInfo, err := os.Lstat(path)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, CustodyJournalState{}, errors.Join(ErrCustodyJournal, err)
	}
	lockInfo, err := os.Lstat(filepath.Join(path, custodyJournalLockName))
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Size() != 0 {
		return nil, CustodyJournalState{}, errors.Join(ErrCustodyJournal, err)
	}
	lock, err := acquireCustodyEvidenceLockContext(ctx, path, custodyJournalLockName, false)
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			openedJournal = nil
			openedState = CustodyJournalState{}
			returnErr = errors.Join(returnErr, closeErr)
		}
	}()
	checkIdentity := func() error {
		opened, openErr := lock.Stat()
		root, rootErr := os.Lstat(path)
		currentLock, lockErr := os.Lstat(filepath.Join(path, custodyJournalLockName))
		if openErr != nil || rootErr != nil || lockErr != nil ||
			!os.SameFile(opened, lockInfo) || !os.SameFile(root, rootInfo) ||
			!currentLock.Mode().IsRegular() || currentLock.Size() != 0 || !os.SameFile(currentLock, lockInfo) {
			return errors.Join(ErrCustodyJournal, openErr, rootErr, lockErr)
		}
		return ctx.Err()
	}
	if err := checkIdentity(); err != nil {
		return nil, CustodyJournalState{}, err
	}
	if err := requireActiveCustodyJournal(path); err != nil {
		return nil, CustodyJournalState{}, err
	}
	headerBytes, err := readRegularArchiveFile(filepath.Join(path, custodyJournalHeaderName), MaximumCustodyJournalHeaderBytes)
	if err != nil {
		return nil, CustodyJournalState{}, errors.Join(ErrCustodyJournal, err)
	}
	header, err := DecodeCustodyJournalHeader(headerBytes)
	if err != nil {
		return nil, CustodyJournalState{}, errors.Join(ErrCustodyJournal, err)
	}
	if header.Version != CustodyJournalHeaderVersion0 {
		return nil, CustodyJournalState{}, ErrCustodyJournalHistoricalOnly
	}
	if header != expected || !bytes.Equal(headerBytes, expectedBytes) {
		return nil, CustodyJournalState{}, ErrCustodyJournal
	}
	journal := &CustodyJournal{path: path, header: header, manifest: manifest, policy: policy, limits: limits}
	state, err := journal.scanContext(ctx)
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	if err := checkIdentity(); err != nil {
		return nil, CustodyJournalState{}, err
	}
	if err := requireActiveCustodyJournal(path); err != nil {
		return nil, CustodyJournalState{}, err
	}
	return journal, state, nil
}

// Directory returns the immutable journal root configured when it was opened.
// A path is placement information and does not prove live custody authority.
func (journal *CustodyJournal) Directory() string {
	if journal == nil {
		return ""
	}
	return journal.path
}
