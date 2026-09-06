package workarchive

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	CustodyCheckpointVersion0     uint16 = 0
	MaximumCustodyCheckpointBytes        = 210
	custodyCheckpointIDDomain            = "OMESH/workgraph/archive/custody-checkpoint/id/v0"
	custodyCheckpointHeaderDomain        = "OMESH/workgraph/archive/custody-checkpoint/header/v0"
)

var (
	ErrCustodyCheckpoint         = errors.New("invalid custody evidence checkpoint")
	ErrCustodyCheckpointMismatch = errors.New("custody evidence does not match the independently retained checkpoint")
	custodyCheckpointMagic       = [8]byte{'O', 'M', 'W', 'A', 'C', 'C', 'P', 'T'}
)

// CustodyCheckpointTree commits to every relative name, directory, and regular
// file's bytes. It does not commit to timestamps, permissions, or inode numbers.
type CustodyCheckpointTree struct {
	ID    types.Hash
	Bytes uint64
	Paths uint64
}

// CustodyCheckpoint is a point-in-time inventory, not a signed decision or a
// backup. Keep its ID outside the backup's failure/rollback domain. Artifacts
// must be present for an auditor: an uncommitted signed request is not in Head.
type CustodyCheckpoint struct {
	Version     uint16
	HeaderID    types.Hash
	Sequence    uint64
	HeadEntryID types.Hash
	ReceiptID   types.Hash
	Journal     CustodyCheckpointTree
	Artifacts   CustodyCheckpointTree
}

func (checkpoint CustodyCheckpoint) validate() error {
	validTree := func(tree CustodyCheckpointTree) bool {
		return !tree.ID.IsZero() && tree.Paths != 0 &&
			tree.Paths <= MaximumCustodyJournalPaths && tree.Bytes <= MaximumCustodyJournalBytes
	}
	if checkpoint.Version != CustodyCheckpointVersion0 || checkpoint.HeaderID.IsZero() ||
		checkpoint.ReceiptID.IsZero() || (checkpoint.Sequence == 0) != checkpoint.HeadEntryID.IsZero() ||
		!validTree(checkpoint.Journal) ||
		(checkpoint.Artifacts != (CustodyCheckpointTree{}) && !validTree(checkpoint.Artifacts)) {
		return ErrCustodyCheckpoint
	}
	return nil
}

func (checkpoint CustodyCheckpoint) CanonicalBytes() ([]byte, error) {
	if err := checkpoint.validate(); err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(MaximumCustodyCheckpointBytes)
	encoder.Fixed(custodyCheckpointMagic[:])
	encoder.U16(checkpoint.Version)
	encoder.Fixed(checkpoint.HeaderID[:])
	encoder.U64(checkpoint.Sequence)
	encoder.Fixed(checkpoint.HeadEntryID[:])
	encoder.Fixed(checkpoint.ReceiptID[:])
	for _, tree := range []CustodyCheckpointTree{checkpoint.Journal, checkpoint.Artifacts} {
		encoder.Fixed(tree.ID[:])
		encoder.U64(tree.Bytes)
		encoder.U64(tree.Paths)
	}
	return encoder.Bytes(), nil
}

func DecodeCustodyCheckpoint(input []byte) (CustodyCheckpoint, error) {
	if len(input) != MaximumCustodyCheckpointBytes {
		return CustodyCheckpoint{}, ErrCustodyCheckpoint
	}
	// Every field is fixed-width; the exact length check covers all reads below.
	decoder := codec.NewDecoder(input)
	magic, _ := decoder.Fixed(len(custodyCheckpointMagic))
	var checkpoint CustodyCheckpoint
	checkpoint.Version, _ = decoder.U16()
	header, _ := decoder.Fixed(types.HashSize)
	copy(checkpoint.HeaderID[:], header)
	checkpoint.Sequence, _ = decoder.U64()
	head, _ := decoder.Fixed(types.HashSize)
	copy(checkpoint.HeadEntryID[:], head)
	receipt, _ := decoder.Fixed(types.HashSize)
	copy(checkpoint.ReceiptID[:], receipt)
	for _, tree := range []*CustodyCheckpointTree{&checkpoint.Journal, &checkpoint.Artifacts} {
		id, _ := decoder.Fixed(types.HashSize)
		copy(tree.ID[:], id)
		tree.Bytes, _ = decoder.U64()
		tree.Paths, _ = decoder.U64()
	}
	if !bytes.Equal(magic, custodyCheckpointMagic[:]) || decoder.Finish() != nil || checkpoint.validate() != nil {
		return CustodyCheckpoint{}, ErrCustodyCheckpoint
	}
	return checkpoint, nil
}

func (checkpoint CustodyCheckpoint) ID() (types.Hash, error) {
	encoded, err := checkpoint.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(custodyCheckpointIDDomain, encoded), nil
}

// CaptureCustodyCheckpoint replays an existing journal and inventories it while
// holding the artifact lock, then the journal lock. Only an absent artifact lock
// may be created; no journal initialization, rotation repair, or cleanup occurs.
// Empty artifactsPath explicitly selects a replica-only checkpoint. All writers
// must honor these locks. Stop them before making a separate filesystem copy.
func CaptureCustodyCheckpoint(
	journalPath, artifactsPath string, manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) (CustodyCheckpoint, error) {
	return captureCustodyCheckpoint(journalPath, artifactsPath, manifest, initial, policy, true)
}

// VerifyCustodyCheckpoint checks the externally pinned ID before touching the
// candidate directories, then requires exact inventory equality and full replay.
// It never initializes or repairs the copy. A newer valid head is not an exact
// copy either; reconciliation is a separate operator decision.
func VerifyCustodyCheckpoint(
	expected CustodyCheckpoint, expectedID types.Hash,
	journalPath, artifactsPath string, manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) error {
	id, err := expected.ID()
	if err != nil || expectedID.IsZero() || id != expectedID ||
		(artifactsPath == "") != (expected.Artifacts == (CustodyCheckpointTree{})) {
		return errors.Join(ErrCustodyCheckpointMismatch, err)
	}
	actual, err := captureCustodyCheckpoint(journalPath, artifactsPath, manifest, initial, policy, false)
	if err != nil {
		return errors.Join(ErrCustodyCheckpointMismatch, err)
	}
	if actual != expected {
		return ErrCustodyCheckpointMismatch
	}
	return nil
}

func captureCustodyCheckpoint(
	journalPath, artifactsPath string, manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
	createArtifactLock bool,
) (CustodyCheckpoint, error) {
	if journalPath == "" || manifest.Validate() != nil || initial.verifySignature() != nil || policy.validate() != nil {
		return CustodyCheckpoint{}, ErrCustodyCheckpoint
	}
	if artifactsPath != "" {
		if CustodyEvidencePathsOverlap(journalPath, artifactsPath) {
			return CustodyCheckpoint{}, fmt.Errorf("%w: journal and artifacts must be separate", ErrCustodyCheckpoint)
		}
		lock, err := acquireCustodyEvidenceLock(artifactsPath, custodyArtifactsLockName, createArtifactLock)
		if err != nil {
			return CustodyCheckpoint{}, err
		}
		defer lock.Close()
	}
	lock, err := acquireCustodyEvidenceLock(journalPath, custodyJournalLockName, false)
	if err != nil {
		return CustodyCheckpoint{}, err
	}
	defer lock.Close()
	headerBytes, err := readRegularArchiveFile(filepath.Join(journalPath, custodyJournalHeaderName), MaximumCustodyJournalHeaderBytes)
	if err != nil {
		return CustodyCheckpoint{}, err
	}
	header, err := DecodeCustodyJournalHeader(headerBytes)
	if err != nil || header.InitialReceipt != initial {
		return CustodyCheckpoint{}, errors.Join(ErrCustodyCheckpoint, err)
	}
	// scan validates the manifest/policy binding and every historical decision.
	journal := &CustodyJournal{path: journalPath, header: header, manifest: manifest, policy: policy}
	state, err := journal.scan()
	if err != nil {
		return CustodyCheckpoint{}, err
	}
	receiptID, err := state.CurrentReceipt.ID()
	if err != nil {
		return CustodyCheckpoint{}, err
	}
	checkpoint := CustodyCheckpoint{
		Version:  CustodyCheckpointVersion0,
		HeaderID: types.DomainHash(custodyCheckpointHeaderDomain, headerBytes),
		Sequence: state.Sequence, HeadEntryID: state.HeadEntryID, ReceiptID: receiptID,
	}
	checkpoint.Journal, err = digestCustodyEvidenceTree(journalPath, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
	if err != nil {
		return CustodyCheckpoint{}, err
	}
	if artifactsPath != "" {
		checkpoint.Artifacts, err = digestCustodyEvidenceTree(artifactsPath, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
		if err != nil {
			return CustodyCheckpoint{}, err
		}
	}
	return checkpoint, checkpoint.validate()
}

// CustodyEvidencePathsOverlap resolves existing symlink ancestors even when a
// destination does not exist yet. Existing inode ancestry also catches case
// aliases on case-insensitive volumes. Resolution errors fail closed.
func CustodyEvidencePathsOverlap(left, right string) bool {
	left, leftErr := resolveCustodyEvidencePath(left)
	right, rightErr := resolveCustodyEvidencePath(right)
	if leftErr != nil || rightErr != nil {
		return true
	}
	contains := func(parent, child string) bool {
		relative, err := filepath.Rel(parent, child)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
		parentInfo, err := os.Stat(parent)
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		if err != nil {
			return true
		}
		for {
			childInfo, err := os.Stat(child)
			if err == nil && os.SameFile(parentInfo, childInfo) {
				return true
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return true
			}
			next := filepath.Dir(child)
			if next == child {
				return false
			}
			child = next
		}
	}
	return contains(left, right) || contains(right, left)
}

func resolveCustodyEvidencePath(path string) (string, error) {
	if path == "" {
		return "", ErrCustodyCheckpoint
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var suffix []string
	for {
		if _, err := os.Lstat(path); err == nil {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return "", err
			}
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return resolved, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", ErrCustodyCheckpoint
		}
		suffix = append(suffix, filepath.Base(path))
		path = parent
	}
}
