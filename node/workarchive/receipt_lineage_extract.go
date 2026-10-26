package workarchive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// CustodyReceiptLineageSource names one existing journal and an independently
// reviewed journal-only checkpoint. Assignment and selected receipt are external
// pins, not values discovered from that journal. Inputs must remain immutable
// during extraction. The output is historical evidence, never live permission.
type CustodyReceiptLineageSource struct {
	JournalPath     string
	Checkpoint      CustodyCheckpoint
	CheckpointID    types.Hash
	Assignment      custodyauthority.Assignment
	AssignmentID    types.Hash
	Manifest        []byte
	InitialReceipt  ReplicaReceipt
	Policy          CustodyPolicy
	SelectedReceipt ReplicaReceipt
}

type receiptLineageExtractHooks struct{ at func(string) error }

func (hooks receiptLineageExtractHooks) reach(point string) error {
	if hooks.at != nil {
		return hooks.at(point)
	}
	return nil
}

type receiptLineageBody struct {
	path string
	info os.FileInfo
}

type receiptLineageSource struct {
	source   CustodyReceiptLineageSource
	manifest Manifest
	rootInfo os.FileInfo
	lockInfo os.FileInfo
	bodies   []receiptLineageBody
}

// ExtractCustodyReceiptLineages returns detached complete prefixes in source
// order. One 1,024-entry/256 MiB budget applies to the ENTIRE batch, including
// every manifest. Counts are checked before replay; every winning body length
// is checked before allocating output bodies. Canonical losing sibling bodies
// remain valid journal history but are never included in the returned prefix.
//
// Existing permanent journal locks are held together, in canonical path order,
// through full checkpoint verification, copying and final source revalidation.
// No directory, lock, journal or artifact is created, repaired, resumed, rotated
// or removed. Valid retired/historical sources remain historical. This function
// does not establish Audit admissions, a unique head, physical durability or
// permission to execute. All source writers must honor the original locks;
// hostile out-of-band mutation and copied-owner fencing remain outside them.
func ExtractCustodyReceiptLineages(ctx context.Context, sources []CustodyReceiptLineageSource) ([]CustodyReceiptLineage, error) {
	return extractCustodyReceiptLineages(ctx, sources, receiptLineageExtractHooks{})
}

func extractCustodyReceiptLineages(ctx context.Context, sources []CustodyReceiptLineageSource,
	hooks receiptLineageExtractHooks,
) (result []CustodyReceiptLineage, err error) {
	var locks []*os.File
	defer func() {
		for i := len(locks) - 1; i >= 0; i-- {
			err = errors.Join(err, locks[i].Close())
		}
		if err != nil {
			result = nil
			err = errors.Join(ErrReceiptLineage, err)
		}
	}()
	if ctx == nil || len(sources) == 0 || len(sources) > MaximumReplicas {
		return nil, ErrReceiptLineage
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	remainingEntries, remainingBytes := uint64(MaximumReceiptLineageEntries), int64(MaximumReceiptLineageBytes)
	seen := make(map[types.Hash]struct{}, len(sources))
	// Reject untrusted count/manifest metadata across ALL sources before parsing
	// manifests, opening a source or allocating any journal/output body.
	for _, source := range sources {
		checkpointID, pinErr := source.Checkpoint.ID()
		assignmentID, assignmentErr := source.Assignment.ID()
		selectedID, selectedErr := source.SelectedReceipt.ID()
		_, duplicate := seen[source.AssignmentID]
		if pinErr != nil || source.CheckpointID.IsZero() || checkpointID != source.CheckpointID ||
			source.Checkpoint.Artifacts != (CustodyCheckpointTree{}) || assignmentErr != nil ||
			source.AssignmentID.IsZero() || assignmentID != source.AssignmentID || duplicate ||
			selectedErr != nil || selectedID != source.Checkpoint.ReceiptID ||
			source.JournalPath == "" || source.InitialReceipt.Version != ReplicaReceiptVersion0 ||
			len(source.Manifest) == 0 || len(source.Manifest) > MaximumManifestBytes ||
			int64(len(source.Manifest)) > remainingBytes || source.Checkpoint.Sequence > remainingEntries ||
			source.Policy.validate() != nil ||
			(source.Checkpoint.Sequence == 0 && source.SelectedReceipt != source.InitialReceipt) {
			return nil, ErrReceiptLineage
		}
		seen[source.AssignmentID] = struct{}{}
		remainingEntries -= source.Checkpoint.Sequence
		remainingBytes -= int64(len(source.Manifest))
	}
	prepared := make([]receiptLineageSource, len(sources))
	// All cryptographic scope checks precede filesystem access, including when
	// another process presently owns a valid journal.
	for i, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		manifest, err := DecodeManifest(source.Manifest)
		if err != nil {
			return nil, err
		}
		canonical, err := manifest.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, source.Manifest) {
			return nil, errors.Join(ErrReceiptLineage, err)
		}
		rebuilt, err := CreateCustodyAuthorityAssignment(manifest, source.InitialReceipt, source.Policy,
			source.Assignment.IncarnationID, source.Assignment.AuthorityPublicKey, source.Assignment.Consumers,
			source.Assignment.MaximumOperations, source.Assignment.MaximumPending)
		if err != nil {
			return nil, err
		}
		rebuiltID, err := rebuilt.ID()
		if err != nil || rebuiltID != source.AssignmentID {
			return nil, errors.Join(ErrReceiptLineage, err)
		}
		prepared[i] = receiptLineageSource{source: source, manifest: manifest}
	}
	order := make([]int, len(prepared))
	for i := range prepared {
		p := &prepared[i]
		path, err := filepath.Abs(p.source.JournalPath)
		if err != nil {
			return nil, err
		}
		// A symlink root is never followed. Existing ancestor aliases resolve to
		// their real paths before overlap checks or lock ordering.
		if err := requireCustodyJournalDirectory(path); err != nil {
			return nil, err
		}
		path, err = filepath.EvalSymlinks(path)
		if err != nil {
			return nil, err
		}
		p.source.JournalPath = path
		p.rootInfo, err = os.Lstat(path)
		if err != nil || !p.rootInfo.IsDir() {
			return nil, errors.Join(ErrReceiptLineage, err)
		}
		p.lockInfo, err = os.Lstat(filepath.Join(path, custodyJournalLockName))
		if err != nil || !p.lockInfo.Mode().IsRegular() || p.lockInfo.Size() != 0 {
			return nil, errors.Join(ErrReceiptLineage, err)
		}
		for j := 0; j < i; j++ {
			if CustodyEvidencePathsOverlap(path, prepared[j].source.JournalPath) ||
				os.SameFile(p.lockInfo, prepared[j].lockInfo) {
				return nil, ErrReceiptLineage
			}
		}
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool {
		return prepared[order[i]].source.JournalPath < prepared[order[j]].source.JournalPath
	})
	for _, i := range order {
		p := &prepared[i]
		lock, err := acquireCustodyEvidenceLockContext(ctx, p.source.JournalPath, custodyJournalLockName, false)
		if err != nil {
			return nil, err
		}
		locks = append(locks, lock)
		opened, err := lock.Stat()
		root, rootErr := os.Lstat(p.source.JournalPath)
		if err != nil || rootErr != nil || !os.SameFile(opened, p.lockInfo) || !os.SameFile(root, p.rootInfo) {
			return nil, errors.Join(err, rootErr, ErrReceiptLineage)
		}
	}
	if err := hooks.reach("locks-acquired"); err != nil {
		return nil, err
	}
	for i := range prepared {
		p := &prepared[i]
		// Hash first, so a changed tree fails before replay allocates its indexes.
		if err := verifyReceiptLineageSourceTree(ctx, p.source); err != nil {
			return nil, err
		}
		headerBytes, err := readRegularArchiveFile(filepath.Join(p.source.JournalPath, custodyJournalHeaderName), MaximumCustodyJournalHeaderBytes)
		if err != nil {
			return nil, err
		}
		header, err := DecodeCustodyJournalHeader(headerBytes)
		if err != nil || header.InitialReceipt != p.source.InitialReceipt ||
			types.DomainHash(custodyCheckpointHeaderDomain, headerBytes) != p.source.Checkpoint.HeaderID {
			return nil, errors.Join(ErrReceiptLineage, err)
		}
		journal := &CustodyJournal{path: p.source.JournalPath, header: header, manifest: p.manifest, policy: p.source.Policy}
		state, err := journal.scanContext(ctx)
		if err != nil || state.Sequence != p.source.Checkpoint.Sequence ||
			state.HeadEntryID != p.source.Checkpoint.HeadEntryID || state.CurrentReceipt != p.source.SelectedReceipt {
			return nil, errors.Join(ErrReceiptLineage, err)
		}
		slots, err := journal.scanSlotsContext(ctx)
		if err != nil || uint64(len(slots)) != p.source.Checkpoint.Sequence {
			return nil, errors.Join(ErrReceiptLineage, err)
		}
		bodies, err := journal.scanBodyPathsContext(ctx)
		if err != nil {
			return nil, err
		}
		p.bodies = make([]receiptLineageBody, len(slots))
		for j, slot := range slots {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			paths := bodies[slot.EntryID]
			if slot.Sequence != uint64(j)+1 || len(paths) == 0 {
				return nil, ErrReceiptLineage
			}
			info, err := os.Lstat(paths[0])
			if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 ||
				info.Size() > MaximumCustodyJournalEntryBytes || info.Size() > remainingBytes {
				return nil, errors.Join(ErrReceiptLineage, err)
			}
			remainingBytes -= info.Size()
			p.bodies[j] = receiptLineageBody{path: paths[0], info: info}
		}
	}
	if err := hooks.reach("before-body-copy"); err != nil {
		return nil, err
	}
	result = make([]CustodyReceiptLineage, len(prepared))
	for i, p := range prepared {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lineage := CustodyReceiptLineage{AssignmentID: p.source.AssignmentID, Manifest: bytes.Clone(p.source.Manifest),
			InitialReceipt: p.source.InitialReceipt, Policy: p.source.Policy, Entries: make([][]byte, len(p.bodies))}
		lineage.Policy.TrustedAuditors = append([][32]byte(nil), p.source.Policy.TrustedAuditors...)
		for j, body := range p.bodies {
			lineage.Entries[j], err = readReceiptLineageBody(ctx, body)
			if err != nil {
				return nil, err
			}
		}
		if err := VerifyCustodyReceiptLineage(ctx, lineage, p.source.Assignment, p.source.AssignmentID, p.source.SelectedReceipt); err != nil {
			return nil, err
		}
		result[i] = lineage
	}
	for _, p := range prepared {
		if err := verifyReceiptLineageSourceTree(ctx, p.source); err != nil {
			return nil, err
		}
	}
	return result, ctx.Err()
}

func verifyReceiptLineageSourceTree(ctx context.Context, source CustodyReceiptLineageSource) error {
	tree, err := walkCustodyEvidenceTree(ctx, source.JournalPath, "", source.Checkpoint.Journal.Bytes, source.Checkpoint.Journal.Paths)
	if err != nil || tree != source.Checkpoint.Journal {
		return errors.Join(ErrCustodyCheckpointMismatch, err)
	}
	return nil
}

func readReceiptLineageBody(ctx context.Context, body receiptLineageBody) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open(body.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	current, currentErr := os.Lstat(body.path)
	if err != nil || currentErr != nil || !sameCustodyEvidenceFile(body.info, opened) || !sameCustodyEvidenceFile(body.info, current) {
		return nil, errors.Join(ErrReceiptLineage, err, currentErr)
	}
	encoded := make([]byte, int(body.info.Size())) // charged across all sources before this allocation
	for offset := 0; offset < len(encoded); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := min(offset+(64<<10), len(encoded))
		if _, err := io.ReadFull(file, encoded[offset:end]); err != nil {
			return nil, err
		}
		offset = end
	}
	var trailing [1]byte
	if n, err := file.Read(trailing[:]); n != 0 || !errors.Is(err, io.EOF) {
		return nil, errors.Join(ErrReceiptLineage, err)
	}
	current, err = os.Lstat(body.path)
	if err != nil || !sameCustodyEvidenceFile(body.info, current) {
		return nil, errors.Join(ErrReceiptLineage, err)
	}
	return encoded, ctx.Err()
}
