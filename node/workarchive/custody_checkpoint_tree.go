package workarchive

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/codec"
)

const (
	custodyCheckpointFileDomain      = "OMESH/workgraph/archive/custody-checkpoint/file/v0"
	custodyCheckpointDirectoryDomain = "OMESH/workgraph/archive/custody-checkpoint/directory/v0"
)

// Payloads are streamed; directory metadata is bounded before sorting. The
// depth ceiling matches journals, and includes the shallower auditor layout.
// The caller holds both writer locks; hostile out-of-band mutation is not a
// supported filesystem model, but changed inodes/sizes/timestamps fail closed.
func digestCustodyEvidenceTree(root string, maximumBytes, maximumPaths uint64) (CustodyCheckpointTree, error) {
	if maximumPaths == 0 || maximumPaths > MaximumCustodyJournalPaths || maximumBytes > MaximumCustodyJournalBytes {
		return CustodyCheckpointTree{}, ErrCustodyCheckpoint
	}
	if err := requireCustodyJournalDirectory(root); err != nil {
		return CustodyCheckpointTree{}, err
	}
	discovered := uint64(1) // root; children are charged before retaining metadata
	var totalBytes uint64
	buffer := make([]byte, 32*1024)
	var visit func(string, int) (CustodyCheckpointTree, byte, error)
	visit = func(path string, depth int) (CustodyCheckpointTree, byte, error) {
		fail := func(err error) (CustodyCheckpointTree, byte, error) {
			return CustodyCheckpointTree{}, 0, errors.Join(ErrCustodyCheckpoint, err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fail(err)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fail(errors.New("evidence path is not a regular file or real directory"))
		}
		if info.IsDir() && depth > 3 {
			return fail(errors.New("evidence directory depth exceeds 3"))
		}
		file, err := os.Open(path)
		if err != nil {
			return fail(err)
		}
		defer file.Close()
		opened, err := file.Stat()
		if err != nil || !sameCustodyEvidenceFile(info, opened) {
			return fail(err)
		}
		tree := CustodyCheckpointTree{Paths: 1}
		hasher := sha256.New()
		kind := byte(0)
		if info.IsDir() {
			kind = 1
			_, _ = hasher.Write([]byte(custodyCheckpointDirectoryDomain))
			var entries []os.DirEntry
			for {
				batch, readErr := file.ReadDir(128)
				if uint64(len(batch)) > maximumPaths-discovered {
					return fail(fmt.Errorf("evidence path ceiling %d", maximumPaths))
				}
				discovered += uint64(len(batch))
				entries = append(entries, batch...)
				if errors.Is(readErr, io.EOF) {
					break
				}
				if readErr != nil {
					return fail(readErr)
				}
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			count := codec.NewEncoder(8)
			count.U64(uint64(len(entries)))
			_, _ = hasher.Write(count.Bytes())
			for _, entry := range entries {
				child, childKind, err := visit(filepath.Join(path, entry.Name()), depth+1)
				if err != nil {
					return fail(err)
				}
				encoded := codec.NewEncoder(len(entry.Name()) + 64)
				encoded.BytesField([]byte(entry.Name()))
				encoded.U8(childKind)
				encoded.Fixed(child.ID[:])
				encoded.U64(child.Bytes)
				encoded.U64(child.Paths)
				_, _ = hasher.Write(encoded.Bytes())
				tree.Bytes += child.Bytes // bounded by the shared byte/path counters
				tree.Paths += child.Paths
			}
		} else {
			if info.Size() < 0 || uint64(info.Size()) > maximumBytes-totalBytes {
				return fail(fmt.Errorf("evidence byte ceiling %d", maximumBytes))
			}
			tree.Bytes = uint64(info.Size())
			totalBytes += tree.Bytes
			_, _ = hasher.Write([]byte(custodyCheckpointFileDomain))
			written, err := io.CopyBuffer(hasher, io.LimitReader(file, info.Size()+1), buffer)
			if err != nil || written != info.Size() {
				return fail(err)
			}
		}
		current, err := os.Lstat(path)
		if err != nil || !sameCustodyEvidenceFile(info, current) {
			return fail(err)
		}
		copy(tree.ID[:], hasher.Sum(nil))
		return tree, kind, nil
	}
	tree, _, err := visit(filepath.Clean(root), 0)
	return tree, err
}

func sameCustodyEvidenceFile(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) &&
		left.Mode() == right.Mode() && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}
