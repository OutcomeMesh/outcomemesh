package workarchive

import (
	"context"
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
	return walkCustodyEvidenceTree(context.Background(), root, "", maximumBytes, maximumPaths)
}

// A nonempty destination enables a no-replace streaming copy while hashing the
// same bytes. All created files have separate inodes, even source hard links.
// Failed or canceled copies remain incomplete; this walker never removes them.
func walkCustodyEvidenceTree(ctx context.Context, root, destination string, maximumBytes, maximumPaths uint64) (CustodyCheckpointTree, error) {
	if ctx == nil {
		return CustodyCheckpointTree{}, ErrCustodyCheckpoint
	}
	if maximumPaths == 0 || maximumPaths > MaximumCustodyJournalPaths || maximumBytes > MaximumCustodyJournalBytes {
		return CustodyCheckpointTree{}, ErrCustodyCheckpoint
	}
	if err := requireCustodyJournalDirectory(root); err != nil {
		return CustodyCheckpointTree{}, err
	}
	discovered := uint64(1) // root; children are charged before retaining metadata
	var totalBytes uint64
	buffer := make([]byte, 32*1024)
	var visit func(string, string, int) (CustodyCheckpointTree, byte, error)
	visit = func(path, target string, depth int) (CustodyCheckpointTree, byte, error) {
		fail := func(err error) (CustodyCheckpointTree, byte, error) {
			return CustodyCheckpointTree{}, 0, errors.Join(ErrCustodyCheckpoint, err)
		}
		if err := ctx.Err(); err != nil {
			return fail(err)
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
			if target != "" {
				if err := os.Mkdir(target, 0o700); err != nil {
					return fail(err)
				}
			}
			kind = 1
			_, _ = hasher.Write([]byte(custodyCheckpointDirectoryDomain))
			var entries []os.DirEntry
			for {
				if err := ctx.Err(); err != nil {
					return fail(err)
				}
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
				childTarget := ""
				if target != "" {
					childTarget = filepath.Join(target, entry.Name())
				}
				child, childKind, err := visit(filepath.Join(path, entry.Name()), childTarget, depth+1)
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
			if target != "" {
				if err := syncDirectory(target); err != nil {
					return fail(err)
				}
			}
		} else {
			if info.Size() < 0 || uint64(info.Size()) > maximumBytes-totalBytes {
				return fail(fmt.Errorf("evidence byte ceiling %d", maximumBytes))
			}
			tree.Bytes = uint64(info.Size())
			totalBytes += tree.Bytes
			_, _ = hasher.Write([]byte(custodyCheckpointFileDomain))
			var writer io.Writer = hasher
			var output *os.File
			if target != "" {
				output, err = os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
				if err != nil {
					return fail(err)
				}
				defer output.Close()
				writer = io.MultiWriter(hasher, output)
			}
			reader := custodyEvidenceContextReader{ctx: ctx, reader: io.LimitReader(file, info.Size()+1)}
			written, err := io.CopyBuffer(writer, reader, buffer)
			if err != nil || written != info.Size() {
				return fail(err)
			}
			if output != nil {
				if err := output.Sync(); err != nil {
					return fail(err)
				}
				if err := output.Close(); err != nil {
					return fail(err)
				}
			}
		}
		current, err := os.Lstat(path)
		if err != nil || !sameCustodyEvidenceFile(info, current) {
			return fail(err)
		}
		copy(tree.ID[:], hasher.Sum(nil))
		return tree, kind, nil
	}
	tree, _, err := visit(filepath.Clean(root), destination, 0)
	if err == nil && destination != "" {
		err = syncDirectory(filepath.Dir(destination))
	}
	return tree, err
}

type custodyEvidenceContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader custodyEvidenceContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func sameCustodyEvidenceFile(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) &&
		left.Mode() == right.Mode() && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}
