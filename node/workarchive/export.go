package workarchive

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

const manifestFileName = "manifest.omwm"

type ExportOptions struct {
	BlocksPerChunk uint16
	Limits         Limits
}

func DefaultExportOptions() ExportOptions {
	return ExportOptions{BlocksPerChunk: DefaultChunkBlocks, Limits: DefaultLimits()}
}

func (options ExportOptions) Validate() error {
	if options.BlocksPerChunk == 0 || options.BlocksPerChunk > MaximumChunkBlocks ||
		options.Limits.Validate() != nil {
		return ErrArchiveLimit
	}
	return nil
}

// ExportDirectory writes an immutable content-addressed archive into a new
// directory. Selection is captured before block reads and checked again before
// publication. The manifest records that checked snapshot, but callers must
// still run VerifyChain immediately before signing its statement; the archive
// itself never freezes fork choice.
func ExportDirectory(
	path string,
	binding Binding,
	chain *workchain.Store,
	anchorID types.Hash,
	options ExportOptions,
) (Manifest, types.Hash, error) {
	return exportDirectory(path, binding, chain, anchorID, options, nil)
}

func exportDirectory(
	path string,
	binding Binding,
	chain *workchain.Store,
	anchorID types.Hash,
	options ExportOptions,
	beforePublish func() error,
) (Manifest, types.Hash, error) {
	if path == "" || chain == nil || anchorID.IsZero() || binding.Validate() != nil ||
		options.Validate() != nil {
		return Manifest{}, types.Hash{}, ErrArchive
	}
	if _, err := os.Lstat(path); err == nil {
		return Manifest{}, types.Hash{}, ErrArchiveExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, types.Hash{}, err
	}
	history, err := chain.SelectedHistorySnapshot(anchorID, options.Limits.MaximumBlocks)
	if err != nil {
		return Manifest{}, types.Hash{}, err
	}
	if history.BaseID != binding.BaseID || len(history.BlockIDs) == 0 ||
		uint64(len(history.BlockIDs)) > options.Limits.MaximumBlocks ||
		history.Anchor.Height < binding.ActivationHeight ||
		history.AncestryNodes != uint64(len(history.BlockIDs))+1 {
		return Manifest{}, types.Hash{}, ErrArchive
	}

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return Manifest{}, types.Hash{}, err
	}
	temporaryPath, err := os.MkdirTemp(parent, ".outcomemesh-work-archive-*")
	if err != nil {
		return Manifest{}, types.Hash{}, err
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temporaryPath)
		}
	}()

	descriptors := make([]ChunkDescriptor, 0)
	current := make([]workblock.Block, 0, int(options.BlocksPerChunk))
	currentFieldBytes := 0
	var totalChunkBytes uint64
	flush := func() error {
		if len(current) == 0 || len(descriptors) >= int(options.Limits.MaximumChunks) {
			return ErrArchiveLimit
		}
		chunk := Chunk{
			Version: ChunkVersion0, NetworkID: binding.NetworkID, BaseID: binding.BaseID,
			AnchorID: history.Anchor.ID, Index: uint32(len(descriptors)),
			FirstHeight: current[0].Header.Seal.Height,
			Blocks:      append([]workblock.Block(nil), current...),
		}
		encoded, err := chunk.CanonicalBytes()
		if err != nil {
			return err
		}
		if uint64(len(encoded)) > options.Limits.MaximumBytes ||
			totalChunkBytes > options.Limits.MaximumBytes-uint64(len(encoded)) {
			return ErrArchiveLimit
		}
		id := types.DomainHash(chunkIDDomain, encoded)
		lastHeight := current[len(current)-1].Header.Seal.Height
		descriptor := ChunkDescriptor{
			ID: id, Index: chunk.Index, FirstHeight: chunk.FirstHeight,
			LastHeight: lastHeight, BlockCount: uint16(len(current)),
			EncodedBytes: uint32(len(encoded)),
		}
		if err := writeNewArchiveFile(
			filepath.Join(temporaryPath, chunkFileName(chunk.Index)), encoded,
		); err != nil {
			return err
		}
		descriptors = append(descriptors, descriptor)
		totalChunkBytes += uint64(len(encoded))
		current = current[:0]
		currentFieldBytes = 0
		return nil
	}

	for _, id := range history.BlockIDs {
		block, err := chain.BlockByID(id)
		if err != nil {
			return Manifest{}, types.Hash{}, err
		}
		blockID, err := block.Header.ID()
		if err != nil || blockID != id {
			return Manifest{}, types.Hash{}, storage.ErrCorrupt
		}
		blockBytes := block.CanonicalBytes()
		blockFieldBytes := uvarintSize(uint64(len(blockBytes))) + len(blockBytes)
		candidateCount := len(current) + 1
		candidateBytes := 8 + 2 + 4 + 2*types.HashSize + 4 + 8 +
			uvarintSize(uint64(candidateCount)) + currentFieldBytes + blockFieldBytes
		if len(current) == int(options.BlocksPerChunk) ||
			(len(current) > 0 && candidateBytes > MaximumChunkBytes) {
			if err := flush(); err != nil {
				return Manifest{}, types.Hash{}, err
			}
			candidateCount = 1
			candidateBytes = 8 + 2 + 4 + 2*types.HashSize + 4 + 8 +
				uvarintSize(1) + blockFieldBytes
		}
		if candidateCount > MaximumChunkBlocks || candidateBytes > MaximumChunkBytes {
			return Manifest{}, types.Hash{}, ErrChunk
		}
		current = append(current, block)
		currentFieldBytes += blockFieldBytes
	}
	if err := flush(); err != nil {
		return Manifest{}, types.Hash{}, err
	}

	manifest := Manifest{
		Version: ManifestVersion0, Binding: binding, Anchor: history.Anchor,
		AncestryNodes: history.AncestryNodes, AncestryRoot: history.AncestryRoot,
		BlockCount: uint64(len(history.BlockIDs)), TotalChunkBytes: totalChunkBytes,
		Chunks: descriptors,
	}
	if uint32(len(descriptors)) > options.Limits.MaximumChunks {
		return Manifest{}, types.Hash{}, ErrArchiveLimit
	}
	manifestBytes, err := manifest.CanonicalBytes()
	if err != nil {
		return Manifest{}, types.Hash{}, err
	}
	manifestID := types.DomainHash(manifestIDDomain, manifestBytes)
	if err := writeNewArchiveFile(
		filepath.Join(temporaryPath, manifestFileName), manifestBytes,
	); err != nil {
		return Manifest{}, types.Hash{}, err
	}

	if beforePublish != nil {
		if err := beforePublish(); err != nil {
			return Manifest{}, types.Hash{}, errors.Join(ErrArchivePublish, err)
		}
	}
	baseID, baseErr := chain.BaseID()
	tip, tipErr := chain.TipByID(anchorID)
	root, count, ancestryErr := chain.SelectedAncestryCommitment(anchorID)
	if baseErr != nil || tipErr != nil || ancestryErr != nil || baseID != history.BaseID ||
		!storage.EqualTips(tip, history.Anchor) || root != history.AncestryRoot ||
		count != history.AncestryNodes {
		return Manifest{}, types.Hash{}, errors.Join(
			ErrChain, baseErr, tipErr, ancestryErr,
		)
	}
	if err := syncDirectory(temporaryPath); err != nil {
		return Manifest{}, types.Hash{}, err
	}
	if _, err := os.Lstat(path); err == nil {
		return Manifest{}, types.Hash{}, ErrArchiveExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, types.Hash{}, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return Manifest{}, types.Hash{}, err
	}
	published = true
	if err := syncDirectory(parent); err != nil {
		return Manifest{}, types.Hash{}, errors.Join(ErrArchivePublish, err)
	}
	return manifest, manifestID, nil
}

func writeNewArchiveFile(path string, encoded []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	written, err := file.Write(encoded)
	if err != nil {
		return err
	}
	if written != len(encoded) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func chunkFileName(index uint32) string {
	return fmt.Sprintf("chunk-%08d.omwc", index)
}
