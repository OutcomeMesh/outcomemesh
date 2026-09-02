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

type archivePlan struct {
	Anchor        storage.Tip
	AncestryNodes uint64
	AncestryRoot  types.Hash
	BlockCount    uint64
}

type archiveBlockStream func(func(workblock.Block) error) error

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
	plan := archivePlan{
		Anchor: history.Anchor, AncestryNodes: history.AncestryNodes,
		AncestryRoot: history.AncestryRoot, BlockCount: uint64(len(history.BlockIDs)),
	}
	stream := func(yield func(workblock.Block) error) error {
		for _, id := range history.BlockIDs {
			block, readErr := chain.BlockByID(id)
			if readErr != nil {
				return readErr
			}
			blockID, idErr := block.Header.ID()
			if idErr != nil || blockID != id {
				return storage.ErrCorrupt
			}
			if err := yield(block); err != nil {
				return err
			}
		}
		return nil
	}
	verifySelection := func() error {
		baseID, baseErr := chain.BaseID()
		tip, tipErr := chain.TipByID(anchorID)
		root, count, ancestryErr := chain.SelectedAncestryCommitment(anchorID)
		if baseErr != nil || tipErr != nil || ancestryErr != nil || baseID != history.BaseID ||
			!storage.EqualTips(tip, history.Anchor) || root != history.AncestryRoot ||
			count != history.AncestryNodes {
			return errors.Join(ErrChain, baseErr, tipErr, ancestryErr)
		}
		return nil
	}
	return publishArchiveDirectory(
		path, binding, plan, options, stream, beforePublish, verifySelection,
	)
}

func publishArchiveDirectory(
	path string,
	binding Binding,
	plan archivePlan,
	options ExportOptions,
	stream archiveBlockStream,
	beforePublish func() error,
	verifySelection func() error,
) (Manifest, types.Hash, error) {
	if path == "" || binding.Validate() != nil || plan.Anchor.Validate() != nil ||
		plan.Anchor.Height < binding.ActivationHeight || plan.AncestryRoot.IsZero() ||
		plan.BlockCount == 0 || plan.BlockCount > options.Limits.MaximumBlocks ||
		plan.AncestryNodes != plan.BlockCount+1 || options.Validate() != nil || stream == nil {
		return Manifest{}, types.Hash{}, ErrArchive
	}
	if _, err := os.Lstat(path); err == nil {
		return Manifest{}, types.Hash{}, ErrArchiveExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, types.Hash{}, err
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
			AnchorID: plan.Anchor.ID, Index: uint32(len(descriptors)),
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
		descriptor := ChunkDescriptor{
			ID: id, Index: chunk.Index, FirstHeight: chunk.FirstHeight,
			LastHeight: current[len(current)-1].Header.Seal.Height,
			BlockCount: uint16(len(current)), EncodedBytes: uint32(len(encoded)),
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

	expectedParent := binding.BaseID
	expectedHeight := binding.ActivationHeight
	var blockCount uint64
	emit := func(block workblock.Block) error {
		if blockCount >= plan.BlockCount || block.ValidateBasic() != nil ||
			block.Header.Seal.NetworkID != binding.NetworkID ||
			block.Header.Seal.Height != expectedHeight ||
			block.Header.Seal.AnchorParent != expectedParent {
			return ErrArchiveOrder
		}
		blockID, err := block.Header.ID()
		if err != nil {
			return err
		}
		blockBytes := block.CanonicalBytes()
		blockFieldBytes := uvarintSize(uint64(len(blockBytes))) + len(blockBytes)
		candidateCount := len(current) + 1
		candidateBytes := 8 + 2 + 4 + 2*types.HashSize + 4 + 8 +
			uvarintSize(uint64(candidateCount)) + currentFieldBytes + blockFieldBytes
		if len(current) == int(options.BlocksPerChunk) ||
			(len(current) > 0 && candidateBytes > MaximumChunkBytes) {
			if err := flush(); err != nil {
				return err
			}
			candidateCount = 1
			candidateBytes = 8 + 2 + 4 + 2*types.HashSize + 4 + 8 +
				uvarintSize(1) + blockFieldBytes
		}
		if candidateCount > MaximumChunkBlocks || candidateBytes > MaximumChunkBytes {
			return ErrChunk
		}
		current = append(current, block)
		currentFieldBytes += blockFieldBytes
		blockCount++
		expectedParent = blockID
		if blockCount < plan.BlockCount {
			if expectedHeight == ^uint64(0) {
				return ErrArchiveOrder
			}
			expectedHeight++
		}
		return nil
	}
	if err := stream(emit); err != nil {
		return Manifest{}, types.Hash{}, err
	}
	if blockCount != plan.BlockCount || expectedParent != plan.Anchor.ID {
		return Manifest{}, types.Hash{}, ErrArchiveOrder
	}
	if err := flush(); err != nil {
		return Manifest{}, types.Hash{}, err
	}

	manifest := Manifest{
		Version: ManifestVersion0, Binding: binding, Anchor: plan.Anchor,
		AncestryNodes: plan.AncestryNodes, AncestryRoot: plan.AncestryRoot,
		BlockCount: blockCount, TotalChunkBytes: totalChunkBytes, Chunks: descriptors,
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
	if verifySelection != nil {
		if err := verifySelection(); err != nil {
			return Manifest{}, types.Hash{}, err
		}
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
