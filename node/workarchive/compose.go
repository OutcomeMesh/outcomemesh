package workarchive

import (
	"bytes"
	"errors"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

// ComposeDirectory builds a new self-contained version-0 archive after local
// canonical pruning. The already archived prefix is read from the exact
// manifest recorded in the retained floor; only the executable suffix is read
// from WorkChain. Every source byte is checked again and the selected ancestry
// and floor are rechecked immediately before atomic publication.
func ComposeDirectory(
	path string,
	previousArchivePath string,
	previousCheckpoint Checkpoint,
	policy Policy,
	base workchain.Base,
	parameters workblock.Parameters,
	chain *workchain.Store,
	anchorID types.Hash,
	options ExportOptions,
) (Manifest, types.Hash, error) {
	return composeDirectory(
		path, previousArchivePath, previousCheckpoint, policy, base, parameters,
		chain, anchorID, options, nil,
	)
}

func composeDirectory(
	path string,
	previousArchivePath string,
	previousCheckpoint Checkpoint,
	policy Policy,
	base workchain.Base,
	parameters workblock.Parameters,
	chain *workchain.Store,
	anchorID types.Hash,
	options ExportOptions,
	beforePublish func() error,
) (Manifest, types.Hash, error) {
	if path == "" || previousArchivePath == "" || chain == nil || anchorID.IsZero() ||
		options.Validate() != nil {
		return Manifest{}, types.Hash{}, ErrArchiveCompose
	}
	previousResolved, err := resolvedArchivePath(previousArchivePath)
	if err != nil {
		return Manifest{}, types.Hash{}, errors.Join(ErrArchiveCompose, err)
	}
	destinationResolved, err := resolvedArchivePath(path)
	if err != nil || pathContains(previousResolved, destinationResolved) {
		return Manifest{}, types.Hash{}, errors.Join(ErrArchiveCompose, err)
	}
	previous, err := VerifyArchiveDirectory(
		previousArchivePath, previousCheckpoint, policy, base, parameters, options.Limits,
	)
	if err != nil {
		return Manifest{}, types.Hash{}, errors.Join(ErrArchiveCompose, err)
	}
	previousManifestID, err := previous.ID()
	if err != nil {
		return Manifest{}, types.Hash{}, errors.Join(ErrArchiveCompose, err)
	}
	previousStatementID, err := previousCheckpoint.Statement.ID()
	if err != nil {
		return Manifest{}, types.Hash{}, errors.Join(ErrArchiveCompose, err)
	}
	floor, err := chain.CanonicalFloor()
	if err != nil || !floor.Pruned || floor.BaseID != policy.Binding.BaseID ||
		!storage.EqualTips(floor.Anchor, previous.Anchor) ||
		floor.AncestryNodes != previous.AncestryNodes || floor.AncestryRoot != previous.AncestryRoot ||
		floor.StatementID != previousStatementID || floor.ManifestID != previousManifestID {
		return Manifest{}, types.Hash{}, errors.Join(ErrArchiveCompose, err)
	}
	history, err := chain.SelectedHistorySnapshot(anchorID, options.Limits.MaximumBlocks)
	if err != nil {
		return Manifest{}, types.Hash{}, errors.Join(ErrArchiveCompose, err)
	}
	if history.BaseID != policy.Binding.BaseID || history.AncestryRoot.IsZero() ||
		history.AncestryNodes != uint64(len(history.BlockIDs))+1 ||
		previous.BlockCount >= uint64(len(history.BlockIDs)) ||
		history.BlockIDs[int(previous.BlockCount)-1] != previous.Anchor.ID {
		return Manifest{}, types.Hash{}, ErrArchiveCompose
	}
	plan := archivePlan{
		Anchor: history.Anchor, AncestryNodes: history.AncestryNodes,
		AncestryRoot: history.AncestryRoot, BlockCount: uint64(len(history.BlockIDs)),
	}
	stream := func(yield func(workblock.Block) error) error {
		if err := streamArchiveBlocks(
			previousArchivePath, previous, options.Limits, yield,
		); err != nil {
			return errors.Join(ErrArchiveCompose, err)
		}
		for _, id := range history.BlockIDs[int(previous.BlockCount):] {
			block, readErr := chain.BlockByID(id)
			if readErr != nil {
				return errors.Join(ErrArchiveCompose, readErr)
			}
			blockID, idErr := block.Header.ID()
			if idErr != nil || blockID != id {
				return errors.Join(ErrArchiveCompose, storage.ErrCorrupt)
			}
			if err := yield(block); err != nil {
				return err
			}
		}
		return nil
	}
	verifySelection := func() error {
		currentFloor, floorErr := chain.CanonicalFloor()
		baseID, baseErr := chain.BaseID()
		tip, tipErr := chain.TipByID(anchorID)
		root, count, ancestryErr := chain.SelectedAncestryCommitment(anchorID)
		if floorErr != nil || baseErr != nil || tipErr != nil || ancestryErr != nil ||
			!equalCompositionFloor(currentFloor, floor) || baseID != history.BaseID ||
			!storage.EqualTips(tip, history.Anchor) || root != history.AncestryRoot ||
			count != history.AncestryNodes {
			return errors.Join(
				ErrChain, ErrArchiveCompose, floorErr, baseErr, tipErr, ancestryErr,
			)
		}
		return nil
	}
	manifest, manifestID, err := publishArchiveDirectory(
		path, policy.Binding, plan, options, stream, beforePublish, verifySelection,
	)
	if err != nil {
		return Manifest{}, types.Hash{}, errors.Join(ErrArchiveCompose, err)
	}
	return manifest, manifestID, nil
}

func streamArchiveBlocks(
	path string,
	manifest Manifest,
	limits Limits,
	yield func(workblock.Block) error,
) error {
	if path == "" || manifest.Validate() != nil || limits.Validate() != nil || yield == nil ||
		manifest.BlockCount > limits.MaximumBlocks ||
		uint32(len(manifest.Chunks)) > limits.MaximumChunks ||
		manifest.TotalChunkBytes > limits.MaximumBytes {
		return ErrArchiveCompose
	}
	manifestBytes, err := manifest.CanonicalBytes()
	if err != nil {
		return err
	}
	currentManifestBytes, err := readRegularArchiveFile(
		filepath.Join(path, manifestFileName), MaximumManifestBytes,
	)
	if err != nil || !bytes.Equal(currentManifestBytes, manifestBytes) {
		return errors.Join(ErrArchiveCompose, err)
	}
	if err := verifyArchiveDirectoryEntries(path, manifest); err != nil {
		return err
	}
	expectedParent := manifest.Binding.BaseID
	expectedHeight := manifest.Binding.ActivationHeight
	var blockCount uint64
	var totalBytes uint64
	for index, descriptor := range manifest.Chunks {
		encoded, err := readRegularArchiveFile(
			filepath.Join(path, chunkFileName(uint32(index))), MaximumChunkBytes,
		)
		if err != nil || len(encoded) != int(descriptor.EncodedBytes) ||
			types.DomainHash(chunkIDDomain, encoded) != descriptor.ID {
			return errors.Join(ErrChunk, err)
		}
		chunk, err := DecodeChunk(encoded)
		if err != nil {
			return err
		}
		canonical, err := chunk.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, encoded) || chunk.Index != descriptor.Index ||
			chunk.NetworkID != manifest.Binding.NetworkID || chunk.BaseID != manifest.Binding.BaseID ||
			chunk.AnchorID != manifest.Anchor.ID || chunk.FirstHeight != descriptor.FirstHeight ||
			len(chunk.Blocks) != int(descriptor.BlockCount) {
			return errors.Join(ErrChunk, err)
		}
		for _, block := range chunk.Blocks {
			if block.Header.Seal.Height != expectedHeight ||
				block.Header.Seal.AnchorParent != expectedParent {
				return ErrArchiveOrder
			}
			blockID, err := block.Header.ID()
			if err != nil {
				return err
			}
			if err := yield(block); err != nil {
				return err
			}
			expectedParent = blockID
			blockCount++
			if blockCount < manifest.BlockCount {
				if expectedHeight == ^uint64(0) {
					return ErrArchiveOrder
				}
				expectedHeight++
			}
		}
		if uint64(len(encoded)) > limits.MaximumBytes ||
			totalBytes > limits.MaximumBytes-uint64(len(encoded)) {
			return ErrArchiveLimit
		}
		totalBytes += uint64(len(encoded))
	}
	if blockCount != manifest.BlockCount || totalBytes != manifest.TotalChunkBytes ||
		expectedParent != manifest.Anchor.ID {
		return ErrArchiveCompose
	}
	return nil
}

func equalCompositionFloor(left, right workchain.CanonicalFloor) bool {
	return left.Pruned == right.Pruned && left.BaseID == right.BaseID &&
		storage.EqualTips(left.Anchor, right.Anchor) && left.AncestryNodes == right.AncestryNodes &&
		left.AncestryRoot == right.AncestryRoot && left.StatementID == right.StatementID &&
		left.ManifestID == right.ManifestID && left.AvailabilityID == right.AvailabilityID &&
		left.VerifiedAt == right.VerifiedAt && left.RetainUntil == right.RetainUntil
}
