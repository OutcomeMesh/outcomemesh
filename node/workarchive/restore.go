package workarchive

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

type replayChain interface {
	BaseID() (types.Hash, error)
	Tip() (storage.Tip, error)
	Commit(workblock.Block, uint64) (storage.Tip, workblock.Result, error)
	SelectedAncestryCommitment(types.Hash) (types.Hash, uint64, error)
}

type restoreHooks struct {
	beforePublish func() error
	afterPublish  func()
}

// VerifyArchiveDirectory strictly verifies every content-addressed chunk and
// replays every block through a fresh in-memory WorkChain. A matching state
// root is therefore derived from consensus execution, not trusted archive
// state.
func VerifyArchiveDirectory(
	path string,
	checkpoint Checkpoint,
	policy Policy,
	base workchain.Base,
	parameters workblock.Parameters,
	limits Limits,
) (Manifest, error) {
	chain, err := workchain.New(base, parameters)
	if err != nil {
		return Manifest{}, err
	}
	return replayArchiveDirectory(path, checkpoint, policy, base, parameters, limits, chain)
}

// RestoreDirectory replays a verified archive into a new Pebble WorkChain
// directory, closes and fully reopens the temporary database, then publishes
// it with a directory rename and parent fsync. Existing destinations are never
// replaced.
func RestoreDirectory(
	archivePath string,
	destinationPath string,
	checkpoint Checkpoint,
	policy Policy,
	base workchain.Base,
	parameters workblock.Parameters,
	limits Limits,
	workPolicy workchain.Policy,
) (Manifest, error) {
	return restoreDirectory(
		archivePath, destinationPath, checkpoint, policy, base, parameters,
		limits, workPolicy, restoreHooks{},
	)
}

func restoreDirectory(
	archivePath string,
	destinationPath string,
	checkpoint Checkpoint,
	policy Policy,
	base workchain.Base,
	parameters workblock.Parameters,
	limits Limits,
	workPolicy workchain.Policy,
	hooks restoreHooks,
) (Manifest, error) {
	if archivePath == "" || destinationPath == "" || limits.Validate() != nil {
		return Manifest{}, ErrArchive
	}
	if _, err := os.Lstat(destinationPath); err == nil {
		return Manifest{}, ErrArchiveExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	parent := filepath.Dir(destinationPath)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return Manifest{}, err
	}
	temporaryPath, err := os.MkdirTemp(parent, ".outcomemesh-work-restore-*")
	if err != nil {
		return Manifest{}, err
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temporaryPath)
		}
	}()

	chain, err := workchain.OpenWithPolicy(temporaryPath, base, parameters, workPolicy)
	if err != nil {
		return Manifest{}, err
	}
	chainOpen := true
	defer func() {
		if chainOpen {
			_ = chain.Close()
		}
	}()
	manifest, err := replayArchiveDirectory(
		archivePath, checkpoint, policy, base, parameters, limits, chain,
	)
	if err != nil {
		return Manifest{}, err
	}
	if err := chain.Close(); err != nil {
		return Manifest{}, err
	}
	chainOpen = false

	reopened, err := workchain.OpenWithPolicy(temporaryPath, base, parameters, workPolicy)
	if err != nil {
		return Manifest{}, err
	}
	if err := verifyReplayedTip(reopened, manifest); err != nil {
		_ = reopened.Close()
		return Manifest{}, err
	}
	if err := reopened.Close(); err != nil {
		return Manifest{}, err
	}
	if hooks.beforePublish != nil {
		if err := hooks.beforePublish(); err != nil {
			return Manifest{}, errors.Join(ErrArchivePublish, err)
		}
	}
	if err := syncDirectory(temporaryPath); err != nil {
		return Manifest{}, err
	}
	if _, err := os.Lstat(destinationPath); err == nil {
		return Manifest{}, ErrArchiveExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	if err := os.Rename(temporaryPath, destinationPath); err != nil {
		return Manifest{}, err
	}
	published = true
	if hooks.afterPublish != nil {
		hooks.afterPublish()
	}
	if err := syncDirectory(parent); err != nil {
		return Manifest{}, errors.Join(ErrArchivePublish, err)
	}
	return manifest, nil
}

func replayArchiveDirectory(
	path string,
	checkpoint Checkpoint,
	policy Policy,
	base workchain.Base,
	parameters workblock.Parameters,
	limits Limits,
	chain replayChain,
) (Manifest, error) {
	if path == "" || chain == nil || limits.Validate() != nil ||
		checkpoint.Verify(policy) != nil || base.Tip.ID != policy.Binding.BaseID ||
		parameters.NetworkID != policy.Binding.NetworkID ||
		parameters.ActivationHeight != policy.Binding.ActivationHeight {
		return Manifest{}, ErrArchive
	}
	manifestBytes, err := readRegularArchiveFile(
		filepath.Join(path, manifestFileName), MaximumManifestBytes,
	)
	if err != nil {
		return Manifest{}, err
	}
	manifest, err := DecodeManifest(manifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	if manifest.BlockCount > limits.MaximumBlocks ||
		uint32(len(manifest.Chunks)) > limits.MaximumChunks ||
		manifest.TotalChunkBytes > limits.MaximumBytes {
		return Manifest{}, ErrArchiveLimit
	}
	if manifest.VerifyStatement(checkpoint.Statement) != nil {
		return Manifest{}, ErrArchive
	}
	if err := verifyArchiveDirectoryEntries(path, manifest); err != nil {
		return Manifest{}, err
	}

	expectedParent := base.Tip.ID
	expectedHeight := parameters.ActivationHeight
	var blockCount uint64
	var totalBytes uint64
	for index, descriptor := range manifest.Chunks {
		encoded, err := readRegularArchiveFile(
			filepath.Join(path, chunkFileName(uint32(index))), MaximumChunkBytes,
		)
		if err != nil {
			return Manifest{}, err
		}
		if len(encoded) != int(descriptor.EncodedBytes) ||
			types.DomainHash(chunkIDDomain, encoded) != descriptor.ID {
			return Manifest{}, ErrChunk
		}
		chunk, err := DecodeChunk(encoded)
		if err != nil {
			return Manifest{}, err
		}
		canonical, err := chunk.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, encoded) || chunk.Version != manifest.Version ||
			chunk.Index != descriptor.Index ||
			chunk.NetworkID != manifest.Binding.NetworkID || chunk.BaseID != manifest.Binding.BaseID ||
			(manifest.Version == ManifestVersion0 && chunk.AnchorID != manifest.Anchor.ID) ||
			(manifest.Version == ManifestVersion1 && !chunk.AnchorID.IsZero()) ||
			chunk.FirstHeight != descriptor.FirstHeight ||
			len(chunk.Blocks) != int(descriptor.BlockCount) {
			return Manifest{}, ErrChunk
		}
		for _, block := range chunk.Blocks {
			if block.Header.Seal.Height != expectedHeight ||
				block.Header.Seal.AnchorParent != expectedParent {
				return Manifest{}, ErrArchiveOrder
			}
			blockID, err := block.Header.ID()
			if err != nil {
				return Manifest{}, err
			}
			if _, _, err := chain.Commit(block, block.Header.Seal.Timestamp); err != nil {
				return Manifest{}, err
			}
			expectedParent = blockID
			blockCount++
			if blockCount < manifest.BlockCount {
				if expectedHeight == ^uint64(0) {
					return Manifest{}, ErrArchiveOrder
				}
				expectedHeight++
			}
		}
		if blockCount > limits.MaximumBlocks || uint64(len(encoded)) > limits.MaximumBytes ||
			totalBytes > limits.MaximumBytes-uint64(len(encoded)) {
			return Manifest{}, ErrArchiveLimit
		}
		totalBytes += uint64(len(encoded))
	}
	if blockCount != manifest.BlockCount || totalBytes != manifest.TotalChunkBytes ||
		expectedParent != manifest.Anchor.ID {
		return Manifest{}, ErrArchive
	}
	if err := verifyReplayedTip(chain, manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func verifyReplayedTip(chain replayChain, manifest Manifest) error {
	baseID, baseErr := chain.BaseID()
	tip, tipErr := chain.Tip()
	root, count, ancestryErr := chain.SelectedAncestryCommitment(manifest.Anchor.ID)
	if baseErr != nil || tipErr != nil || ancestryErr != nil ||
		baseID != manifest.Binding.BaseID || !storage.EqualTips(tip, manifest.Anchor) ||
		root != manifest.AncestryRoot || count != manifest.AncestryNodes {
		return errors.Join(ErrArchive, baseErr, tipErr, ancestryErr)
	}
	return nil
}

func verifyArchiveDirectoryEntries(path string, manifest Manifest) error {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return ErrArchive
	}
	expected := make(map[string]struct{}, len(manifest.Chunks)+1)
	expected[manifestFileName] = struct{}{}
	for index := range manifest.Chunks {
		expected[chunkFileName(uint32(index))] = struct{}{}
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	for {
		entries, readErr := directory.ReadDir(256)
		for _, entry := range entries {
			if _, exists := expected[entry.Name()]; !exists {
				return ErrArchive
			}
			info, infoErr := entry.Info()
			if infoErr != nil || !info.Mode().IsRegular() {
				return ErrArchive
			}
			delete(expected, entry.Name())
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if len(expected) != 0 {
		return ErrArchive
	}
	return nil
}

func readRegularArchiveFile(path string, maximum int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > int64(maximum) {
		return nil, ErrArchive
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, ErrArchive
	}
	encoded, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > maximum {
		return nil, ErrArchive
	}
	return encoded, nil
}
