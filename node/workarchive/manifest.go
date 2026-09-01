package workarchive

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/storage"
)

const (
	ManifestVersion0     uint16 = 0
	ChunkVersion0        uint16 = 0
	DefaultChunkBlocks          = 128
	MaximumChunkBlocks          = 256
	MaximumArchiveBlocks uint64 = 4_194_304
	MaximumArchiveChunks        = 65_536
	MaximumManifestBytes        = 8 << 20
	MaximumChunkBytes           = 64 << 20
	MaximumArchiveBytes  uint64 = 64 << 40
)

const (
	manifestIDDomain = "OMESH/workgraph/archive/manifest/id/v0"
	chunkIDDomain    = "OMESH/workgraph/archive/chunk/id/v0"
)

var (
	ErrManifest       = errors.New("invalid WorkGraph archive manifest")
	ErrChunk          = errors.New("invalid WorkGraph archive chunk")
	ErrArchive        = errors.New("invalid WorkGraph archive")
	ErrArchiveLimit   = errors.New("WorkGraph archive policy limit exceeded")
	ErrArchiveOrder   = errors.New("WorkGraph archive blocks are out of order")
	ErrArchiveExists  = errors.New("WorkGraph archive destination already exists")
	ErrArchivePublish = errors.New("WorkGraph archive publication failed")
)

var (
	manifestMagic = [8]byte{'O', 'M', 'W', 'A', 'R', 'M', 'A', 'N'}
	chunkMagic    = [8]byte{'O', 'M', 'W', 'A', 'R', 'B', 'L', 'K'}
)

// Limits are local resource controls applied before archive allocation or
// replay. Values may be stricter than the hard codec ceilings.
type Limits struct {
	MaximumBlocks uint64
	MaximumChunks uint32
	MaximumBytes  uint64
}

func DefaultLimits() Limits {
	return Limits{
		MaximumBlocks: MaximumArchiveBlocks,
		MaximumChunks: MaximumArchiveChunks,
		MaximumBytes:  MaximumArchiveBytes,
	}
}

func (limits Limits) Validate() error {
	if limits.MaximumBlocks == 0 || limits.MaximumBlocks > MaximumArchiveBlocks ||
		limits.MaximumChunks == 0 || limits.MaximumChunks > MaximumArchiveChunks ||
		limits.MaximumBytes == 0 || limits.MaximumBytes > MaximumArchiveBytes {
		return ErrArchiveLimit
	}
	return nil
}

type ChunkDescriptor struct {
	ID           types.Hash
	Index        uint32
	FirstHeight  uint64
	LastHeight   uint64
	BlockCount   uint16
	EncodedBytes uint32
}

// Manifest commits the complete activation-to-anchor block stream. The base
// state is intentionally external and must come from the independently
// verified version-0 activation parent named by Binding.BaseID.
type Manifest struct {
	Version         uint16
	Binding         Binding
	Anchor          storage.Tip
	AncestryNodes   uint64
	AncestryRoot    types.Hash
	BlockCount      uint64
	TotalChunkBytes uint64
	Chunks          []ChunkDescriptor
}

func (manifest Manifest) Validate() error {
	if manifest.Version != ManifestVersion0 || manifest.Binding.Validate() != nil ||
		manifest.Anchor.Validate() != nil ||
		manifest.Anchor.Height < manifest.Binding.ActivationHeight ||
		manifest.AncestryRoot.IsZero() || manifest.BlockCount == 0 ||
		manifest.BlockCount > MaximumArchiveBlocks || len(manifest.Chunks) == 0 ||
		len(manifest.Chunks) > MaximumArchiveChunks ||
		manifest.TotalChunkBytes == 0 || manifest.TotalChunkBytes > MaximumArchiveBytes {
		return ErrManifest
	}
	distance := manifest.Anchor.Height - manifest.Binding.ActivationHeight
	if distance > ^uint64(0)-2 || manifest.AncestryNodes != distance+2 ||
		manifest.BlockCount != manifest.AncestryNodes-1 {
		return ErrManifest
	}
	expectedHeight := manifest.Binding.ActivationHeight
	var blocks uint64
	var encodedBytes uint64
	for index, descriptor := range manifest.Chunks {
		if descriptor.ID.IsZero() || descriptor.Index != uint32(index) ||
			descriptor.BlockCount == 0 || descriptor.BlockCount > MaximumChunkBlocks ||
			descriptor.EncodedBytes == 0 || descriptor.EncodedBytes > MaximumChunkBytes ||
			descriptor.FirstHeight != expectedHeight {
			return ErrManifest
		}
		lastOffset := uint64(descriptor.BlockCount) - 1
		if descriptor.FirstHeight > ^uint64(0)-lastOffset ||
			descriptor.LastHeight != descriptor.FirstHeight+lastOffset {
			return ErrManifest
		}
		if index+1 < len(manifest.Chunks) {
			if descriptor.LastHeight == ^uint64(0) {
				return ErrManifest
			}
			expectedHeight = descriptor.LastHeight + 1
		}
		if blocks > MaximumArchiveBlocks-uint64(descriptor.BlockCount) ||
			encodedBytes > MaximumArchiveBytes-uint64(descriptor.EncodedBytes) {
			return ErrManifest
		}
		blocks += uint64(descriptor.BlockCount)
		encodedBytes += uint64(descriptor.EncodedBytes)
	}
	last := manifest.Chunks[len(manifest.Chunks)-1]
	if blocks != manifest.BlockCount || encodedBytes != manifest.TotalChunkBytes ||
		last.LastHeight != manifest.Anchor.Height {
		return ErrManifest
	}
	return nil
}

func (manifest Manifest) CanonicalBytes() ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(256 + len(manifest.Chunks)*64)
	encoder.Fixed(manifestMagic[:])
	encoder.U16(manifest.Version)
	encodeBinding(encoder, manifest.Binding)
	encoder.BytesField(manifest.Anchor.CanonicalBytes())
	encoder.U64(manifest.AncestryNodes)
	encoder.Fixed(manifest.AncestryRoot[:])
	encoder.U64(manifest.BlockCount)
	encoder.U64(manifest.TotalChunkBytes)
	encoder.Uvarint(uint64(len(manifest.Chunks)))
	for _, descriptor := range manifest.Chunks {
		encoder.Fixed(descriptor.ID[:])
		encoder.U32(descriptor.Index)
		encoder.U64(descriptor.FirstHeight)
		encoder.U64(descriptor.LastHeight)
		encoder.U16(descriptor.BlockCount)
		encoder.U32(descriptor.EncodedBytes)
	}
	encoded := encoder.Bytes()
	if len(encoded) > MaximumManifestBytes {
		return nil, ErrManifest
	}
	return encoded, nil
}

func DecodeManifest(input []byte) (Manifest, error) {
	if len(input) == 0 || len(input) > MaximumManifestBytes {
		return Manifest{}, ErrManifest
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(manifestMagic))
	if err != nil || !bytes.Equal(magic, manifestMagic[:]) {
		return Manifest{}, ErrManifest
	}
	var manifest Manifest
	if manifest.Version, err = decoder.U16(); err != nil {
		return Manifest{}, err
	}
	if manifest.Binding, err = decodeBinding(decoder); err != nil {
		return Manifest{}, err
	}
	tipBytes, err := decoder.BytesField(256)
	if err != nil {
		return Manifest{}, err
	}
	if manifest.Anchor, err = storage.DecodeTip(tipBytes); err != nil {
		return Manifest{}, err
	}
	if manifest.AncestryNodes, err = decoder.U64(); err != nil {
		return Manifest{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return Manifest{}, decodeErr
	} else {
		copy(manifest.AncestryRoot[:], value)
	}
	if manifest.BlockCount, err = decoder.U64(); err != nil {
		return Manifest{}, err
	}
	if manifest.TotalChunkBytes, err = decoder.U64(); err != nil {
		return Manifest{}, err
	}
	count, err := decoder.ListLength(MaximumArchiveChunks)
	if err != nil {
		return Manifest{}, err
	}
	manifest.Chunks = make([]ChunkDescriptor, count)
	for index := range manifest.Chunks {
		descriptor := &manifest.Chunks[index]
		if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
			return Manifest{}, decodeErr
		} else {
			copy(descriptor.ID[:], value)
		}
		if descriptor.Index, err = decoder.U32(); err != nil {
			return Manifest{}, err
		}
		if descriptor.FirstHeight, err = decoder.U64(); err != nil {
			return Manifest{}, err
		}
		if descriptor.LastHeight, err = decoder.U64(); err != nil {
			return Manifest{}, err
		}
		if descriptor.BlockCount, err = decoder.U16(); err != nil {
			return Manifest{}, err
		}
		if descriptor.EncodedBytes, err = decoder.U32(); err != nil {
			return Manifest{}, err
		}
	}
	if err := decoder.Finish(); err != nil {
		return Manifest{}, err
	}
	return manifest, manifest.Validate()
}

func (manifest Manifest) ID() (types.Hash, error) {
	encoded, err := manifest.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(manifestIDDomain, encoded), nil
}

func (manifest Manifest) VerifyStatement(statement Statement) error {
	manifestID, err := manifest.ID()
	if err != nil || statement.Validate(manifest.Binding) != nil ||
		manifestID != statement.ArchiveManifestID ||
		!storage.EqualTips(manifest.Anchor, statement.Anchor) ||
		manifest.AncestryNodes != statement.AncestryNodes ||
		manifest.AncestryRoot != statement.AncestryRoot {
		return errors.Join(ErrArchive, err)
	}
	return nil
}

// ArchiveStatement constructs the exact signing statement for this manifest.
// Sequence one requires a zero previous ID; later sequences require the prior
// statement ID, as enforced by Statement.Validate.
func (manifest Manifest) ArchiveStatement(
	sequence uint64,
	previousID types.Hash,
) (Statement, error) {
	manifestID, err := manifest.ID()
	if err != nil {
		return Statement{}, err
	}
	statement := Statement{
		Version:   StatementVersion0,
		NetworkID: manifest.Binding.NetworkID, GenesisID: manifest.Binding.GenesisID,
		ActivationHeight: manifest.Binding.ActivationHeight, BaseID: manifest.Binding.BaseID,
		Sequence: sequence, PreviousID: previousID, Anchor: manifest.Anchor,
		AncestryNodes: manifest.AncestryNodes, AncestryRoot: manifest.AncestryRoot,
		ArchiveManifestID: manifestID,
	}
	if err := statement.Validate(manifest.Binding); err != nil {
		return Statement{}, err
	}
	return statement, nil
}

type Chunk struct {
	Version     uint16
	NetworkID   uint32
	BaseID      types.Hash
	AnchorID    types.Hash
	Index       uint32
	FirstHeight uint64
	Blocks      []workblock.Block
}

func (chunk Chunk) Validate() error {
	if chunk.Version != ChunkVersion0 || chunk.NetworkID == 0 || chunk.BaseID.IsZero() ||
		chunk.AnchorID.IsZero() || chunk.FirstHeight == 0 || len(chunk.Blocks) == 0 ||
		len(chunk.Blocks) > MaximumChunkBlocks {
		return ErrChunk
	}
	encodedSize := 8 + 2 + 4 + 2*types.HashSize + 4 + 8 + uvarintSize(uint64(len(chunk.Blocks)))
	var previousID types.Hash
	for index, block := range chunk.Blocks {
		if err := block.ValidateBasic(); err != nil || block.Header.Seal.NetworkID != chunk.NetworkID ||
			uint64(index) > ^uint64(0)-chunk.FirstHeight ||
			block.Header.Seal.Height != chunk.FirstHeight+uint64(index) {
			return ErrChunk
		}
		id, err := block.Header.ID()
		if err != nil {
			return ErrChunk
		}
		if index > 0 && block.Header.Seal.AnchorParent != previousID {
			return ErrArchiveOrder
		}
		blockBytes := block.CanonicalBytes()
		fieldBytes := uvarintSize(uint64(len(blockBytes))) + len(blockBytes)
		if fieldBytes > MaximumChunkBytes || encodedSize > MaximumChunkBytes-fieldBytes {
			return ErrChunk
		}
		encodedSize += fieldBytes
		previousID = id
	}
	return nil
}

func (chunk Chunk) CanonicalBytes() ([]byte, error) {
	if err := chunk.Validate(); err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(128)
	encoder.Fixed(chunkMagic[:])
	encoder.U16(chunk.Version)
	encoder.U32(chunk.NetworkID)
	encoder.Fixed(chunk.BaseID[:])
	encoder.Fixed(chunk.AnchorID[:])
	encoder.U32(chunk.Index)
	encoder.U64(chunk.FirstHeight)
	encoder.Uvarint(uint64(len(chunk.Blocks)))
	for _, block := range chunk.Blocks {
		encoder.BytesField(block.CanonicalBytes())
	}
	encoded := encoder.Bytes()
	if len(encoded) > MaximumChunkBytes {
		return nil, ErrChunk
	}
	return encoded, nil
}

func DecodeChunk(input []byte) (Chunk, error) {
	if len(input) == 0 || len(input) > MaximumChunkBytes {
		return Chunk{}, ErrChunk
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(chunkMagic))
	if err != nil || !bytes.Equal(magic, chunkMagic[:]) {
		return Chunk{}, ErrChunk
	}
	var chunk Chunk
	if chunk.Version, err = decoder.U16(); err != nil {
		return Chunk{}, err
	}
	if chunk.NetworkID, err = decoder.U32(); err != nil {
		return Chunk{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return Chunk{}, decodeErr
	} else {
		copy(chunk.BaseID[:], value)
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return Chunk{}, decodeErr
	} else {
		copy(chunk.AnchorID[:], value)
	}
	if chunk.Index, err = decoder.U32(); err != nil {
		return Chunk{}, err
	}
	if chunk.FirstHeight, err = decoder.U64(); err != nil {
		return Chunk{}, err
	}
	count, err := decoder.ListLength(MaximumChunkBlocks)
	if err != nil || count == 0 {
		return Chunk{}, ErrChunk
	}
	chunk.Blocks = make([]workblock.Block, count)
	for index := range chunk.Blocks {
		blockBytes, decodeErr := decoder.BytesField(workblock.MaxCanonicalBytes)
		if decodeErr != nil {
			return Chunk{}, decodeErr
		}
		chunk.Blocks[index], err = workblock.Decode(blockBytes)
		if err != nil {
			return Chunk{}, err
		}
	}
	if err := decoder.Finish(); err != nil {
		return Chunk{}, err
	}
	return chunk, chunk.Validate()
}

func (chunk Chunk) ID() (types.Hash, error) {
	encoded, err := chunk.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(chunkIDDomain, encoded), nil
}

func encodeBinding(encoder *codec.Encoder, binding Binding) {
	encoder.U32(binding.NetworkID)
	encoder.Fixed(binding.GenesisID[:])
	encoder.U64(binding.ActivationHeight)
	encoder.Fixed(binding.BaseID[:])
}

func decodeBinding(decoder *codec.Decoder) (Binding, error) {
	var binding Binding
	var err error
	if binding.NetworkID, err = decoder.U32(); err != nil {
		return Binding{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return Binding{}, decodeErr
	} else {
		copy(binding.GenesisID[:], value)
	}
	if binding.ActivationHeight, err = decoder.U64(); err != nil {
		return Binding{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return Binding{}, decodeErr
	} else {
		copy(binding.BaseID[:], value)
	}
	return binding, nil
}

func uvarintSize(value uint64) int {
	var encoded [binary.MaxVarintLen64]byte
	return binary.PutUvarint(encoded[:], value)
}
