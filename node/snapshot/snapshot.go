package snapshot

import (
	"errors"
	"fmt"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

const (
	Version0              uint16 = 0
	DefaultChunkResources        = 256
	MaxChunkResources            = 512
	MaxSnapshotResources  uint64 = 262_144
	MaxManifestBytes             = 128
	MaxChunkBytes                = 128 * 1024
)

var (
	ErrVersion      = errors.New("unsupported snapshot version")
	ErrManifest     = errors.New("invalid snapshot manifest")
	ErrChunk        = errors.New("invalid snapshot chunk")
	ErrAnchor       = errors.New("snapshot does not match expected chain anchor")
	ErrLimit        = errors.New("snapshot resource limit exceeded")
	ErrOrder        = errors.New("snapshot resources are not strictly ordered")
	ErrChunkOrder   = errors.New("snapshot chunks are out of order")
	ErrIncomplete   = errors.New("snapshot is incomplete")
	ErrStateRoot    = errors.New("snapshot state root mismatch")
	ErrSourceState  = errors.New("source state does not match source tip")
	ErrAlreadyFinal = errors.New("snapshot collector is already finalized")
)

type Manifest struct {
	Version        uint16
	NetworkID      uint32
	BlockID        types.Hash
	Height         uint64
	StateRoot      types.Hash
	ResourceCount  uint64
	ChunkResources uint16
	ChunkCount     uint32
}

type Anchor struct {
	NetworkID uint32
	BlockID   types.Hash
	Height    uint64
	StateRoot types.Hash
}

type Chunk struct {
	Version   uint16
	BlockID   types.Hash
	Index     uint32
	Resources []resource.Resource
}

type Exporter struct {
	manifest  Manifest
	resources []resource.Resource
}

func NewExporter(networkID uint32, tip storage.Tip, source *state.Memory, chunkResources uint16) (*Exporter, error) {
	if source == nil || source.Root() != tip.StateRoot {
		return nil, ErrSourceState
	}
	resources := source.Resources()
	if uint64(len(resources)) > MaxSnapshotResources {
		return nil, ErrLimit
	}
	manifest := Manifest{
		Version:        Version0,
		NetworkID:      networkID,
		BlockID:        tip.ID,
		Height:         tip.Height,
		StateRoot:      tip.StateRoot,
		ResourceCount:  uint64(len(resources)),
		ChunkResources: chunkResources,
	}
	manifest.ChunkCount = chunkCount(manifest.ResourceCount, chunkResources)
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return &Exporter{manifest: manifest, resources: resources}, nil
}

func (exporter *Exporter) Manifest() Manifest { return exporter.manifest }

func (exporter *Exporter) Chunk(index uint32) (Chunk, error) {
	if exporter == nil || index >= exporter.manifest.ChunkCount {
		return Chunk{}, ErrChunk
	}
	start := uint64(index) * uint64(exporter.manifest.ChunkResources)
	end := start + uint64(exporter.manifest.ChunkResources)
	if end > uint64(len(exporter.resources)) {
		end = uint64(len(exporter.resources))
	}
	values := append([]resource.Resource(nil), exporter.resources[int(start):int(end)]...)
	return Chunk{Version: Version0, BlockID: exporter.manifest.BlockID, Index: index, Resources: values}, nil
}

func (manifest Manifest) Validate() error {
	if manifest.Version != Version0 {
		return ErrVersion
	}
	if manifest.NetworkID == 0 || manifest.BlockID.IsZero() || manifest.StateRoot.IsZero() ||
		manifest.ChunkResources == 0 || manifest.ChunkResources > MaxChunkResources ||
		manifest.ResourceCount > MaxSnapshotResources {
		return ErrManifest
	}
	if manifest.ChunkCount != chunkCount(manifest.ResourceCount, manifest.ChunkResources) {
		return ErrManifest
	}
	return nil
}

func (manifest Manifest) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(MaxManifestBytes)
	encoder.U16(manifest.Version)
	encoder.U32(manifest.NetworkID)
	encoder.Fixed(manifest.BlockID[:])
	encoder.U64(manifest.Height)
	encoder.Fixed(manifest.StateRoot[:])
	encoder.U64(manifest.ResourceCount)
	encoder.U16(manifest.ChunkResources)
	encoder.U32(manifest.ChunkCount)
	return encoder.Bytes()
}

func DecodeManifest(input []byte) (Manifest, error) {
	if len(input) > MaxManifestBytes {
		return Manifest{}, ErrManifest
	}
	decoder := codec.NewDecoder(input)
	var result Manifest
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return Manifest{}, err
	}
	result.NetworkID, err = decoder.U32()
	if err != nil {
		return Manifest{}, err
	}
	blockID, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Manifest{}, err
	}
	copy(result.BlockID[:], blockID)
	result.Height, err = decoder.U64()
	if err != nil {
		return Manifest{}, err
	}
	stateRoot, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Manifest{}, err
	}
	copy(result.StateRoot[:], stateRoot)
	result.ResourceCount, err = decoder.U64()
	if err != nil {
		return Manifest{}, err
	}
	result.ChunkResources, err = decoder.U16()
	if err != nil {
		return Manifest{}, err
	}
	result.ChunkCount, err = decoder.U32()
	if err != nil {
		return Manifest{}, err
	}
	if err := decoder.Finish(); err != nil {
		return Manifest{}, err
	}
	return result, result.Validate()
}

func (chunk Chunk) Validate() error {
	if chunk.Version != Version0 {
		return ErrVersion
	}
	if chunk.BlockID.IsZero() || len(chunk.Resources) == 0 || len(chunk.Resources) > MaxChunkResources {
		return ErrChunk
	}
	for index, value := range chunk.Resources {
		if err := value.Validate(); err != nil {
			return fmt.Errorf("%w: resource %d: %v", ErrChunk, index, err)
		}
		if index > 0 && types.CompareResourceID(chunk.Resources[index-1].ID, value.ID) >= 0 {
			return ErrOrder
		}
	}
	return nil
}

func (chunk Chunk) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(2 + types.HashSize + 4 + len(chunk.Resources)*resource.CanonicalSize)
	encoder.U16(chunk.Version)
	encoder.Fixed(chunk.BlockID[:])
	encoder.U32(chunk.Index)
	encoder.Uvarint(uint64(len(chunk.Resources)))
	for _, value := range chunk.Resources {
		value.EncodeTo(encoder)
	}
	return encoder.Bytes()
}

func DecodeChunk(input []byte) (Chunk, error) {
	if len(input) > MaxChunkBytes {
		return Chunk{}, ErrChunk
	}
	decoder := codec.NewDecoder(input)
	var result Chunk
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return Chunk{}, err
	}
	blockID, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Chunk{}, err
	}
	copy(result.BlockID[:], blockID)
	result.Index, err = decoder.U32()
	if err != nil {
		return Chunk{}, err
	}
	count, err := decoder.ListLength(MaxChunkResources)
	if err != nil {
		return Chunk{}, err
	}
	result.Resources = make([]resource.Resource, count)
	for index := range result.Resources {
		result.Resources[index], err = resource.Decode(decoder)
		if err != nil {
			return Chunk{}, err
		}
	}
	if err := decoder.Finish(); err != nil {
		return Chunk{}, err
	}
	return result, result.Validate()
}

type Collector struct {
	commitmentVersion uint16
	manifest          Manifest
	resources         []resource.Resource
	next              uint32
	finalized         bool
}

func NewCollector(manifest Manifest, anchor Anchor, maxResources uint64) (*Collector, error) {
	return NewCollectorVersion(manifest, anchor, maxResources, state.CommitmentV0)
}

// NewCollectorVersion takes the commitment from the trusted local chain, never the peer.
func NewCollectorVersion(manifest Manifest, anchor Anchor, maxResources uint64, commitment uint16) (*Collector, error) {
	if !state.ValidCommitment(commitment) {
		return nil, state.ErrCommitmentVersion
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	if maxResources == 0 || maxResources > MaxSnapshotResources || manifest.ResourceCount > maxResources {
		return nil, ErrLimit
	}
	if manifest.NetworkID != anchor.NetworkID || manifest.BlockID != anchor.BlockID ||
		manifest.Height != anchor.Height || manifest.StateRoot != anchor.StateRoot {
		return nil, ErrAnchor
	}
	return &Collector{commitmentVersion: commitment, manifest: manifest, resources: make([]resource.Resource, 0, int(manifest.ResourceCount))}, nil
}

func (collector *Collector) Add(chunk Chunk) error {
	if collector == nil {
		return ErrManifest
	}
	if collector.finalized {
		return ErrAlreadyFinal
	}
	if err := chunk.Validate(); err != nil {
		return err
	}
	if chunk.BlockID != collector.manifest.BlockID || chunk.Index != collector.next {
		return ErrChunkOrder
	}
	remaining := collector.manifest.ResourceCount - uint64(len(collector.resources))
	want := uint64(collector.manifest.ChunkResources)
	if remaining < want {
		want = remaining
	}
	if uint64(len(chunk.Resources)) != want {
		return ErrChunk
	}
	if len(collector.resources) > 0 &&
		types.CompareResourceID(collector.resources[len(collector.resources)-1].ID, chunk.Resources[0].ID) >= 0 {
		return ErrOrder
	}
	collector.resources = append(collector.resources, chunk.Resources...)
	collector.next++
	return nil
}

func (collector *Collector) Finalize() (*state.Memory, error) {
	if collector == nil {
		return nil, ErrManifest
	}
	if collector.finalized {
		return nil, ErrAlreadyFinal
	}
	if collector.next != collector.manifest.ChunkCount || uint64(len(collector.resources)) != collector.manifest.ResourceCount {
		return nil, ErrIncomplete
	}
	result, err := state.NewVersion(collector.resources, collector.commitmentVersion)
	if err != nil {
		return nil, err
	}
	if result.Root() != collector.manifest.StateRoot {
		return nil, ErrStateRoot
	}
	collector.finalized = true
	return result, nil
}

func chunkCount(resources uint64, perChunk uint16) uint32 {
	if resources == 0 || perChunk == 0 {
		return 0
	}
	return uint32((resources + uint64(perChunk) - 1) / uint64(perChunk))
}
