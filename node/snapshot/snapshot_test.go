package snapshot

import (
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestChunkedSnapshotRoundTripVerifiesRoot(t *testing.T) {
	t.Parallel()

	source := testState(t, 600)
	tip := testTip(source)
	exporter, err := NewExporter(91, tip, source, 256)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := DecodeManifest(exporter.Manifest().CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ResourceCount != 600 || manifest.ChunkCount != 3 {
		t.Fatalf("manifest count=%d chunks=%d", manifest.ResourceCount, manifest.ChunkCount)
	}
	collector, err := NewCollector(manifest, testAnchor(manifest), MaxSnapshotResources)
	if err != nil {
		t.Fatal(err)
	}
	for index := uint32(0); index < manifest.ChunkCount; index++ {
		chunk, err := exporter.Chunk(index)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeChunk(chunk.CanonicalBytes())
		if err != nil {
			t.Fatal(err)
		}
		if err := collector.Add(decoded); err != nil {
			t.Fatal(err)
		}
	}
	result, err := collector.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if result.Len() != source.Len() || result.Root() != source.Root() {
		t.Fatal("verified snapshot differs from source")
	}
}

func TestCollectorRejectsOutOfOrderIncompleteAndWrongRoot(t *testing.T) {
	t.Parallel()

	source := testState(t, 3)
	tip := testTip(source)
	exporter, err := NewExporter(91, tip, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	manifest := exporter.Manifest()
	collector, err := NewCollector(manifest, testAnchor(manifest), 3)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := exporter.Chunk(1)
	if err := collector.Add(second); !errors.Is(err, ErrChunkOrder) {
		t.Fatalf("out-of-order error = %v", err)
	}
	if _, err := collector.Finalize(); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("incomplete error = %v", err)
	}

	collector, err = NewCollector(manifest, testAnchor(manifest), 3)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := exporter.Chunk(0)
	first.Resources[0].Amount++
	if err := collector.Add(first); err != nil {
		t.Fatal(err)
	}
	if err := collector.Add(second); err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Finalize(); !errors.Is(err, ErrStateRoot) {
		t.Fatalf("root mismatch error = %v", err)
	}
}

func TestManifestEnforcesAnchorAndResourcePolicy(t *testing.T) {
	t.Parallel()

	source := testState(t, 2)
	tip := testTip(source)
	exporter, err := NewExporter(91, tip, source, 1)
	if err != nil {
		t.Fatal(err)
	}
	manifest := exporter.Manifest()
	wrong := testAnchor(manifest)
	wrong.StateRoot = types.DomainHash("test/snapshot/wrong-root")
	if _, err := NewCollector(manifest, wrong, 2); !errors.Is(err, ErrAnchor) {
		t.Fatalf("anchor error = %v", err)
	}
	if _, err := NewCollector(manifest, testAnchor(manifest), 1); !errors.Is(err, ErrLimit) {
		t.Fatalf("resource policy error = %v", err)
	}
	badTip := tip
	badTip.StateRoot = types.DomainHash("test/snapshot/source-root")
	if _, err := NewExporter(91, badTip, source, 1); !errors.Is(err, ErrSourceState) {
		t.Fatalf("source root error = %v", err)
	}
}

func TestSnapshotDecodersRejectTrailingAndOversizeInput(t *testing.T) {
	t.Parallel()

	source := testState(t, 1)
	exporter, err := NewExporter(91, testTip(source), source, 1)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes := append(exporter.Manifest().CanonicalBytes(), 0)
	if _, err := DecodeManifest(manifestBytes); !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("manifest trailing error = %v", err)
	}
	chunk, _ := exporter.Chunk(0)
	chunkBytes := append(chunk.CanonicalBytes(), 0)
	if _, err := DecodeChunk(chunkBytes); !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("chunk trailing error = %v", err)
	}
	if _, err := DecodeChunk(make([]byte, MaxChunkBytes+1)); !errors.Is(err, ErrChunk) {
		t.Fatalf("chunk oversize error = %v", err)
	}
}

func FuzzDecodeManifestNeverPanics(f *testing.F) {
	source := testState(f, 1)
	exporter, err := NewExporter(91, testTip(source), source, 1)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(exporter.Manifest().CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeManifest(input)
	})
}

func FuzzDecodeChunkNeverPanics(f *testing.F) {
	source := testState(f, 1)
	exporter, err := NewExporter(91, testTip(source), source, 1)
	if err != nil {
		f.Fatal(err)
	}
	chunk, err := exporter.Chunk(0)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(chunk.CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeChunk(input)
	})
}

func testState(t testing.TB, count int) *state.Memory {
	t.Helper()
	owner := types.Address(types.DomainHash("test/snapshot/owner"))
	resources := make([]resource.Resource, count)
	for index := range resources {
		label := []byte{byte(index >> 8), byte(index)}
		resources[index] = resource.Resource{
			ID:         types.ResourceID(types.DomainHash("test/snapshot/resource", label)),
			Version:    resource.Version0,
			Owner:      owner,
			Asset:      types.NativeAssetID(),
			Amount:     uint64(index + 1),
			SpendAfter: uint64(index),
		}
	}
	result, err := state.New(resources)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testTip(value *state.Memory) storage.Tip {
	return storage.Tip{
		ID:        types.DomainHash("test/snapshot/tip"),
		Height:    77,
		StateRoot: value.Root(),
	}
}

func testAnchor(manifest Manifest) Anchor {
	return Anchor{
		NetworkID: manifest.NetworkID,
		BlockID:   manifest.BlockID,
		Height:    manifest.Height,
		StateRoot: manifest.StateRoot,
	}
}
