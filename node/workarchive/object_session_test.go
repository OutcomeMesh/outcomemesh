package workarchive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestArchiveObjectSessionTransfersComposedSuffixOverAuthenticatedQUIC(t *testing.T) {
	fixture, firstSuffixTip := preparePrunedArchiveFixture(t)
	secondSuffix, _ := mineArchiveChild(
		t, fixture.source, firstSuffixTip.ID,
		firstSuffixTip.Timestamp+fixture.parameters.TargetSpacing, "network-object-suffix",
	)
	if _, _, err := fixture.source.Commit(
		secondSuffix, secondSuffix.Header.Seal.Timestamp,
	); err != nil {
		t.Fatal(err)
	}
	secondAnchor, err := fixture.source.TipByID(mustArchiveBlockID(t, secondSuffix))
	if err != nil {
		t.Fatal(err)
	}
	compositionPath := filepath.Join(t.TempDir(), "network-composed")
	options := DefaultExportOptions()
	options.BlocksPerChunk = 2
	manifest, manifestID, err := ComposeDirectory(
		compositionPath, fixture.archivePath, fixture.checkpoint, fixture.policy,
		fixture.base, fixture.parameters, fixture.source, secondAnchor.ID, options,
	)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := manifest.ArchiveStatement(
		2, mustStatementID(t, fixture.checkpoint.Statement),
	)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := signedCheckpoint(t, statement, fixture.keys)

	sourceStore, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "network-source-objects"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sourceStore.ImportArchiveDirectory(
		compositionPath, checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}
	destinationStore, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "network-destination-objects"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := destinationStore.ImportArchiveDirectory(
		fixture.archivePath, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}
	sourceSession, err := NewObjectSession(
		manifest, sourceStore, DefaultObjectSessionConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}
	destinationSession, err := NewObjectSession(
		manifest, destinationStore, DefaultObjectSessionConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	serverConfig := libp2ptransport.DefaultConfig()
	serverConfig.MaxArchiveObjectStreamsPerMinute = 1
	serverConfig.MaxArchiveObjectStreamsGlobalPerMinute = 1
	server, err := libp2ptransport.New(
		ctx, archiveObjectTransportKey("server"), serverConfig, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := libp2ptransport.New(
		ctx, archiveObjectTransportKey("authorized-client"),
		libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	serveDone := make(chan struct {
		report ObjectServeReport
		err    error
	}, 2)
	if err := server.SetArchiveObjectHandler(
		[]types.Hash{client.ID()},
		func(handlerContext context.Context, peerID types.Hash, stream network.Stream) {
			if peerID != client.ID() {
				serveDone <- struct {
					report ObjectServeReport
					err    error
				}{err: ErrObjectSession}
				_ = stream.Reset()
				return
			}
			report, serveErr := sourceSession.Serve(handlerContext, stream)
			serveDone <- struct {
				report ObjectServeReport
				err    error
			}{report: report, err: serveErr}
		},
	); err != nil {
		t.Fatal(err)
	}

	unauthorized, err := libp2ptransport.New(
		ctx, archiveObjectTransportKey("unauthorized-client"),
		libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer unauthorized.Close()
	address := server.Addresses()[0]
	if stream, _, err := unauthorized.OpenArchiveObjectStream(ctx, address, server.ID()); err == nil {
		_, err = destinationSession.Fetch(ctx, stream)
		if err == nil {
			t.Fatal("unauthorized archive-object peer completed a session")
		}
	}
	select {
	case result := <-serveDone:
		t.Fatalf("unauthorized peer reached handler: %+v", result)
	case <-time.After(200 * time.Millisecond):
	}

	wrongServer := types.DomainHash("test/workarchive/wrong-network-server")
	if _, _, err := client.OpenArchiveObjectStream(
		ctx, address, wrongServer,
	); !errors.Is(err, libp2ptransport.ErrUnexpectedPeer) {
		t.Fatalf("wrong archive server pin error=%v", err)
	}
	stream, remoteID, err := client.OpenArchiveObjectStream(ctx, address, server.ID())
	if err != nil {
		t.Fatal(err)
	}
	if remoteID != server.ID() || stream.Protocol() != libp2ptransport.ArchiveObjectProtocol {
		t.Fatalf("archive remote=%s protocol=%q", remoteID, stream.Protocol())
	}
	fetched, err := destinationSession.Fetch(ctx, stream)
	if err != nil || !fetched.Complete || fetched.Requests != 1 || fetched.Objects != 1 ||
		fetched.AddedObjects != 1 || fetched.ReusedObjects != 0 {
		t.Fatalf("network object fetch=%+v err=%v", fetched, err)
	}
	served := <-serveDone
	if served.err != nil || served.report.ManifestID != manifestID ||
		served.report.Requests != 1 || served.report.Objects != 1 ||
		served.report.SentBytes != fetched.ReceivedBytes {
		t.Fatalf("network object serve=%+v err=%v", served.report, served.err)
	}

	materializedPath := filepath.Join(t.TempDir(), "network-materialized")
	if _, err := destinationStore.MaterializeDirectory(
		materializedPath, manifest, checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyArchiveDirectory(
		materializedPath, checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedID, err := verified.ID(); err != nil || verifiedID != manifestID {
		t.Fatalf("network materialized manifest=%s want=%s err=%v", verifiedID, manifestID, err)
	}
}

func TestArchiveObjectSessionRejectsRepeatedAndIncompleteResponses(t *testing.T) {
	fixture := newArchiveFixture(t)
	sourceStore, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "session-source"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sourceStore.ImportArchiveDirectory(
		fixture.archivePath, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}
	sourceSession, err := NewObjectSession(
		fixture.manifest, sourceStore, DefaultObjectSessionConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("repeated request", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done := make(chan struct {
			report ObjectServeReport
			err    error
		}, 1)
		go func() {
			report, serveErr := sourceSession.Serve(ctx, server)
			done <- struct {
				report ObjectServeReport
				err    error
			}{report: report, err: serveErr}
		}()
		request := ChunkRequest{
			Version: ObjectExchangeVersion0, ManifestID: fixture.manifestID,
			IDs: []types.Hash{fixture.manifest.Chunks[0].ID},
		}
		requestBytes, err := request.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		writeObjectTestFrame(t, client, requestBytes)
		if _, err := readObjectSessionFrame(client, MaximumObjectBatchBytes); err != nil {
			t.Fatal(err)
		}
		writeObjectTestFrame(t, client, requestBytes)
		result := <-done
		if !errors.Is(result.err, ErrObjectSession) || result.report.Requests != 1 {
			t.Fatalf("repeated request serve=%+v err=%v", result.report, result.err)
		}
	})

	t.Run("incomplete response", func(t *testing.T) {
		destinationStore, err := OpenObjectStore(
			filepath.Join(t.TempDir(), "incomplete-destination"), DefaultObjectStorePolicy(),
		)
		if err != nil {
			t.Fatal(err)
		}
		destinationSession, err := NewObjectSession(
			fixture.manifest, destinationStore, DefaultObjectSessionConfig(),
		)
		if err != nil {
			t.Fatal(err)
		}
		client, server := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go func() {
			defer server.Close()
			requestBytes, readErr := readObjectSessionFrame(server, MaximumObjectRequestBytes)
			if readErr != nil {
				return
			}
			request, decodeErr := DecodeChunkRequest(requestBytes)
			if decodeErr != nil {
				return
			}
			batch, serveErr := ServeChunkRequest(sourceStore, fixture.manifest, request)
			if serveErr != nil || len(batch.Objects) < 2 {
				return
			}
			batch.Objects = batch.Objects[:1]
			encoded, encodeErr := batch.CanonicalBytes()
			if encodeErr == nil {
				var prefix [4]byte
				binary.BigEndian.PutUint32(prefix[:], uint32(len(encoded)))
				_ = writeObjectSessionBytes(server, prefix[:])
				_ = writeObjectSessionBytes(server, encoded)
			}
		}()
		report, err := destinationSession.Fetch(ctx, client)
		if !errors.Is(err, ErrObjectSession) || report.AddedObjects != 0 {
			t.Fatalf("incomplete response fetch=%+v err=%v", report, err)
		}
		if objects, _, err := destinationStore.Usage(); err != nil || objects != 0 {
			t.Fatalf("incomplete response stored objects=%d err=%v", objects, err)
		}
	})

	t.Run("valid prefix before corrupt object", func(t *testing.T) {
		destinationStore, err := OpenObjectStore(
			filepath.Join(t.TempDir(), "corrupt-tail-destination"), DefaultObjectStorePolicy(),
		)
		if err != nil {
			t.Fatal(err)
		}
		destinationSession, err := NewObjectSession(
			fixture.manifest, destinationStore, DefaultObjectSessionConfig(),
		)
		if err != nil {
			t.Fatal(err)
		}
		client, server := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go func() {
			defer server.Close()
			requestBytes, readErr := readObjectSessionFrame(server, MaximumObjectRequestBytes)
			if readErr != nil {
				return
			}
			request, decodeErr := DecodeChunkRequest(requestBytes)
			if decodeErr != nil {
				return
			}
			batch, serveErr := ServeChunkRequest(sourceStore, fixture.manifest, request)
			if serveErr != nil || len(batch.Objects) < 2 {
				return
			}
			last := len(batch.Objects) - 1
			batch.Objects[last].Encoded = append([]byte(nil), batch.Objects[last].Encoded...)
			batch.Objects[last].Encoded[len(batch.Objects[last].Encoded)-1] ^= 1
			encoded, encodeErr := batch.CanonicalBytes()
			if encodeErr == nil {
				var prefix [4]byte
				binary.BigEndian.PutUint32(prefix[:], uint32(len(encoded)))
				_ = writeObjectSessionBytes(server, prefix[:])
				_ = writeObjectSessionBytes(server, encoded)
			}
		}()
		report, err := destinationSession.Fetch(ctx, client)
		if !errors.Is(err, ErrObjectSession) || report.Objects != 2 ||
			report.AddedObjects != 1 || report.ReusedObjects != 0 {
			t.Fatalf("corrupt-tail fetch=%+v err=%v", report, err)
		}
		if objects, _, err := destinationStore.Usage(); err != nil || objects != 1 {
			t.Fatalf("corrupt-tail stored objects=%d err=%v", objects, err)
		}
	})
}

func TestArchiveObjectSessionStopsAtFiniteBatchBudgetAndResumes(t *testing.T) {
	manifestBytes, chunkBytes := archiveCodecSeedsForVersion(t, ManifestVersion1)
	seedManifest, err := DecodeManifest(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	seedChunk, err := DecodeChunk(chunkBytes)
	if err != nil {
		t.Fatal(err)
	}
	const objects = MaximumObjectSessionBatches*MaximumObjectRequestIDs + 1
	manifest := seedManifest
	manifest.Chunks = make([]ChunkDescriptor, 0, objects)
	manifest.BlockCount = objects
	manifest.AncestryNodes = objects + 1
	manifest.AncestryRoot = types.DomainHash("test/workarchive/finite-session-ancestry")
	manifest.TotalChunkBytes = 0
	encodedObjects := make(map[types.Hash][]byte, objects)
	parentID := manifest.Binding.BaseID
	for index := 0; index < objects; index++ {
		block := seedChunk.Blocks[0]
		block.Header.Seal.Height = manifest.Binding.ActivationHeight + uint64(index)
		block.Header.Seal.AnchorParent = parentID
		block.Header.Seal.Timestamp = seedChunk.Blocks[0].Header.Seal.Timestamp + uint64(index)
		block.Header.Seal.Nonce = uint64(index)
		blockID, err := block.Header.ID()
		if err != nil {
			t.Fatal(err)
		}
		chunk := Chunk{
			Version: ManifestVersion1, NetworkID: manifest.Binding.NetworkID,
			BaseID: manifest.Binding.BaseID, Index: uint32(index),
			FirstHeight: block.Header.Seal.Height, Blocks: []workblock.Block{block},
		}
		encoded, err := chunk.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		id := types.DomainHash(chunkIDDomain, encoded)
		manifest.Chunks = append(manifest.Chunks, ChunkDescriptor{
			ID: id, Index: uint32(index), FirstHeight: block.Header.Seal.Height,
			LastHeight: block.Header.Seal.Height, BlockCount: 1,
			EncodedBytes: uint32(len(encoded)),
		})
		manifest.TotalChunkBytes += uint64(len(encoded))
		encodedObjects[id] = encoded
		parentID = blockID
		if index == objects-1 {
			manifest.Anchor = storage.Tip{
				ID: blockID, Height: block.Header.Seal.Height,
				Timestamp: block.Header.Seal.Timestamp, Target: block.Header.Seal.Target,
				StateRoot: block.Header.StateRoot, CumulativeWork: []byte{1},
			}
		}
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	sourceStore, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "finite-source"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, descriptor := range manifest.Chunks {
		if added, err := sourceStore.Put(
			manifest, descriptor.ID, encodedObjects[descriptor.ID],
		); err != nil || !added {
			t.Fatalf("finite source object=%s added=%t err=%v", descriptor.ID, added, err)
		}
	}
	destinationStore, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "finite-destination"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	sourceSession, err := NewObjectSession(
		manifest, sourceStore, DefaultObjectSessionConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}
	destinationSession, err := NewObjectSession(
		manifest, destinationStore, DefaultObjectSessionConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}

	firstFetch, firstServe := runObjectPipeSession(
		t, sourceSession, destinationSession,
	)
	if firstFetch.Complete || firstFetch.Requests != MaximumObjectSessionBatches ||
		firstFetch.AddedObjects != objects-1 || firstServe.Objects != objects-1 {
		t.Fatalf("finite first fetch=%+v serve=%+v", firstFetch, firstServe)
	}
	secondFetch, secondServe := runObjectPipeSession(
		t, sourceSession, destinationSession,
	)
	if !secondFetch.Complete || secondFetch.Requests != 1 ||
		secondFetch.AddedObjects != 1 || secondServe.Objects != 1 {
		t.Fatalf("finite second fetch=%+v serve=%+v", secondFetch, secondServe)
	}
	if stored, _, err := destinationStore.Usage(); err != nil || stored != objects {
		t.Fatalf("finite destination objects=%d want=%d err=%v", stored, objects, err)
	}
}

func TestArchiveObjectSessionFrameRejectsLimitsAndTruncation(t *testing.T) {
	for _, input := range [][]byte{
		{0, 0, 0, 0},
		{0, 0, 0, 2, 1},
		{0xff, 0xff, 0xff, 0xff},
	} {
		if _, err := readObjectSessionFrame(
			bytes.NewReader(input), MaximumObjectRequestBytes,
		); !errors.Is(err, ErrObjectSession) {
			t.Fatalf("frame %x error=%v", input, err)
		}
	}
	if _, err := readObjectSessionFrame(
		bytes.NewReader(nil), MaximumObjectRequestBytes,
	); !errors.Is(err, io.EOF) {
		t.Fatalf("clean EOF error=%v", err)
	}
}

func FuzzReadObjectSessionFrameNeverPanics(f *testing.F) {
	requestBytes, _ := objectExchangeCodecSeeds(f)
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(requestBytes)))
	f.Add(append(prefix[:], requestBytes...))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = readObjectSessionFrame(bytes.NewReader(input), MaximumObjectRequestBytes)
	})
}

func archiveObjectTransportKey(label string) ed25519.PrivateKey {
	seed := types.DomainHash("test/workarchive/object-transport/" + label)
	return ed25519.NewKeyFromSeed(seed[:])
}

func runObjectPipeSession(
	t testing.TB,
	source *ObjectSession,
	destination *ObjectSession,
) (ObjectFetchReport, ObjectServeReport) {
	t.Helper()
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct {
		report ObjectServeReport
		err    error
	}, 1)
	go func() {
		report, err := source.Serve(ctx, server)
		done <- struct {
			report ObjectServeReport
			err    error
		}{report: report, err: err}
	}()
	fetched, err := destination.Fetch(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	served := <-done
	if served.err != nil {
		t.Fatal(served.err)
	}
	return fetched, served.report
}

func writeObjectTestFrame(t testing.TB, writer io.Writer, encoded []byte) {
	t.Helper()
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(encoded)))
	if err := writeObjectSessionBytes(writer, prefix[:]); err != nil {
		t.Fatal(err)
	}
	if err := writeObjectSessionBytes(writer, encoded); err != nil {
		t.Fatal(err)
	}
}
