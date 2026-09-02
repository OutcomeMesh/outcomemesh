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
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestCustodySessionRenewsReceiptOverAuthenticatedQUIC(t *testing.T) {
	fixture := newArchiveFixture(t)
	replicas, _ := archiveReplicaFixture(t, fixture, 1_000, 20_000)
	receipt := replicas[0].Receipt
	replicaKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, ed25519.SeedSize))
	auditorKey := custodyTestKey(81)
	policy := custodyTestPolicy(auditorKey)
	store, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "network-custody-objects"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportArchiveDirectory(
		replicas[0].Directory, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}
	clock := func() uint64 { return 1_002 }
	config := DefaultCustodySessionConfig()
	config.Now = clock
	replicaSession, err := NewCustodyReplicaSession(
		fixture.manifest, receipt, store, policy, replicaKey, config,
	)
	if err != nil {
		t.Fatal(err)
	}
	auditorSession, err := NewCustodyAuditorSession(
		fixture.manifest, receipt, policy, config,
	)
	if err != nil {
		t.Fatal(err)
	}
	badConfig := config
	badConfig.Now = nil
	if _, err := NewCustodyAuditorSession(
		fixture.manifest, receipt, policy, badConfig,
	); !errors.Is(err, ErrCustodySession) {
		t.Fatalf("nil custody clock error=%v", err)
	}
	if _, err := NewCustodyReplicaSession(
		fixture.manifest, receipt, store, policy, custodyTestKey(99), config,
	); !errors.Is(err, ErrCustodySession) {
		t.Fatalf("wrong session replica key error=%v", err)
	}
	challenge, err := createCustodyChallenge(
		fixture.manifest, receipt, auditorKey, 1_001, 60, 2, 25_000,
		bytes.NewReader(bytes.Repeat([]byte{122}, types.HashSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	zeroClient, zeroServer := net.Pipe()
	_ = zeroServer.Close()
	var zeroSession CustodySession
	if _, _, err := zeroSession.Audit(
		context.Background(), zeroClient, challenge,
	); !errors.Is(err, ErrCustodySession) {
		t.Fatalf("zero custody session error=%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server, err := libp2ptransport.New(
		ctx, archiveObjectTransportKey("custody-replica"),
		libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := libp2ptransport.New(
		ctx, archiveObjectTransportKey("custody-auditor"),
		libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	served := make(chan struct {
		report CustodyServeReport
		err    error
	}, 1)
	if err := server.SetArchiveCustodyHandler(
		[]types.Hash{client.ID()},
		func(handlerContext context.Context, peerID types.Hash, stream network.Stream) {
			if peerID != client.ID() {
				served <- struct {
					report CustodyServeReport
					err    error
				}{err: ErrCustodySession}
				_ = stream.Reset()
				return
			}
			report, serveErr := replicaSession.Serve(handlerContext, stream)
			served <- struct {
				report CustodyServeReport
				err    error
			}{report: report, err: serveErr}
		},
	); err != nil {
		t.Fatal(err)
	}
	address := server.Addresses()[0]
	stream, remoteID, err := client.OpenArchiveCustodyStream(ctx, address, server.ID())
	if err != nil {
		t.Fatal(err)
	}
	if remoteID != server.ID() || stream.Protocol() != libp2ptransport.ArchiveCustodyProtocol {
		t.Fatalf("custody remote=%s protocol=%q", remoteID, stream.Protocol())
	}
	response, audited, err := auditorSession.Audit(ctx, stream, challenge)
	if err != nil {
		t.Fatal(err)
	}
	result := <-served
	if result.err != nil {
		t.Fatal(result.err)
	}
	if audited.ChallengeID != result.report.ChallengeID ||
		audited.ProofID != result.report.ProofID ||
		audited.RenewedReceiptID != result.report.RenewedReceiptID ||
		audited.Objects != 2 || result.report.Objects != 2 ||
		audited.ReceivedBytes != result.report.SentBytes || audited.RespondedAt != 1_002 {
		t.Fatalf("custody audit=%+v serve=%+v", audited, result.report)
	}
	if response.RenewedReceipt.Version != ReplicaReceiptVersion1 ||
		response.RenewedReceipt.RetainUntil != challenge.RenewUntil {
		t.Fatalf("network renewal=%+v", response.RenewedReceipt)
	}
	if err := VerifyReplicaRenewal(
		fixture.manifest, receipt, response.RenewedReceipt, challenge,
		response.Batch, response.Proof, policy, 1_002,
	); err != nil {
		t.Fatal(err)
	}
}

func TestCustodySessionRejectsReorderedAndTruncatedFrames(t *testing.T) {
	fixture := newArchiveFixture(t)
	replicas, _ := archiveReplicaFixture(t, fixture, 1_000, 20_000)
	receipt := replicas[0].Receipt
	replicaKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, ed25519.SeedSize))
	auditorKey := custodyTestKey(81)
	policy := custodyTestPolicy(auditorKey)
	store, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "invalid-custody-session"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportArchiveDirectory(
		replicas[0].Directory, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}
	config := DefaultCustodySessionConfig()
	config.RequestTimeout = time.Second
	config.Now = func() uint64 { return 1_002 }
	auditorSession, err := NewCustodyAuditorSession(
		fixture.manifest, receipt, policy, config,
	)
	if err != nil {
		t.Fatal(err)
	}
	replicaSession, err := NewCustodyReplicaSession(
		fixture.manifest, receipt, store, policy, replicaKey, config,
	)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := createCustodyChallenge(
		fixture.manifest, receipt, auditorKey, 1_001, 60, 1, 21_000,
		bytes.NewReader(bytes.Repeat([]byte{123}, types.HashSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	encodedChallenge, err := challenge.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	var challengePrefix [4]byte
	binary.BigEndian.PutUint32(challengePrefix[:], uint32(len(encodedChallenge)))
	failing := &custodyFailWriteStream{reader: bytes.NewReader(append(
		challengePrefix[:], encodedChallenge...,
	))}
	if _, err := replicaSession.Serve(
		context.Background(), failing,
	); !errors.Is(err, ErrCustodySession) {
		t.Fatalf("failed first renewal write error=%v", err)
	}
	trailingInput := append(append([]byte(nil), challengePrefix[:]...), encodedChallenge...)
	trailingInput = append(trailingInput, 1)
	trailing := &custodyMemoryStream{reader: bytes.NewReader(trailingInput)}
	if _, err := replicaSession.Serve(
		context.Background(), trailing,
	); !errors.Is(err, ErrCustodySession) {
		t.Fatalf("post-response auditor data error=%v", err)
	}
	firstResponse, firstAudit, firstServe := runCustodyPipeSession(
		t, replicaSession, auditorSession, challenge,
	)
	secondResponse, secondAudit, secondServe := runCustodyPipeSession(
		t, replicaSession, auditorSession, challenge,
	)
	if firstAudit != secondAudit || firstServe != secondServe ||
		firstResponse.Proof != secondResponse.Proof ||
		firstResponse.RenewedReceipt != secondResponse.RenewedReceipt ||
		!equalChunkBatches(firstResponse.Batch, secondResponse.Batch) {
		t.Fatal("identical custody retry created a different signed response")
	}
	differentChallenge, err := createCustodyChallenge(
		fixture.manifest, receipt, auditorKey, 1_001, 60, 1, 21_000,
		bytes.NewReader(bytes.Repeat([]byte{124}, types.HashSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	rejectClient, rejectServer := net.Pipe()
	rejected := make(chan error, 1)
	go func() {
		_, serveErr := replicaSession.Serve(context.Background(), rejectServer)
		rejected <- serveErr
	}()
	if _, _, err := auditorSession.Audit(
		context.Background(), rejectClient, differentChallenge,
	); !errors.Is(err, ErrCustodySession) {
		t.Fatalf("sibling renewal audit error=%v", err)
	}
	if err := <-rejected; !errors.Is(err, ErrCustodySession) {
		t.Fatalf("sibling renewal serve error=%v", err)
	}

	t.Run("response order", func(t *testing.T) {
		client, server := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			defer server.Close()
			if _, err := readObjectSessionFrame(server, MaximumCustodyChallengeBytes); err != nil {
				done <- err
				return
			}
			encoded, _ := challenge.CanonicalBytes()
			var prefix [4]byte
			binary.BigEndian.PutUint32(prefix[:], uint32(len(encoded)))
			_, prefixErr := server.Write(prefix[:])
			if prefixErr == nil {
				_, prefixErr = server.Write(encoded)
			}
			done <- prefixErr
		}()
		if _, _, err := auditorSession.Audit(
			ctx, client, challenge,
		); !errors.Is(err, ErrCustodySession) {
			t.Fatalf("reordered response error=%v", err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("truncated challenge", func(t *testing.T) {
		client, server := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, serveErr := replicaSession.Serve(ctx, server)
			done <- serveErr
		}()
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], 10)
		if _, err := client.Write(append(prefix[:], byte(1))); err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		if err := <-done; !errors.Is(err, ErrCustodySession) {
			t.Fatalf("truncated challenge error=%v", err)
		}
	})
}

func FuzzReadCustodySessionFrameNeverPanics(f *testing.F) {
	challengeBytes, _ := custodyCodecSeeds(f)
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(challengeBytes)))
	f.Add(append(prefix[:], challengeBytes...))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = readCustodySessionFrame(
			bytes.NewReader(input), MaximumCustodyChallengeBytes,
		)
	})
}

func runCustodyPipeSession(
	t testing.TB,
	replica *CustodySession,
	auditor *CustodySession,
	challenge CustodyChallenge,
) (CustodyResponse, CustodyAuditReport, CustodyServeReport) {
	t.Helper()
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct {
		report CustodyServeReport
		err    error
	}, 1)
	go func() {
		report, err := replica.Serve(ctx, server)
		done <- struct {
			report CustodyServeReport
			err    error
		}{report: report, err: err}
	}()
	response, audit, err := auditor.Audit(ctx, client, challenge)
	if err != nil {
		t.Fatal(err)
	}
	served := <-done
	if served.err != nil {
		t.Fatal(served.err)
	}
	return response, audit, served.report
}

func equalChunkBatches(left, right ChunkBatch) bool {
	leftBytes, leftErr := left.CanonicalBytes()
	rightBytes, rightErr := right.CanonicalBytes()
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

type custodyFailWriteStream struct {
	reader *bytes.Reader
}

func (stream *custodyFailWriteStream) Read(destination []byte) (int, error) {
	return stream.reader.Read(destination)
}

func (*custodyFailWriteStream) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (*custodyFailWriteStream) Close() error { return nil }

func (*custodyFailWriteStream) SetDeadline(time.Time) error { return nil }

type custodyMemoryStream struct {
	reader *bytes.Reader
	writer bytes.Buffer
}

func (stream *custodyMemoryStream) Read(destination []byte) (int, error) {
	return stream.reader.Read(destination)
}

func (stream *custodyMemoryStream) Write(source []byte) (int, error) {
	return stream.writer.Write(source)
}

func (*custodyMemoryStream) Close() error { return nil }

func (*custodyMemoryStream) SetDeadline(time.Time) error { return nil }
