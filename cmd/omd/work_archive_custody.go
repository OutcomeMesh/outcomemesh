package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"

	"github.com/outcomemesh/outcomemesh/core/types"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const defaultCustodyRenewalTerm = 30 * 24 * 60 * 60

type archiveCustodyPolicyFlags struct {
	challengeLifetime *uint64
	proofAge          *uint64
	renewalTerm       *uint64
}

func addArchiveCustodyPolicyFlags(flags *flag.FlagSet) archiveCustodyPolicyFlags {
	return archiveCustodyPolicyFlags{
		challengeLifetime: flags.Uint64(
			"max-challenge-lifetime-seconds", 120,
			"maximum accepted signed challenge lifetime",
		),
		proofAge: flags.Uint64(
			"max-proof-age-seconds", 120,
			"maximum accepted proof age",
		),
		renewalTerm: flags.Uint64(
			"max-renewal-term-seconds", defaultCustodyRenewalTerm,
			"maximum renewed receipt term from challenge issue time",
		),
	}
}

func (values archiveCustodyPolicyFlags) policy(
	auditor [ed25519.PublicKeySize]byte,
) workarchive.CustodyPolicy {
	return workarchive.CustodyPolicy{
		TrustedAuditors:          [][ed25519.PublicKeySize]byte{auditor},
		MaximumChallengeLifetime: *values.challengeLifetime,
		MaximumProofAge:          *values.proofAge,
		MaximumRenewalTerm:       *values.renewalTerm,
	}
}

func (values archiveCustodyPolicyFlags) validate() error {
	if *values.challengeLifetime == 0 ||
		*values.challengeLifetime > workarchive.MaximumCustodyChallengeLifetime ||
		*values.proofAge == 0 || *values.proofAge > workarchive.MaximumCustodyProofAge ||
		*values.renewalTerm == 0 ||
		*values.renewalTerm > workarchive.MaximumReplicaTermSeconds {
		return errors.New("custody policy bounds are invalid")
	}
	return nil
}

func runWorkArchiveCustodyServeQUIC(arguments []string) error {
	flags := flag.NewFlagSet("work-archive-custody-serve-quic", flag.ContinueOnError)
	transportKeyPath := flags.String("key", "", "replica QUIC transport Ed25519 seed file")
	listenAddress := flags.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "direct QUIC-v1 listen multiaddress")
	auditorPeerIDText := flags.String("auditor-peer-id", "", "allowed auditor OutcomeMesh transport peer ID")
	replicaKeyPath := flags.String("replica-key", "", "portable replica receipt/proof Ed25519 seed file")
	auditorPublicKeyText := flags.String("auditor-public-key", "", "trusted custody auditor Ed25519 public key")
	manifestPath := flags.String("manifest", "", "canonical archive manifest file")
	receiptPath := flags.String("receipt", "", "current canonical replica receipt file")
	objectStorePath := flags.String("object-store", "", "verified content-addressed archive object store")
	recordPath := flags.String("record", "", "durable no-replace custody response record")
	policyFlags := addArchiveCustodyPolicyFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *transportKeyPath == "" || *auditorPeerIDText == "" || *replicaKeyPath == "" ||
		*auditorPublicKeyText == "" || *manifestPath == "" || *receiptPath == "" ||
		*objectStorePath == "" || *recordPath == "" {
		return errors.New("transport/replica keys, auditor identities, manifest, receipt, object store, and record are required")
	}
	if err := policyFlags.validate(); err != nil {
		return err
	}
	transportKey, err := loadPrivateKey(*transportKeyPath)
	if err != nil {
		return err
	}
	replicaKey, err := loadPrivateKey(*replicaKeyPath)
	if err != nil {
		return err
	}
	auditorPeerID, err := parseHash(*auditorPeerIDText)
	if err != nil {
		return fmt.Errorf("auditor-peer-id: %w", err)
	}
	auditorPublicKey, err := parseArchivePublicKey(*auditorPublicKeyText)
	if err != nil {
		return fmt.Errorf("auditor-public-key: %w", err)
	}
	manifest, err := loadArchiveManifest(*manifestPath)
	if err != nil {
		return err
	}
	receipt, err := loadArchiveReplicaReceipt(*receiptPath)
	if err != nil {
		return err
	}
	policy := policyFlags.policy(auditorPublicKey)
	if err := validateCustodyKeySeparation(
		transportKey.Public().(ed25519.PublicKey), receipt.ReplicaPublicKey,
		auditorPeerID, auditorPublicKey,
	); err != nil {
		return err
	}
	store, err := workarchive.OpenObjectStore(
		*objectStorePath, workarchive.DefaultObjectStorePolicy(),
	)
	if err != nil {
		return err
	}
	sessionConfig := workarchive.DefaultCustodySessionConfig()
	session, err := workarchive.NewDurableCustodyReplicaSession(
		manifest, receipt, store, policy, replicaKey, *recordPath, sessionConfig,
	)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.Listen = []string{*listenAddress}
	host, err := libp2ptransport.New(ctx, transportKey, config, nil)
	if err != nil {
		return err
	}
	defer host.Close()
	if host.ID() == auditorPeerID {
		return errors.New("replica and auditor transport identities must be distinct")
	}
	type result struct {
		report workarchive.CustodyServeReport
		err    error
	}
	completed := make(chan result, 1)
	if err := host.SetArchiveCustodyHandler(
		[]types.Hash{auditorPeerID},
		func(handlerContext context.Context, remoteID types.Hash, stream libp2pnetwork.Stream) {
			if remoteID != auditorPeerID {
				_ = stream.Reset()
				return
			}
			report, serveErr := session.Serve(handlerContext, stream)
			select {
			case completed <- result{report: report, err: serveErr}:
			default:
			}
		},
	); err != nil {
		return err
	}
	addresses := host.Addresses()
	if len(addresses) == 0 {
		return errors.New("custody replica has no direct QUIC address")
	}
	fmt.Printf(
		"work_archive_custody_receiving transport_peer_id=%s auditor_peer_id=%s replica=%s listen=%s\n",
		host.ID(), auditorPeerID, types.Hash(receipt.ReplicaPublicKey), strings.Join(addresses, ","),
	)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case outcome := <-completed:
		if outcome.err != nil {
			return outcome.err
		}
		fmt.Printf(
			"work_archive_custody_served challenge=%s proof=%s renewal=%s objects=%d bytes=%d responded_at=%d record=%s\n",
			outcome.report.ChallengeID, outcome.report.ProofID,
			outcome.report.RenewedReceiptID, outcome.report.Objects,
			outcome.report.SentBytes, outcome.report.RespondedAt, *recordPath,
		)
		return nil
	}
}

func runWorkArchiveCustodyChallengeQUIC(arguments []string) error {
	flags := flag.NewFlagSet("work-archive-custody-challenge-quic", flag.ContinueOnError)
	transportKeyPath := flags.String("key", "", "auditor QUIC transport Ed25519 seed file")
	peerAddress := flags.String("peer", "", "replica direct QUIC-v1 multiaddress including /p2p/<id>")
	replicaPeerIDText := flags.String("peer-id", "", "expected replica OutcomeMesh transport peer ID")
	auditorKeyPath := flags.String("auditor-key", "", "portable custody challenge Ed25519 seed file")
	manifestPath := flags.String("manifest", "", "canonical archive manifest file")
	receiptPath := flags.String("receipt", "", "current canonical replica receipt file")
	challengePath := flags.String("challenge", "", "durable no-replace signed challenge file")
	recordPath := flags.String("record", "", "durable no-replace verified custody response record")
	outReceiptPath := flags.String("out-receipt", "", "no-replace renewed replica receipt output")
	renewUntil := flags.Uint64("renew-until", 0, "requested receipt retention deadline as Unix seconds")
	lifetime := flags.Uint64("lifetime-seconds", 60, "signed challenge lifetime")
	samples := flags.Uint("samples", 2, "requested deterministic chunk samples")
	policyFlags := addArchiveCustodyPolicyFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *transportKeyPath == "" || *peerAddress == "" || *replicaPeerIDText == "" ||
		*auditorKeyPath == "" || *manifestPath == "" || *receiptPath == "" ||
		*challengePath == "" || *recordPath == "" || *outReceiptPath == "" ||
		*renewUntil == 0 || *samples < workarchive.MinimumCustodySamples ||
		*samples > workarchive.MaximumCustodySamples {
		return errors.New("transport/auditor keys, pinned replica, artifacts, outputs, renewal deadline, and bounded samples are required")
	}
	if err := policyFlags.validate(); err != nil {
		return err
	}
	transportKey, err := loadPrivateKey(*transportKeyPath)
	if err != nil {
		return err
	}
	auditorKey, err := loadPrivateKey(*auditorKeyPath)
	if err != nil {
		return err
	}
	replicaPeerID, err := parseHash(*replicaPeerIDText)
	if err != nil {
		return fmt.Errorf("peer-id: %w", err)
	}
	manifest, err := loadArchiveManifest(*manifestPath)
	if err != nil {
		return err
	}
	receipt, err := loadArchiveReplicaReceipt(*receiptPath)
	if err != nil {
		return err
	}
	var auditorPublicKey [ed25519.PublicKeySize]byte
	copy(auditorPublicKey[:], auditorKey.Public().(ed25519.PublicKey))
	policy := policyFlags.policy(auditorPublicKey)
	if err := validateCustodyKeySeparation(
		transportKey.Public().(ed25519.PublicKey), auditorPublicKey,
		replicaPeerID, receipt.ReplicaPublicKey,
	); err != nil {
		return err
	}

	if record, loadErr := workarchive.LoadCustodyRecordFile(
		*recordPath, manifest, receipt, policy,
	); loadErr == nil {
		if record.Challenge.RenewUntil != *renewUntil ||
			record.Challenge.RequestedSamples != uint16(*samples) ||
			record.Challenge.ExpiresAt-record.Challenge.IssuedAt != *lifetime {
			return errors.New("durable custody result conflicts with requested challenge parameters")
		}
		challengeBytes, err := record.Challenge.CanonicalBytes()
		if err != nil {
			return err
		}
		if err := publishImmutableArtifact(*challengePath, challengeBytes); err != nil {
			return err
		}
		receiptBytes, err := record.RenewedReceipt.CanonicalBytes()
		if err != nil {
			return err
		}
		if err := publishImmutableArtifact(*outReceiptPath, receiptBytes); err != nil {
			return err
		}
		renewedID, _ := record.RenewedReceipt.ID()
		fmt.Printf(
			"work_archive_custody_verified renewal=%s retain_until=%d record=%s receipt=%s recovered=true\n",
			renewedID, record.RenewedReceipt.RetainUntil, *recordPath, *outReceiptPath,
		)
		return nil
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		return loadErr
	}

	now := unixNow()
	if *lifetime == 0 || *lifetime > *policyFlags.challengeLifetime ||
		*renewUntil <= now || *renewUntil-now > *policyFlags.renewalTerm {
		return errors.New("challenge lifetime or requested renewal term exceeds policy")
	}
	challenge, err := loadOrCreateCustodyChallenge(
		*challengePath, manifest, receipt, policy, auditorKey, now,
		*lifetime, uint16(*samples), *renewUntil,
	)
	if err != nil {
		return err
	}
	if challenge.RenewUntil != *renewUntil ||
		challenge.RequestedSamples != uint16(*samples) ||
		challenge.ExpiresAt-challenge.IssuedAt != *lifetime {
		return errors.New("durable custody challenge conflicts with requested parameters")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	host, err := libp2ptransport.New(ctx, transportKey, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		return err
	}
	defer host.Close()
	if host.ID() == replicaPeerID {
		return errors.New("auditor and replica transport identities must be distinct")
	}
	stream, remoteID, err := host.OpenArchiveCustodyStream(
		ctx, *peerAddress, replicaPeerID,
	)
	if err != nil {
		return err
	}
	auditorSession, err := workarchive.NewCustodyAuditorSession(
		manifest, receipt, policy, workarchive.DefaultCustodySessionConfig(),
	)
	if err != nil {
		_ = stream.Reset()
		return err
	}
	response, report, err := auditorSession.Audit(ctx, stream, challenge)
	if err != nil {
		return err
	}
	record := workarchive.CustodyRecord{
		Version: workarchive.CustodyRecordVersion0, Challenge: challenge,
		Batch: response.Batch, Proof: response.Proof, RenewedReceipt: response.RenewedReceipt,
	}
	committed, _, err := workarchive.PublishCustodyRecordFile(
		*recordPath, record, manifest, receipt, policy,
	)
	if err != nil {
		return err
	}
	receiptBytes, err := committed.RenewedReceipt.CanonicalBytes()
	if err != nil {
		return err
	}
	if err := publishImmutableArtifact(*outReceiptPath, receiptBytes); err != nil {
		return err
	}
	renewedID, _ := committed.RenewedReceipt.ID()
	fmt.Printf(
		"work_archive_custody_verified peer_id=%s challenge=%s proof=%s renewal=%s objects=%d bytes=%d retain_until=%d record=%s receipt=%s recovered=false\n",
		remoteID, report.ChallengeID, report.ProofID, renewedID, report.Objects,
		report.ReceivedBytes, committed.RenewedReceipt.RetainUntil,
		*recordPath, *outReceiptPath,
	)
	return nil
}

func loadOrCreateCustodyChallenge(
	path string,
	manifest workarchive.Manifest,
	receipt workarchive.ReplicaReceipt,
	policy workarchive.CustodyPolicy,
	auditorKey ed25519.PrivateKey,
	now uint64,
	lifetime uint64,
	samples uint16,
	renewUntil uint64,
) (workarchive.CustodyChallenge, error) {
	if encoded, err := readRegularArtifact(path, workarchive.MaximumCustodyChallengeBytes); err == nil {
		challenge, decodeErr := workarchive.DecodeCustodyChallenge(encoded)
		if decodeErr != nil || challenge.Verify(manifest, receipt, policy, now) != nil {
			return workarchive.CustodyChallenge{}, errors.Join(workarchive.ErrCustodyChallenge, decodeErr)
		}
		return challenge, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return workarchive.CustodyChallenge{}, err
	}
	challenge, err := workarchive.CreateCustodyChallenge(
		manifest, receipt, auditorKey, now, lifetime, samples, renewUntil,
	)
	if err != nil {
		return workarchive.CustodyChallenge{}, err
	}
	encoded, err := challenge.CanonicalBytes()
	if err != nil {
		return workarchive.CustodyChallenge{}, err
	}
	if err := publishImmutableArtifact(path, encoded); err != nil {
		committed, loadErr := readRegularArtifact(path, workarchive.MaximumCustodyChallengeBytes)
		if loadErr != nil {
			return workarchive.CustodyChallenge{}, errors.Join(err, loadErr)
		}
		result, decodeErr := workarchive.DecodeCustodyChallenge(committed)
		if decodeErr != nil || result.Verify(manifest, receipt, policy, now) != nil {
			return workarchive.CustodyChallenge{}, errors.Join(err, decodeErr)
		}
		return result, nil
	}
	committed, err := readRegularArtifact(path, workarchive.MaximumCustodyChallengeBytes)
	if err != nil {
		return workarchive.CustodyChallenge{}, err
	}
	result, err := workarchive.DecodeCustodyChallenge(committed)
	if err != nil || result.Verify(manifest, receipt, policy, now) != nil {
		return workarchive.CustodyChallenge{}, errors.Join(workarchive.ErrCustodyChallenge, err)
	}
	return result, nil
}

func loadArchiveManifest(path string) (workarchive.Manifest, error) {
	encoded, err := readRegularArtifact(path, workarchive.MaximumManifestBytes)
	if err != nil {
		return workarchive.Manifest{}, err
	}
	manifest, err := workarchive.DecodeManifest(encoded)
	if err != nil {
		return workarchive.Manifest{}, err
	}
	return manifest, nil
}

func loadArchiveReplicaReceipt(path string) (workarchive.ReplicaReceipt, error) {
	encoded, err := readRegularArtifact(path, workarchive.MaximumReplicaReceiptBytes)
	if err != nil {
		return workarchive.ReplicaReceipt{}, err
	}
	receipt, err := workarchive.DecodeReplicaReceipt(encoded)
	if err != nil {
		return workarchive.ReplicaReceipt{}, err
	}
	return receipt, nil
}

func parseArchivePublicKey(input string) ([ed25519.PublicKeySize]byte, error) {
	parsed, err := parseHash(input)
	if err != nil {
		return [ed25519.PublicKeySize]byte{}, err
	}
	return [ed25519.PublicKeySize]byte(parsed), nil
}

func validateCustodyKeySeparation(
	localTransport ed25519.PublicKey,
	localEvidence [ed25519.PublicKeySize]byte,
	remoteTransportID types.Hash,
	remoteEvidence [ed25519.PublicKeySize]byte,
) error {
	localTransportID := types.DomainHash("OMESH/p2p/ed25519/v0", localTransport)
	localEvidenceTransportID := types.DomainHash("OMESH/p2p/ed25519/v0", localEvidence[:])
	remoteEvidenceTransportID := types.DomainHash("OMESH/p2p/ed25519/v0", remoteEvidence[:])
	identities := []types.Hash{
		localTransportID, remoteTransportID, localEvidenceTransportID, remoteEvidenceTransportID,
	}
	for left := range identities {
		for right := left + 1; right < len(identities); right++ {
			if identities[left] == identities[right] {
				return errors.New("custody transport, auditor, and replica evidence identities must be separate")
			}
		}
	}
	if localEvidence == remoteEvidence {
		return errors.New("custody transport, auditor, and replica evidence identities must be separate")
	}
	return nil
}

func readRegularArtifact(path string, maximum int) ([]byte, error) {
	if path == "" || maximum <= 0 {
		return nil, errors.New("invalid artifact path or size")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 ||
		info.Size() > int64(maximum) {
		return nil, errors.New("artifact is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > maximum {
		return nil, errors.New("artifact exceeds its canonical bound")
	}
	return encoded, nil
}

func publishImmutableArtifact(path string, encoded []byte) error {
	if path == "" || len(encoded) == 0 {
		return errors.New("invalid immutable artifact")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".outcomemesh-work-artifact-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	written, err := temporary.Write(encoded)
	if err != nil {
		return err
	}
	if written != len(encoded) {
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		current, readErr := readRegularArtifact(path, len(encoded))
		if readErr != nil || !bytes.Equal(current, encoded) {
			return errors.Join(errors.New("immutable artifact conflict"), readErr)
		}
		return nil
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}
