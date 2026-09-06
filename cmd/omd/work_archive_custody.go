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

type archiveCustodyJournalLimitFlags struct {
	bytes *uint64
	paths *uint64
}

func addArchiveCustodyJournalLimitFlags(flags *flag.FlagSet) archiveCustodyJournalLimitFlags {
	defaults := workarchive.DefaultCustodyJournalLimits()
	return archiveCustodyJournalLimitFlags{
		bytes: flags.Uint64("journal-max-bytes", defaults.MaximumBytes, "local journal logical-byte growth limit, including temporary links"),
		paths: flags.Uint64("journal-max-paths", defaults.MaximumPaths, "local journal path growth limit, including directories and temporary links"),
	}
}

func (values archiveCustodyJournalLimitFlags) limits() workarchive.CustodyJournalLimits {
	return workarchive.CustodyJournalLimits{MaximumBytes: *values.bytes, MaximumPaths: *values.paths}
}

func (values archiveCustodyJournalLimitFlags) validate(flags *flag.FlagSet, journalPath string) error {
	explicit := false
	flags.Visit(func(value *flag.Flag) {
		if value.Name == "journal-max-bytes" || value.Name == "journal-max-paths" {
			explicit = true
		}
	})
	if explicit && journalPath == "" {
		return errors.New("journal-max-bytes and journal-max-paths require a custody journal")
	}
	return values.limits().Validate()
}

func reportCustodyJournalUsage(journal *workarchive.CustodyJournal, limits workarchive.CustodyJournalLimits) error {
	usage, err := journal.Usage()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stderr, "work_archive_custody_journal_usage bytes=%d max_bytes=%d paths=%d max_paths=%d pending_bytes=%d pending_files=%d over_budget=%t\n",
		usage.Bytes, limits.MaximumBytes, usage.Paths, limits.MaximumPaths,
		usage.PendingBytes, usage.PendingFiles, usage.OverBudget(limits))
	return err
}

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
	journalPath := flags.String("journal", "", "append-only custody journal (receipt is its immutable initial receipt)")
	rotateEvery := flags.Uint64("rotate-every", 0, "seal active journal bodies after each N completed renewals (zero disables)")
	policyFlags := addArchiveCustodyPolicyFlags(flags)
	journalLimitFlags := addArchiveCustodyJournalLimitFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *transportKeyPath == "" || *auditorPeerIDText == "" || *replicaKeyPath == "" ||
		*auditorPublicKeyText == "" || *manifestPath == "" || *receiptPath == "" ||
		*objectStorePath == "" || (*recordPath == "" && *journalPath == "") ||
		(*recordPath != "" && *journalPath != "") {
		return errors.New("keys, auditor identities, manifest, receipt, object store, and exactly one of record or journal are required")
	}
	if *journalPath == "" && *rotateEvery != 0 {
		return errors.New("rotate-every requires a custody journal")
	}
	if err := journalLimitFlags.validate(flags, *journalPath); err != nil {
		return err
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
	var journal *workarchive.CustodyJournal
	if *journalPath != "" {
		var state workarchive.CustodyJournalState
		journal, state, err = workarchive.OpenOrCreateCustodyJournalWithLimits(
			*journalPath, manifest, receipt, policy, journalLimitFlags.limits(),
		)
		if err != nil {
			return err
		}
		if err := reportCustodyJournalUsage(journal, journalLimitFlags.limits()); err != nil {
			return err
		}
		receipt = state.CurrentReceipt
	}
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
	var session *workarchive.CustodySession
	if journal != nil {
		session, err = workarchive.NewJournalCustodyReplicaSession(
			journal, store, replicaKey, sessionConfig,
		)
	} else {
		session, err = workarchive.NewDurableCustodyReplicaSession(
			manifest, receipt, store, policy, replicaKey, *recordPath, sessionConfig,
		)
	}
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
		sequence := outcome.report.JournalSequence
		if journal != nil {
			if *rotateEvery != 0 && sequence%*rotateEvery == 0 {
				if _, rotateErr := journal.Rotate(); rotateErr != nil {
					return rotateErr
				}
			}
		}
		fmt.Printf(
			"work_archive_custody_served challenge=%s proof=%s renewal=%s objects=%d bytes=%d responded_at=%d record=%s journal=%s sequence=%d\n",
			outcome.report.ChallengeID, outcome.report.ProofID,
			outcome.report.RenewedReceiptID, outcome.report.Objects,
			outcome.report.SentBytes, outcome.report.RespondedAt, *recordPath,
			*journalPath, sequence,
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
	journalPath := flags.String("journal", "", "append-only custody journal (receipt is its immutable initial receipt)")
	artifactDirectory := flags.String("artifacts", "", "durable per-sequence challenge/record/receipt directory")
	renewUntil := flags.Uint64("renew-until", 0, "requested receipt retention deadline as Unix seconds")
	renewalSeconds := flags.Uint64("renewal-seconds", 0, "retention term from first attempt time in journal mode")
	minimumInterval := flags.Uint64("minimum-interval-seconds", 0, "skip a fresh journal cycle until this interval has elapsed")
	rotateEvery := flags.Uint64("rotate-every", 0, "seal active journal bodies after each N completed renewals (zero disables)")
	lifetime := flags.Uint64("lifetime-seconds", 60, "signed challenge lifetime")
	samples := flags.Uint("samples", 2, "requested deterministic chunk samples")
	policyFlags := addArchiveCustodyPolicyFlags(flags)
	journalLimitFlags := addArchiveCustodyJournalLimitFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *transportKeyPath == "" || *peerAddress == "" || *replicaPeerIDText == "" ||
		*auditorKeyPath == "" || *manifestPath == "" || *receiptPath == "" ||
		((*journalPath == "" && (*challengePath == "" || *recordPath == "" ||
			*outReceiptPath == "" || *renewUntil == 0)) ||
			(*journalPath != "" && (*artifactDirectory == "" || *challengePath != "" ||
				*recordPath != "" || *outReceiptPath != "" || *renewUntil != 0 ||
				*renewalSeconds == 0))) ||
		*samples < workarchive.MinimumCustodySamples ||
		*samples > workarchive.MaximumCustodySamples {
		return errors.New("transport/auditor keys, pinned replica, artifacts, outputs, renewal deadline, and bounded samples are required")
	}
	if *journalPath == "" && (*artifactDirectory != "" || *renewalSeconds != 0 || *minimumInterval != 0 || *rotateEvery != 0) {
		return errors.New("artifacts, renewal-seconds, minimum-interval-seconds, and rotate-every require a custody journal")
	}
	if err := journalLimitFlags.validate(flags, *journalPath); err != nil {
		return err
	}
	if err := policyFlags.validate(); err != nil {
		return err
	}
	if *journalPath != "" && *renewalSeconds > *policyFlags.renewalTerm {
		return errors.New("requested custody renewal term exceeds policy")
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
	var journal *workarchive.CustodyJournal
	var journalState workarchive.CustodyJournalState
	if *journalPath != "" {
		if custodyPathsOverlap(*journalPath, *artifactDirectory) {
			return errors.New("custody journal and cycle artifacts must be separate directories")
		}
		journal, journalState, err = workarchive.OpenOrCreateCustodyJournalWithLimits(
			*journalPath, manifest, receipt, policy, journalLimitFlags.limits(),
		)
		if err != nil {
			return err
		}
		if err := reportCustodyJournalUsage(journal, journalLimitFlags.limits()); err != nil {
			return err
		}
		receipt = journalState.CurrentReceipt
		cycle := journalState.Sequence + 1
		if cycle == 0 {
			return errors.New("custody journal sequence exhausted")
		}
		*challengePath, *recordPath, *outReceiptPath = custodyCycleArtifactPaths(
			*artifactDirectory, cycle,
		)
	}
	if err := validateCustodyKeySeparation(
		transportKey.Public().(ed25519.PublicKey), auditorPublicKey,
		replicaPeerID, receipt.ReplicaPublicKey,
	); err != nil {
		return err
	}
	if journal != nil {
		head, exists, headErr := journal.Head()
		if headErr != nil {
			return headErr
		}
		if exists {
			recovered, recoverErr := recoverCustodyCycleArtifacts(*artifactDirectory, head)
			if recoverErr != nil {
				return recoverErr
			}
			if *rotateEvery != 0 && head.Sequence%*rotateEvery == 0 {
				if _, err := journal.Rotate(); err != nil {
					return err
				}
			}
			if recovered {
				_, recordOutput, receiptOutput := custodyCycleArtifactPaths(*artifactDirectory, head.Sequence)
				renewedID, _ := head.Record.RenewedReceipt.ID()
				fmt.Printf("work_archive_custody_verified renewal=%s retain_until=%d record=%s receipt=%s recovered=true journal=%s sequence=%d\n",
					renewedID, head.Record.RenewedReceipt.RetainUntil, recordOutput, receiptOutput, *journalPath, head.Sequence)
				return nil
			}
		}
	}

	if record, loadErr := workarchive.LoadCustodyRecordFile(
		*recordPath, manifest, receipt, policy,
	); loadErr == nil {
		if (journal == nil && record.Challenge.RenewUntil != *renewUntil) ||
			(journal != nil && record.Challenge.RenewUntil-record.Challenge.IssuedAt != *renewalSeconds) ||
			record.Challenge.RequestedSamples != uint16(*samples) ||
			record.Challenge.ExpiresAt-record.Challenge.IssuedAt != *lifetime {
			return errors.New("durable custody result conflicts with requested challenge parameters")
		}
		if journal != nil {
			entry, _, appendErr := journal.Append(record)
			if appendErr != nil {
				return appendErr
			}
			journalState.Sequence = entry.Sequence
			record = entry.Record
			if _, err := recoverCustodyCycleArtifacts(*artifactDirectory, entry); err != nil {
				return err
			}
			if *rotateEvery != 0 && journalState.Sequence%*rotateEvery == 0 {
				if _, rotateErr := journal.Rotate(); rotateErr != nil {
					return rotateErr
				}
			}
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
			"work_archive_custody_verified renewal=%s retain_until=%d record=%s receipt=%s recovered=true journal=%s sequence=%d\n",
			renewedID, record.RenewedReceipt.RetainUntil, *recordPath, *outReceiptPath,
			*journalPath, journalState.Sequence,
		)
		return nil
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		return loadErr
	}

	now := unixNow()
	if journal != nil {
		pending := custodyArtifactExists(*challengePath) || custodyArtifactExists(*recordPath)
		if !pending && *minimumInterval != 0 &&
			journalState.CurrentReceipt.StoredAt > ^uint64(0)-*minimumInterval {
			return errors.New("custody due time overflows")
		}
		if !pending && *minimumInterval != 0 &&
			now < journalState.CurrentReceipt.StoredAt+*minimumInterval {
			due := journalState.CurrentReceipt.StoredAt + *minimumInterval
			fmt.Printf(
				"work_archive_custody_not_due journal=%s sequence=%d due_at=%d now=%d\n",
				*journalPath, journalState.Sequence+1, due, now,
			)
			return nil
		}
		if now > ^uint64(0)-*renewalSeconds {
			return errors.New("custody renewal deadline overflows")
		}
		*renewUntil = now + *renewalSeconds
	}
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
	if (journal == nil && challenge.RenewUntil != *renewUntil) ||
		(journal != nil && challenge.RenewUntil-challenge.IssuedAt != *renewalSeconds) ||
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
	if journal != nil {
		entry, _, err := journal.Append(committed)
		if err != nil {
			return err
		}
		committed = entry.Record
		journalState.Sequence = entry.Sequence
		if _, err := recoverCustodyCycleArtifacts(*artifactDirectory, entry); err != nil {
			return err
		}
		if *rotateEvery != 0 && journalState.Sequence%*rotateEvery == 0 {
			if _, rotateErr := journal.Rotate(); rotateErr != nil {
				return rotateErr
			}
		}
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
		"work_archive_custody_verified peer_id=%s challenge=%s proof=%s renewal=%s objects=%d bytes=%d retain_until=%d record=%s receipt=%s recovered=false journal=%s sequence=%d\n",
		remoteID, report.ChallengeID, report.ProofID, renewedID, report.Objects,
		report.ReceivedBytes, committed.RenewedReceipt.RetainUntil,
		*recordPath, *outReceiptPath, *journalPath, journalState.Sequence,
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
		if decodeErr != nil || verifyCustodyChallengeAttempt(
			challenge, manifest, receipt, policy, now,
		) != nil {
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
		if decodeErr != nil || verifyCustodyChallengeAttempt(
			result, manifest, receipt, policy, now,
		) != nil {
			return workarchive.CustodyChallenge{}, errors.Join(err, decodeErr)
		}
		return result, nil
	}
	committed, err := readRegularArtifact(path, workarchive.MaximumCustodyChallengeBytes)
	if err != nil {
		return workarchive.CustodyChallenge{}, err
	}
	result, err := workarchive.DecodeCustodyChallenge(committed)
	if err != nil || verifyCustodyChallengeAttempt(
		result, manifest, receipt, policy, now,
	) != nil {
		return workarchive.CustodyChallenge{}, errors.Join(workarchive.ErrCustodyChallenge, err)
	}
	return result, nil
}

func verifyCustodyChallengeAttempt(
	challenge workarchive.CustodyChallenge,
	manifest workarchive.Manifest,
	receipt workarchive.ReplicaReceipt,
	policy workarchive.CustodyPolicy,
	now uint64,
) error {
	if err := challenge.Verify(manifest, receipt, policy, now); err == nil {
		return nil
	}
	if now <= challenge.ExpiresAt || now-challenge.ExpiresAt > policy.MaximumProofAge {
		return workarchive.ErrCustodyChallenge
	}
	return challenge.Verify(manifest, receipt, policy, challenge.ExpiresAt)
}

func custodyCycleArtifactPaths(root string, sequence uint64) (string, string, string) {
	directory := filepath.Join(root, fmt.Sprintf("cycle-%020d", sequence))
	return filepath.Join(directory, "challenge.omcc"),
		filepath.Join(directory, "record.omcr"),
		filepath.Join(directory, "receipt.omrr")
}

// A completed slot is authoritative even if the caller died before publishing
// its output receipt. Restore the exact head artifacts before starting a cycle.
func recoverCustodyCycleArtifacts(root string, head workarchive.CustodyJournalEntry) (bool, error) {
	challengePath, recordPath, receiptPath := custodyCycleArtifactPaths(root, head.Sequence)
	challenge, err := head.Record.Challenge.CanonicalBytes()
	if err != nil {
		return false, err
	}
	record, err := head.Record.CanonicalBytes()
	if err != nil {
		return false, err
	}
	receipt, err := head.Record.RenewedReceipt.CanonicalBytes()
	if err != nil {
		return false, err
	}
	recovered := false
	for _, artifact := range []struct {
		path    string
		encoded []byte
	}{
		{challengePath, challenge}, {recordPath, record}, {receiptPath, receipt},
	} {
		if _, err := os.Lstat(artifact.path); errors.Is(err, os.ErrNotExist) {
			recovered = true
		} else if err != nil {
			return false, err
		}
		if err := publishImmutableArtifact(artifact.path, artifact.encoded); err != nil {
			return false, err
		}
	}
	return recovered, nil
}

func custodyArtifactExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

func custodyPathsOverlap(left, right string) bool {
	left, leftErr := resolveCustodyArtifactPath(left)
	right, rightErr := resolveCustodyArtifactPath(right)
	if leftErr != nil || rightErr != nil {
		return true
	}
	contains := func(parent, child string) bool {
		relative, err := filepath.Rel(parent, child)
		return err == nil && relative != ".." &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator))
	}
	return contains(left, right) || contains(right, left)
}

func resolveCustodyArtifactPath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var suffix []string
	for {
		if _, err := os.Lstat(path); err == nil {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return "", err
			}
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return resolved, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", errors.New("cannot resolve custody artifact path")
		}
		suffix = append(suffix, filepath.Base(path))
		path = parent
	}
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
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("artifact changed while opening")
	}
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
	if err := makeCustodyArtifactDirectory(directory); err != nil {
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
		return syncCustodyArtifactDirectory(directory)
	}
	return syncCustodyArtifactDirectory(directory)
}

func makeCustodyArtifactDirectory(directory string) error {
	info, err := os.Stat(directory)
	if err == nil {
		if !info.IsDir() {
			return errors.New("custody artifact parent is not a directory")
		}
		return syncCustodyArtifactDirectory(filepath.Dir(directory))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(directory)
	if parent == directory {
		return err
	}
	if err := makeCustodyArtifactDirectory(parent); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		return errors.Join(errors.New("custody artifact parent is not a directory"), err)
	}
	return syncCustodyArtifactDirectory(parent)
}

func syncCustodyArtifactDirectory(directory string) error {
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}
