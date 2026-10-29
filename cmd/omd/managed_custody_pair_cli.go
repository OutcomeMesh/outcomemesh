package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	multiaddr "github.com/multiformats/go-multiaddr"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const managedCustodyPairCommand = "work-archive-custody-managed-pair-quic"

var errManagedCustodyPairUnobserved = errors.New("paired custody result was not reported; inspect both retained journals before a separate reviewed retry")

type managedCustodyPairOptions struct {
	mode, listen                       string
	config                             authoritystore.ManagedCustodyPairRuntimeConfig
	intent                             workarchive.CustodyAuditIntent
	auditorTransport, replicaTransport ed25519.PrivateKey
	auditTicket, serveTicket           types.Hash
}

func runManagedCustodyPairCLI(arguments []string) error {
	brokenPipe := make(chan os.Signal, 1)
	signal.Notify(brokenPipe, syscall.SIGPIPE)
	defer signal.Stop(brokenPipe)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runManagedCustodyPair(ctx, arguments, os.Stdin, os.Stdout)
}

func runManagedCustodyPair(ctx context.Context, arguments []string, input io.ReadCloser, output io.Writer) (returnErr error) {
	if ctx == nil || output == nil {
		return errors.New("managed custody pair needs context and output")
	}
	options, err := loadManagedCustodyPairOptions(ctx, arguments)
	if err != nil {
		return err
	}
	if options.mode == "review" {
		service, err := authoritystore.OpenManagedCustodyPairRuntime(ctx, options.config)
		if err != nil {
			return err
		}
		review, reviewErr := service.Review(ctx)
		if err := errors.Join(reviewErr, service.Close(), ctx.Err()); err != nil {
			return err
		}
		// Native pipe output stays interruptible after every owner has closed.
		if file, ok := output.(*os.File); ok {
			info, err := file.Stat()
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeNamedPipe != 0 && (runtime.GOOS == "darwin" || runtime.GOOS == "linux") {
				owned, err := ownPruneEffectOutput(output)
				if err != nil {
					return err
				}
				defer func() { returnErr = errors.Join(returnErr, owned.Close()) }()
				done := make(chan struct{})
				stop := context.AfterFunc(ctx, func() { defer close(done); _ = owned.Close() })
				defer func() {
					if !stop() {
						<-done
					}
				}()
				output = owned
			}
		}
		_, _, err = writeManagedCustodyPairReview(output, options, review, false)
		return err
	}
	control, err := ownPruneControlInput(input)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, control.Close()) }()
	writer, err := ownPruneEffectOutput(output)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, writer.Close()) }()
	return runManagedCustodyPairControl(ctx, options, control, writer)
}

func loadManagedCustodyPairOptions(ctx context.Context, arguments []string) (managedCustodyPairOptions, error) {
	if ctx == nil || len(arguments) == 0 || arguments[0] != managedCustodyPairCommand {
		return managedCustodyPairOptions{}, errors.New("managed custody pair needs its explicit command and context")
	}
	if err := ctx.Err(); err != nil {
		return managedCustodyPairOptions{}, err
	}
	f := flag.NewFlagSet(managedCustodyPairCommand, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	scheduleFlags := addCustodyScheduleFlags(f)
	mode := f.String("mode", "review", "review (default), or supervised control")
	assignmentPath := f.String("assignment", "", "existing canonical assignment file (required)")
	assignmentText := f.String("assignment-id", "", "independently pinned assignment ID (required)")
	auditAdmission := f.String("audit-admission", "", "existing co-signed Audit admission (required)")
	auditTicketText := f.String("audit-ticket-id", "", "independently pinned Audit ticket ID (required)")
	serveAdmission := f.String("serve-admission", "", "existing co-signed Serve admission (required)")
	serveTicketText := f.String("serve-ticket-id", "", "independently pinned Serve ticket ID (required)")
	intentPath := f.String("intent", "", "existing canonical unsigned audit intent (required)")
	intentText := f.String("intent-id", "", "independently pinned audit intent ID (required)")
	challengeText := f.String("challenge-id", "", "independently pinned signed challenge ID (required)")
	manifestPath := f.String("manifest", "", "existing canonical manifest file (required)")
	receiptPath := f.String("receipt", "", "existing immutable initial receipt (required)")
	authority := f.String("authority", "", "existing original authority root (required)")
	pins := f.String("authority-pins", "", "existing original authority pin root (required)")
	auditJournal := f.String("audit-journal", "", "existing auditor journal root (required)")
	replicaJournal := f.String("replica-journal", "", "existing replica journal root (required)")
	artifacts := f.String("artifacts", "", "existing auditor artifact root and lock (required)")
	objects := f.String("objects", "", "existing verified object store (required)")
	auditorKeyPath := f.String("auditor-key", "", "existing auditor evidence seed file (required)")
	replicaKeyPath := f.String("replica-key", "", "existing replica proof seed file (required)")
	auditorTransportPath := f.String("auditor-transport-key", "", "existing auditor transport-only seed file (required)")
	replicaTransportPath := f.String("replica-transport-key", "", "existing replica transport-only seed file (required)")
	auditorText := f.String("auditor-peer-id", "", "independently pinned auditor transport ID (required)")
	replicaText := f.String("replica-peer-id", "", "independently pinned replica transport ID (required)")
	listen := f.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "dedicated direct IP/UDP/QUIC-v1 listen address for each local host")
	timeout := f.Duration("timeout", 10*time.Second, "per-exchange timeout, 100ms..10m; not a filesystem deadline")
	policyFlags := addArchiveCustodyPolicyFlags(f)
	journalFlags := addArchiveCustodyJournalLimitFlags(f)
	objectPolicy := workarchive.DefaultObjectStorePolicy()
	f.Uint64Var(&objectPolicy.MaximumObjects, "max-objects", objectPolicy.MaximumObjects, "local existing object count budget")
	f.Uint64Var(&objectPolicy.MaximumBytes, "max-object-bytes", objectPolicy.MaximumBytes, "local existing object byte budget")
	if err := parsePruneFlags(f, arguments[1:]); err != nil {
		return managedCustodyPairOptions{}, err
	}
	if *mode != "review" && *mode != "control" {
		return managedCustodyPairOptions{}, errors.New("pair mode must be review or control")
	}
	for _, value := range []string{*assignmentPath, *auditAdmission, *serveAdmission, *intentPath, *manifestPath, *receiptPath, *authority, *pins, *auditJournal, *replicaJournal, *artifacts, *objects, *auditorKeyPath, *replicaKeyPath, *auditorTransportPath, *replicaTransportPath, *listen} {
		if value == "" || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return managedCustodyPairOptions{}, errors.New("all canonical input files, existing participant roots, four seed files and listen are required as exact UTF-8 text")
		}
	}
	address, err := multiaddr.NewMultiaddr(*listen)
	if err != nil {
		return managedCustodyPairOptions{}, err
	}
	protocols := address.Protocols()
	if address.String() != *listen || len(protocols) != 3 || (protocols[0].Code != multiaddr.P_IP4 && protocols[0].Code != multiaddr.P_IP6) || protocols[1].Code != multiaddr.P_UDP || protocols[2].Code != multiaddr.P_QUIC_V1 {
		return managedCustodyPairOptions{}, errors.New("pair listen must be a canonical direct IP/UDP/QUIC-v1 multiaddress")
	}
	if err := errors.Join(policyFlags.validate(), journalFlags.limits().Validate(), objectPolicy.Validate()); err != nil {
		return managedCustodyPairOptions{}, err
	}
	configuration := workarchive.DefaultCustodySessionConfig()
	configuration.RequestTimeout = *timeout
	if err := configuration.Validate(); err != nil {
		return managedCustodyPairOptions{}, err
	}
	var assignmentID, auditTicket, serveTicket, intentID, challengeID, auditorID, replicaID types.Hash
	for _, field := range []struct {
		name, text string
		dst        *types.Hash
	}{
		{"assignment-id", *assignmentText, &assignmentID}, {"audit-ticket-id", *auditTicketText, &auditTicket}, {"serve-ticket-id", *serveTicketText, &serveTicket},
		{"intent-id", *intentText, &intentID}, {"challenge-id", *challengeText, &challengeID}, {"auditor-peer-id", *auditorText, &auditorID}, {"replica-peer-id", *replicaText, &replicaID},
	} {
		*field.dst, err = pruneExternalID(field.name, field.text)
		if err != nil {
			return managedCustodyPairOptions{}, err
		}
	}
	assignment, err := loadPruneOfflineAssignment(*assignmentPath, assignmentID)
	if err != nil {
		return managedCustodyPairOptions{}, err
	}
	schedule, err := scheduleFlags.load(assignment)
	if err != nil {
		return managedCustodyPairOptions{}, err
	}
	intent, err := workarchive.LoadCustodyAuditIntent(*intentPath, intentID)
	if err != nil || intent.AssignmentID != assignmentID || intent.ReplicaPeerID != replicaID {
		return managedCustodyPairOptions{}, errors.Join(errors.New("audit intent differs from assignment or replica transport pin"), err)
	}
	auditEntry, err := loadManagedCustodyPairAdmission(*auditAdmission, auditTicket, assignment, custodyauthority.Audit, intentID)
	if err != nil {
		return managedCustodyPairOptions{}, err
	}
	if auditEntry.Command.ActorPublicKey != intent.ConsumerPublicKey {
		return managedCustodyPairOptions{}, custodyauthority.ErrOperation
	}
	serveEntry, err := loadManagedCustodyPairAdmission(*serveAdmission, serveTicket, assignment, custodyauthority.Serve, challengeID)
	if err != nil {
		return managedCustodyPairOptions{}, err
	}
	manifest, err := loadArchiveManifest(*manifestPath)
	if err != nil {
		return managedCustodyPairOptions{}, err
	}
	receipt, err := loadArchiveReplicaReceipt(*receiptPath)
	if err != nil {
		return managedCustodyPairOptions{}, err
	}
	policy := workarchive.CustodyPolicy{TrustedAuditors: append([][32]byte(nil), assignment.Auditors...), MaximumChallengeLifetime: *policyFlags.challengeLifetime, MaximumProofAge: *policyFlags.proofAge, MaximumRenewalTerm: *policyFlags.renewalTerm}
	derived, err := workarchive.CreateCustodyAuthorityAssignment(manifest, receipt, policy, assignment.IncarnationID, assignment.AuthorityPublicKey, assignment.Consumers, assignment.MaximumOperations, assignment.MaximumPending)
	if err != nil {
		return managedCustodyPairOptions{}, err
	}
	derivedID, err := derived.ID()
	if err != nil || derivedID != assignmentID {
		return managedCustodyPairOptions{}, errors.Join(custodyauthority.ErrAssignment, err)
	}
	trustedAuditor := false
	for _, key := range assignment.Auditors {
		trustedAuditor = trustedAuditor || key == intent.AuditorPublicKey
	}
	if !trustedAuditor {
		return managedCustodyPairOptions{}, custodyauthority.ErrAssignment
	}
	if err := authoritystore.ValidatePruneRuntimePeers(assignment, auditorID, replicaID); err != nil {
		return managedCustodyPairOptions{}, err
	}
	canonicalIntent, _, err := canonicalPruneLineageFile(*intentPath)
	if err != nil {
		return managedCustodyPairOptions{}, err
	}
	roots := []*string{authority, pins, auditJournal, replicaJournal, artifacts, objects}
	for _, root := range roots {
		*root, err = canonicalPruneLineageDirectory(*root)
		if err != nil || !utf8.ValidString(*root) {
			return managedCustodyPairOptions{}, errors.Join(errors.New("pair roots must be existing exact UTF-8 directories"), err)
		}
	}
	allRoots := []string{*authority, *pins, *auditJournal, *replicaJournal, *artifacts, *objects, filepath.Dir(canonicalIntent)}
	for i := range allRoots {
		for j := i + 1; j < len(allRoots); j++ {
			if err := authoritystore.ValidateBootstrapPaths(allRoots[i], allRoots[j]); err != nil {
				return managedCustodyPairOptions{}, err
			}
		}
	}
	if !utf8.ValidString(canonicalIntent) {
		return managedCustodyPairOptions{}, errors.New("intent path must be exact UTF-8 text")
	}
	if err := ctx.Err(); err != nil {
		return managedCustodyPairOptions{}, err
	}
	// Every public content/role/path pin above is checked before opening seeds.
	auditorKey, err := loadPruneOfflineKey(*auditorKeyPath)
	if err != nil {
		return managedCustodyPairOptions{}, err
	}
	replicaKey, err := loadPruneOfflineKey(*replicaKeyPath)
	if err != nil {
		return managedCustodyPairOptions{}, err
	}
	auditorTransport, err := loadPruneOfflineKey(*auditorTransportPath)
	if err != nil {
		return managedCustodyPairOptions{}, err
	}
	replicaTransport, err := loadPruneOfflineKey(*replicaTransportPath)
	if err != nil {
		return managedCustodyPairOptions{}, err
	}
	if [32]byte(auditorKey.Public().(ed25519.PublicKey)) != intent.AuditorPublicKey || [32]byte(replicaKey.Public().(ed25519.PublicKey)) != receipt.ReplicaPublicKey {
		return managedCustodyPairOptions{}, errors.New("evidence seed files do not match the pinned auditor and replica keys")
	}
	for _, key := range []struct {
		key ed25519.PrivateKey
		id  types.Hash
	}{{auditorTransport, auditorID}, {replicaTransport, replicaID}} {
		id, err := transport.PeerIDFromPublicKey(key.key.Public().(ed25519.PublicKey))
		if err != nil || id != key.id {
			return managedCustodyPairOptions{}, errors.Join(errors.New("transport seed file differs from its independently pinned peer ID"), err)
		}
	}
	auditConfig := authoritystore.ManagedCustodyAuditConfig{Schedule: schedule, AssignmentID: assignmentID, IntentID: intentID, Admission: auditEntry, IntentPath: canonicalIntent,
		JournalPath: *auditJournal, ArtifactsPath: *artifacts, Manifest: manifest, InitialReceipt: receipt, CustodyPolicy: policy, JournalLimits: journalFlags.limits(), AuditorPrivateKey: auditorKey, SessionConfig: configuration}
	serveConfig := authoritystore.ManagedCustodyServeConfig{Schedule: schedule, AssignmentID: assignmentID, Admission: serveEntry, ChallengeID: challengeID, AuditorPeerID: auditorID,
		JournalPath: *replicaJournal, Manifest: manifest, InitialReceipt: receipt, CustodyPolicy: policy, JournalLimits: journalFlags.limits(), ReplicaPrivateKey: replicaKey, SessionConfig: configuration}
	return managedCustodyPairOptions{mode: *mode, listen: *listen, intent: intent, auditTicket: auditTicket, serveTicket: serveTicket, auditorTransport: auditorTransport, replicaTransport: replicaTransport,
		config: authoritystore.ManagedCustodyPairRuntimeConfig{AuthorityPath: *authority, AuthorityPinsPath: *pins, Assignment: assignment, Audit: auditConfig, Serve: serveConfig,
			ObjectPath: *objects, ObjectPolicy: objectPolicy, AuditorPeerID: auditorID, ReplicaPeerID: replicaID}}, nil
}

func loadManagedCustodyPairAdmission(path string, expected types.Hash, assignment custodyauthority.Assignment, purpose custodyauthority.Purpose, operation types.Hash) (custodyauthority.Entry, error) {
	encoded, err := readRegularArtifact(path, custodyauthority.MaximumEntryBytes)
	if err != nil {
		return custodyauthority.Entry{}, err
	}
	entry, err := custodyauthority.DecodeEntry(encoded)
	if err != nil {
		return custodyauthority.Entry{}, err
	}
	id, err := entry.ID()
	aid, _ := assignment.ID()
	c := entry.Command
	if err != nil || id != expected || entry.AuthorityPublicKey != assignment.AuthorityPublicKey || c.AssignmentID != aid || c.Kind != custodyauthority.Admit || c.Purpose != purpose || c.OperationID != operation {
		return custodyauthority.Entry{}, errors.Join(errors.New("admission differs from its exact ticket, assignment, purpose or operation pin"), err)
	}
	for _, consumer := range assignment.Consumers {
		if consumer.PublicKey == c.ActorPublicKey && consumer.Purposes&purpose != 0 {
			return entry, nil
		}
	}
	return custodyauthority.Entry{}, custodyauthority.ErrOperation
}

func writeManagedCustodyPairReview(output io.Writer, options managedCustodyPairOptions, review authoritystore.ManagedCustodyPairReview, retained bool) (types.Hash, types.Hash, error) {
	baseID, err := review.ID()
	if err != nil {
		return types.Hash{}, types.Hash{}, err
	}
	a := review.Audit
	public := struct {
		Authority, AuthorityPins, Intent, Artifacts, AuditJournal, ReplicaJournal, Objects, Listen      string
		ManifestID, InitialReceiptID, CustodyPolicyID                                                   string
		AssignmentID, AuditTicketID, ServeTicketID, IntentID, ChallengeID, AuditorPeerID, ReplicaPeerID string
		AuthoritySequence                                                                               uint64
		AuthorityHeadID                                                                                 string
		AuditSequence                                                                                   uint64
		AuditHeadID, AuditReceiptID                                                                     string
		ReplicaSequence                                                                                 uint64
		ReplicaHeadID, ReplicaReceiptID                                                                 string
		IssuedAt, ExpiresAt, RenewUntil                                                                 uint64
		RequestedSamples                                                                                uint16
		AuditRequestTimeout, ReplicaRequestTimeout                                                      string
		ChallengeLifetime, ProofAge, RenewalTerm                                                        uint64
		Auditors                                                                                        []string
		AuditJournalLimits, ReplicaJournalLimits                                                        workarchive.CustodyJournalLimits
		ObjectPolicy                                                                                    workarchive.ObjectStorePolicy
	}{Authority: a.AuthorityPath, AuthorityPins: a.AuthorityPinsPath, Intent: a.IntentPath, Artifacts: a.ArtifactsPath, AuditJournal: a.JournalPath,
		ReplicaJournal: review.ReplicaJournalPath, Objects: review.ObjectPath, Listen: options.listen,
		ManifestID: options.config.Assignment.ManifestID.String(), InitialReceiptID: options.config.Assignment.InitialReceiptID.String(), CustodyPolicyID: options.config.Assignment.CustodyPolicyID.String(),
		AssignmentID: a.AssignmentID.String(), AuditTicketID: a.AuditTicketID.String(), ServeTicketID: review.ServeTicketID.String(), IntentID: a.IntentID.String(), ChallengeID: review.ChallengeID.String(),
		AuditorPeerID: a.AuditorPeerID.String(), ReplicaPeerID: a.ReplicaPeerID.String(), AuthoritySequence: a.AuthorityPosition.Sequence, AuthorityHeadID: a.AuthorityPosition.HeadID.String(),
		AuditSequence: a.JournalSequence, AuditHeadID: a.JournalHeadID.String(), AuditReceiptID: a.CurrentReceiptID.String(), ReplicaSequence: review.ReplicaJournalSequence, ReplicaHeadID: review.ReplicaJournalHeadID.String(), ReplicaReceiptID: review.ReplicaReceiptID.String(),
		IssuedAt: options.intent.IssuedAt, ExpiresAt: options.intent.ExpiresAt, RenewUntil: options.intent.RenewUntil, RequestedSamples: options.intent.RequestedSamples,
		AuditRequestTimeout: a.RequestTimeout.String(), ReplicaRequestTimeout: review.ReplicaRequestTimeout.String(), ChallengeLifetime: options.config.Audit.CustodyPolicy.MaximumChallengeLifetime, ProofAge: options.config.Audit.CustodyPolicy.MaximumProofAge, RenewalTerm: options.config.Audit.CustodyPolicy.MaximumRenewalTerm,
		AuditJournalLimits: a.JournalLimits, ReplicaJournalLimits: review.ReplicaJournalLimits, ObjectPolicy: review.ObjectPolicy}
	for _, key := range options.config.Assignment.Auditors {
		public.Auditors = append(public.Auditors, types.Hash(key).String())
	}
	encoded, err := json.MarshalIndent(public, "", "  ")
	if err != nil {
		return types.Hash{}, types.Hash{}, err
	}
	id := types.DomainHash("OMESH/operator/custody-pair-cli-review/v0", baseID[:], encoded)
	if err := writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_managed_pair_review review_id=%s runtime_review_id=%s assignment_id=%s audit_ticket_id=%s serve_ticket_id=%s intent_id=%s challenge_id=%s owners_retained=%t exchange_authorized=false automatic_completion=false\n", id, baseID, a.AssignmentID, a.AuditTicketID, review.ServeTicketID, a.IntentID, review.ChallengeID, retained)); err != nil {
		return types.Hash{}, types.Hash{}, err
	}
	if err := writePruneOutputLine(output, "scope:\n"+string(encoded)+"\nwork_archive_custody_managed_pair_scope_end\n"); err != nil {
		return types.Hash{}, types.Hash{}, err
	}
	return id, baseID, nil
}

func readManagedCustodyPairControl(ctx context.Context, input io.Reader, lines chan<- string, terminal chan<- error, cancel context.CancelFunc) {
	fail := func(err error) { terminal <- err; cancel() }
	reader := bufio.NewReaderSize(input, maximumPruneControlLine)
	for {
		line, err := reader.ReadSlice('\n')
		if ctx.Err() != nil {
			terminal <- ctx.Err()
			return
		}
		if err != nil || len(line) > maximumPruneControlLine {
			if errors.Is(err, io.EOF) && len(line) == 0 {
				fail(io.EOF)
			} else {
				fail(errors.Join(errors.New("paired custody control needs bounded complete LF-terminated commands"), err))
			}
			return
		}
		text := string(line[:len(line)-1])
		select {
		case lines <- text:
		case <-ctx.Done():
			return
		default:
			fail(errors.New("paired custody control permits at most one queued command"))
			return
		}
		if text == "close" {
			return
		}
	}
}

func runManagedCustodyPairControl(parent context.Context, options managedCustodyPairOptions, input *pruneControlInput, output *pruneEffectOutput) (returnErr error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	lines, terminal := make(chan string, 1), make(chan error, 1)
	readerDone, ioDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(readerDone); readManagedCustodyPairControl(ctx, input, lines, terminal, cancel) }()
	stopIO := context.AfterFunc(ctx, func() { defer close(ioDone); _ = input.Close(); _ = output.Close() })
	defer func() {
		cancel()
		if !stopIO() {
			<-ioDone
		}
		_ = input.Close()
		_ = output.Close()
		<-readerDone
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	service, err := authoritystore.OpenManagedCustodyPairRuntime(ctx, options.config)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, service.Close()) }()
	if err := writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_managed_pair_ready assignment_id=%s audit_ticket_id=%s serve_ticket_id=%s intent_id=%s challenge_id=%s owners_retained=true listener_started=false automatic_exchange=false automatic_completion=false\n", options.config.Audit.AssignmentID, options.auditTicket, options.serveTicket, options.config.Audit.IntentID, options.config.Serve.ChallengeID)); err != nil {
		return err
	}
	var reported, base types.Hash
	for {
		select {
		case <-ctx.Done():
			select {
			case err := <-terminal:
				if err == io.EOF {
					return nil
				}
				return err
			default:
				return ctx.Err()
			}
		case err := <-terminal:
			if err == io.EOF {
				return nil
			}
			return err
		case line := <-lines:
			if err := ctx.Err(); err != nil {
				return err
			}
			switch {
			case line == "close":
				return nil
			case line == "review":
				review, err := service.Review(ctx)
				if err != nil {
					return err
				}
				reported, base, err = writeManagedCustodyPairReview(output, options, review, true)
				if err != nil {
					return err
				}
			case strings.HasPrefix(line, "exchange "):
				text := strings.TrimPrefix(line, "exchange ")
				id, err := pruneExternalID("review-id", text)
				if err != nil || reported.IsZero() || id != reported {
					return errors.Join(errors.New("exchange requires the exact complete review already reported by this session"), err)
				}
				expected := base
				reported, base = types.Hash{}, types.Hash{}
				transportConfig := libp2ptransport.DefaultConfig()
				transportConfig.Listen = []string{options.listen}
				result, err := service.ExchangeQUICReviewed(ctx, expected, options.auditorTransport, options.replicaTransport, transportConfig)
				if err != nil {
					return err
				}
				if err := writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_managed_pair_exchanged expected_review_id=%s intent_id=%s challenge_id=%s proof_id=%s renewal_id=%s audit_sequence=%d replica_sequence=%d recovered=%t owners_retained=true automatic_completion=false\n", id, options.config.Audit.IntentID, result.Serve.ChallengeID, result.Serve.ProofID, result.Serve.RenewedReceiptID, result.Audit.JournalSequence, result.Serve.JournalSequence, result.Audit.Recovered)); err != nil {
					return errors.Join(errManagedCustodyPairUnobserved, err)
				}
			default:
				return errors.New("paired custody control accepts only review, exchange <review-id>, or close")
			}
		}
	}
}
