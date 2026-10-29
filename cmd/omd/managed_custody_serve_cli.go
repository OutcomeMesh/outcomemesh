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

const managedCustodyServeCommand = "work-archive-custody-managed-serve-quic"

type managedCustodyServeOptions struct {
	mode, listen string
	config       authoritystore.ManagedCustodyServeServiceConfig
	transportKey ed25519.PrivateKey
	ticketID     types.Hash
}

func runManagedCustodyServeCLI(arguments []string) error {
	brokenPipe := make(chan os.Signal, 1)
	signal.Notify(brokenPipe, syscall.SIGPIPE)
	defer signal.Stop(brokenPipe)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runManagedCustodyServe(ctx, arguments, os.Stdin, os.Stdout)
}

// Review never starts a listener and releases every original owner before
// reporting its scope. Serve explicitly transfers dedicated control pipes and
// retains the owners until cancellation has drained accepted handlers.
func runManagedCustodyServe(ctx context.Context, arguments []string, input io.ReadCloser, output io.Writer) (returnErr error) {
	if ctx == nil || output == nil {
		return errors.New("managed custody serving requires context and output")
	}
	options, err := loadManagedCustodyServeOptions(ctx, arguments)
	if err != nil {
		return err
	}
	if options.mode == "review" {
		service, err := authoritystore.OpenManagedCustodyServeServiceContext(ctx, options.config)
		if err != nil {
			return err
		}
		if err := service.Close(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if file, ok := output.(*os.File); ok {
			info, err := file.Stat()
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeNamedPipe != 0 && (runtime.GOOS == "darwin" || runtime.GOOS == "linux") {
				writer, err := ownPruneEffectOutput(output)
				if err != nil {
					return err
				}
				defer func() { returnErr = errors.Join(returnErr, writer.Close()) }()
				closed := make(chan struct{})
				stop := context.AfterFunc(ctx, func() { _ = writer.Close(); close(closed) })
				defer func() {
					if !stop() {
						<-closed
					}
				}()
				output = writer
			}
		}
		return writeManagedCustodyServeReview(output, options)
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
	return runManagedCustodyServeControl(ctx, options, control, writer)
}

func loadManagedCustodyServeOptions(ctx context.Context, arguments []string) (managedCustodyServeOptions, error) {
	if ctx == nil || len(arguments) == 0 || arguments[0] != managedCustodyServeCommand {
		return managedCustodyServeOptions{}, errors.New("managed custody serving requires its explicit command and context")
	}
	if err := ctx.Err(); err != nil {
		return managedCustodyServeOptions{}, err
	}
	flags := flag.NewFlagSet(managedCustodyServeCommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	scheduleFlags := addCustodyScheduleFlags(flags)
	mode := flags.String("mode", "review", "review (default) or explicitly supervised serve")
	assignmentPath := flags.String("assignment", "", "existing canonical assignment file (required)")
	assignmentText := flags.String("assignment-id", "", "independently pinned assignment ID (required)")
	admissionPath := flags.String("admission", "", "existing canonical signed Serve admission file (required)")
	ticketText := flags.String("ticket-id", "", "independently pinned Serve admission ticket ID (required)")
	challengeText := flags.String("challenge-id", "", "independently pinned signed challenge ID (required)")
	manifestPath := flags.String("manifest", "", "existing canonical archive manifest file (required)")
	receiptPath := flags.String("receipt", "", "existing canonical initial replica receipt file (required)")
	authority := flags.String("authority", "", "existing original authority root (required)")
	pins := flags.String("authority-pins", "", "existing original authority pin root (required)")
	journal := flags.String("journal", "", "existing active version-0 custody journal (required)")
	objects := flags.String("objects", "", "existing verified archive object store (required)")
	keyPath := flags.String("key", "", "existing transport-only 32-byte seed file (required)")
	replicaKeyPath := flags.String("replica-key", "", "existing receipt/proof 32-byte seed file (required)")
	serverText := flags.String("server-peer-id", "", "independently pinned server transport ID (required)")
	auditorText := flags.String("auditor-peer-id", "", "independently pinned allowed auditor transport ID (required)")
	listen := flags.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "dedicated direct QUIC-v1 listen address")
	timeout := flags.Duration("timeout", 10*time.Second, "per-exchange timeout, 100ms..10m; not a filesystem deadline")
	policyFlags := addArchiveCustodyPolicyFlags(flags)
	journalFlags := addArchiveCustodyJournalLimitFlags(flags)
	objectPolicy := workarchive.DefaultObjectStorePolicy()
	flags.Uint64Var(&objectPolicy.MaximumObjects, "max-objects", objectPolicy.MaximumObjects, "local existing object-store count budget")
	flags.Uint64Var(&objectPolicy.MaximumBytes, "max-object-bytes", objectPolicy.MaximumBytes, "local existing object-store byte budget")
	if err := parsePruneFlags(flags, arguments[1:]); err != nil {
		return managedCustodyServeOptions{}, err
	}
	if *mode != "review" && *mode != "serve" {
		return managedCustodyServeOptions{}, errors.New("managed custody mode must be review or serve")
	}
	for _, path := range []string{*assignmentPath, *admissionPath, *manifestPath, *receiptPath, *authority, *pins, *journal, *objects, *keyPath, *replicaKeyPath, *listen} {
		if path == "" || !utf8.ValidString(path) || strings.ContainsRune(path, '\x00') {
			return managedCustodyServeOptions{}, errors.New("assignment, admission, manifest, receipt, all existing roots, both seed files and listen are required")
		}
	}
	address, err := multiaddr.NewMultiaddr(*listen)
	if err != nil {
		return managedCustodyServeOptions{}, errors.Join(errors.New("listen must be a canonical direct IP/UDP/QUIC-v1 multiaddress"), err)
	}
	protocols := address.Protocols()
	if address.String() != *listen || len(protocols) != 3 ||
		(protocols[0].Code != multiaddr.P_IP4 && protocols[0].Code != multiaddr.P_IP6) ||
		protocols[1].Code != multiaddr.P_UDP || protocols[2].Code != multiaddr.P_QUIC_V1 {
		return managedCustodyServeOptions{}, errors.New("listen must be a canonical direct IP/UDP/QUIC-v1 multiaddress")
	}
	if err := errors.Join(policyFlags.validate(), journalFlags.limits().Validate(), objectPolicy.Validate()); err != nil {
		return managedCustodyServeOptions{}, err
	}
	configuration := workarchive.DefaultCustodySessionConfig()
	configuration.RequestTimeout = *timeout
	if err := configuration.Validate(); err != nil {
		return managedCustodyServeOptions{}, err
	}
	var assignmentID, ticketID, challengeID, serverID, auditorID types.Hash
	for _, field := range []struct {
		name, text string
		value      *types.Hash
	}{{"assignment-id", *assignmentText, &assignmentID}, {"ticket-id", *ticketText, &ticketID}, {"challenge-id", *challengeText, &challengeID},
		{"server-peer-id", *serverText, &serverID}, {"auditor-peer-id", *auditorText, &auditorID}} {
		id, err := pruneExternalID(field.name, field.text)
		if err != nil {
			return managedCustodyServeOptions{}, err
		}
		*field.value = id
	}
	assignment, err := loadPruneOfflineAssignment(*assignmentPath, assignmentID)
	if err != nil {
		return managedCustodyServeOptions{}, err
	}
	schedule, err := scheduleFlags.load(assignment)
	if err != nil {
		return managedCustodyServeOptions{}, err
	}
	encoded, err := readRegularArtifact(*admissionPath, custodyauthority.MaximumEntryBytes)
	if err != nil {
		return managedCustodyServeOptions{}, err
	}
	admission, err := custodyauthority.DecodeEntry(encoded)
	if err != nil {
		return managedCustodyServeOptions{}, err
	}
	id, err := admission.ID()
	c := admission.Command
	if err != nil || id != ticketID || admission.AuthorityPublicKey != assignment.AuthorityPublicKey ||
		c.AssignmentID != assignmentID || c.Kind != custodyauthority.Admit || c.Purpose != custodyauthority.Serve || c.OperationID != challengeID {
		return managedCustodyServeOptions{}, errors.Join(errors.New("Serve admission differs from its independently selected ticket, assignment or challenge"), err)
	}
	consumer := false
	for _, selected := range assignment.Consumers {
		consumer = consumer || (selected.PublicKey == c.ActorPublicKey && selected.Purposes&custodyauthority.Serve != 0)
	}
	if !consumer {
		return managedCustodyServeOptions{}, custodyauthority.ErrOperation
	}
	manifest, err := loadArchiveManifest(*manifestPath)
	if err != nil {
		return managedCustodyServeOptions{}, err
	}
	receipt, err := loadArchiveReplicaReceipt(*receiptPath)
	if err != nil {
		return managedCustodyServeOptions{}, err
	}
	policy := workarchive.CustodyPolicy{TrustedAuditors: append([][32]byte(nil), assignment.Auditors...),
		MaximumChallengeLifetime: *policyFlags.challengeLifetime, MaximumProofAge: *policyFlags.proofAge, MaximumRenewalTerm: *policyFlags.renewalTerm}
	derived, err := workarchive.CreateCustodyAuthorityAssignment(manifest, receipt, policy, assignment.IncarnationID,
		assignment.AuthorityPublicKey, assignment.Consumers, assignment.MaximumOperations, assignment.MaximumPending)
	if err != nil {
		return managedCustodyServeOptions{}, err
	}
	derivedID, err := derived.ID()
	if err != nil || derivedID != assignmentID {
		return managedCustodyServeOptions{}, errors.Join(custodyauthority.ErrAssignment, err)
	}
	if err := authoritystore.ValidatePruneRuntimePeers(assignment, serverID, auditorID); err != nil {
		return managedCustodyServeOptions{}, err
	}
	// Public pins and pairwise existing-root placement are checked before any
	// seed is read. Current authority and journal replay remain the service's job.
	roots := []*string{authority, pins, journal, objects}
	for _, root := range roots {
		*root, err = canonicalPruneLineageDirectory(*root)
		if err != nil {
			return managedCustodyServeOptions{}, err
		}
		if !utf8.ValidString(*root) {
			return managedCustodyServeOptions{}, errors.New("existing root paths must be representable as exact UTF-8 scope text")
		}
	}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if err := authoritystore.ValidateBootstrapPaths(*roots[i], *roots[j]); err != nil {
				return managedCustodyServeOptions{}, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return managedCustodyServeOptions{}, err
	}
	replicaKey, err := loadPruneOfflineKey(*replicaKeyPath)
	if err != nil {
		return managedCustodyServeOptions{}, err
	}
	transportKey, err := loadPruneOfflineKey(*keyPath)
	if err != nil {
		return managedCustodyServeOptions{}, err
	}
	keyID, err := transport.PeerIDFromPublicKey(transportKey.Public().(ed25519.PublicKey))
	if err != nil || keyID != serverID || [32]byte(replicaKey.Public().(ed25519.PublicKey)) != receipt.ReplicaPublicKey {
		return managedCustodyServeOptions{}, errors.Join(errors.New("seed files do not match the independently pinned transport and replica keys"), err)
	}
	return managedCustodyServeOptions{mode: *mode, listen: *listen, ticketID: ticketID, transportKey: transportKey,
		config: authoritystore.ManagedCustodyServeServiceConfig{AuthorityPath: *authority, AuthorityPinsPath: *pins,
			Assignment: assignment, ObjectPath: *objects, ObjectPolicy: objectPolicy, ServerPeerID: serverID,
			Session: authoritystore.ManagedCustodyServeConfig{Schedule: schedule, AssignmentID: assignmentID, Admission: admission, ChallengeID: challengeID,
				AuditorPeerID: auditorID, JournalPath: *journal, Manifest: manifest, InitialReceipt: receipt, CustodyPolicy: policy,
				JournalLimits: journalFlags.limits(), ReplicaPrivateKey: replicaKey, SessionConfig: configuration}}}, nil
}

func writeManagedCustodyServeReview(output io.Writer, options managedCustodyServeOptions) error {
	c, s := options.config, options.config.Session
	scope := struct {
		ScheduleID     string                           `json:"schedule_id,omitempty"`
		Authority      string                           `json:"authority"`
		AuthorityPins  string                           `json:"authority_pins"`
		Journal        string                           `json:"journal"`
		Objects        string                           `json:"objects"`
		Listen         string                           `json:"listen"`
		RequestTimeout string                           `json:"request_timeout"`
		ManifestID     string                           `json:"manifest_id"`
		InitialReceipt string                           `json:"initial_receipt_id"`
		CustodyPolicy  string                           `json:"custody_policy_id"`
		Auditors       []string                         `json:"trusted_auditors"`
		ChallengeLimit uint64                           `json:"max_challenge_lifetime_seconds"`
		ProofAge       uint64                           `json:"max_proof_age_seconds"`
		RenewalTerm    uint64                           `json:"max_renewal_term_seconds"`
		JournalLimits  workarchive.CustodyJournalLimits `json:"journal_limits"`
		ObjectPolicy   workarchive.ObjectStorePolicy    `json:"object_policy"`
	}{Authority: c.AuthorityPath, AuthorityPins: c.AuthorityPinsPath, Journal: s.JournalPath, Objects: c.ObjectPath,
		Listen: options.listen, RequestTimeout: s.SessionConfig.RequestTimeout.String(), ManifestID: c.Assignment.ManifestID.String(),
		InitialReceipt: c.Assignment.InitialReceiptID.String(), CustodyPolicy: c.Assignment.CustodyPolicyID.String(),
		ChallengeLimit: s.CustodyPolicy.MaximumChallengeLifetime, ProofAge: s.CustodyPolicy.MaximumProofAge,
		RenewalTerm: s.CustodyPolicy.MaximumRenewalTerm, JournalLimits: s.JournalLimits, ObjectPolicy: c.ObjectPolicy}
	if s.Schedule != nil {
		scope.ScheduleID = s.Schedule.ExpectedID.String()
	}
	for _, key := range s.CustodyPolicy.TrustedAuditors {
		scope.Auditors = append(scope.Auditors, types.Hash(key).String())
	}
	encoded, err := json.MarshalIndent(scope, "", "  ")
	if err != nil {
		return err
	}
	return writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_managed_serve_review assignment_id=%s ticket_id=%s challenge_id=%s server_peer_id=%s auditor_peer_id=%s owners_retained=false listener_started=false automatic_completion=false\nscope:\n%s\nwork_archive_custody_managed_serve_scope_end\n",
		s.AssignmentID, options.ticketID, s.ChallengeID, c.ServerPeerID, s.AuditorPeerID, encoded))
}

func runManagedCustodyServeControl(parent context.Context, options managedCustodyServeOptions, input *pruneControlInput, output *pruneEffectOutput) (returnErr error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	terminal, readerDone := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(readerDone)
		reader := bufio.NewReaderSize(input, maximumPruneControlLine)
		line, err := reader.ReadSlice('\n')
		if ctx.Err() != nil {
			terminal <- nil
			return
		}
		if errors.Is(err, io.EOF) && len(line) == 0 || err == nil && string(line) == "close\n" {
			terminal <- nil
		} else {
			terminal <- errors.Join(errors.New("managed custody control accepts only close followed by LF or EOF"), err)
		}
		cancel()
	}()
	ioDone := make(chan struct{})
	stopIO := context.AfterFunc(ctx, func() {
		defer close(ioDone)
		_ = input.Close()
		_ = output.Close()
	})
	defer func() {
		cancel()
		if !stopIO() {
			<-ioDone
		}
		// When cancellation won before the callback was scheduled, Close still
		// interrupts the reader. No input goroutine outlives its owned pipes.
		_ = input.Close()
		_ = output.Close()
		<-readerDone
	}()
	if err := ctx.Err(); err != nil {
		select {
		case result := <-terminal:
			return result
		default:
			return err
		}
	}
	service, err := authoritystore.OpenManagedCustodyServeServiceContext(ctx, options.config)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, service.Close()) }()
	transportConfig := libp2ptransport.DefaultConfig()
	transportConfig.Listen = []string{options.listen}
	if err := service.Start(ctx, options.transportKey, transportConfig); err != nil {
		return err
	}
	s := options.config.Session
	if err := writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_managed_serve_ready assignment_id=%s ticket_id=%s challenge_id=%s server_peer_id=%s auditor_peer_id=%s listen=%s owners_retained=true automatic_completion=false\n",
		s.AssignmentID, options.ticketID, s.ChallengeID, options.config.ServerPeerID, s.AuditorPeerID, strings.Join(service.Addresses(), ","))); err != nil {
		return err
	}
	select {
	case err := <-terminal:
		return err
	case <-ctx.Done():
		select {
		case err := <-terminal:
			return err
		default:
			return nil // outer Close still reports shutdown/storage failures
		}
	case <-service.Done():
		select {
		case err := <-terminal:
			return err
		default:
			return nil // outer Close reads the service's retained shutdown error
		}
	}
}
