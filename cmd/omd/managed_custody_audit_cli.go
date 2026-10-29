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

const managedCustodyAuditCommand = "work-archive-custody-managed-audit-quic"

var errManagedCustodyAuditUnobserved = errors.New("audit action result was not observed; inspect retained intent, journal and artifacts before an explicit retry")

type managedCustodyAuditOptions struct {
	mode, address, listen string
	config                authoritystore.ManagedCustodyAuditRuntimeConfig
	transportKey          ed25519.PrivateKey
	ticketID              types.Hash
}

func runManagedCustodyAuditCLI(arguments []string) error {
	brokenPipe := make(chan os.Signal, 1)
	signal.Notify(brokenPipe, syscall.SIGPIPE)
	defer signal.Stop(brokenPipe)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runManagedCustodyAudit(ctx, arguments, os.Stdin, os.Stdout)
}

func runManagedCustodyAudit(ctx context.Context, arguments []string, input io.ReadCloser, output io.Writer) (returnErr error) {
	if ctx == nil || output == nil {
		return errors.New("managed audit requires context and output")
	}
	options, err := loadManagedCustodyAuditOptions(ctx, arguments)
	if err != nil {
		return err
	}
	if options.mode == "review" {
		owner, err := authoritystore.OpenManagedCustodyAuditRuntime(ctx, options.config)
		if err != nil {
			return err
		}
		review, reviewErr := owner.Review(ctx)
		if err := errors.Join(reviewErr, owner.Close()); err != nil {
			return err
		}
		return managedCustodyAuditReviewOutput(ctx, output, options, review, false)
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
	return runManagedCustodyAuditControl(ctx, options, control, writer)
}

func managedCustodyExternalID(name, text string) (types.Hash, error) {
	id, err := pruneExternalID(name, text)
	if err != nil || id.String() != text {
		return types.Hash{}, errors.Join(fmt.Errorf("%s requires an exact lowercase nonzero 32-byte hexadecimal ID", name), err)
	}
	return id, nil
}

func managedCustodyCanonicalDirectory(path string) (string, error) {
	if path == "" || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
		return "", errors.New("existing root must be nonempty UTF-8 text without NUL")
	}
	canonical, err := canonicalPruneLineageDirectory(path)
	if err != nil || !utf8.ValidString(canonical) {
		return "", errors.Join(errors.New("existing root must have an exact UTF-8 canonical placement"), err)
	}
	return canonical, nil
}

func managedCustodyDirectAddress(text string, withPeer bool) error {
	address, err := multiaddr.NewMultiaddr(text)
	if err != nil {
		return err
	}
	ps := address.Protocols()
	count := 3
	if withPeer {
		count = 4
	}
	if address.String() != text || len(ps) != count || (ps[0].Code != multiaddr.P_IP4 && ps[0].Code != multiaddr.P_IP6) || ps[1].Code != multiaddr.P_UDP || ps[2].Code != multiaddr.P_QUIC_V1 || (withPeer && ps[3].Code != multiaddr.P_P2P) {
		return errors.New("route must be a canonical direct IP/UDP/QUIC-v1 address with a peer suffix only for a remote route")
	}
	return nil
}

func loadManagedCustodyAuditOptions(ctx context.Context, arguments []string) (managedCustodyAuditOptions, error) {
	if ctx == nil || len(arguments) == 0 || arguments[0] != managedCustodyAuditCommand {
		return managedCustodyAuditOptions{}, errors.New("managed audit requires its explicit command and context")
	}
	if err := ctx.Err(); err != nil {
		return managedCustodyAuditOptions{}, err
	}
	flags := flag.NewFlagSet(managedCustodyAuditCommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	scheduleFlags := addCustodyScheduleFlags(flags)
	mode := flags.String("mode", "review", "review (default), or supervised control")
	assignmentPath := flags.String("assignment", "", "existing canonical assignment file (required)")
	assignmentText := flags.String("assignment-id", "", "independently pinned assignment ID (required)")
	admissionPath := flags.String("admission", "", "existing canonical co-signed Audit admission (required)")
	ticketText := flags.String("ticket-id", "", "independently pinned Audit admission ID (required)")
	intentPath := flags.String("intent", "", "existing unsigned canonical intent in a separate parent (required)")
	intentText := flags.String("intent-id", "", "independently pinned unsigned intent ID (required)")
	manifestPath := flags.String("manifest", "", "existing canonical manifest (required)")
	receiptPath := flags.String("receipt", "", "existing journal initial receipt (required)")
	authority := flags.String("authority", "", "existing original authority root (required)")
	pins := flags.String("authority-pins", "", "existing original authority pin root (required)")
	journal := flags.String("journal", "", "existing active auditor journal (required)")
	artifacts := flags.String("artifacts", "", "existing auditor artifact root and custody.lock (required)")
	auditorKey := flags.String("auditor-key", "", "existing auditor evidence-key 32-byte seed (required)")
	auditorPeerText := flags.String("auditor-peer-id", "", "independently pinned auditor transport ID (required)")
	transportKey := flags.String("transport-key", "", "existing transport-only 32-byte seed; supply together with peer for network audit")
	address := flags.String("peer", "", "direct pinned replica route; requires transport-key")
	listen := flags.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "local client direct QUIC listen address")
	timeout := flags.Duration("timeout", 10*time.Second, "network deadline, 100ms..10m; not a filesystem deadline")
	policyFlags := addArchiveCustodyPolicyFlags(flags)
	journalFlags := addArchiveCustodyJournalLimitFlags(flags)
	if err := parsePruneFlags(flags, arguments[1:]); err != nil {
		return managedCustodyAuditOptions{}, err
	}
	if *mode != "review" && *mode != "control" {
		return managedCustodyAuditOptions{}, errors.New("managed audit mode must be review or control")
	}
	for _, p := range []string{*assignmentPath, *admissionPath, *intentPath, *manifestPath, *receiptPath, *authority, *pins, *journal, *artifacts, *auditorKey, *listen} {
		if p == "" || !utf8.ValidString(p) || strings.ContainsRune(p, 0) {
			return managedCustodyAuditOptions{}, errors.New("all existing scope paths, evidence seed and local listen are required as exact UTF-8 text")
		}
	}
	if (*transportKey == "") != (*address == "") {
		return managedCustodyAuditOptions{}, errors.New("peer and transport-key must be supplied together")
	}
	if !utf8.ValidString(*transportKey) || !utf8.ValidString(*address) || strings.ContainsRune(*transportKey, 0) || strings.ContainsRune(*address, 0) {
		return managedCustodyAuditOptions{}, errors.New("network route and key path must be exact UTF-8 text")
	}
	if err := managedCustodyDirectAddress(*listen, false); err != nil {
		return managedCustodyAuditOptions{}, err
	}
	if *address != "" {
		if err := managedCustodyDirectAddress(*address, true); err != nil {
			return managedCustodyAuditOptions{}, err
		}
	}
	if err := errors.Join(policyFlags.validate(), journalFlags.limits().Validate()); err != nil {
		return managedCustodyAuditOptions{}, err
	}
	config := workarchive.DefaultCustodySessionConfig()
	config.RequestTimeout = *timeout
	if err := config.Validate(); err != nil {
		return managedCustodyAuditOptions{}, err
	}
	var assignmentID, ticketID, intentID, auditorPeer types.Hash
	for _, f := range []struct {
		name, text string
		out        *types.Hash
	}{{"assignment-id", *assignmentText, &assignmentID}, {"ticket-id", *ticketText, &ticketID}, {"intent-id", *intentText, &intentID}, {"auditor-peer-id", *auditorPeerText, &auditorPeer}} {
		id, err := managedCustodyExternalID(f.name, f.text)
		if err != nil {
			return managedCustodyAuditOptions{}, err
		}
		*f.out = id
	}
	a, err := loadPruneOfflineAssignment(*assignmentPath, assignmentID)
	if err != nil {
		return managedCustodyAuditOptions{}, err
	}
	schedule, err := scheduleFlags.load(a)
	if err != nil {
		return managedCustodyAuditOptions{}, err
	}
	intent, err := workarchive.LoadCustodyAuditIntent(*intentPath, intentID)
	if err != nil {
		return managedCustodyAuditOptions{}, err
	}
	if err := validateManagedCustodyIntentAssignment(a, assignmentID, intent); err != nil {
		return managedCustodyAuditOptions{}, err
	}
	if err := authoritystore.ValidatePruneRuntimePeers(a, auditorPeer, intent.ReplicaPeerID); err != nil {
		return managedCustodyAuditOptions{}, err
	}
	if *address != "" {
		routeID, err := libp2ptransport.PeerIDFromAddress(*address)
		if err != nil || routeID != intent.ReplicaPeerID {
			return managedCustodyAuditOptions{}, errors.Join(errors.New("peer route differs from the independently pinned replica transport identity"), err)
		}
	}
	encoded, err := readRegularArtifact(*admissionPath, custodyauthority.MaximumEntryBytes)
	if err != nil {
		return managedCustodyAuditOptions{}, err
	}
	admission, err := custodyauthority.DecodeEntry(encoded)
	if err != nil {
		return managedCustodyAuditOptions{}, err
	}
	id, err := admission.ID()
	c := admission.Command
	if err != nil || id != ticketID || admission.AuthorityPublicKey != a.AuthorityPublicKey || c.AssignmentID != assignmentID || c.Kind != custodyauthority.Admit || c.Purpose != custodyauthority.Audit || c.OperationID != intentID || c.ActorPublicKey != intent.ConsumerPublicKey {
		return managedCustodyAuditOptions{}, errors.Join(errors.New("Audit admission differs from pinned ticket, intent, actor or assignment"), err)
	}
	manifest, err := loadArchiveManifest(*manifestPath)
	if err != nil {
		return managedCustodyAuditOptions{}, err
	}
	receipt, err := loadArchiveReplicaReceipt(*receiptPath)
	if err != nil {
		return managedCustodyAuditOptions{}, err
	}
	policy := workarchive.CustodyPolicy{TrustedAuditors: append([][32]byte(nil), a.Auditors...), MaximumChallengeLifetime: *policyFlags.challengeLifetime, MaximumProofAge: *policyFlags.proofAge, MaximumRenewalTerm: *policyFlags.renewalTerm}
	derived, err := workarchive.CreateCustodyAuthorityAssignment(manifest, receipt, policy, a.IncarnationID, a.AuthorityPublicKey, a.Consumers, a.MaximumOperations, a.MaximumPending)
	if err != nil {
		return managedCustodyAuditOptions{}, err
	}
	derivedID, err := derived.ID()
	if err != nil || derivedID != assignmentID {
		return managedCustodyAuditOptions{}, errors.Join(custodyauthority.ErrAssignment, err)
	}
	for _, root := range []*string{authority, pins, journal, artifacts} {
		*root, err = managedCustodyCanonicalDirectory(*root)
		if err != nil {
			return managedCustodyAuditOptions{}, err
		}
	}
	canonicalIntent, _, err := canonicalPruneLineageFile(*intentPath)
	if err != nil {
		return managedCustodyAuditOptions{}, err
	}
	if !utf8.ValidString(canonicalIntent) {
		return managedCustodyAuditOptions{}, errors.New("canonical intent placement must be exact UTF-8 text")
	}
	roots := []string{*authority, *pins, *journal, *artifacts, filepath.Dir(canonicalIntent)}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if err := authoritystore.ValidateBootstrapPaths(roots[i], roots[j]); err != nil {
				return managedCustodyAuditOptions{}, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return managedCustodyAuditOptions{}, err
	}
	evidence, err := loadPruneOfflineKey(*auditorKey)
	if err != nil {
		return managedCustodyAuditOptions{}, err
	}
	if [32]byte(evidence.Public().(ed25519.PublicKey)) != intent.AuditorPublicKey {
		return managedCustodyAuditOptions{}, errors.New("auditor evidence seed does not match the retained intent")
	}
	var transportPrivate ed25519.PrivateKey
	if *transportKey != "" {
		transportPrivate, err = loadPruneOfflineKey(*transportKey)
		if err != nil {
			return managedCustodyAuditOptions{}, err
		}
		id, err := transport.PeerIDFromPublicKey(transportPrivate.Public().(ed25519.PublicKey))
		if err != nil || id != auditorPeer {
			return managedCustodyAuditOptions{}, errors.Join(errors.New("transport seed does not match auditor peer pin"), err)
		}
	}
	return managedCustodyAuditOptions{mode: *mode, address: *address, listen: *listen, ticketID: ticketID, transportKey: transportPrivate,
		config: authoritystore.ManagedCustodyAuditRuntimeConfig{AuthorityPath: *authority, AuthorityPinsPath: *pins, Assignment: a, AuditorPeerID: auditorPeer,
			Audit: authoritystore.ManagedCustodyAuditConfig{Schedule: schedule, AssignmentID: assignmentID, IntentID: intentID, Admission: admission, IntentPath: canonicalIntent, JournalPath: *journal, ArtifactsPath: *artifacts, Manifest: manifest, InitialReceipt: receipt, CustodyPolicy: policy, JournalLimits: journalFlags.limits(), AuditorPrivateKey: evidence, SessionConfig: config}}}, nil
}

func validateManagedCustodyIntentAssignment(a custodyauthority.Assignment, id types.Hash, intent workarchive.CustodyAuditIntent) error {
	if intent.Validate() != nil || intent.AssignmentID != id {
		return custodyauthority.ErrAssignment
	}
	if intent.PriorSequence == 0 && intent.PriorReceiptID != a.InitialReceiptID {
		return custodyauthority.ErrAssignment
	}
	consumer, auditor := false, false
	for _, c := range a.Consumers {
		consumer = consumer || (c.PublicKey == intent.ConsumerPublicKey && c.Purposes&custodyauthority.Audit != 0)
	}
	for _, k := range a.Auditors {
		auditor = auditor || k == intent.AuditorPublicKey
	}
	if !consumer || !auditor {
		return custodyauthority.ErrOperation
	}
	for _, k := range append(append([][32]byte{a.AuthorityPublicKey, a.ReplicaPublicKey}, a.Auditors...), intent.ConsumerPublicKey) {
		peer, err := transport.PeerIDFromPublicKey(k[:])
		if err != nil || peer == intent.ReplicaPeerID {
			return errors.Join(custodyauthority.ErrAssignment, err)
		}
	}
	for _, c := range a.Consumers {
		peer, err := transport.PeerIDFromPublicKey(c.PublicKey[:])
		if err != nil || peer == intent.ReplicaPeerID {
			return errors.Join(custodyauthority.ErrAssignment, err)
		}
	}
	return nil
}

func managedCustodyAuditScope(options managedCustodyAuditOptions, review authoritystore.ManagedCustodyAuditReview) ([]byte, types.Hash, error) {
	base, err := review.ID()
	if err != nil {
		return nil, types.Hash{}, err
	}
	encoded, err := json.MarshalIndent(struct {
		Review         authoritystore.ManagedCustodyAuditReview `json:"review"`
		BaseID         string                                   `json:"base_review_id"`
		AuditorPeerID  string                                   `json:"auditor_peer_id"`
		ReplicaPeerID  string                                   `json:"replica_peer_id"`
		AuthorityHead  string                                   `json:"authority_head_id"`
		JournalHead    string                                   `json:"journal_head_id"`
		CurrentReceipt string                                   `json:"current_receipt_id"`
		Address        string                                   `json:"replica_route"`
		Listen         string                                   `json:"client_listen"`
		NetworkEnabled bool                                     `json:"network_enabled"`
		Policy         workarchive.CustodyPolicy                `json:"custody_policy"`
	}{review, base.String(), review.AuditorPeerID.String(), review.ReplicaPeerID.String(), review.AuthorityPosition.HeadID.String(), review.JournalHeadID.String(), review.CurrentReceiptID.String(), options.address, options.listen, len(options.transportKey) != 0, options.config.Audit.CustodyPolicy}, "", "  ")
	if err != nil {
		return nil, types.Hash{}, err
	}
	return encoded, types.DomainHash("OMESH/local/custody-audit-cli-review/v0", encoded), nil
}

func managedCustodyAuditReviewOutput(ctx context.Context, output io.Writer, options managedCustodyAuditOptions, review authoritystore.ManagedCustodyAuditReview, retained bool) (returnErr error) {
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
			done := make(chan struct{})
			stop := context.AfterFunc(ctx, func() { defer close(done); _ = writer.Close() })
			defer func() {
				if !stop() {
					<-done
				}
			}()
			output = writer
		}
	}
	encoded, id, err := managedCustodyAuditScope(options, review)
	if err != nil {
		return err
	}
	return writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_managed_audit_review review_id=%s assignment_id=%s ticket_id=%s intent_id=%s owners_retained=%t execution_authorized=false\nscope:\n%s\nwork_archive_custody_managed_audit_scope_end\n", id, options.config.Audit.AssignmentID, options.ticketID, options.config.Audit.IntentID, retained, encoded))
}

func runManagedCustodyAuditControl(parent context.Context, options managedCustodyAuditOptions, input *pruneControlInput, output *pruneEffectOutput) (returnErr error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	lines, terminal := make(chan string, 1), make(chan error, 1)
	readerDone, ioDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(readerDone); readManagedCustodyAuditControl(ctx, input, lines, terminal, cancel) }()
	go func() { defer close(ioDone); <-ctx.Done(); _ = input.Close(); _ = output.Close() }()
	defer func() { cancel(); <-readerDone; <-ioDone }()
	owner, err := authoritystore.OpenManagedCustodyAuditRuntime(ctx, options.config)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, owner.Close()) }()
	if err := writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_managed_audit_ready assignment_id=%s ticket_id=%s intent_id=%s owners_retained=true automatic_completion=false network_enabled=%t\n", options.config.Audit.AssignmentID, options.ticketID, options.config.Audit.IntentID, len(options.transportKey) != 0)); err != nil {
		return err
	}
	var reported, baseID types.Hash
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
			if line == "close" {
				return nil
			}
			if line == "review" {
				review, err := owner.Review(ctx)
				if err != nil {
					return err
				}
				if err := managedCustodyAuditReviewOutput(ctx, output, options, review, true); err != nil {
					return err
				}
				_, reported, err = managedCustodyAuditScope(options, review)
				if err != nil {
					return err
				}
				baseID, err = review.ID()
				if err != nil {
					return err
				}
				continue
			}
			action, text, ok := strings.Cut(line, " ")
			if !ok || (action != "prepare" && action != "recover" && action != "audit") {
				return errors.New("audit control accepts review, prepare/recover/audit <review-id>, or close")
			}
			id, err := managedCustodyExternalID("review-id", text)
			if err != nil || reported.IsZero() || id != reported {
				return errors.Join(errors.New("action requires the exact same-session fully reported review ID"), err)
			}
			reported = types.Hash{}
			if action == "prepare" {
				challenge, err := owner.PrepareChallengeReviewed(ctx, baseID)
				if err != nil {
					return err
				}
				challengeID, err := challenge.ID()
				if err != nil {
					return errors.Join(errManagedCustodyAuditUnobserved, err)
				}
				if err := writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_managed_audit_prepared expected_review_id=%s challenge_id=%s owners_retained=true completion_submitted=false\n", id, challengeID)); err != nil {
					return errors.Join(errManagedCustodyAuditUnobserved, err)
				}
				continue
			}
			var result workarchive.CustodyAuditResult
			if action == "recover" {
				result, err = owner.RecoverReviewed(ctx, baseID)
			} else {
				if len(options.transportKey) == 0 {
					return errors.New("audit requires reviewed peer and transport-key flags")
				}
				tcg := libp2ptransport.DefaultConfig()
				tcg.Listen = []string{options.listen}
				result, err = owner.AuditQUICReviewed(ctx, baseID, options.transportKey, tcg, options.address)
			}
			if err != nil {
				return err
			}
			if err := writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_managed_audit_result action=%s expected_review_id=%s challenge_id=%s proof_id=%s receipt_id=%s sequence=%d recovered=%t owners_retained=true completion_submitted=false\n", action, id, result.Report.ChallengeID, result.Report.ProofID, result.Report.RenewedReceiptID, result.JournalSequence, result.Recovered)); err != nil {
				return errors.Join(errManagedCustodyAuditUnobserved, err)
			}
		}
	}
}

func readManagedCustodyAuditControl(ctx context.Context, input io.Reader, lines chan<- string, terminal chan<- error, cancel context.CancelFunc) {
	fail := func(err error) { terminal <- err; cancel() }
	reader := bufio.NewReaderSize(input, maximumPruneControlLine)
	for {
		encoded, err := reader.ReadSlice('\n')
		if ctx.Err() != nil {
			fail(ctx.Err())
			return
		}
		if err != nil || len(encoded) > maximumPruneControlLine {
			if err == nil {
				err = errors.New("audit control line exceeds its bound")
			}
			if !(err == io.EOF && len(encoded) == 0) {
				err = errors.Join(errors.New("audit input requires complete bounded LF-terminated commands"), err)
			}
			fail(err)
			return
		}
		line := string(encoded[:len(encoded)-1])
		select {
		case lines <- line:
		case <-ctx.Done():
			return
		default:
			fail(errors.New("audit control permits at most one queued command; wait for the preceding response"))
			return
		}
		if line == "close" {
			return
		}
	}
}
