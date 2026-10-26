package main

import (
	"context"
	"encoding/hex"
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
	"unicode/utf8"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const managedCustodyIntentCommand = "work-archive-custody-audit-intent"

func runManagedCustodyIntentCLI(arguments []string) error {
	broken := make(chan os.Signal, 1)
	signal.Notify(broken, syscall.SIGPIPE)
	defer signal.Stop(broken)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runManagedCustodyIntent(ctx, arguments, os.Stdout)
}

func runManagedCustodyIntent(ctx context.Context, arguments []string, output io.Writer) (returnErr error) {
	if ctx == nil || output == nil || len(arguments) == 0 || arguments[0] != managedCustodyIntentCommand {
		return errors.New("unsigned audit intent requires its explicit command, context and output")
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
	flags := flag.NewFlagSet(managedCustodyIntentCommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "review", "review (default), publish, or verify")
	assignmentPath := flags.String("assignment", "", "existing canonical assignment file (required)")
	assignmentText := flags.String("assignment-id", "", "independently pinned assignment ID (required)")
	path := flags.String("intent", "", "explicit intent path in an existing dedicated parent (required)")
	expectedText := flags.String("intent-id", "", "independently retained expected ID; required for publish/verify")
	consumerText := flags.String("consumer-public-key", "", "selected admitted control actor public key (review/publish)")
	auditorText := flags.String("auditor-public-key", "", "selected auditor evidence public key (review/publish)")
	peerText := flags.String("replica-peer-id", "", "independently pinned replica transport ID (review/publish)")
	priorSequence := flags.Uint64("prior-sequence", 0, "exact predecessor sequence, including explicit zero (review/publish)")
	priorHeadText := flags.String("prior-head-id", "", "exact predecessor head; 64 zero digits iff sequence is zero")
	priorReceiptText := flags.String("prior-receipt-id", "", "independently pinned predecessor receipt ID")
	issued := flags.Uint64("issued-at", 0, "explicit fixed issue time in Unix seconds")
	expires := flags.Uint64("expires-at", 0, "explicit fixed request expiry in Unix seconds")
	renew := flags.Uint64("renew-until", 0, "explicit fixed renewal deadline in Unix seconds")
	samples := flags.Uint64("samples", 0, "explicit requested sample count")
	noncePath := flags.String("nonce-file", "", "existing separate 32-byte nonzero random nonce file; never a key seed")
	if err := parsePruneFlags(flags, arguments[1:]); err != nil {
		return err
	}
	if *mode != "review" && *mode != "publish" && *mode != "verify" {
		return errors.New("intent mode must be review, publish or verify")
	}
	present := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { present[f.Name] = true })
	for _, p := range []string{*assignmentPath, *path} {
		if p == "" || !utf8.ValidString(p) || strings.ContainsRune(p, 0) {
			return errors.New("assignment and intent require exact existing UTF-8 placement")
		}
	}
	assignmentID, err := managedCustodyExternalID("assignment-id", *assignmentText)
	if err != nil {
		return err
	}
	a, err := loadPruneOfflineAssignment(*assignmentPath, assignmentID)
	if err != nil {
		return err
	}
	canonicalPath, err := canonicalPruneLineageOutput(*path)
	if err != nil {
		return err
	}
	if !utf8.ValidString(canonicalPath) {
		return errors.New("canonical intent placement must be exact UTF-8 text")
	}
	assignmentFile, _, err := canonicalPruneLineageFile(*assignmentPath)
	if err != nil {
		return err
	}
	if workarchive.CustodyEvidencePathsOverlap(filepath.Dir(canonicalPath), filepath.Dir(assignmentFile)) {
		return errors.New("intent parent must be separate from assignment metadata")
	}
	var intent workarchive.CustodyAuditIntent
	var expected types.Hash
	var nonceSource string
	if present["intent-id"] && *expectedText == "" {
		return errors.New("an explicitly supplied intent-id must be nonempty")
	}
	if *expectedText != "" {
		expected, err = managedCustodyExternalID("intent-id", *expectedText)
		if err != nil {
			return err
		}
	}
	if *mode == "verify" {
		for _, name := range []string{"consumer-public-key", "auditor-public-key", "replica-peer-id", "prior-sequence", "prior-head-id", "prior-receipt-id", "issued-at", "expires-at", "renew-until", "samples", "nonce-file"} {
			if present[name] {
				return errors.New("verify accepts only assignment and intent pins, not construction fields")
			}
		}
		if expected.IsZero() {
			return errors.New("verify requires independently retained intent-id")
		}
		intent, err = workarchive.LoadCustodyAuditIntent(canonicalPath, expected)
		if err != nil {
			return err
		}
	} else {
		for _, name := range []string{"consumer-public-key", "auditor-public-key", "replica-peer-id", "prior-sequence", "prior-head-id", "prior-receipt-id", "issued-at", "expires-at", "renew-until", "samples", "nonce-file"} {
			if !present[name] {
				return fmt.Errorf("%s must be explicitly supplied; intent preparation does not infer current time, nonce or predecessor", name)
			}
		}
		if *samples > uint64(^uint16(0)) || *noncePath == "" || !utf8.ValidString(*noncePath) || strings.ContainsRune(*noncePath, 0) {
			return errors.New("sample count must fit u16 and nonce-file must be exact UTF-8 text")
		}
		consumer, err := managedCustodyExternalID("consumer-public-key", *consumerText)
		if err != nil {
			return err
		}
		auditor, err := managedCustodyExternalID("auditor-public-key", *auditorText)
		if err != nil {
			return err
		}
		peer, err := managedCustodyExternalID("replica-peer-id", *peerText)
		if err != nil {
			return err
		}
		receipt, err := managedCustodyExternalID("prior-receipt-id", *priorReceiptText)
		if err != nil {
			return err
		}
		headBytes, err := hex.DecodeString(*priorHeadText)
		if err != nil || len(headBytes) != types.HashSize || hex.EncodeToString(headBytes) != *priorHeadText {
			return errors.New("prior-head-id must be exact lowercase 32-byte hexadecimal; zero only for sequence zero")
		}
		var head types.Hash
		copy(head[:], headBytes)
		intent = workarchive.CustodyAuditIntent{AssignmentID: assignmentID, ConsumerPublicKey: [32]byte(consumer), AuditorPublicKey: [32]byte(auditor), ReplicaPeerID: peer, PriorSequence: *priorSequence, PriorHeadID: head, PriorReceiptID: receipt, IssuedAt: *issued, ExpiresAt: *expires, RenewUntil: *renew, RequestedSamples: uint16(*samples)}
		// Validate role and fixed-field bounds BEFORE reading private nonce data.
		intent.Nonce = types.Hash{1}
		if err := validateManagedCustodyIntentAssignment(a, assignmentID, intent); err != nil {
			return err
		}
		nonceFile, _, err := canonicalPruneLineageFile(*noncePath)
		if err != nil {
			return err
		}
		if workarchive.CustodyEvidencePathsOverlap(filepath.Dir(canonicalPath), filepath.Dir(nonceFile)) {
			return errors.New("intent parent must be separate from the nonce source")
		}
		if !utf8.ValidString(nonceFile) {
			return errors.New("canonical nonce source must be exact UTF-8 text")
		}
		nonceSource = nonceFile
		nonce, err := readRegularArtifact(nonceFile, types.HashSize)
		if err != nil {
			return err
		}
		if len(nonce) != types.HashSize {
			return errors.New("nonce-file must contain exactly 32 nonzero bytes")
		}
		copy(intent.Nonce[:], nonce)
		if err := intent.Validate(); err != nil {
			return err
		}
	}
	if err := validateManagedCustodyIntentAssignment(a, assignmentID, intent); err != nil {
		return err
	}
	id, err := intent.ID()
	if err != nil {
		return err
	}
	if !expected.IsZero() && expected != id {
		return errors.New("intent differs from independently retained intent-id")
	}
	if *mode == "publish" {
		if expected.IsZero() {
			return errors.New("publish requires the exact intent-id already reviewed independently")
		}
		if err := workarchive.PublishCustodyAuditIntent(ctx, canonicalPath, intent); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(struct {
		AssignmentID, IntentID, Consumer, Auditor, ReplicaPeer, PriorHead, PriorReceipt, NonceSource string
		PriorSequence, IssuedAt, ExpiresAt, RenewUntil                                               uint64
		Samples                                                                                      uint16
		Path                                                                                         string
	}{assignmentID.String(), id.String(), types.Hash(intent.ConsumerPublicKey).String(), types.Hash(intent.AuditorPublicKey).String(), intent.ReplicaPeerID.String(), intent.PriorHeadID.String(), intent.PriorReceiptID.String(), nonceSource, intent.PriorSequence, intent.IssuedAt, intent.ExpiresAt, intent.RenewUntil, intent.RequestedSamples, canonicalPath}, "", "  ")
	if err != nil {
		return err
	}
	if err := writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_audit_intent mode=%s intent_id=%s published=%t signed=false admitted=false\nscope:\n%s\nwork_archive_custody_audit_intent_scope_end\n", *mode, id, *mode == "publish", encoded)); err != nil {
		if *mode == "publish" {
			return errors.Join(errors.New("intent publication output was not observed; verify the retained exact intent before retry"), err)
		}
		return err
	}
	return nil
}
