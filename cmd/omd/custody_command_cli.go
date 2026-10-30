package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const (
	custodyCommandSignCommand   = "work-archive-custody-command-sign"
	custodyCommandCosignCommand = "work-archive-custody-command-cosign"
	custodyTerminalCommand      = "work-archive-custody-terminal"
	custodyCommandApplyCommand  = "work-archive-custody-command-apply"
)

func runCustodyCommandCLI(arguments []string) error {
	broken := make(chan os.Signal, 1)
	signal.Notify(broken, syscall.SIGPIPE)
	defer signal.Stop(broken)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runCustodyCommand(ctx, arguments, os.Stdin, os.Stdout)
}

func runCustodyCommand(ctx context.Context, arguments []string, input io.ReadCloser, output io.Writer) (resultErr error) {
	if ctx == nil || output == nil || len(arguments) == 0 {
		return errors.New("custody command requires context, output and an explicit command")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	switch arguments[0] {
	case custodyCommandSignCommand, custodyCommandCosignCommand,
		remoteCustodyAssignmentCommand, remoteCustodyPlanCommand, remoteCustodySignCommand,
		remoteCustodyCosignCommand, remoteCustodyWorkerPrepareCommand, remoteCustodyAuthorityBootstrapCommand, remoteCustodySourceCommand:
		// Static commands own no journals, but a full pipe must still observe
		// cancellation and preserve any already published immutable artifact.
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
				defer func() { resultErr = errors.Join(resultErr, writer.Close()) }()
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
		if arguments[0] == custodyCommandSignCommand || arguments[0] == custodyCommandCosignCommand {
			return runCustodyCommandSigning(ctx, arguments, output)
		}
		return runRemoteCustodyOffline(ctx, arguments, output)
	case custodyTerminalCommand, custodyCommandApplyCommand, remoteCustodyAdmissionApplyCommand, remoteCustodyChallengeCommand:
		return runCustodyCommandOwned(ctx, arguments, input, output)
	default:
		return errors.New("unsupported custody command")
	}
}

type custodyCommandScopeFlags struct {
	schedule                                                                *custodyScheduleFlags
	assignment, assignmentID, manifest, receipt, intent, intentID, previous *string
	policy                                                                  archiveCustodyPolicyFlags
}

type custodyCommandSources struct {
	Assignment      string `json:"assignment_file"`
	Manifest        string `json:"manifest_file"`
	InitialReceipt  string `json:"initial_receipt_file"`
	Intent          string `json:"intent_file"`
	PreviousReceipt string `json:"previous_receipt_file"`
}

func addCustodyCommandScopeFlags(f *flag.FlagSet) custodyCommandScopeFlags {
	return custodyCommandScopeFlags{
		schedule:     addCustodyScheduleFlags(f),
		assignment:   f.String("assignment", "", "existing canonical assignment"),
		assignmentID: f.String("assignment-id", "", "independently retained assignment ID"),
		manifest:     f.String("manifest", "", "existing canonical archive manifest"),
		receipt:      f.String("receipt", "", "existing initial replica receipt"),
		intent:       f.String("intent", "", "existing unsigned audit intent"),
		intentID:     f.String("intent-id", "", "independently retained intent ID"),
		previous:     f.String("previous-receipt", "", "exact predecessor receipt pinned by the intent"),
		policy:       addArchiveCustodyPolicyFlags(f),
	}
}

func custodyCommandFile(path string) (string, error) {
	if path == "" || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
		return "", errors.New("source requires an existing UTF-8 regular-file path without NUL")
	}
	canonical, _, err := canonicalPruneLineageFile(path)
	if err != nil || !utf8.ValidString(canonical) {
		return "", errors.Join(errors.New("source requires an exact canonical UTF-8 placement"), err)
	}
	return canonical, nil
}

func custodyCommandOutput(path string) (string, error) {
	if path == "" || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
		return "", errors.New("output requires an existing UTF-8 parent without NUL")
	}
	canonical, err := canonicalPruneLineageOutput(path)
	if err != nil || !utf8.ValidString(canonical) {
		return "", errors.Join(errors.New("output requires an existing canonical parent"), err)
	}
	return canonical, nil
}

func (f custodyCommandScopeFlags) load() (authoritystore.CustodyCommandScope, custodyCommandSources, error) {
	return f.loadVersion(custodyauthority.Version0)
}

func (f custodyCommandScopeFlags) loadVersion(version uint16) (authoritystore.CustodyCommandScope, custodyCommandSources, error) {
	var scope authoritystore.CustodyCommandScope
	var paths custodyCommandSources
	if err := f.policy.validate(); err != nil {
		return scope, paths, err
	}
	for _, p := range []struct {
		source *string
		target *string
	}{
		{f.assignment, &paths.Assignment}, {f.manifest, &paths.Manifest}, {f.receipt, &paths.InitialReceipt},
		{f.intent, &paths.Intent}, {f.previous, &paths.PreviousReceipt},
	} {
		path, err := custodyCommandFile(*p.source)
		if err != nil {
			return scope, paths, err
		}
		*p.target = path
	}
	var err error
	scope.AssignmentID, err = managedCustodyExternalID("assignment-id", *f.assignmentID)
	if err != nil {
		return scope, paths, err
	}
	intentID, err := managedCustodyExternalID("intent-id", *f.intentID)
	if err != nil {
		return scope, paths, err
	}
	scope.Assignment, err = loadPruneOfflineAssignment(paths.Assignment, scope.AssignmentID)
	if err != nil {
		return scope, paths, err
	}
	scope.Manifest, err = loadArchiveManifest(paths.Manifest)
	if err != nil {
		return scope, paths, err
	}
	scope.InitialReceipt, err = loadArchiveReplicaReceipt(paths.InitialReceipt)
	if err != nil {
		return scope, paths, err
	}
	scope.PreviousReceipt, err = loadArchiveReplicaReceipt(paths.PreviousReceipt)
	if err != nil {
		return scope, paths, err
	}
	scope.Intent, err = workarchive.LoadCustodyAuditIntent(paths.Intent, intentID)
	if err != nil {
		return scope, paths, err
	}
	scope.CustodyPolicy = workarchive.CustodyPolicy{TrustedAuditors: append([][32]byte(nil), scope.Assignment.Auditors...), MaximumChallengeLifetime: *f.policy.challengeLifetime, MaximumProofAge: *f.policy.proofAge, MaximumRenewalTerm: *f.policy.renewalTerm}
	scope.Schedule, err = f.schedule.load(scope.Assignment)
	if err != nil {
		return scope, paths, err
	}
	if version == custodyauthority.Version1 {
		return scope, paths, authoritystore.ValidateRemoteCustodyCommandScope(scope)
	}
	return scope, paths, authoritystore.ValidateCustodyCommandScope(scope)
}

func custodyCommandPurpose(text string) (custodyauthority.Purpose, error) {
	switch text {
	case "audit":
		return custodyauthority.Audit, nil
	case "serve":
		return custodyauthority.Serve, nil
	}
	return 0, errors.New("purpose must be audit or serve")
}

func custodyCommandEntry(path, text string) (custodyauthority.Entry, string, error) {
	var zero custodyauthority.Entry
	id, err := managedCustodyExternalID("entry/admission-id", text)
	if err != nil {
		return zero, "", err
	}
	canonical, err := custodyCommandFile(path)
	if err != nil {
		return zero, "", err
	}
	b, err := readRegularArtifact(canonical, custodyauthority.MaximumEntryBytes)
	if err != nil {
		return zero, "", err
	}
	e, err := custodyauthority.DecodeEntry(b)
	if err != nil {
		return zero, "", err
	}
	actual, err := e.ID()
	if err != nil || actual != id {
		return zero, "", errors.Join(errors.New("entry differs from its independently retained ID"), err)
	}
	return e, canonical, nil
}

func custodyCommandChallenge(path, text string) (workarchive.CustodyChallenge, string, error) {
	var zero workarchive.CustodyChallenge
	id, err := managedCustodyExternalID("challenge-id", text)
	if err != nil {
		return zero, "", err
	}
	canonical, err := custodyCommandFile(path)
	if err != nil {
		return zero, "", err
	}
	b, err := readRegularArtifact(canonical, workarchive.MaximumCustodyChallengeBytes)
	if err != nil {
		return zero, "", err
	}
	c, err := workarchive.DecodeCustodyChallenge(b)
	if err != nil {
		return zero, "", err
	}
	actual, err := c.ID()
	if err != nil || actual != id {
		return zero, "", errors.Join(errors.New("challenge differs from its independently retained ID"), err)
	}
	return c, canonical, nil
}

func custodyCommandTerminal(path, text string) (authoritystore.CustodyTerminal, string, error) {
	var zero authoritystore.CustodyTerminal
	id, err := managedCustodyExternalID("terminal-id", text)
	if err != nil {
		return zero, "", err
	}
	canonical, err := custodyCommandFile(path)
	if err != nil {
		return zero, "", err
	}
	t, err := authoritystore.LoadCustodyTerminalFile(canonical, id)
	return t, canonical, err
}

func custodyCommandPresence(flags *flag.FlagSet) map[string]bool {
	p := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { p[f.Name] = true })
	return p
}

func custodyCommandForbid(present map[string]bool, names ...string) error {
	for _, name := range names {
		if present[name] {
			return fmt.Errorf("this command forbids --%s, including an empty value", name)
		}
	}
	return nil
}

// Public metadata deliberately omits the intent nonce and every private seed.
type custodyCommandPublicScope struct {
	ScheduleID        string                    `json:"schedule_id,omitempty"`
	Sources           custodyCommandSources     `json:"sources"`
	AssignmentID      string                    `json:"assignment_id"`
	ManifestID        string                    `json:"manifest_id"`
	InitialReceiptID  string                    `json:"initial_receipt_id"`
	CustodyPolicyID   string                    `json:"custody_policy_id"`
	IntentID          string                    `json:"intent_id"`
	PriorSequence     uint64                    `json:"prior_sequence"`
	PriorHeadID       string                    `json:"prior_head_id"`
	PriorReceiptID    string                    `json:"prior_receipt_id"`
	ConsumerPublicKey string                    `json:"intent_consumer_public_key"`
	AuditorPublicKey  string                    `json:"auditor_public_key"`
	ReplicaPeerID     string                    `json:"replica_peer_id"`
	IssuedAt          uint64                    `json:"issued_at"`
	ExpiresAt         uint64                    `json:"expires_at"`
	RenewUntil        uint64                    `json:"renew_until"`
	RequestedSamples  uint16                    `json:"requested_samples"`
	Policy            workarchive.CustodyPolicy `json:"custody_policy"`
}

func custodyCommandPublic(scope authoritystore.CustodyCommandScope, paths custodyCommandSources) custodyCommandPublicScope {
	id, _ := scope.Intent.ID()
	schedule := ""
	if scope.Schedule != nil {
		schedule = scope.Schedule.ExpectedID.String()
	}
	return custodyCommandPublicScope{ScheduleID: schedule, Sources: paths, AssignmentID: scope.AssignmentID.String(), ManifestID: scope.Assignment.ManifestID.String(), InitialReceiptID: scope.Assignment.InitialReceiptID.String(), CustodyPolicyID: scope.Assignment.CustodyPolicyID.String(), IntentID: id.String(), PriorSequence: scope.Intent.PriorSequence, PriorHeadID: scope.Intent.PriorHeadID.String(), PriorReceiptID: scope.Intent.PriorReceiptID.String(), ConsumerPublicKey: fmt.Sprintf("%x", scope.Intent.ConsumerPublicKey), AuditorPublicKey: fmt.Sprintf("%x", scope.Intent.AuditorPublicKey), ReplicaPeerID: scope.Intent.ReplicaPeerID.String(), IssuedAt: scope.Intent.IssuedAt, ExpiresAt: scope.Intent.ExpiresAt, RenewUntil: scope.Intent.RenewUntil, RequestedSamples: scope.Intent.RequestedSamples, Policy: scope.CustodyPolicy}
}
