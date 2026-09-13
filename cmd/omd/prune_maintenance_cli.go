package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

const (
	pruneMaintenanceCommand = "work-prune-maintenance"
	maximumPruneControlLine = 96 // including the mandatory LF; no unbounded scanner
)

var errPruneMaintenanceUnobserved = errors.New("maintenance result was not observed; review retained state before retrying")

// A separate offline invocation acquires existing owners without starting a
// transport. A prior process must have closed them; no PID, signal, force-unlock,
// signer or WorkChain API is accepted here. Review never advances a journal.
func runPruneMaintenance(ctx context.Context, arguments []string, output io.Writer) (err error) {
	if ctx == nil || output == nil || len(arguments) == 0 || arguments[0] != pruneMaintenanceCommand {
		return errors.New("maintenance needs context, output and an explicit command")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	flags := flag.NewFlagSet(pruneMaintenanceCommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "review", "review (default), cancel, recovery-review or recover; never execute")
	assignmentPath := flags.String("assignment", "", "trusted canonical assignment file (required)")
	assignmentText := flags.String("assignment-id", "", "independently retained assignment ID (required)")
	authorityPath := flags.String("authority", "", "existing authority root (required)")
	authorityPins := flags.String("authority-pins", "", "existing independent authority intent/pin root (required)")
	executorPath := flags.String("executor", "", "existing executor root (required)")
	executorPins := flags.String("executor-pins", "", "existing independent executor pin root (required)")
	requestText := flags.String("request-id", "", "independently retained request ID (required)")
	serverText := flags.String("server-peer-id", "", "retained service transport identity pin (required; never dialled)")
	clientText := flags.String("client-peer-id", "", "retained client transport identity pin (required; never dialled)")
	expectedText := flags.String("expected-review-id", "", "cancel/recover only: independently reviewed exact state ID")
	actionText := flags.String("recovery-action", "", "recover only: independently chosen single retained transition")
	if err := parsePruneFlags(flags, arguments[1:]); err != nil {
		return err
	}
	present := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { present[f.Name] = true })
	if *mode != "review" && *mode != "cancel" && *mode != "recovery-review" && *mode != "recover" {
		return errors.New("maintenance mode must be review, cancel, recovery-review or recover")
	}
	if (*mode == "review" || *mode == "recovery-review") && present["expected-review-id"] {
		return errors.New("review forbids expected-review-id, including an empty value")
	}
	if *mode != "recover" && present["recovery-action"] {
		return errors.New("recovery-action is allowed only in recover mode, including an empty value")
	}
	var action authoritystore.PruneRecoveryAction
	if *mode == "recover" {
		if action, err = parsePruneRecoveryAction(*actionText); err != nil {
			return err
		}
	}
	var expected types.Hash
	if *mode == "cancel" || *mode == "recover" {
		if expected, err = pruneExternalID("expected-review-id", *expectedText); err != nil {
			return err
		}
	}
	if *assignmentPath == "" || *authorityPath == "" || *authorityPins == "" || *executorPath == "" || *executorPins == "" {
		return errors.New("assignment and all four existing authority/executor roots are required")
	}
	var assignmentID, requestID, serverID, clientID types.Hash
	for _, pin := range []struct {
		name, text string
		id         *types.Hash
	}{{"assignment-id", *assignmentText, &assignmentID}, {"request-id", *requestText, &requestID},
		{"server-peer-id", *serverText, &serverID}, {"client-peer-id", *clientText, &clientID}} {
		if *pin.id, err = pruneExternalID(pin.name, pin.text); err != nil {
			return err
		}
	}
	assignment, err := loadPruneOfflineAssignment(*assignmentPath, assignmentID)
	if err != nil {
		return err
	}
	service, err := authoritystore.OpenPruneCommandService(authoritystore.PruneCommandServiceConfig{
		AuthorityPath: *authorityPath, AuthorityPinsPath: *authorityPins, ExecutorPath: *executorPath, ExecutorPinsPath: *executorPins,
		Assignment: assignment, AssignmentID: assignmentID, RequestID: requestID, ServerPeerID: serverID, ClientPeerID: clientID,
		Timeout: 10 * time.Second, // constructor bound only: this path never calls Start
	})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, service.Close()) }()
	owner, err := service.EnterMaintenance(ctx)
	if err != nil {
		return err
	}
	switch *mode {
	case "review":
		return writePruneMaintenanceReview(ctx, owner, output)
	case "recovery-review":
		return writePruneRecoveryReview(ctx, owner, output)
	case "recover":
		return recoverPruneMaintenance(ctx, owner, expected, action, output)
	default:
		return cancelPruneMaintenance(ctx, owner, expected, output)
	}
}

func parsePruneRecoveryAction(text string) (authoritystore.PruneRecoveryAction, error) {
	for action := authoritystore.PruneRecoveryAuthorityAdmission; action <= authoritystore.PruneRecoveryExecutorCancellation; action++ {
		if action.String() == text {
			return action, nil
		}
	}
	return authoritystore.PruneRecoveryNone, errors.New("recover requires an exact recovery-action: authority-admission, authority-completion, executor-admission, executor-start, executor-result or executor-cancellation")
}

// Recovery is deliberately offline-only. The live stdin grammar below remains
// review/cancel-before-start/close and cannot promote an incomplete intent.
func pruneRecoveryFields(review authoritystore.PruneRecoveryReview) string {
	return fmt.Sprintf("assignment_id=%s request_id=%s storage_id=%s binding_id=%s authority_confirmed_sequence=%d authority_confirmed_head=%s authority_observed_sequence=%d authority_observed_head=%s authority_phase=%d authority_pending_id=%s authority_pending_kind=%d executor_confirmed_stage=%d executor_confirmed_head=%s executor_observed_stage=%d executor_observed_head=%s executor_pending_stage=%d executor_pending_head=%s retained_admission_id=%s retained_terminal_id=%s recovery_action=%s network_stopped=true historical_only=true execution_authorized=false effect_execution=false automatic_resume=false",
		review.AssignmentID, review.RequestID, review.StorageID, review.BindingID,
		review.AuthorityConfirmed.Sequence, review.AuthorityConfirmed.HeadID, review.AuthorityObserved.Sequence, review.AuthorityObserved.HeadID,
		review.AuthorityPhase, review.AuthorityPendingID, review.AuthorityPendingKind,
		review.ExecutorConfirmed.Stage, review.ExecutorConfirmed.HeadID, review.ExecutorObserved.Stage, review.ExecutorObserved.HeadID,
		review.ExecutorPending.Stage, review.ExecutorPending.HeadID, review.AdmissionID, review.TerminalID, review.Action)
}

func writePruneRecoveryReview(ctx context.Context, owner *authoritystore.PruneMaintenance, output io.Writer) error {
	review, err := owner.ReviewRecovery(ctx)
	if err != nil {
		return err
	}
	id, err := review.ID()
	if err != nil {
		return err
	}
	return writePruneOutputLine(output, fmt.Sprintf("work_prune_recovery_review review_id=%s recovery_performed=false %s\n", id, pruneRecoveryFields(review)))
}

func recoverPruneMaintenance(ctx context.Context, owner *authoritystore.PruneMaintenance, expected types.Hash, action authoritystore.PruneRecoveryAction, output io.Writer) error {
	result, err := owner.Recover(ctx, expected, action)
	if err != nil {
		return err
	}
	afterID, err := result.After.ID()
	if err != nil {
		return errors.Join(errPruneMaintenanceUnobserved, err)
	}
	err = writePruneOutputLine(output, fmt.Sprintf("work_prune_recovered expected_review_id=%s after_review_id=%s recovered_action=%s recovery_performed=true single_transition=true automatic_retry=false %s\n", expected, afterID, action, pruneRecoveryFields(result.After)))
	if err != nil {
		return errors.Join(errPruneMaintenanceUnobserved, err)
	}
	return nil
}

// The native command accepts a dedicated pipe, not a terminal, regular file or
// socket. Closing that pipe must interrupt Read. Tests inject the same contract
// with io.Pipe. Ownership transfers only when --maintenance-control=stdin is set.
type pruneControlInput struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func ownPruneControlInput(input io.ReadCloser) (*pruneControlInput, error) {
	if input == nil {
		return nil, errors.New("stdin maintenance requires a dedicated readable pipe")
	}
	if file, ok := input.(*os.File); ok {
		info, err := file.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			return nil, errors.Join(errors.New("stdin maintenance requires a dedicated pipe, not a terminal or file"), err)
		}
		input, err = preparePruneControlPipe(file)
		if err != nil {
			return nil, err
		}
	}
	return &pruneControlInput{ReadCloser: input}, nil
}

func (input *pruneControlInput) Close() error {
	input.once.Do(func() { input.err = input.ReadCloser.Close() })
	return input.err
}

// EOF, a malformed command, a read/write error, parent cancellation or service
// failure ends this local session. The outer command ALWAYS closes the service.
// After handoff the parent context still supervises stdin, not just transport.
func runPruneMaintenanceControl(ctx context.Context, service *authoritystore.PruneCommandService, input *pruneControlInput, output io.Writer) (err error) {
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
		case <-service.Done():
		case <-stop:
		}
		_ = input.Close()
	}()
	defer func() { close(stop); <-stopped }()
	reader := bufio.NewReaderSize(input, maximumPruneControlLine)
	var owner *authoritystore.PruneMaintenance
	for {
		line, readErr := reader.ReadSlice('\n')
		if ctx.Err() != nil {
			return nil // the outer Close still returns storage/shutdown uncertainty
		}
		select {
		case <-service.Done():
			return nil
		default:
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) && len(line) == 0 {
				return nil
			}
			return errors.Join(errors.New("maintenance input requires a complete LF-terminated command of at most 96 bytes"), readErr)
		}
		command := string(line[:len(line)-1])
		switch {
		case command == "close":
			return nil
		case command == "review":
			if owner == nil {
				owner, err = service.EnterMaintenance(ctx)
				if err != nil {
					return err
				}
			}
			if err := writePruneMaintenanceReview(ctx, owner, output); err != nil {
				return err
			}
		case strings.HasPrefix(command, "cancel-before-start "):
			if owner == nil {
				return errors.New("request and independently inspect review before cancellation; no automatic handoff")
			}
			text := strings.TrimPrefix(command, "cancel-before-start ")
			id, err := pruneExternalID("review-id", text)
			if err != nil || id.String() != text {
				return errors.Join(errors.New("cancel-before-start requires one canonical lowercase review ID"), err)
			}
			if err := cancelPruneMaintenance(ctx, owner, id, output); err != nil {
				return err
			}
		default:
			return errors.New("maintenance accepts only review, cancel-before-start <review-id>, or close")
		}
	}
}

func writePruneMaintenanceReview(ctx context.Context, owner *authoritystore.PruneMaintenance, output io.Writer) error {
	review, err := owner.Review(ctx)
	if err != nil {
		return err
	}
	id, err := review.ID()
	if err != nil {
		return err
	}
	return writePruneOutputLine(output, fmt.Sprintf("work_prune_maintenance_review review_id=%s assignment_id=%s request_id=%s storage_id=%s binding_id=%s authority_sequence=%d authority_head=%s authority_phase=%d executor_stage=%d executor_head=%s ticket_id=%s terminal_id=%s network_stopped=true historical_only=true execution_authorized=false automatic_resume=false\n",
		id, review.AssignmentID, review.RequestID, review.StorageID, review.BindingID, review.Authority.Sequence, review.Authority.HeadID,
		review.Phase, review.Executor.Stage, review.Executor.HeadID, review.TicketID, review.TerminalID))
}

func cancelPruneMaintenance(ctx context.Context, owner *authoritystore.PruneMaintenance, expected types.Hash, output io.Writer) error {
	cancellation, err := owner.CancelBeforeStart(ctx, expected)
	if err != nil {
		return err
	}
	encoded, err := cancellation.CanonicalBytes()
	if err != nil {
		return err
	}
	id, err := cancellation.ID()
	if err != nil {
		return err
	}
	// Canonical bytes are transportable historical evidence, NOT a portable
	// durability certificate. No output path can alias or mutate an owned root.
	err = writePruneOutputLine(output, fmt.Sprintf("work_prune_maintenance_cancelled expected_review_id=%s assignment_id=%s request_id=%s binding_id=%s ticket_id=%s terminal_id=%s canonical_hex=%x historical_only=true completion_submitted=false execution_authorized=false automatic_retry=false\n",
		expected, cancellation.AssignmentID, cancellation.RequestID, cancellation.BindingID, cancellation.TicketID, id, encoded))
	if err != nil {
		return errors.Join(errPruneMaintenanceUnobserved, err)
	}
	return nil
}

func writePruneOutputLine(output io.Writer, line string) error {
	n, err := io.WriteString(output, line)
	if n != len(line) {
		err = errors.Join(err, io.ErrShortWrite)
	}
	return err
}
