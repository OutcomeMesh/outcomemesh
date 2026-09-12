package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/outcomemesh/outcomemesh/core/types"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

const (
	pruneAuthorityBootstrapCommand = "work-prune-authority-bootstrap"
	pruneExecutorPrepareCommand    = "work-prune-executor-prepare"
)

// Bootstrap is an explicit offline operator action, never a service-startup or
// recovery fallback. Review does not open the roots; verify may re-establish
// existing record durability but never appends, confirms or resumes an attempt.
func runPruneBootstrap(ctx context.Context, arguments []string, output io.Writer) error {
	if ctx == nil || output == nil || len(arguments) == 0 {
		return errors.New("prune bootstrap needs a context, output and explicit command")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	name := arguments[0]
	authority := name == pruneAuthorityBootstrapCommand
	if !authority && name != pruneExecutorPrepareCommand {
		return errors.New("unsupported prune bootstrap command")
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "review", "review placement only, create both new roots, or verify both existing roots")
	assignmentPath := flags.String("assignment", "", "trusted canonical assignment file (required)")
	assignmentText := flags.String("assignment-id", "", "independently retained assignment ID (required)")
	var writerPath, pinPath, requestPath, requestText string
	if authority {
		flags.StringVar(&writerPath, "authority", "", "authority root with an existing parent (required)")
		flags.StringVar(&pinPath, "authority-pins", "", "disjoint independent authority intent/pin root (required)")
	} else {
		flags.StringVar(&writerPath, "executor", "", "executor root with an existing parent (required)")
		flags.StringVar(&pinPath, "executor-pins", "", "disjoint independent executor pin root (required)")
		flags.StringVar(&requestPath, "request", "", "canonical storage-bound prune request file (required)")
		flags.StringVar(&requestText, "request-id", "", "independently retained request ID (required)")
	}
	if err := parsePruneFlags(flags, arguments[1:]); err != nil {
		return err
	}
	if *mode != "review" && *mode != "create" && *mode != "verify" {
		return errors.New("mode must be review, create or verify")
	}
	if *assignmentPath == "" || writerPath == "" || pinPath == "" {
		return errors.New("assignment and both explicitly configured roots are required")
	}
	assignmentID, err := pruneExternalID("assignment-id", *assignmentText)
	if err != nil {
		return err
	}
	assignment, err := loadPruneOfflineAssignment(*assignmentPath, assignmentID)
	if err != nil {
		return err
	}
	var request authoritystore.PruneRequest
	var requestID types.Hash
	if !authority {
		if requestPath == "" {
			return errors.New("canonical request file is required")
		}
		requestID, err = pruneExternalID("request-id", requestText)
		if err != nil {
			return err
		}
		encoded, err := readRegularArtifact(requestPath, authoritystore.MaximumPruneRequestBytes)
		if err != nil {
			return fmt.Errorf("read prune request: %w", err)
		}
		request, err = authoritystore.DecodePruneRequest(encoded)
		if err != nil {
			return err
		}
		if err := validatePruneOfflineRequest(assignment, request, requestID); err != nil {
			return err
		}
		if request.StorageID.IsZero() {
			return errors.New("operator executor preparation requires a nonzero retained storage ID")
		}
	}
	if err := authoritystore.ValidateBootstrapPaths(writerPath, pinPath); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if *mode == "review" {
		_, err := fmt.Fprintf(output, "work_prune_bootstrap_review command=%s assignment_id=%s request_id=%s placement_valid=true roots_inspected=false roots_created=false non_authoritative=true execution_authorized=false\n", name, assignmentID, requestID)
		return err
	}
	// Close before output: a printed success must not precede a lock-release
	// failure. A failed stdout write never removes the already retained roots.
	var observation string
	if authority {
		var coordinator *authoritystore.Coordinator
		if *mode == "create" {
			coordinator, err = authoritystore.CreateCoordinatedAuthority(writerPath, pinPath, assignment, assignmentID)
		} else {
			coordinator, err = authoritystore.OpenCoordinator(writerPath, pinPath, assignment, assignmentID)
		}
		if err != nil {
			return err
		}
		state, snapshotErr := coordinator.Snapshot()
		if err := errors.Join(snapshotErr, coordinator.Close()); err != nil {
			return err
		}
		observation = fmt.Sprintf("observed_phase=%d observed_sequence=%d observed_head=%s confirmed_sequence=%d confirmed_head=%s retained_attempt=%t", state.Authority.Phase, state.Authority.Sequence, state.Authority.HeadID, state.Confirmed.Sequence, state.Confirmed.HeadID, state.Pending != nil)
	} else {
		var executor *authoritystore.PruneExecutor
		if *mode == "create" {
			executor, err = authoritystore.CreatePinnedPruneExecutor(writerPath, pinPath, assignment, request, requestID)
		} else {
			executor, err = authoritystore.OpenPinnedPruneExecutor(writerPath, pinPath, assignment, requestID)
		}
		if err != nil {
			return err
		}
		state, snapshotErr := executor.Snapshot()
		if snapshotErr == nil {
			retained, retainedErr := state.Request.CanonicalBytes()
			expected, expectedErr := request.CanonicalBytes()
			if retainedErr != nil || expectedErr != nil || !bytes.Equal(retained, expected) || state.RequestID != requestID || state.Protection == nil {
				snapshotErr = errors.Join(authoritystore.ErrPruneRequest, retainedErr, expectedErr)
			}
		}
		if err := errors.Join(snapshotErr, executor.Close()); err != nil {
			return err
		}
		observation = fmt.Sprintf("observed_stage=%d confirmed_stage=%d retained_attempt=%t storage_id=%s", state.Stage, state.Protection.Confirmed.Stage, state.Protection.Pending != nil, state.Request.StorageID)
	}
	if err := ctx.Err(); err != nil {
		return err // initialized roots stay retained even if cancellation won
	}
	_, err = fmt.Fprintf(output, "work_prune_bootstrap command=%s mode=%s assignment_id=%s request_id=%s %s owners_closed=true historical_only=true execution_authorized=false automatic_resume=false\n", name, *mode, assignmentID, requestID, observation)
	return err
}
