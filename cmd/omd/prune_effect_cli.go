package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

const pruneArchiveEffectCommand = "work-prune-archive-effect"

var errPruneEffectUnobserved = errors.New("archive effect result was not observed; inspect retained state before any separate recovery")

func runPruneArchiveEffectCLI(arguments []string) error {
	brokenPipe := make(chan os.Signal, 1)
	signal.Notify(brokenPipe, syscall.SIGPIPE)
	defer signal.Stop(brokenPipe)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runPruneArchiveEffect(ctx, arguments, os.Stdin, os.Stdout)
}

// Review is the default and closes long-lived owners before writing any output.
// Control is opt-in: two dedicated native pipes (or interruptible test streams)
// supervise the original owners until explicit close, EOF or any failure.
func runPruneArchiveEffect(ctx context.Context, arguments []string, input io.ReadCloser, output io.Writer) (resultErr error) {
	if ctx == nil || output == nil {
		return errors.New("archive effect command needs context and output")
	}
	options, err := loadPruneArchiveEffectOptions(ctx, arguments)
	if err != nil {
		return err
	}
	if options.mode == "review" {
		service, err := authoritystore.OpenPruneArchiveEffectService(options.config)
		if err != nil {
			return err
		}
		review, reviewErr := service.Review(ctx)
		// Output may be a terminal or file; no journal/database owner can be
		// retained behind a blocked or failed one-shot review write.
		if err := errors.Join(reviewErr, service.Close()); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// Native pipe output remains cancellable even after owners close.
		// Terminal/regular-file review output never holds those owners.
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
		return writePruneEffectReview(output, options, review, false)
	}
	control, err := ownPruneControlInput(input)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, control.Close()) }()
	writer, err := ownPruneEffectOutput(output)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, writer.Close()) }()
	return runPruneEffectControl(ctx, options, control, writer)
}

type pruneEffectOutput struct {
	io.Writer
	closer io.Closer
	once   sync.Once
	err    error
}

func ownPruneEffectOutput(output io.Writer) (*pruneEffectOutput, error) {
	if file, ok := output.(*os.File); ok {
		info, err := file.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			return nil, errors.Join(errors.New("control output requires a dedicated pipe"), err)
		}
		pipe, err := preparePruneEffectOutputPipe(file)
		if err != nil {
			return nil, err
		}
		return &pruneEffectOutput{Writer: pipe, closer: pipe}, nil
	}
	// Embedded callers must supply either a nonblocking writer or a closer
	// whose Close interrupts Write. The public native CLI always adopts pipes.
	closer, _ := output.(io.Closer)
	return &pruneEffectOutput{Writer: output, closer: closer}, nil
}

func (output *pruneEffectOutput) Close() error {
	output.once.Do(func() {
		if output.closer != nil {
			output.err = output.closer.Close()
		}
	})
	return output.err
}

// The reader has at most one unconsumed command, with a 96-byte frame bound.
// EOF/error cancels in-flight replay/effects; the controller must keep its input
// open until it has observed the result. An explicit queued close is ordered
// after the preceding action rather than interpreted as an execution request.
func readPruneEffectControl(ctx context.Context, input io.Reader, lines chan<- string, terminal chan<- error, cancel context.CancelFunc) {
	fail := func(err error) {
		terminal <- err // separate single-producer, one-item channel; never waits for an action
		cancel()
	}
	reader := bufio.NewReaderSize(input, maximumPruneControlLine)
	for {
		encoded, readErr := reader.ReadSlice('\n')
		if readErr != nil || len(encoded) > maximumPruneControlLine {
			if readErr == nil {
				readErr = errors.New("archive effect control line exceeds its bound")
			}
			if !(errors.Is(readErr, io.EOF) && len(encoded) == 0) {
				readErr = errors.Join(errors.New("archive effect input requires complete bounded LF-terminated commands"), readErr)
			}
			fail(readErr)
			return
		}
		line := string(encoded[:len(encoded)-1])
		select {
		case lines <- line:
		case <-ctx.Done():
			return
		default:
			fail(errors.New("archive effect control permits at most one queued command; wait for the preceding response"))
			return
		}
		if line == "close" {
			return // main loop will cancel/close after the preceding action drains
		}
	}
}

func runPruneEffectControl(parent context.Context, options pruneArchiveEffectOptions, input *pruneControlInput, output *pruneEffectOutput) (err error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	lines, terminal := make(chan string, 1), make(chan error, 1)
	readerDone, supervisorDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(readerDone); readPruneEffectControl(ctx, input, lines, terminal, cancel) }()
	go func() {
		defer close(supervisorDone)
		<-ctx.Done()
		_ = input.Close()
		_ = output.Close()
	}()
	defer func() {
		cancel()
		<-readerDone
		<-supervisorDone
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	service, err := authoritystore.OpenPruneArchiveEffectService(options.config)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, service.Close()) }()
	if err := writePruneOutputLine(output, fmt.Sprintf("work_prune_archive_effect_ready mode=control inventory_id=%s policy_id=%s owners_retained=true effect_execution=false automatic_resume=false\n", options.config.InventoryID, options.config.PolicyID)); err != nil {
		return err
	}
	var reported types.Hash
	for {
		select {
		case <-ctx.Done():
			select {
			case readErr := <-terminal:
				if readErr == io.EOF {
					return nil
				}
				return readErr
			default:
			}
			return ctx.Err()
		case readErr := <-terminal:
			if readErr == io.EOF {
				return nil
			}
			return readErr
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
				if err := writePruneEffectReview(output, options, review, true); err != nil {
					return err
				}
				reported, err = review.ID()
				if err != nil {
					return err
				}
			case strings.HasPrefix(line, "execute "):
				text := strings.TrimPrefix(line, "execute ")
				id, err := pruneExternalID("review-id", text)
				if err != nil || id.String() != text || reported.IsZero() || id != reported {
					return errors.Join(errors.New("execute requires the canonical exact review ID already reported by this session"), err)
				}
				// A failed action cannot reuse a successfully reported token as an
				// automatic retry, and no action signs/completes an authority ticket.
				reported = types.Hash{}
				result, err := service.Execute(ctx, id)
				if err != nil {
					return err
				}
				encoded, err := result.Effect.CanonicalBytes()
				if err != nil {
					return errors.Join(errPruneEffectUnobserved, err)
				}
				terminalID, err := result.Effect.ID()
				if err != nil {
					return errors.Join(errPruneEffectUnobserved, err)
				}
				if err := writePruneOutputLine(output, fmt.Sprintf("work_prune_archive_effect_executed expected_review_id=%s inventory_id=%s policy_id=%s terminal_id=%s applied=%t canonical_hex=%x owners_retained=true completion_submitted=false automatic_retry=false\n", id, options.config.InventoryID, options.config.PolicyID, terminalID, result.Applied, encoded)); err != nil {
					return errors.Join(errPruneEffectUnobserved, err)
				}
			default:
				return errors.New("archive effect control accepts only review, execute <review-id>, or close")
			}
		}
	}
}

func writePruneEffectReview(output io.Writer, options pruneArchiveEffectOptions, review authoritystore.PruneArchiveEffectReview, retained bool) error {
	id, err := review.ID()
	if err != nil {
		return err
	}
	c := options.config
	root := c.Base.State.Root()
	authorities := append([]authoritystore.PruneArchiveAuthorityRoots(nil), c.Authorities...)
	replicas := append([]authoritystore.PruneArchiveReplicaPath(nil), c.Replicas...)
	sort.Slice(authorities, func(i, j int) bool {
		return types.CompareHash(authorities[i].AssignmentID, authorities[j].AssignmentID) < 0
	})
	sort.Slice(replicas, func(i, j int) bool { return types.CompareHash(replicas[i].AssignmentID, replicas[j].AssignmentID) < 0 })
	ownerPaths, replicaPaths, positions := make([]map[string]any, len(authorities)), make([]map[string]any, len(replicas)), make([]map[string]any, len(review.Authorities))
	for i, owner := range authorities {
		ownerPaths[i] = map[string]any{"assignment_id": owner.AssignmentID.String(), "authority": owner.AuthorityPath, "authority_pins": owner.AuthorityPinsPath}
	}
	for i, replica := range replicas {
		replicaPaths[i] = map[string]any{"assignment_id": replica.AssignmentID.String(), "directory": replica.Directory}
	}
	for i, owner := range review.Authorities {
		positions[i] = map[string]any{"assignment_id": owner.AssignmentID.String(), "sequence": owner.Position.Sequence, "head_id": owner.Position.HeadID.String(), "phase": owner.Phase, "ticket_id": owner.TicketID.String()}
	}
	p := c.Parameters
	scope := map[string]any{
		"source_data": options.sourceData, "roots_metadata": options.rootsPath,
		"inventory": c.InventoryPath, "executor": c.ExecutorPath, "executor_pins": c.ExecutorPinsPath,
		"chain": c.ChainPath, "chain_pins": c.ChainPinsPath, "availability": c.AvailabilityPath,
		"lineage_evidence": c.LineagePath, "mode": review.Mode,
		"authorities": ownerPaths, "replicas": replicaPaths,
		"executor_position":   map[string]any{"stage": review.Executor.Stage, "head_id": review.Executor.HeadID.String()},
		"storage_position":    map[string]any{"sequence": review.Storage.Sequence, "commit_id": review.Storage.CommitID.String()},
		"executor_binding_id": review.ExecutorBindingID.String(), "storage_pair_id": review.StoragePairID.String(), "authority_positions": positions,
		"base": map[string]any{"id": c.Base.Tip.ID.String(), "height": c.Base.Tip.Height, "timestamp": c.Base.Tip.Timestamp,
			"cumulative_work": fmt.Sprintf("%x", c.Base.Tip.CumulativeWork), "state_root": root.String(), "recent_timestamps": c.Base.RecentTimestamps},
		"parameters": map[string]any{"network_id": p.NetworkID, "block_subsidy": p.BlockSubsidy, "reward_maturity": p.RewardMaturity,
			"activation_height": p.ActivationHeight, "difficulty_anchor_timestamp": p.DifficultyAnchorTimestamp,
			"difficulty_anchor_target": p.DifficultyAnchorTarget.String(), "target_spacing": p.TargetSpacing, "asert_half_life": p.ASERTHalfLife, "fee_delay": p.FeeDelay},
		"storage_policy": c.StoragePolicy, "replay_limits": c.Limits,
	}
	encoded, err := json.MarshalIndent(scope, "", "  ")
	if err != nil {
		return err
	}
	if err := writePruneOutputLine(output, fmt.Sprintf("work_prune_archive_effect_review review_id=%s scope_id=%s inventory_id=%s policy_id=%s lineage_evidence_id=%s request_id=%s storage_id=%s owners_retained=%t historical_only=true execution_authorized=false effect_execution=false automatic_resume=false\n", id, review.ScopeID, review.InventoryID, review.PolicyID, review.LineageEvidenceID, review.RequestID, review.StorageID, retained)); err != nil {
		return err
	}
	return writePruneOutputLine(output, "scope:\n"+string(encoded)+"\nwork_prune_archive_effect_scope_end\n")
}
