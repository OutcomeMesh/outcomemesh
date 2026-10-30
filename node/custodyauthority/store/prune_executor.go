package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type PruneStage uint8

const maximumPruneRecordBytes = prunefence.MaximumResultBytes + workchain.MaximumCanonicalPruneEffectBytes + 128

const (
	PrunePrepared PruneStage = 1 + iota
	PruneAdmitted
	PruneStarted
	PruneSucceeded
	PruneCancelled // terminal alternative to Started, never follows a start
)

const (
	pruneLockName    = "prune.lock"
	pruneRequestName = "request.omcpr"
	pruneReadyName   = "ready.omcpx"
	pruneRecordsName = "records"
)

var pruneRecordNames = [...]string{"01-admission.omcae", "02-started.omcps", "03-result.omcpfx"}

// PruneExecution is detached local evidence, never an authority completion or a
// current availability assertion. A Started operation may have no effect, a
// committed effect, or an outcome that cannot yet be resolved.
type PruneExecution struct {
	FenceCandidate *prunefence.Candidate
	FenceClaim     *prunefence.Claim
	FenceResult    *prunefence.Result
	RequestID      types.Hash
	Request        PruneRequest
	Stage          PruneStage
	Admission      *custodyauthority.Entry
	Effect         *workchain.CanonicalPruneEffect
	Cancellation   *PruneCancellation
	// ArchiveInventoryID is nonzero after an inventory-bound v1 or fenced v2 start.
	// Started is still an unresolved attempt, not proof of a committed effect.
	ArchiveInventoryID types.Hash
	// Protection is nil for raw version-0 journals. With independent pins, Stage
	// may be one exact unconfirmed transition ahead of Protection.Confirmed.
	Protection *PruneProtection
}

// PruneExecutor owns one bounded operation journal and its lifetime process
// lock. Use an independent protected root and request pin; never recreate a lost
// journal or replace/roll back its chain database as recovery. The optional pinned
// constructor retains independent stage history and accepts storage-incarnation
// requests. Neither mode provides physical identity, shared-rollback protection
// or networking.
type PruneExecutor struct {
	fenceCandidate     *prunefence.Candidate
	fenceClaim         *prunefence.Claim
	fenceResult        *prunefence.Result
	mu                 sync.Mutex
	path               string
	lock               *os.File
	identity           map[string]os.FileInfo
	assignment         custodyauthority.Assignment
	request            PruneRequest
	id                 types.Hash
	stage              PruneStage
	admission          *custodyauthority.Entry
	effect             *workchain.CanonicalPruneEffect
	cancellation       *PruneCancellation
	archiveInventoryID types.Hash
	failed             bool
	hooks              storeHooks
	pins               *prunePinJournal
}

func pruneReadyBytes(id types.Hash) []byte { return append([]byte("OMCPINIT\x00\x00"), id[:]...) }
func pruneBoundReadyBytes(id, binding types.Hash) []byte {
	if binding.IsZero() {
		return pruneReadyBytes(id)
	}
	return append(append([]byte("OMCPINIT\x00\x01"), id[:]...), binding[:]...)
}
func pruneStartedBytes(id, ticket types.Hash) []byte {
	return append(append([]byte("OMCPSTRT\x00\x00"), id[:]...), ticket[:]...)
}

// CreatePruneExecutor retains a new exact request before admission/execution.
// It refuses every existing root, including partial initialization. This raw
// version-0 mode has no independent stage pins; use CreatePinnedPruneExecutor for
// the opt-in two-root protocol. Existing roots cannot be upgraded by attaching pins.
func CreatePruneExecutor(path string, assignment custodyauthority.Assignment, request PruneRequest, expectedID types.Hash) (*PruneExecutor, error) {
	return createPruneExecutor(path, assignment, request, expectedID, storeHooks{})
}

func createPruneExecutor(path string, assignment custodyauthority.Assignment, request PruneRequest, expectedID types.Hash, hooks storeHooks) (_ *PruneExecutor, err error) {
	return createPruneExecutorBound(path, assignment, request, expectedID, types.Hash{}, hooks)
}

func createPruneExecutorBound(path string, assignment custodyauthority.Assignment, request PruneRequest, expectedID, binding types.Hash, hooks storeHooks) (_ *PruneExecutor, err error) {
	if err := validatePruneRequest(assignment, request, expectedID); err != nil {
		return nil, err
	}
	if !request.StorageID.IsZero() && binding.IsZero() {
		return nil, ErrPruneRequest // storage-bound requests require independent stage pins
	}
	path, err = storePath(path)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openNamedLock(path, pruneLockName, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	for _, name := range []string{pruneRecordsName, pendingName} {
		if err := os.Mkdir(filepath.Join(path, name), 0o700); err != nil {
			return nil, err
		}
		if err := syncDirectory(filepath.Join(path, name)); err != nil {
			return nil, err
		}
	}
	if !request.FencePolicyID.IsZero() {
		if err := os.Mkdir(filepath.Join(path, "fence"), 0700); err != nil {
			return nil, err
		}
	}
	a, _ := assignment.CanonicalBytes()
	r, _ := request.CanonicalBytes()
	for _, file := range []struct {
		name string
		data []byte
	}{{assignmentName, a}, {pruneRequestName, r}} {
		if err := writeExclusive(filepath.Join(path, file.name), file.data); err != nil {
			return nil, err
		}
	}
	if err := syncDirectory(path); err != nil {
		return nil, err
	}
	if err := hooks.reach("prune-before-ready"); err != nil {
		return nil, err
	}
	if err := writeExclusive(filepath.Join(path, pruneReadyName), pruneBoundReadyBytes(expectedID, binding)); err != nil {
		return nil, err
	}
	if err := hooks.reach("prune-ready-file-synced"); err != nil {
		return nil, err
	}
	if err := syncDirectory(path); err != nil {
		return nil, err
	}
	if err := hooks.reach("prune-ready-directory-synced"); err != nil {
		return nil, err
	}
	return loadPruneExecutor(path, lock, assignment, expectedID, binding, hooks)
}

// OpenPruneExecutor only verifies/re-syncs retained records. It does not query
// authority or chain state, bind an admission, start work or fabricate a result.
// It refuses pinned version-1 roots: use OpenPinnedPruneExecutor for those.
func OpenPruneExecutor(path string, assignment custodyauthority.Assignment, expectedID types.Hash) (_ *PruneExecutor, err error) {
	return openPruneExecutorBound(path, assignment, expectedID, types.Hash{}, storeHooks{})
}

func openPruneExecutorBound(path string, assignment custodyauthority.Assignment, expectedID, binding types.Hash, hooks storeHooks) (_ *PruneExecutor, err error) {
	if expectedID.IsZero() {
		return nil, ErrPruneRequest
	}
	if _, err := assignment.ID(); err != nil {
		return nil, err
	}
	path, err = storePath(path)
	if err != nil {
		return nil, err
	}
	lock, err := openNamedLock(path, pruneLockName, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	return loadPruneExecutor(path, lock, assignment, expectedID, binding, hooks)
}

func pruneLayout(path string, lock *os.File) (map[string]os.FileInfo, error) {
	kinds := map[string]bool{
		"": true, pruneLockName: false, assignmentName: false, pruneRequestName: false, pruneReadyName: false, pruneRecordsName: true, pendingName: true,
	}
	if _, err := os.Lstat(filepath.Join(path, "fence")); err == nil {
		kinds["fence"] = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return inspectNamedLayout(path, lock, pruneLockName, kinds)
}

func loadPruneExecutor(path string, lock *os.File, assignment custodyauthority.Assignment, expectedID, binding types.Hash, hooks storeHooks) (*PruneExecutor, error) {
	identity, err := pruneLayout(path, lock)
	if err != nil {
		return nil, err
	}
	a, err := readRegular(filepath.Join(path, assignmentName), custodyauthority.MaximumAssignmentBytes)
	expected, _ := assignment.CanonicalBytes()
	if err != nil || !bytes.Equal(a, expected) {
		return nil, errors.Join(custodyauthority.ErrAssignment, err)
	}
	// Decode owned copies: callers cannot later mutate the retained trust set.
	assignment, err = custodyauthority.DecodeAssignment(a)
	if err != nil {
		return nil, err
	}
	r, err := readRegular(filepath.Join(path, pruneRequestName), MaximumPruneRequestBytes)
	if err != nil {
		return nil, err
	}
	request, err := DecodePruneRequest(r)
	if err != nil {
		return nil, err
	}
	if err := validatePruneRequest(assignment, request, expectedID); err != nil {
		return nil, err
	}
	if !request.StorageID.IsZero() && binding.IsZero() {
		return nil, ErrPruneRequest
	}
	expectedReady := pruneBoundReadyBytes(expectedID, binding)
	ready, err := readRegular(filepath.Join(path, pruneReadyName), len(expectedReady))
	if err != nil || !bytes.Equal(ready, expectedReady) {
		return nil, errors.Join(ErrPruneRequest, err)
	}
	if _, err := inspectSizedPending(path, pruneRecordLimit(request)); err != nil {
		return nil, err
	}
	names, err := boundedNames(filepath.Join(path, pruneRecordsName), len(pruneRecordNames))
	if err != nil {
		return nil, err
	}
	executor := &PruneExecutor{path: path, lock: lock, identity: identity, assignment: assignment, request: request, id: expectedID, stage: PrunePrepared, hooks: hooks}
	for index, name := range names {
		key := filepath.Join(pruneRecordsName, name)
		encoded, err := readRegular(filepath.Join(path, key), pruneRecordLimit(request))
		if err != nil {
			return nil, err
		}
		next, err := advancePruneExecution(assignment, executor.execution(), encoded)
		if err != nil {
			return nil, err
		}
		if name != pruneRecordName(index, next.Stage) {
			return nil, ErrPruneStage
		}
		if err := checkPruneExecutionBinding(next, binding); err != nil {
			return nil, err
		}
		executor.installExecution(next)
		info, err := os.Lstat(filepath.Join(path, key))
		if err != nil {
			return nil, err
		}
		identity[key] = info
		if err := syncPath(filepath.Join(path, key)); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{assignmentName, pruneRequestName, pruneReadyName, pruneLockName, pruneRecordsName, pendingName, ""} {
		if err := syncPath(filepath.Join(path, name)); err != nil {
			return nil, err
		}
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := executor.loadFenceCandidate(binding); err != nil {
		return nil, err
	}
	if err := executor.check(); err != nil {
		return nil, err
	}
	return executor, nil
}

func (executor *PruneExecutor) check() error {
	if executor == nil || executor.lock == nil {
		return ErrClosed
	}
	if executor.failed {
		return ErrUncertain
	}
	if _, err := pruneLayout(executor.path, executor.lock); err != nil {
		return executor.poison(err)
	}
	for name, original := range executor.identity {
		current, err := os.Lstat(filepath.Join(executor.path, name))
		if err != nil || !os.SameFile(original, current) || original.Mode().Type() != current.Mode().Type() ||
			(original.Mode().IsRegular() && original.Size() != current.Size()) {
			return executor.poison(errors.Join(ErrStore, err))
		}
	}
	names, err := boundedNames(filepath.Join(executor.path, pruneRecordsName), len(pruneRecordNames))
	if err != nil || len(names) != pruneRecordCount(executor.stage) {
		return executor.poison(errors.Join(ErrPruneStage, err))
	}
	for index, name := range names {
		if name != pruneRecordName(index, executor.stage) {
			return executor.poison(ErrPruneStage)
		}
	}
	if executor.pins != nil {
		if err := executor.pins.verifyExecutor(executor); err != nil {
			return executor.poison(err)
		}
	}
	return executor.checkFenceCandidate()
}

func (executor *PruneExecutor) operationCheck() error {
	if err := executor.check(); err != nil {
		return err
	}
	if executor.pins != nil && executor.pins.pending != nil {
		return ErrPrunePinPending
	}
	return nil
}

// execution is an internal view, only used while the executor is locked.
func (executor *PruneExecutor) execution() PruneExecution {
	return PruneExecution{RequestID: executor.id, Request: executor.request, Stage: executor.stage, Admission: executor.admission, Effect: executor.effect, Cancellation: executor.cancellation,
		ArchiveInventoryID: executor.archiveInventoryID, FenceClaim: executor.fenceClaim, FenceResult: executor.fenceResult}
}

func (executor *PruneExecutor) installExecution(next PruneExecution) {
	executor.stage, executor.admission, executor.effect = next.Stage, next.Admission, next.Effect
	executor.cancellation = next.Cancellation
	executor.archiveInventoryID = next.ArchiveInventoryID
	executor.fenceClaim, executor.fenceResult = next.FenceClaim, next.FenceResult
}
func (executor *PruneExecutor) poison(err error) error {
	executor.failed = true
	return errors.Join(ErrUncertain, err)
}

func (executor *PruneExecutor) Snapshot() (PruneExecution, error) {
	if executor == nil {
		return PruneExecution{}, ErrClosed
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if err := executor.check(); err != nil {
		return PruneExecution{}, err
	}
	return executor.snapshot(), nil
}

// snapshot requires the executor mutex and a successful owner check.
func (executor *PruneExecutor) snapshot() PruneExecution {
	r, _ := executor.request.CanonicalBytes()
	request, _ := DecodePruneRequest(r)
	result := PruneExecution{RequestID: executor.id, Request: request, Stage: executor.stage, ArchiveInventoryID: executor.archiveInventoryID}
	if executor.fenceCandidate != nil {
		raw, _ := executor.fenceCandidate.CanonicalBytes()
		c, _ := prunefence.DecodeCandidate(raw)
		result.FenceCandidate = &c
	}
	if executor.fenceClaim != nil {
		raw, _ := executor.fenceClaim.CanonicalBytes()
		c, _ := prunefence.DecodeClaim(raw)
		result.FenceClaim = &c
	}
	if executor.fenceResult != nil {
		raw, _ := executor.fenceResult.CanonicalBytes()
		r, _ := prunefence.DecodeResult(raw)
		result.FenceResult = &r
	}
	if executor.admission != nil {
		entry := *executor.admission
		result.Admission = &entry
	}
	if executor.effect != nil {
		encoded, _ := executor.effect.CanonicalBytes()
		effect, _ := workchain.DecodeCanonicalPruneEffect(encoded)
		result.Effect = &effect
	}
	if executor.cancellation != nil {
		cancellation := *executor.cancellation
		result.Cancellation = &cancellation
	}
	if executor.pins != nil {
		protection := executor.pins.protection()
		result.Protection = &protection
	}
	return result
}

// BindAdmission retains only a matching, currently pending local admission.
// An exact retained retry is an observation and does not refresh permission.
func (executor *PruneExecutor) BindAdmission(ctx context.Context, coordinator *Coordinator, entry custodyauthority.Entry) error {
	if executor == nil {
		return ErrClosed
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if err := executor.operationCheck(); err != nil {
		return err
	}
	if ctx == nil {
		return ErrPruneRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	binding, err := pruneAdmissionBinding(executor.assignment, executor.request, entry)
	if err != nil {
		return err
	}
	if executor.admission != nil {
		if *executor.admission == entry {
			return nil
		}
		return ErrPruneStage
	}
	return coordinator.WithOperation(ctx, binding, func() error {
		if err := executor.checkAuthorityRoots(coordinator); err != nil {
			return err
		}
		encoded, _ := entry.CanonicalBytes()
		if err := executor.publish(ctx, 0, encoded, "prune-admission"); err != nil {
			return err
		}
		executor.admission = &entry
		executor.stage = PruneAdmitted
		return executor.applied("prune-admission")
	})
}

func (executor *PruneExecutor) checkAuthorityRoots(coordinator *Coordinator) error {
	// Called only inside WithOperation while both lifetime owners are locked.
	for _, path := range []string{coordinator.authority.path, coordinator.journal.path} {
		if _, _, err := coordinatorPaths(executor.path, path); err != nil {
			return err
		}
		if executor.pins != nil {
			if _, _, err := coordinatorPaths(executor.pins.path, path); err != nil {
				return err
			}
		}
	}
	return nil
}

// Execute uses a current local ticket guard and the concrete atomic WorkChain
// primitive. The caller supplies live archive verification/final time policy;
// this is not a public archive-policy bypass or an installed CLI acceptance path.
// Lock order is executor -> coordinator -> WorkChain. authorize must not re-enter
// any of them or launch effects that outlive the call. A persisted start is never
// repeated by this executor; use Recover for read-only effect resolution.
func (executor *PruneExecutor) Execute(ctx context.Context, coordinator *Coordinator, chain *workchain.Store, authorize func() (uint64, error)) (workchain.CanonicalPruneCommit, error) {
	if executor == nil {
		return workchain.CanonicalPruneCommit{}, ErrClosed
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if err := executor.operationCheck(); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	if !executor.request.ScheduleID.IsZero() {
		return workchain.CanonicalPruneCommit{}, ErrPruneArchivePolicy
	}
	if ctx == nil || authorize == nil {
		return workchain.CanonicalPruneCommit{}, ErrPruneRequest
	}
	if err := ctx.Err(); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	if executor.stage == PruneSucceeded {
		return executor.retainedResult(), nil
	}
	if executor.stage == PruneCancelled {
		return workchain.CanonicalPruneCommit{}, ErrPruneCancelled
	}
	if executor.stage == PruneStarted {
		return workchain.CanonicalPruneCommit{}, ErrPruneOutcome
	}
	if executor.stage != PruneAdmitted {
		return workchain.CanonicalPruneCommit{}, ErrPruneStage
	}
	if err := chain.VerifyContext(executor.assignment.NetworkID, executor.assignment.ActivationHeight, executor.assignment.BaseID); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	if err := chain.VerifyStorageID(executor.request.StorageID); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	binding, err := pruneAdmissionBinding(executor.assignment, executor.request, *executor.admission)
	if err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	var result workchain.CanonicalPruneCommit
	err = coordinator.WithOperation(ctx, binding, func() error {
		if err := executor.checkAuthorityRoots(coordinator); err != nil {
			return err
		}
		result, err = executor.executeGuarded(ctx, chain, binding, authorize)
		return err
	})
	if err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	return result, nil
}

// executeGuarded requires the executor and every required coordinator guard,
// with all binding/storage/archive preflight complete. It never acquires another
// authority mutex. Keep those guards through independently confirmed result.
func (executor *PruneExecutor) executeGuarded(ctx context.Context, chain *workchain.Store, binding OperationBinding, authorize func() (uint64, error)) (workchain.CanonicalPruneCommit, error) {
	return executor.executeGuardedInventory(ctx, chain, binding, authorize, types.Hash{})
}

// Nonzero inventory IDs are supplied only by the fully verified prepared-archive
// path. The existing two-root intent/record/confirmation protocol retains the ID
// before any effect. No recovery path supplies or retrofits an inventory ID.
func (executor *PruneExecutor) executeGuardedInventory(ctx context.Context, chain *workchain.Store, binding OperationBinding, authorize func() (uint64, error), inventoryID types.Hash) (workchain.CanonicalPruneCommit, error) {
	if !executor.request.FencePolicyID.IsZero() {
		return workchain.CanonicalPruneCommit{}, prunefence.ErrFence
	}
	if err := executor.publish(ctx, 1, pruneInventoryStartedBytes(executor.id, binding.TicketID, inventoryID), "prune-start"); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	executor.stage = PruneStarted
	executor.archiveInventoryID = inventoryID
	if err := executor.applied("prune-start"); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	if err := executor.hooks.reach("prune-before-effect"); err != nil {
		return workchain.CanonicalPruneCommit{}, errors.Join(ErrPruneOutcome, err)
	}
	commit, err := chain.PruneCanonicalPrefixOnce(workchain.CanonicalPruneOperation{
		AssignmentID: executor.request.AssignmentID, TicketID: binding.TicketID, Boundary: executor.request.Boundary,
		StorageID: executor.request.StorageID, ScheduleID: executor.request.ScheduleID,
	}, func() (uint64, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return authorize()
	})
	if err != nil {
		return workchain.CanonicalPruneCommit{}, errors.Join(ErrPruneOutcome, err)
	}
	if !inventoryID.IsZero() && !commit.Applied {
		// A cached primitive result cannot certify that this invocation applied
		// an effect. Concurrent raw access is outside the guarded-owner contract.
		return workchain.CanonicalPruneCommit{}, ErrPruneOutcome
	}
	if err := executor.hooks.reach("prune-after-effect"); err != nil {
		return workchain.CanonicalPruneCommit{}, errors.Join(ErrPruneOutcome, err)
	}
	if err := executor.saveResult(context.Background(), commit.Effect); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	return commit, nil
}

// Recover resolves Started only from the concrete database's already committed,
// exact matching effect. Absence/error never triggers execution or completion.
// This can retain historical evidence after authority retirement; it grants no
// permission and is not a substitute for independently pinned storage recovery.
func (executor *PruneExecutor) Recover(ctx context.Context, chain *workchain.Store) (workchain.CanonicalPruneCommit, error) {
	if executor == nil {
		return workchain.CanonicalPruneCommit{}, ErrClosed
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if err := executor.operationCheck(); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	if ctx == nil {
		return workchain.CanonicalPruneCommit{}, ErrPruneRequest
	}
	if err := ctx.Err(); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	if executor.stage == PruneSucceeded {
		return executor.retainedResult(), nil
	}
	if executor.stage == PruneCancelled {
		return workchain.CanonicalPruneCommit{}, ErrPruneCancelled
	}
	if executor.stage != PruneStarted {
		return workchain.CanonicalPruneCommit{}, ErrPruneStage
	}
	// A bare storage effect cannot recreate the lost volatile session signature.
	if !executor.request.FencePolicyID.IsZero() {
		return workchain.CanonicalPruneCommit{}, ErrPruneOutcome
	}
	if err := chain.VerifyContext(executor.assignment.NetworkID, executor.assignment.ActivationHeight, executor.assignment.BaseID); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	if err := chain.VerifyStorageID(executor.request.StorageID); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	ticket, _ := executor.admission.ID()
	effect, found, err := chain.CanonicalPruneEffect(ticket)
	if err != nil || !found {
		return workchain.CanonicalPruneCommit{}, errors.Join(ErrPruneOutcome, err)
	}
	if err := executor.saveResult(ctx, effect); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	return executor.retainedResult(), nil
}

func (executor *PruneExecutor) saveResult(ctx context.Context, effect workchain.CanonicalPruneEffect) error {
	if !executor.request.FencePolicyID.IsZero() {
		return prunefence.ErrFence
	}
	if !pruneEffectMatches(executor.request, *executor.admission, effect) {
		return ErrPruneOutcome
	}
	encoded, _ := effect.CanonicalBytes()
	if err := executor.publish(ctx, 2, encoded, "prune-result"); err != nil {
		return err
	}
	owned, _ := workchain.DecodeCanonicalPruneEffect(encoded)
	executor.effect = &owned
	executor.stage = PruneSucceeded
	return executor.applied("prune-result")
}
func (executor *PruneExecutor) retainedResult() workchain.CanonicalPruneCommit {
	encoded, _ := executor.effect.CanonicalBytes()
	effect, _ := workchain.DecodeCanonicalPruneEffect(encoded)
	return workchain.CanonicalPruneCommit{Effect: effect}
}
func (executor *PruneExecutor) applied(prefix string) error {
	if err := executor.hooks.reach(prefix + "-after-apply"); err != nil {
		return executor.poison(err)
	}
	if executor.pins != nil {
		if err := executor.pins.confirm(executor); err != nil {
			return executor.poison(err)
		}
	}
	return nil
}

func (executor *PruneExecutor) publish(ctx context.Context, index int, encoded []byte, prefix string) error {
	if executor.pins != nil {
		if err := executor.pins.prepare(ctx, encoded); err != nil {
			if executor.pins.failed {
				return executor.poison(err)
			}
			return err
		}
	}
	return executor.publishRecord(ctx, index, encoded, prefix)
}

func (executor *PruneExecutor) publishRecord(ctx context.Context, index int, encoded []byte, prefix string) error {
	if pruneRecordCount(executor.stage) != index || len(encoded) > pruneRecordLimit(executor.request) {
		return ErrPruneStage
	}
	next, err := advancePruneExecution(executor.assignment, executor.execution(), encoded)
	if err != nil {
		return err
	}
	var binding types.Hash
	if executor.pins != nil {
		binding = executor.pins.binding
	}
	if err := checkPruneExecutionBinding(next, binding); err != nil {
		return err
	}
	if next.FenceClaim != nil {
		if executor.fenceCandidate == nil {
			return prunefence.ErrFence
		}
		have, _ := executor.fenceCandidate.CanonicalBytes()
		want, _ := next.FenceClaim.Candidate.CanonicalBytes()
		if !bytes.Equal(have, want) {
			return prunefence.ErrFence
		}
	}
	count, err := inspectSizedPending(executor.path, pruneRecordLimit(executor.request))
	if err != nil {
		return executor.poison(err)
	}
	if count == MaximumPendingFiles {
		return custodyauthority.ErrLimit
	}
	hooks := storeHooks{at: func(stage string) error { return executor.hooks.reach(prefix + "-" + stage) }}
	if err := hooks.reach("before-write"); err != nil {
		return executor.poison(err)
	}
	file, err := os.CreateTemp(filepath.Join(executor.path, pendingName), "entry-")
	if err != nil {
		return executor.poison(err)
	}
	if err := writeAndSync(file, encoded, hooks); err != nil {
		return executor.poison(err)
	}
	if err := hooks.reach("before-publish"); err != nil {
		return executor.poison(err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := executor.check(); err != nil {
		return err
	}
	key := filepath.Join(pruneRecordsName, pruneRecordName(index, next.Stage))
	destination := filepath.Join(executor.path, key)
	if err := os.Link(file.Name(), destination); err != nil {
		return executor.poison(err)
	}
	if err := hooks.reach("after-publish"); err != nil {
		return executor.poison(err)
	}
	syncDir := executor.hooks.syncEntriesDirectory
	if syncDir == nil {
		syncDir = syncDirectory
	}
	if err := syncDir(filepath.Join(executor.path, pruneRecordsName)); err != nil {
		return executor.poison(err)
	}
	if err := hooks.reach("directory-synced"); err != nil {
		return executor.poison(err)
	}
	info, err := os.Lstat(destination)
	if err != nil || !info.Mode().IsRegular() {
		return executor.poison(errors.Join(ErrStore, err))
	}
	executor.identity[key] = info
	if err := os.Remove(file.Name()); err == nil {
		_ = syncDirectory(filepath.Join(executor.path, pendingName))
	}
	return nil
}

func (executor *PruneExecutor) Close() error {
	if executor == nil {
		return nil
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.lock == nil {
		return nil
	}
	err := executor.lock.Close()
	executor.lock = nil
	if executor.pins != nil {
		err = errors.Join(err, executor.pins.lock.Close())
		executor.pins = nil
	}
	return err
}
