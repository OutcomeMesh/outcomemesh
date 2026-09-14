package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const (
	prunePinLockName  = "prune-pins.lock"
	prunePinReadyName = "ready.omcpp"
)

var prunePinConfirmNames = [...]string{"01.omcpp", "02.omcpp", "03.omcpp"}

// Accessed only under the owning executor mutex and pin-root lifetime lock.
// records/state/position contain confirmed transitions only; pending is the one
// irrevocable next attempt. No filesystem discovery supplies an expected head.
type prunePinJournal struct {
	path       string
	lock       *os.File
	identity   map[string]os.FileInfo
	binding    types.Hash
	assignment custodyauthority.Assignment
	state      PruneExecution
	position   PrunePosition
	records    [][]byte
	pending    []byte
	next       PruneExecution
	failed     bool
	hooks      storeHooks
}

func prunePinReadyBytes(id, binding types.Hash) []byte {
	return append(append([]byte("OMCPINSJ\x00\x00"), id[:]...), binding[:]...)
}

func pruneConfirmationBytes(id types.Hash, position PrunePosition) []byte {
	encoded := append([]byte("OMCPPOSN\x00\x00"), id[:]...)
	encoded = append(encoded, byte(position.Stage))
	return append(encoded, position.HeadID[:]...)
}

func createPrunePinJournal(path string, assignment custodyauthority.Assignment, request PruneRequest, id, binding types.Hash, createExecutor func() error, hooks storeHooks) (_ *prunePinJournal, err error) {
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openNamedLock(path, prunePinLockName, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	for _, name := range []string{intentsName, confirmedName, pendingName} {
		if err := os.Mkdir(filepath.Join(path, name), 0o700); err != nil {
			return nil, err
		}
		if err := syncDirectory(filepath.Join(path, name)); err != nil {
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
	if err := createExecutor(); err != nil {
		return nil, err
	}
	if err := hooks.reach("pins-before-ready"); err != nil {
		return nil, err
	}
	if err := writeExclusive(filepath.Join(path, prunePinReadyName), prunePinReadyBytes(id, binding)); err != nil {
		return nil, err
	}
	if err := hooks.reach("pins-ready-file-synced"); err != nil {
		return nil, err
	}
	if err := syncDirectory(path); err != nil {
		return nil, err
	}
	if err := hooks.reach("pins-ready-directory-synced"); err != nil {
		return nil, err
	}
	return loadPrunePinJournal(path, lock, assignment, id, hooks)
}

func openPrunePinJournal(path string, assignment custodyauthority.Assignment, id types.Hash) (_ *prunePinJournal, err error) {
	lock, err := openNamedLock(path, prunePinLockName, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	return loadPrunePinJournal(path, lock, assignment, id, storeHooks{})
}

func prunePinLayout(path string, lock *os.File) (map[string]os.FileInfo, error) {
	return inspectNamedLayout(path, lock, prunePinLockName, map[string]bool{
		"": true, prunePinLockName: false, assignmentName: false, pruneRequestName: false, prunePinReadyName: false,
		intentsName: true, confirmedName: true, pendingName: true,
	})
}

func loadPrunePinJournal(path string, lock *os.File, assignment custodyauthority.Assignment, id types.Hash, hooks storeHooks) (*prunePinJournal, error) {
	identity, err := prunePinLayout(path, lock)
	if err != nil {
		return nil, err
	}
	a, err := readRegular(filepath.Join(path, assignmentName), custodyauthority.MaximumAssignmentBytes)
	expected, _ := assignment.CanonicalBytes()
	if err != nil || !bytes.Equal(a, expected) {
		return nil, errors.Join(custodyauthority.ErrAssignment, err)
	}
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
	if err := validatePruneRequest(assignment, request, id); err != nil {
		return nil, err
	}
	ready, err := readRegular(filepath.Join(path, prunePinReadyName), 74)
	if err != nil || len(ready) != 74 {
		return nil, errors.Join(ErrPrunePin, err)
	}
	var binding types.Hash
	copy(binding[:], ready[42:])
	if binding.IsZero() || !bytes.Equal(ready, prunePinReadyBytes(id, binding)) {
		return nil, ErrPrunePin
	}
	if _, err := inspectSizedPending(path, workchain.MaximumCanonicalPruneEffectBytes); err != nil {
		return nil, err
	}
	intents, err := boundedNames(filepath.Join(path, intentsName), 3)
	if err != nil {
		return nil, err
	}
	confirmations, err := boundedNames(filepath.Join(path, confirmedName), 3)
	if err != nil {
		return nil, err
	}
	if len(intents) < len(confirmations) || len(intents) > len(confirmations)+1 {
		return nil, ErrPrunePin
	}
	pins := &prunePinJournal{path: path, lock: lock, identity: identity, binding: binding, assignment: assignment,
		state:    PruneExecution{RequestID: id, Request: request, Stage: PrunePrepared},
		position: PrunePosition{Stage: PrunePrepared, HeadID: id}, hooks: hooks}
	for index, name := range intents {
		encoded, err := pins.readRetained(filepath.Join(intentsName, name))
		if err != nil {
			return nil, err
		}
		next, err := advancePruneExecution(assignment, pins.state, encoded)
		if err != nil {
			return nil, err
		}
		if name != pruneRecordName(index, next.Stage) {
			return nil, ErrPrunePin
		}
		if err := checkPruneExecutionBinding(next, binding); err != nil {
			return nil, err
		}
		position := nextPrunePosition(pins.position, encoded)
		if index == len(confirmations) {
			pins.pending, pins.next = encoded, next
			continue
		}
		if confirmations[index] != prunePinConfirmNames[index] {
			return nil, ErrPrunePin
		}
		confirmed, err := pins.readRetained(filepath.Join(confirmedName, confirmations[index]))
		if err != nil || !bytes.Equal(confirmed, pruneConfirmationBytes(id, position)) {
			return nil, errors.Join(ErrPrunePin, err)
		}
		pins.records = append(pins.records, encoded)
		pins.state, pins.position = next, position
	}
	// Re-sync accepted evidence before using it to select the other root. Missing
	// records are never manufactured and pending temporary files are never promoted.
	for _, directory := range []string{intentsName, confirmedName} {
		for name := range identity {
			if filepath.Dir(name) == directory {
				if err := syncPath(filepath.Join(path, name)); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, name := range []string{assignmentName, pruneRequestName, prunePinReadyName, prunePinLockName, intentsName, confirmedName, pendingName, ""} {
		if err := syncPath(filepath.Join(path, name)); err != nil {
			return nil, err
		}
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := pins.check(); err != nil {
		return nil, err
	}
	return pins, nil
}

func (pins *prunePinJournal) readRetained(key string) ([]byte, error) {
	encoded, err := readRegular(filepath.Join(pins.path, key), workchain.MaximumCanonicalPruneEffectBytes)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(filepath.Join(pins.path, key))
	if err != nil {
		return nil, err
	}
	pins.identity[key] = info
	return encoded, nil
}

func (pins *prunePinJournal) check() error {
	if pins == nil || pins.lock == nil {
		return ErrClosed
	}
	if pins.failed {
		return ErrUncertain
	}
	if _, err := prunePinLayout(pins.path, pins.lock); err != nil {
		return pins.poison(err)
	}
	for name, original := range pins.identity {
		current, err := os.Lstat(filepath.Join(pins.path, name))
		if err != nil || !os.SameFile(original, current) || original.Mode().Type() != current.Mode().Type() ||
			(original.Mode().IsRegular() && original.Size() != current.Size()) {
			return pins.poison(errors.Join(ErrStore, err))
		}
	}
	for directory, names := range map[string][]string{intentsName: pruneRecordNames[:], confirmedName: prunePinConfirmNames[:]} {
		count := len(pins.records)
		if directory == intentsName && pins.pending != nil {
			count++
		}
		actual, err := boundedNames(filepath.Join(pins.path, directory), 3)
		if err != nil || len(actual) != count {
			return pins.poison(errors.Join(ErrPrunePin, err))
		}
		for index, name := range actual {
			expected := names[index]
			if directory == intentsName {
				stage := pins.state.Stage
				if pins.pending != nil {
					stage = pins.next.Stage
				}
				expected = pruneRecordName(index, stage)
			}
			if name != expected {
				return pins.poison(ErrPrunePin)
			}
		}
	}
	return nil
}

func (pins *prunePinJournal) poison(err error) error {
	pins.failed = true
	return errors.Join(ErrUncertain, err)
}

func (pins *prunePinJournal) publish(ctx context.Context, directory, name string, encoded []byte, prefix string) error {
	if err := pins.check(); err != nil {
		return err
	}
	count, err := inspectSizedPending(pins.path, workchain.MaximumCanonicalPruneEffectBytes)
	if err != nil {
		return pins.poison(err)
	}
	if count == MaximumPendingFiles {
		return custodyauthority.ErrLimit
	}
	hooks := storeHooks{at: func(stage string) error { return pins.hooks.reach(prefix + "-" + stage) }}
	if err := hooks.reach("before-write"); err != nil {
		return pins.poison(err)
	}
	file, err := os.CreateTemp(filepath.Join(pins.path, pendingName), "entry-")
	if err != nil {
		return pins.poison(err)
	}
	if err := writeAndSync(file, encoded, hooks); err != nil {
		return pins.poison(err)
	}
	if err := hooks.reach("before-publish"); err != nil {
		return pins.poison(err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := pins.check(); err != nil {
		return err
	}
	key := filepath.Join(directory, name)
	if err := os.Link(file.Name(), filepath.Join(pins.path, key)); err != nil {
		return pins.poison(err)
	}
	if err := hooks.reach("after-publish"); err != nil {
		return pins.poison(err)
	}
	syncDir := pins.hooks.syncEntriesDirectory
	if syncDir == nil {
		syncDir = syncDirectory
	}
	if err := syncDir(filepath.Join(pins.path, directory)); err != nil {
		return pins.poison(err)
	}
	if err := hooks.reach("directory-synced"); err != nil {
		return pins.poison(err)
	}
	info, err := os.Lstat(filepath.Join(pins.path, key))
	if err != nil || !info.Mode().IsRegular() {
		return pins.poison(errors.Join(ErrStore, err))
	}
	pins.identity[key] = info
	if err := os.Remove(file.Name()); err == nil {
		_ = syncDirectory(filepath.Join(pins.path, pendingName))
	}
	return nil
}

func (pins *prunePinJournal) prepare(ctx context.Context, encoded []byte) error {
	if pins.pending != nil {
		return ErrPrunePinPending
	}
	next, err := advancePruneExecution(pins.assignment, pins.state, encoded)
	if err != nil {
		return err
	}
	if err := checkPruneExecutionBinding(next, pins.binding); err != nil {
		return err
	}
	index := pruneRecordCount(pins.position.Stage)
	prefix := "pins-" + pruneTransitionLabel(index, next.Stage) + "-intent"
	if err := pins.publish(ctx, intentsName, pruneRecordName(index, next.Stage), encoded, prefix); err != nil {
		return err
	}
	pins.pending, pins.next = append([]byte(nil), encoded...), next
	if err := pins.hooks.reach(prefix + "-after-apply"); err != nil {
		return pins.poison(err)
	}
	return nil
}

func (pins *prunePinJournal) confirm(executor *PruneExecutor) error {
	if pins.pending == nil {
		return ErrNoAttempt
	}
	if err := pins.verifyExecutor(executor); err != nil {
		return pins.poison(err)
	}
	position := nextPrunePosition(pins.position, pins.pending)
	if executor.stage != position.Stage {
		return pins.poison(ErrPrunePin)
	}
	index := pruneRecordCount(pins.position.Stage)
	prefix := "pins-" + pruneTransitionLabel(index, pins.next.Stage) + "-confirm"
	// Only a verified durable local publication advances a confirmed pin. Finish
	// this publication even if the caller cancels after that primary result.
	if err := pins.publish(context.Background(), confirmedName, prunePinConfirmNames[index], pruneConfirmationBytes(pins.state.RequestID, position), prefix); err != nil {
		return err
	}
	pins.records = append(pins.records, pins.pending)
	pins.state, pins.position = pins.next, position
	pins.pending, pins.next = nil, PruneExecution{}
	if err := pins.hooks.reach(prefix + "-after-apply"); err != nil {
		return pins.poison(err)
	}
	return nil
}
