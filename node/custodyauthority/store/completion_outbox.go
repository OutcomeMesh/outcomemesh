package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

const (
	completionLockName     = "completion.lock"
	completionIntentName   = "intent.omcci"
	completionReadyName    = "ready.omcco"
	completionReceivedName = "received"
	completionReceiptName  = "ack.omccr"
)

// CompletionDelivery is detached local history. A nil Acknowledgement means
// unresolved, NOT unsent or uncommitted. A retained acknowledgement is not a
// current-authority grant, a new execution permission or proof for another host.
type CompletionDelivery struct {
	IntentID        types.Hash
	Intent          CompletionIntent
	Acknowledgement *completionwire.Acknowledgement
}

// CompletionOutbox retains one immutable Complete and at most one successful
// channel observation under a lifetime process lock. No reset/drop/replace API
// exists. This root needs independent protected deployment; copied or rolled-back
// roots are not fenced. Missing local ACKs can only cause exact network retries,
// never local execution or a claim that the server did not commit.
type CompletionOutbox struct {
	mu              sync.Mutex
	path            string
	lock            *os.File
	identity        map[string]os.FileInfo
	assignmentBytes []byte
	intent          CompletionIntent
	id              types.Hash
	ack             *completionwire.Acknowledgement
	failed          bool
	hooks           storeHooks
}

func completionReadyBytes(id types.Hash) []byte {
	return append([]byte("OMCCINIT\x00\x00"), id[:]...)
}

// CreateCompletionOutbox bootstraps a NEW root and durably retains the exact
// intent before returning. No network action occurs. Existing, partial or lost
// journals must never be recreated as recovery; use Open with the external ID.
func CreateCompletionOutbox(path string, assignment custodyauthority.Assignment, intent CompletionIntent, expectedID types.Hash) (*CompletionOutbox, error) {
	return createCompletionOutbox(path, assignment, intent, expectedID, storeHooks{})
}

func createCompletionOutbox(path string, assignment custodyauthority.Assignment, intent CompletionIntent, expectedID types.Hash, hooks storeHooks) (_ *CompletionOutbox, err error) {
	if err := validateCompletionIntent(assignment, intent, expectedID); err != nil {
		return nil, err
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
	lock, err := openNamedLock(path, completionLockName, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	for _, name := range []string{completionReceivedName, pendingName} {
		if err := os.Mkdir(filepath.Join(path, name), 0o700); err != nil {
			return nil, err
		}
		if err := syncDirectory(filepath.Join(path, name)); err != nil {
			return nil, err
		}
	}
	a, _ := assignment.CanonicalBytes()
	i, _ := intent.CanonicalBytes()
	if err := writeExclusive(filepath.Join(path, assignmentName), a); err != nil {
		return nil, err
	}
	if err := writeExclusive(filepath.Join(path, completionIntentName), i); err != nil {
		return nil, err
	}
	if err := syncDirectory(path); err != nil {
		return nil, err
	}
	if err := hooks.reach("outbox-before-ready"); err != nil {
		return nil, err
	}
	if err := writeExclusive(filepath.Join(path, completionReadyName), completionReadyBytes(expectedID)); err != nil {
		return nil, err
	}
	if err := hooks.reach("outbox-ready-file-synced"); err != nil {
		return nil, err
	}
	if err := syncDirectory(path); err != nil {
		return nil, err
	}
	if err := hooks.reach("outbox-ready-directory-synced"); err != nil {
		return nil, err
	}
	return loadCompletionOutbox(path, lock, assignment, expectedID, hooks)
}

// OpenCompletionOutbox verifies and re-syncs existing local evidence against an
// independently retained intent ID. It creates no files, submits nothing and
// never promotes a temporary receipt. Only explicit Deliver can use the network.
func OpenCompletionOutbox(path string, assignment custodyauthority.Assignment, expectedID types.Hash) (_ *CompletionOutbox, err error) {
	if expectedID.IsZero() {
		return nil, ErrCompletionIntent
	}
	if _, err := assignment.ID(); err != nil {
		return nil, err
	}
	path, err = storePath(path)
	if err != nil {
		return nil, err
	}
	lock, err := openNamedLock(path, completionLockName, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	return loadCompletionOutbox(path, lock, assignment, expectedID, storeHooks{})
}

func completionLayout(path string, lock *os.File) (map[string]os.FileInfo, error) {
	return inspectNamedLayout(path, lock, completionLockName, map[string]bool{
		"": true, completionLockName: false, assignmentName: false,
		completionIntentName: false, completionReadyName: false,
		completionReceivedName: true, pendingName: true,
	})
}

func loadCompletionOutbox(path string, lock *os.File, assignment custodyauthority.Assignment, expectedID types.Hash, hooks storeHooks) (*CompletionOutbox, error) {
	identity, err := completionLayout(path, lock)
	if err != nil {
		return nil, err
	}
	encoded, err := readRegular(filepath.Join(path, completionIntentName), CompletionIntentBytes)
	if err != nil {
		return nil, err
	}
	intent, err := DecodeCompletionIntent(encoded)
	if err != nil {
		return nil, err
	}
	if err := validateCompletionIntent(assignment, intent, expectedID); err != nil {
		return nil, err
	}
	a, _ := assignment.CanonicalBytes()
	outbox := &CompletionOutbox{path: path, lock: lock, identity: identity, assignmentBytes: a, intent: intent, id: expectedID, hooks: hooks}
	names, err := boundedNames(filepath.Join(path, completionReceivedName), 1)
	if err != nil {
		return nil, err
	}
	if len(names) == 1 {
		if names[0] != completionReceiptName {
			return nil, ErrCompletionIntent
		}
		key := filepath.Join(completionReceivedName, completionReceiptName)
		encoded, err := readRegular(filepath.Join(path, key), completionReceiptBytes)
		if err != nil {
			return nil, err
		}
		ack, err := decodeCompletionReceipt(encoded, intent)
		if err != nil {
			return nil, err
		}
		outbox.ack = &ack
		identity[key], err = os.Lstat(filepath.Join(path, key))
		if err != nil {
			return nil, err
		}
	}
	if err := outbox.check(); err != nil {
		return nil, err
	}
	// A visible receipt can precede a failed directory sync. Re-establish all
	// retained dependencies before reporting local delivery; send nothing here.
	for name := range identity {
		if err := syncPath(filepath.Join(path, name)); err != nil {
			return nil, err
		}
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := outbox.check(); err != nil {
		return nil, err
	}
	return outbox, nil
}

func (outbox *CompletionOutbox) check() error {
	if outbox == nil || outbox.lock == nil {
		return ErrClosed
	}
	if outbox.failed {
		return ErrUncertain
	}
	currentLayout, err := completionLayout(outbox.path, outbox.lock)
	if err != nil {
		return outbox.poison(err)
	}
	for name, original := range outbox.identity {
		current := currentLayout[name]
		if current == nil {
			current, err = os.Lstat(filepath.Join(outbox.path, name))
		}
		if err != nil || current == nil || !os.SameFile(original, current) || original.Mode().Type() != current.Mode().Type() ||
			(original.Mode().IsRegular() && original.Size() != current.Size()) {
			return outbox.poison(errors.Join(ErrStore, err))
		}
	}
	intent, _ := outbox.intent.CanonicalBytes()
	for _, file := range []struct {
		name string
		want []byte
	}{
		{assignmentName, outbox.assignmentBytes}, {completionIntentName, intent},
		{completionReadyName, completionReadyBytes(outbox.id)},
	} {
		actual, err := readRegular(filepath.Join(outbox.path, file.name), len(file.want))
		if err != nil || !bytes.Equal(actual, file.want) {
			return outbox.poison(errors.Join(ErrCompletionIntent, err))
		}
	}
	names, err := boundedNames(filepath.Join(outbox.path, completionReceivedName), 1)
	if err != nil {
		return outbox.poison(err)
	}
	if outbox.ack == nil {
		if len(names) != 0 {
			return outbox.poison(ErrCompletionIntent)
		}
	} else {
		if len(names) != 1 || names[0] != completionReceiptName {
			return outbox.poison(ErrCompletionIntent)
		}
		actual, err := readRegular(filepath.Join(outbox.path, completionReceivedName, completionReceiptName), completionReceiptBytes)
		want, _ := completionReceipt(outbox.id, *outbox.ack)
		if err != nil || !bytes.Equal(actual, want) {
			return outbox.poison(errors.Join(ErrCompletionIntent, err))
		}
	}
	if _, err := inspectSizedPending(outbox.path, completionReceiptBytes); err != nil {
		return outbox.poison(err)
	}
	return nil
}

func (outbox *CompletionOutbox) poison(err error) error {
	outbox.failed = true
	return errors.Join(ErrUncertain, err)
}

func (outbox *CompletionOutbox) Snapshot() (CompletionDelivery, error) {
	if outbox == nil {
		return CompletionDelivery{}, ErrClosed
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if err := outbox.check(); err != nil {
		return CompletionDelivery{}, err
	}
	result := CompletionDelivery{IntentID: outbox.id, Intent: outbox.intent}
	if outbox.ack != nil {
		ack := *outbox.ack
		result.Acknowledgement = &ack
	}
	return result, nil
}

// Deliver performs at most ONE exchange through the concrete pinned QUIC client.
// The mutex and process lock cover validation, network I/O and receipt durability.
// No arbitrary success callback or externally supplied ACK can mark delivery.
// A durable historical ACK returns locally without dialing or changing its nonce.
// Failed exchanges retain unresolved intent; retry uses that exact entry and a
// fresh wire nonce. There is no automatic retry, signing, discovery or head refresh.
func (outbox *CompletionOutbox) Deliver(ctx context.Context, client *libp2ptransport.Host, address string, timeout time.Duration) (completionwire.Acknowledgement, error) {
	if outbox == nil {
		return completionwire.Acknowledgement{}, ErrClosed
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if err := outbox.check(); err != nil {
		return completionwire.Acknowledgement{}, err
	}
	if ctx == nil || client == nil || client.ID() != outbox.intent.ClientPeerID ||
		timeout < completionwire.MinimumTimeout || timeout > completionwire.MaximumTimeout {
		return completionwire.Acknowledgement{}, ErrCompletionIntent
	}
	if err := ctx.Err(); err != nil {
		return completionwire.Acknowledgement{}, err
	}
	if outbox.ack != nil {
		return *outbox.ack, nil
	}
	count, err := inspectSizedPending(outbox.path, completionReceiptBytes)
	if err != nil {
		return completionwire.Acknowledgement{}, outbox.poison(err)
	}
	if count == MaximumPendingFiles {
		return completionwire.Acknowledgement{}, custodyauthority.ErrLimit
	}
	if err := outbox.hooks.reach("outbox-before-send"); err != nil {
		return completionwire.Acknowledgement{}, outbox.poison(err)
	}
	ack, err := client.CompletePrune(ctx, address, outbox.intent.ServerPeerID, outbox.intent.Entry, timeout)
	if err != nil {
		return completionwire.Acknowledgement{}, errors.Join(completionwire.ErrUnconfirmed, err)
	}
	if err := outbox.hooks.reach("outbox-reply-verified"); err != nil {
		return completionwire.Acknowledgement{}, outbox.poison(err)
	}
	// Once a complete checked reply is available, finish recording that fact
	// despite caller cancellation. A failed local write returns no acknowledgement.
	if err := outbox.record(ack); err != nil {
		return completionwire.Acknowledgement{}, errors.Join(completionwire.ErrUnconfirmed, err)
	}
	return ack, nil
}

func (outbox *CompletionOutbox) record(ack completionwire.Acknowledgement) error {
	if err := outbox.check(); err != nil {
		return err
	}
	entryID, _ := outbox.intent.Entry.ID()
	if ack.EntryID != entryID || outbox.ack != nil {
		return outbox.poison(ErrCompletionIntent)
	}
	encoded, err := completionReceipt(outbox.id, ack)
	if err != nil {
		return outbox.poison(err)
	}
	hooks := storeHooks{at: func(stage string) error { return outbox.hooks.reach("outbox-" + stage) }}
	if err := hooks.reach("before-write"); err != nil {
		return outbox.poison(err)
	}
	file, err := os.CreateTemp(filepath.Join(outbox.path, pendingName), "entry-")
	if err != nil {
		return outbox.poison(err)
	}
	if err := writeAndSync(file, encoded, hooks); err != nil {
		return outbox.poison(err)
	}
	if err := hooks.reach("before-publish"); err != nil {
		return outbox.poison(err)
	}
	if err := outbox.check(); err != nil {
		return err
	}
	key := filepath.Join(completionReceivedName, completionReceiptName)
	if err := os.Link(file.Name(), filepath.Join(outbox.path, key)); err != nil {
		return outbox.poison(err)
	}
	if err := hooks.reach("after-publish"); err != nil {
		return outbox.poison(err)
	}
	syncDir := outbox.hooks.syncEntriesDirectory
	if syncDir == nil {
		syncDir = syncDirectory
	}
	if err := syncDir(filepath.Join(outbox.path, completionReceivedName)); err != nil {
		return outbox.poison(err)
	}
	if err := hooks.reach("directory-synced"); err != nil {
		return outbox.poison(err)
	}
	if err := os.Remove(file.Name()); err == nil {
		_ = syncDirectory(filepath.Join(outbox.path, pendingName))
	}
	outbox.identity[key], err = os.Lstat(filepath.Join(outbox.path, key))
	if err != nil {
		return outbox.poison(err)
	}
	outbox.ack = &ack
	if err := hooks.reach("after-apply"); err != nil {
		return outbox.poison(err)
	}
	return outbox.check()
}

func (outbox *CompletionOutbox) Close() error {
	if outbox == nil {
		return nil
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if outbox.lock == nil {
		return nil
	}
	err := outbox.lock.Close()
	outbox.lock = nil
	return err
}
