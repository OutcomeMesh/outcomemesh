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
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

const (
	admissionLockName     = "admission.lock"
	admissionIntentName   = "intent.omcai"
	admissionReadyName    = "ready.omcao"
	admissionReceivedName = "received"
	admissionReceiptName  = "ack.omcar"
)

// AdmissionDelivery is detached local history. A nil Acknowledgement means
// unresolved, NOT unsent or uncommitted. A retained acknowledgement is not a
// current-authority grant, a new execution permission or proof for another host.
type AdmissionDelivery struct {
	IntentID        types.Hash
	Intent          AdmissionIntent
	Acknowledgement *admissionwire.Acknowledgement
}

// AdmissionOutbox retains one immutable prune Admit and at most one successful
// channel observation under a lifetime process lock. No reset/drop/replace API
// exists. This root needs independent protected deployment; copied or rolled-back
// roots are not fenced. Missing local ACKs can only cause exact network retries,
// never local execution or a claim that the server did not commit.
type AdmissionOutbox struct {
	mu              sync.Mutex
	path            string
	lock            *os.File
	identity        map[string]os.FileInfo
	assignmentBytes []byte
	intent          AdmissionIntent
	id              types.Hash
	ack             *admissionwire.Acknowledgement
	failed          bool
	hooks           storeHooks
}

func admissionReadyBytes(id types.Hash) []byte {
	return append([]byte("OMCAINIT\x00\x00"), id[:]...)
}

// CreateAdmissionOutbox bootstraps a NEW root and durably retains the exact
// intent before returning. No network action occurs. Existing, partial or lost
// journals must never be recreated as recovery; use Open with the external ID.
func CreateAdmissionOutbox(path string, assignment custodyauthority.Assignment, intent AdmissionIntent, expectedID types.Hash) (*AdmissionOutbox, error) {
	return createAdmissionOutbox(path, assignment, intent, expectedID, storeHooks{})
}

func createAdmissionOutbox(path string, assignment custodyauthority.Assignment, intent AdmissionIntent, expectedID types.Hash, hooks storeHooks) (_ *AdmissionOutbox, err error) {
	if err := validateAdmissionIntent(assignment, intent, expectedID); err != nil {
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
	lock, err := openNamedLock(path, admissionLockName, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	for _, name := range []string{admissionReceivedName, pendingName} {
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
	if err := writeExclusive(filepath.Join(path, admissionIntentName), i); err != nil {
		return nil, err
	}
	if err := syncDirectory(path); err != nil {
		return nil, err
	}
	if err := hooks.reach("admission-outbox-before-ready"); err != nil {
		return nil, err
	}
	if err := writeExclusive(filepath.Join(path, admissionReadyName), admissionReadyBytes(expectedID)); err != nil {
		return nil, err
	}
	if err := hooks.reach("admission-outbox-ready-file-synced"); err != nil {
		return nil, err
	}
	if err := syncDirectory(path); err != nil {
		return nil, err
	}
	if err := hooks.reach("admission-outbox-ready-directory-synced"); err != nil {
		return nil, err
	}
	return loadAdmissionOutbox(path, lock, assignment, expectedID, hooks)
}

// OpenAdmissionOutbox verifies and re-syncs existing local evidence against an
// independently retained intent ID. It creates no files, submits nothing and
// never promotes a temporary receipt. Only explicit Deliver can use the network.
func OpenAdmissionOutbox(path string, assignment custodyauthority.Assignment, expectedID types.Hash) (_ *AdmissionOutbox, err error) {
	if expectedID.IsZero() {
		return nil, ErrAdmissionIntent
	}
	if _, err := assignment.ID(); err != nil {
		return nil, err
	}
	path, err = storePath(path)
	if err != nil {
		return nil, err
	}
	lock, err := openNamedLock(path, admissionLockName, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	return loadAdmissionOutbox(path, lock, assignment, expectedID, storeHooks{})
}

func admissionLayout(path string, lock *os.File) (map[string]os.FileInfo, error) {
	return inspectNamedLayout(path, lock, admissionLockName, map[string]bool{
		"": true, admissionLockName: false, assignmentName: false,
		admissionIntentName: false, admissionReadyName: false,
		admissionReceivedName: true, pendingName: true,
	})
}

func loadAdmissionOutbox(path string, lock *os.File, assignment custodyauthority.Assignment, expectedID types.Hash, hooks storeHooks) (*AdmissionOutbox, error) {
	identity, err := admissionLayout(path, lock)
	if err != nil {
		return nil, err
	}
	encoded, err := readRegular(filepath.Join(path, admissionIntentName), AdmissionIntentBytes)
	if err != nil {
		return nil, err
	}
	intent, err := DecodeAdmissionIntent(encoded)
	if err != nil {
		return nil, err
	}
	if err := validateAdmissionIntent(assignment, intent, expectedID); err != nil {
		return nil, err
	}
	a, _ := assignment.CanonicalBytes()
	outbox := &AdmissionOutbox{path: path, lock: lock, identity: identity, assignmentBytes: a, intent: intent, id: expectedID, hooks: hooks}
	names, err := boundedNames(filepath.Join(path, admissionReceivedName), 1)
	if err != nil {
		return nil, err
	}
	if len(names) == 1 {
		if names[0] != admissionReceiptName {
			return nil, ErrAdmissionIntent
		}
		key := filepath.Join(admissionReceivedName, admissionReceiptName)
		encoded, err := readRegular(filepath.Join(path, key), admissionReceiptBytes)
		if err != nil {
			return nil, err
		}
		ack, err := decodeAdmissionReceipt(encoded, intent)
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

func (outbox *AdmissionOutbox) check() error {
	if outbox == nil || outbox.lock == nil {
		return ErrClosed
	}
	if outbox.failed {
		return ErrUncertain
	}
	currentLayout, err := admissionLayout(outbox.path, outbox.lock)
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
		{assignmentName, outbox.assignmentBytes}, {admissionIntentName, intent},
		{admissionReadyName, admissionReadyBytes(outbox.id)},
	} {
		actual, err := readRegular(filepath.Join(outbox.path, file.name), len(file.want))
		if err != nil || !bytes.Equal(actual, file.want) {
			return outbox.poison(errors.Join(ErrAdmissionIntent, err))
		}
	}
	names, err := boundedNames(filepath.Join(outbox.path, admissionReceivedName), 1)
	if err != nil {
		return outbox.poison(err)
	}
	if outbox.ack == nil {
		if len(names) != 0 {
			return outbox.poison(ErrAdmissionIntent)
		}
	} else {
		if len(names) != 1 || names[0] != admissionReceiptName {
			return outbox.poison(ErrAdmissionIntent)
		}
		actual, err := readRegular(filepath.Join(outbox.path, admissionReceivedName, admissionReceiptName), admissionReceiptBytes)
		want, _ := admissionReceipt(outbox.id, *outbox.ack)
		if err != nil || !bytes.Equal(actual, want) {
			return outbox.poison(errors.Join(ErrAdmissionIntent, err))
		}
	}
	if _, err := inspectSizedPending(outbox.path, admissionReceiptBytes); err != nil {
		return outbox.poison(err)
	}
	return nil
}

func (outbox *AdmissionOutbox) poison(err error) error {
	outbox.failed = true
	return errors.Join(ErrUncertain, err)
}

func (outbox *AdmissionOutbox) Snapshot() (AdmissionDelivery, error) {
	if outbox == nil {
		return AdmissionDelivery{}, ErrClosed
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if err := outbox.check(); err != nil {
		return AdmissionDelivery{}, err
	}
	result := AdmissionDelivery{IntentID: outbox.id, Intent: outbox.intent}
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
func (outbox *AdmissionOutbox) Deliver(ctx context.Context, client *libp2ptransport.Host, address string, timeout time.Duration) (admissionwire.Acknowledgement, error) {
	if outbox == nil {
		return admissionwire.Acknowledgement{}, ErrClosed
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if err := outbox.check(); err != nil {
		return admissionwire.Acknowledgement{}, err
	}
	if ctx == nil || client == nil || client.ID() != outbox.intent.ClientPeerID ||
		timeout < admissionwire.MinimumTimeout || timeout > admissionwire.MaximumTimeout {
		return admissionwire.Acknowledgement{}, ErrAdmissionIntent
	}
	if err := ctx.Err(); err != nil {
		return admissionwire.Acknowledgement{}, err
	}
	if outbox.ack != nil {
		return *outbox.ack, nil
	}
	count, err := inspectSizedPending(outbox.path, admissionReceiptBytes)
	if err != nil {
		return admissionwire.Acknowledgement{}, outbox.poison(err)
	}
	if count == MaximumPendingFiles {
		return admissionwire.Acknowledgement{}, custodyauthority.ErrLimit
	}
	if err := outbox.hooks.reach("admission-outbox-before-send"); err != nil {
		return admissionwire.Acknowledgement{}, outbox.poison(err)
	}
	ack, err := client.AdmitPrune(ctx, address, outbox.intent.ServerPeerID, outbox.intent.Entry, timeout)
	if err != nil {
		return admissionwire.Acknowledgement{}, errors.Join(admissionwire.ErrUnconfirmed, err)
	}
	if err := outbox.hooks.reach("admission-outbox-reply-verified"); err != nil {
		return admissionwire.Acknowledgement{}, outbox.poison(err)
	}
	// Once a complete checked reply is available, finish recording that fact
	// despite caller cancellation. A failed local write returns no acknowledgement.
	if err := outbox.record(ack); err != nil {
		return admissionwire.Acknowledgement{}, errors.Join(admissionwire.ErrUnconfirmed, err)
	}
	return ack, nil
}

func (outbox *AdmissionOutbox) record(ack admissionwire.Acknowledgement) error {
	if err := outbox.check(); err != nil {
		return err
	}
	entryID, _ := outbox.intent.Entry.ID()
	if ack.EntryID != entryID || outbox.ack != nil {
		return outbox.poison(ErrAdmissionIntent)
	}
	encoded, err := admissionReceipt(outbox.id, ack)
	if err != nil {
		return outbox.poison(err)
	}
	hooks := storeHooks{at: func(stage string) error { return outbox.hooks.reach("admission-outbox-" + stage) }}
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
	key := filepath.Join(admissionReceivedName, admissionReceiptName)
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
	if err := syncDir(filepath.Join(outbox.path, admissionReceivedName)); err != nil {
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

func (outbox *AdmissionOutbox) Close() error {
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
