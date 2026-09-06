package workarchive

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	MaximumCustodyBackupPins      = 65_536
	MaximumCustodyPinPendingFiles = 1_024
	custodyPinLockName            = "pins.lock"
	custodyPinEntriesName         = "entries"
	custodyPinPendingName         = "pending"
)

type custodyPinHooks struct {
	beforePublish func()
	afterPublish  func()
}

// PinCustodyBackup advances an independently stored pin journal by explicit
// compare-and-append. The caller supplies the checkpoint ID obtained from the
// authoritative backup operation and the previously observed pin ID. Zero
// expectedPin authorizes only initialization (or its exact committed retry).
// Updates require the previous pinned backup for evidence-preservation checks.
// Keep pins outside live evidence and all backups on independently managed
// storage: path separation alone cannot establish physical independence.
func PinCustodyBackup(pinsPath, backupPath, previousBackupPath string, expectedPin, checkpointID types.Hash,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) (CustodyBackupPin, bool, error) {
	return pinCustodyBackup(pinsPath, backupPath, previousBackupPath, expectedPin, checkpointID, manifest, initial, policy, custodyPinHooks{})
}

func pinCustodyBackup(pinsPath, backupPath, previousBackupPath string, expectedPin, checkpointID types.Hash,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy, hooks custodyPinHooks,
) (CustodyBackupPin, bool, error) {
	if pinsPath == "" || backupPath == "" || checkpointID.IsZero() ||
		CustodyEvidencePathsOverlap(pinsPath, backupPath) ||
		(previousBackupPath != "" && CustodyEvidencePathsOverlap(pinsPath, previousBackupPath)) {
		return CustodyBackupPin{}, false, ErrCustodyBackupPin
	}
	if _, err := os.Lstat(pinsPath); errors.Is(err, os.ErrNotExist) {
		if !expectedPin.IsZero() || previousBackupPath != "" {
			return CustodyBackupPin{}, false, ErrCustodyBackupPinConflict
		}
		// Do not create a pin authority for an unverified backup or wrong trust.
		if _, err := VerifyCustodyBackup(backupPath, checkpointID, manifest, initial, policy); err != nil {
			return CustodyBackupPin{}, false, err
		}
		if err := initializeCustodyPins(pinsPath); err != nil {
			return CustodyBackupPin{}, false, err
		}
	} else if err != nil {
		return CustodyBackupPin{}, false, err
	}
	lock, err := acquireCustodyEvidenceLock(pinsPath, custodyPinLockName, false)
	if err != nil {
		return CustodyBackupPin{}, false, err
	}
	defer lock.Close()
	head, count, pendingCount, err := scanCustodyPins(pinsPath)
	if err != nil {
		return CustodyBackupPin{}, false, err
	}
	var headID, headCheckpointID types.Hash
	if count != 0 {
		headID, _ = head.ID()
		headCheckpointID, _ = head.Checkpoint.ID()
	}
	// A lost success response may repeat the immediately preceding expectation.
	// It can retrieve only this exact last checkpoint, never an older pin.
	exactRetry := count != 0 && checkpointID == headCheckpointID &&
		(expectedPin == headID || expectedPin == head.PreviousPinID)
	if !exactRetry && expectedPin != headID {
		return CustodyBackupPin{}, false, ErrCustodyBackupPinConflict
	}
	if !exactRetry && ((count == 0 && previousBackupPath != "") || (count != 0 && previousBackupPath == "")) {
		return CustodyBackupPin{}, false, ErrCustodyBackupPinConflict
	}
	previousPath := previousBackupPath
	if exactRetry {
		previousPath = ""
	}
	release, err := lockCustodyPinBackups(backupPath, previousPath)
	if err != nil {
		return CustodyBackupPin{}, false, err
	}
	defer release()
	checkpoint, err := verifyCustodyBackupLocked(backupPath, checkpointID, manifest, initial, policy)
	if err != nil {
		return CustodyBackupPin{}, false, err
	}
	if exactRetry {
		return head, false, nil
	}
	pin := CustodyBackupPin{Version: CustodyBackupPinVersion0, Sequence: uint64(count) + 1, PreviousPinID: headID, Checkpoint: checkpoint}
	if count != 0 {
		previous, err := verifyCustodyBackupLocked(previousBackupPath, headCheckpointID, manifest, initial, policy)
		if err != nil {
			return CustodyBackupPin{}, false, err
		}
		if !custodyPinFollows(head, pin) {
			return CustodyBackupPin{}, false, ErrCustodyBackupPinConflict
		}
		if err := custodyBackupPreservesEvidence(previousBackupPath, backupPath, previous, checkpoint); err != nil {
			return CustodyBackupPin{}, false, err
		}
	}
	if count >= MaximumCustodyBackupPins || pendingCount >= MaximumCustodyPinPendingFiles {
		return CustodyBackupPin{}, false, fmt.Errorf("%w: pin journal capacity reached", ErrCustodyBackupPin)
	}
	encoded, err := pin.CanonicalBytes()
	if err != nil {
		return CustodyBackupPin{}, false, err
	}
	if hooks.beforePublish != nil {
		hooks.beforePublish()
	}
	destination := filepath.Join(pinsPath, custodyPinEntriesName, custodyPinEntryName(pin.Sequence))
	if _, err := publishCustodyJournalBytes(filepath.Join(pinsPath, custodyPinPendingName), destination, encoded); err != nil {
		return CustodyBackupPin{}, false, err
	}
	actual, err := readRegularArchiveFile(destination, MaximumCustodyBackupPinBytes)
	if err != nil || !bytes.Equal(actual, encoded) {
		return CustodyBackupPin{}, false, errors.Join(ErrCustodyBackupPinConflict, err)
	}
	if hooks.afterPublish != nil {
		hooks.afterPublish()
	}
	return pin, true, nil
}

// ReadCustodyBackupPinHead never initializes or repairs a journal. A missing or
// empty authority cannot select a restore checkpoint. Its integrity and current
// storage location are operator trust inputs, not inferred from backup files.
func ReadCustodyBackupPinHead(path string) (CustodyBackupPin, error) {
	lock, err := acquireCustodyEvidenceLock(path, custodyPinLockName, false)
	if err != nil {
		return CustodyBackupPin{}, err
	}
	defer lock.Close()
	head, count, _, err := scanCustodyPins(path)
	if err != nil || count == 0 {
		return CustodyBackupPin{}, errors.Join(ErrCustodyBackupPin, err)
	}
	return head, nil
}

// VerifyPinnedCustodyBackup selects only the current pin while holding its
// journal lock. A nonzero expectedPin additionally pins that authority's exact
// head, allowing a caller with a separately retained receipt to detect its
// rollback too. Zero trusts the current independent pin store as authoritative.
func VerifyPinnedCustodyBackup(pinsPath, backupPath string, expectedPin types.Hash,
	manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
) (CustodyBackupPin, error) {
	if CustodyEvidencePathsOverlap(pinsPath, backupPath) {
		return CustodyBackupPin{}, ErrCustodyBackupPin
	}
	lock, err := acquireCustodyEvidenceLock(pinsPath, custodyPinLockName, false)
	if err != nil {
		return CustodyBackupPin{}, err
	}
	defer lock.Close()
	head, count, _, err := scanCustodyPins(pinsPath)
	if err != nil || count == 0 {
		return CustodyBackupPin{}, errors.Join(ErrCustodyBackupPin, err)
	}
	id, _ := head.ID()
	if !expectedPin.IsZero() && expectedPin != id {
		return CustodyBackupPin{}, ErrCustodyBackupPinConflict
	}
	checkpointID, _ := head.Checkpoint.ID()
	if _, err := VerifyCustodyBackup(backupPath, checkpointID, manifest, initial, policy); err != nil {
		return CustodyBackupPin{}, err
	}
	return head, nil
}

func initializeCustodyPins(path string) error {
	if err := makeCustodyJournalRoot(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	lock, err := acquireCustodyEvidenceLock(path, custodyPinLockName, true)
	if err != nil {
		return err
	}
	defer lock.Close()
	for _, name := range []string{custodyPinEntriesName, custodyPinPendingName} {
		if err := ensureCustodyJournalDirectory(filepath.Join(path, name)); err != nil {
			return err
		}
	}
	return nil
}

func custodyPinEntryName(sequence uint64) string { return fmt.Sprintf("pin-%020d.omcpin", sequence) }

func scanCustodyPins(path string) (CustodyBackupPin, int, int, error) {
	fail := func(err error) (CustodyBackupPin, int, int, error) {
		return CustodyBackupPin{}, 0, 0, errors.Join(ErrCustodyBackupPin, err)
	}
	root, err := os.Open(path)
	if err != nil {
		return fail(err)
	}
	rootEntries, err := root.ReadDir(4)
	_ = root.Close()
	if (err != nil && !errors.Is(err, io.EOF)) || len(rootEntries) != 3 {
		return fail(err)
	}
	for _, entry := range rootEntries {
		switch entry.Name() {
		case custodyPinLockName:
			info, err := os.Lstat(filepath.Join(path, entry.Name()))
			if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
				return fail(err)
			}
		case custodyPinEntriesName, custodyPinPendingName:
			if err := requireCustodyJournalDirectory(filepath.Join(path, entry.Name())); err != nil {
				return fail(err)
			}
		default:
			return fail(nil)
		}
	}
	counts := [2]int{}
	for index, name := range []string{custodyPinEntriesName, custodyPinPendingName} {
		directory, err := os.Open(filepath.Join(path, name))
		if err != nil {
			return fail(err)
		}
		for {
			entries, readErr := directory.ReadDir(128)
			for _, entry := range entries {
				counts[index]++
				validName := strings.HasPrefix(entry.Name(), ".outcomemesh-custody-journal-")
				limit := MaximumCustodyPinPendingFiles
				if index == 0 {
					limit = MaximumCustodyBackupPins
					sequence, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "pin-"), ".omcpin"), 10, 64)
					validName = err == nil && sequence != 0 && sequence <= MaximumCustodyBackupPins && custodyPinEntryName(sequence) == entry.Name()
				}
				info, err := os.Lstat(filepath.Join(path, name, entry.Name()))
				if counts[index] > limit || !validName || err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > MaximumCustodyBackupPinBytes || (index == 0 && info.Size() != MaximumCustodyBackupPinBytes) {
					_ = directory.Close()
					return fail(err)
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = directory.Close()
				return fail(readErr)
			}
		}
		_ = directory.Close()
	}
	var head CustodyBackupPin
	for sequence := 1; sequence <= counts[0]; sequence++ {
		encoded, err := readRegularArchiveFile(filepath.Join(path, custodyPinEntriesName, custodyPinEntryName(uint64(sequence))), MaximumCustodyBackupPinBytes)
		if err != nil {
			return fail(err)
		}
		pin, err := DecodeCustodyBackupPin(encoded)
		if err != nil || pin.Sequence != uint64(sequence) || (sequence != 1 && !custodyPinFollows(head, pin)) {
			return fail(err)
		}
		head = pin
	}
	return head, counts[0], counts[1], nil
}
