package workarchive

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

var ErrCustodyJournalRetired = errors.New("custody journal is permanently retired; live decisions are forbidden")

const custodyRetirementFileName = "retirement.omcrt"

// CustodyJournalDecision holds the permanent journal lock for a WHOLE local
// authority operation, including signing, artifact publication and network I/O.
// Acquire an auditor's artifact lock first. Use this handle's methods while it
// is open, not the original journal (which would try to reacquire the lock).
// Close on every exit. Process death releases the kernel lock. A retirement
// cannot commit until the scope has drained; this does not fence remote copies,
// raw signing helpers, legacy sessions or operators who replace journal files.
type CustodyJournalDecision struct {
	mu      sync.Mutex
	journal *CustodyJournal
	lock    *os.File
}

func (journal *CustodyJournal) AcquireDecision() (*CustodyJournalDecision, error) {
	if journal == nil {
		return nil, ErrCustodyJournal
	}
	if journal.header.Version != CustodyJournalHeaderVersion0 {
		return nil, ErrCustodyJournalHistoricalOnly
	}
	journal.mu.Lock()
	lock, err := acquireCustodyEvidenceLock(journal.path, custodyJournalLockName, false)
	if err == nil {
		err = requireActiveCustodyJournal(journal.path)
	}
	if err == nil {
		_, err = journal.scan()
	}
	if err != nil {
		if lock != nil {
			_ = lock.Close()
		}
		journal.mu.Unlock()
		return nil, err
	}
	return &CustodyJournalDecision{journal: journal, lock: lock}, nil
}

func (decision *CustodyJournalDecision) Close() error {
	if decision == nil {
		return nil
	}
	decision.mu.Lock()
	defer decision.mu.Unlock()
	if decision.journal == nil {
		return nil
	}
	err := decision.lock.Close()
	decision.journal.mu.Unlock()
	decision.journal, decision.lock = nil, nil
	return err
}

func (decision *CustodyJournalDecision) State() (CustodyJournalState, error) {
	if decision == nil {
		return CustodyJournalState{}, ErrCustodyJournal
	}
	decision.mu.Lock()
	defer decision.mu.Unlock()
	if decision.journal == nil {
		return CustodyJournalState{}, ErrCustodyJournal
	}
	return decision.journal.scan()
}

func (decision *CustodyJournalDecision) Head() (CustodyJournalEntry, bool, error) {
	if decision == nil {
		return CustodyJournalEntry{}, false, ErrCustodyJournal
	}
	decision.mu.Lock()
	defer decision.mu.Unlock()
	if decision.journal == nil {
		return CustodyJournalEntry{}, false, ErrCustodyJournal
	}
	return decision.journal.headLocked()
}

func (decision *CustodyJournalDecision) Append(record CustodyRecord) (CustodyJournalEntry, bool, error) {
	if decision == nil {
		return CustodyJournalEntry{}, false, ErrCustodyJournal
	}
	decision.mu.Lock()
	defer decision.mu.Unlock()
	if decision.journal == nil {
		return CustodyJournalEntry{}, false, ErrCustodyJournal
	}
	return decision.journal.appendLocked(record, custodyJournalHooks{})
}

func (decision *CustodyJournalDecision) Rotate() (bool, error) {
	if decision == nil {
		return false, ErrCustodyJournal
	}
	decision.mu.Lock()
	defer decision.mu.Unlock()
	if decision.journal == nil {
		return false, ErrCustodyJournal
	}
	return decision.journal.rotateLocked(custodyJournalHooks{})
}

func (decision *CustodyJournalDecision) Usage() (CustodyJournalUsage, error) {
	if decision == nil {
		return CustodyJournalUsage{}, ErrCustodyJournal
	}
	decision.mu.Lock()
	defer decision.mu.Unlock()
	if decision.journal == nil {
		return CustodyJournalUsage{}, ErrCustodyJournal
	}
	return inventoryCustodyJournal(decision.journal.path)
}

// Any named retirement path blocks live use, even an incomplete/corrupt file,
// symlink or directory. Never repair, remove or trust it as an active marker.
func requireActiveCustodyJournal(root string) error {
	if _, err := os.Lstat(filepath.Join(root, custodyRetirementFileName)); err == nil {
		return ErrCustodyJournalRetired
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
