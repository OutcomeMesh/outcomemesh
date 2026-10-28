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
	mu       sync.Mutex
	journal  *CustodyJournal
	lock     *os.File
	handoff  *CustodySourceHandoff
	rootInfo os.FileInfo
	failed   bool
}

func (journal *CustodyJournal) AcquireDecision() (*CustodyJournalDecision, error) {
	return journal.acquireDecision(nil)
}
func (journal *CustodyJournal) acquireDecision(handoff *CustodySourceHandoff) (*CustodyJournalDecision, error) {
	if journal == nil {
		return nil, ErrCustodyJournal
	}
	if journal.header.Version != CustodyJournalHeaderVersion0 {
		return nil, ErrCustodyJournalHistoricalOnly
	}
	journal.mu.Lock()
	lock, err := acquireCustodyEvidenceLock(journal.path, custodyJournalLockName, false)
	if err == nil {
		err = requireCustodySourceAccess(journal.path, handoff)
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
	info, err := os.Lstat(journal.path)
	if err != nil {
		lock.Close()
		journal.mu.Unlock()
		return nil, err
	}
	return &CustodyJournalDecision{journal: journal, lock: lock, handoff: handoff, rootInfo: info}, nil
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
	if err := decision.check(); err != nil {
		return CustodyJournalState{}, err
	}
	if decision.handoff != nil {
		return decision.journal.handoffState()
	}
	return decision.journal.scan()
}

func (decision *CustodyJournalDecision) Head() (CustodyJournalEntry, bool, error) {
	if decision == nil {
		return CustodyJournalEntry{}, false, ErrCustodyJournal
	}
	decision.mu.Lock()
	defer decision.mu.Unlock()
	if err := decision.check(); err != nil {
		return CustodyJournalEntry{}, false, err
	}
	return decision.journal.headLocked()
}

func (decision *CustodyJournalDecision) Append(record CustodyRecord) (CustodyJournalEntry, bool, error) {
	if decision == nil {
		return CustodyJournalEntry{}, false, ErrCustodyJournal
	}
	decision.mu.Lock()
	defer decision.mu.Unlock()
	if err := decision.check(); err != nil {
		return CustodyJournalEntry{}, false, err
	}
	if decision.handoff != nil {
		return CustodyJournalEntry{}, false, ErrCustodySourceHandedOff
	}
	return decision.journal.appendLocked(record, custodyJournalHooks{})
}

func (decision *CustodyJournalDecision) Rotate() (bool, error) {
	if decision == nil {
		return false, ErrCustodyJournal
	}
	decision.mu.Lock()
	defer decision.mu.Unlock()
	if err := decision.check(); err != nil {
		return false, err
	}
	if decision.handoff != nil {
		return false, ErrCustodySourceHandedOff
	}
	return decision.journal.rotateLocked(custodyJournalHooks{})
}

func (decision *CustodyJournalDecision) Usage() (CustodyJournalUsage, error) {
	if decision == nil {
		return CustodyJournalUsage{}, ErrCustodyJournal
	}
	decision.mu.Lock()
	defer decision.mu.Unlock()
	if err := decision.check(); err != nil {
		return CustodyJournalUsage{}, err
	}
	return inventoryCustodyJournal(decision.journal.path)
}

// Any named retirement path blocks live use, even an incomplete/corrupt file,
// symlink or directory. Never repair, remove or trust it as an active marker.
func requireActiveCustodyJournal(root string) error {
	return requireCustodySourceAccess(root, nil)
}

// CheckAccess rechecks the source version and permanent lock while the action
// owns its decision. Call before object reads, signing or output publication.
func (d *CustodyJournalDecision) CheckAccess() error {
	if d == nil {
		return ErrCustodyJournal
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.check()
}
func (d *CustodyJournalDecision) check() error {
	if d.journal == nil || d.lock == nil {
		return ErrCustodyJournal
	}
	if d.failed {
		return ErrCustodySourceHandoff
	}
	root, re := os.Lstat(d.journal.path)
	current, ce := os.Lstat(filepath.Join(d.journal.path, custodyJournalLockName))
	held, he := d.lock.Stat()
	if re != nil || ce != nil || he != nil || !os.SameFile(root, d.rootInfo) || !current.Mode().IsRegular() || current.Size() != 0 || !os.SameFile(current, held) {
		d.failed = true
		return errors.Join(ErrCustodySourceHandoff, re, ce, he)
	}
	if e := requireCustodySourceAccess(d.journal.path, d.handoff); e != nil {
		d.failed = true
		return e
	}
	return nil
}
