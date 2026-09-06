package workarchive

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	DefaultCustodyJournalBytes uint64 = 4 << 30
	MaximumCustodyJournalBytes uint64 = 1 << 40
	DefaultCustodyJournalPaths uint64 = 262_144
	MaximumCustodyJournalPaths uint64 = 1_048_576
)

var ErrCustodyJournalBudget = errors.New("WorkGraph archive custody journal budget exceeded")

// CustodyJournalLimits is a local growth policy, not part of the signed custody
// policy or wire format. Lowering it does not invalidate existing evidence.
type CustodyJournalLimits struct {
	MaximumBytes uint64
	MaximumPaths uint64
}

func DefaultCustodyJournalLimits() CustodyJournalLimits {
	return CustodyJournalLimits{
		MaximumBytes: DefaultCustodyJournalBytes,
		MaximumPaths: DefaultCustodyJournalPaths,
	}
}

func (limits CustodyJournalLimits) Validate() error {
	// Eight permanent paths initialize a journal, plus a temporary header link.
	if limits.MaximumBytes < 2*MaximumCustodyJournalHeaderBytes ||
		limits.MaximumBytes > MaximumCustodyJournalBytes ||
		limits.MaximumPaths < 9 || limits.MaximumPaths > MaximumCustodyJournalPaths {
		return fmt.Errorf("%w: invalid local limits", ErrCustodyJournalBudget)
	}
	return nil
}

// CustodyJournalUsage counts logical file lengths per directory entry, including
// duplicate hard links and abandoned temporary files. Paths includes the root,
// directories, empty files, and journal.lock. This is not allocated disk space.
type CustodyJournalUsage struct {
	Bytes        uint64
	Paths        uint64
	PendingBytes uint64
	PendingFiles uint64
}

func (usage CustodyJournalUsage) OverBudget(limits CustodyJournalLimits) bool {
	return usage.Bytes > limits.MaximumBytes || usage.Paths > limits.MaximumPaths
}

func (usage CustodyJournalUsage) admit(limits CustodyJournalLimits, bytes, paths uint64) error {
	if usage.OverBudget(limits) || bytes > limits.MaximumBytes-usage.Bytes ||
		paths > limits.MaximumPaths-usage.Paths {
		return fmt.Errorf("%w: bytes=%d max_bytes=%d reserve_bytes=%d paths=%d max_paths=%d reserve_paths=%d",
			ErrCustodyJournalBudget, usage.Bytes, limits.MaximumBytes, bytes,
			usage.Paths, limits.MaximumPaths, paths)
	}
	return nil
}

// Usage takes the journal lock and inventories storage without treating pending
// files as evidence. Use State or Head for replay-verified custody decisions.
func (journal *CustodyJournal) Usage() (CustodyJournalUsage, error) {
	if journal == nil {
		return CustodyJournalUsage{}, ErrCustodyJournal
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	lock, err := acquireCustodyJournalLock(journal.path)
	if err != nil {
		return CustodyJournalUsage{}, err
	}
	defer lock.Close()
	return inventoryCustodyJournal(journal.path)
}

// Inventory streams directory entries before replay allocates its path/slot
// indexes. The fixed depth and hard path ceiling also apply when a local growth
// limit has been reduced below existing usage. Files are never followed through
// symlinks, and no payload is read here.
func inventoryCustodyJournal(root string) (CustodyJournalUsage, error) {
	return inventoryCustodyJournalBounded(root, MaximumCustodyJournalPaths)
}

func inventoryCustodyJournalBounded(root string, maximumPaths uint64) (CustodyJournalUsage, error) {
	root = filepath.Clean(root)
	var usage CustodyJournalUsage
	var visit func(string, int) error
	visit = func(path string, depth int) error {
		info, err := os.Lstat(path)
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.Join(ErrCustodyJournal, err)
		}
		if usage.Paths >= maximumPaths {
			return fmt.Errorf("%w: replay path ceiling %d", ErrCustodyJournalBudget, maximumPaths)
		}
		usage.Paths++
		if !info.IsDir() {
			if info.Size() < 0 || uint64(info.Size()) > ^uint64(0)-usage.Bytes {
				return ErrCustodyJournalBudget
			}
			size := uint64(info.Size())
			usage.Bytes += size
			if filepath.Dir(path) == filepath.Join(root, custodyJournalPendingName) {
				usage.PendingFiles++
				usage.PendingBytes += size
			}
			return nil
		}
		if depth > 3 {
			return ErrCustodyJournal
		}
		directory, err := os.Open(path)
		if err != nil {
			return errors.Join(ErrCustodyJournal, err)
		}
		defer directory.Close()
		opened, err := directory.Stat()
		if err != nil || !os.SameFile(info, opened) {
			return errors.Join(ErrCustodyJournal, err)
		}
		for {
			entries, readErr := directory.ReadDir(128)
			for _, entry := range entries {
				if err := visit(filepath.Join(path, entry.Name()), depth+1); err != nil {
					return err
				}
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if readErr != nil {
				return errors.Join(ErrCustodyJournal, readErr)
			}
		}
	}
	if err := visit(root, 0); err != nil {
		return CustodyJournalUsage{}, err
	}
	return usage, nil
}

func (journal *CustodyJournal) admitAppend(bodyExists bool, bodyBytes uint64, slot custodyJournalSlot) error {
	usage, err := inventoryCustodyJournal(journal.path)
	if err != nil {
		return err
	}
	encodedSlot, err := slot.canonicalBytes()
	if err != nil {
		return err
	}
	// Budget both the published path and temporary link. Reserving the body and
	// slot together leaves room to finish after a crash leaves either temporary
	// link behind. Repeated crashes can consume that reserve; none are deleted.
	reserveBytes, reservePaths := 2*uint64(len(encodedSlot)), uint64(2)
	if !bodyExists {
		reserveBytes += 2 * bodyBytes
		reservePaths += 2
	}
	if _, err := os.Lstat(journal.slotBucketPath(slot.Sequence)); errors.Is(err, os.ErrNotExist) {
		reservePaths++
	} else if err != nil {
		return errors.Join(ErrCustodyJournal, err)
	}
	return usage.admit(journal.limits, reserveBytes, reservePaths)
}
