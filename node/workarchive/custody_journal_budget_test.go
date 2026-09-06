package workarchive

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func custodyJournalFirstAppendBudget(t testing.TB, fixture custodyRecordFixture, journal *CustodyJournal) (CustodyJournalLimits, uint64) {
	t.Helper()
	usage, err := journal.Usage()
	if err != nil {
		t.Fatal(err)
	}
	entry := CustodyJournalEntry{Sequence: 1, PreviousReceipt: fixture.receipt, Record: fixture.record}
	encoded, err := entry.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := entry.ID()
	slot, _ := (custodyJournalSlot{Sequence: 1, EntryID: id}).canonicalBytes()
	return CustodyJournalLimits{
		MaximumBytes: usage.Bytes + 2*uint64(len(encoded)+len(slot)),
		MaximumPaths: usage.Paths + 5, // body + temp, slot + temp, first bucket
	}, uint64(len(encoded))
}

func TestCustodyJournalBudgetRejectsBeforePublishingBody(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	for _, dimension := range []string{"bytes", "paths"} {
		t.Run(dimension, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "journal")
			journal, _, err := OpenOrCreateCustodyJournal(root, fixture.manifest, fixture.receipt, fixture.policy)
			if err != nil {
				t.Fatal(err)
			}
			exact, _ := custodyJournalFirstAppendBudget(t, fixture, journal)
			limits := exact
			if dimension == "bytes" {
				limits.MaximumBytes--
			} else {
				limits.MaximumPaths--
			}
			journal, before, err := OpenOrCreateCustodyJournalWithLimits(root, fixture.manifest, fixture.receipt, fixture.policy, limits)
			if err != nil {
				t.Fatal(err)
			}
			usageBefore, _ := journal.Usage()
			if _, created, err := journal.Append(fixture.record); created || !errors.Is(err, ErrCustodyJournalBudget) {
				t.Fatalf("over-budget append created=%t error=%v", created, err)
			}
			if after, err := journal.State(); err != nil || after != before {
				t.Fatalf("budget rejection changed state: %+v %v", after, err)
			}
			if usageAfter, err := journal.Usage(); err != nil || usageAfter != usageBefore {
				t.Fatalf("budget rejection wrote files: %+v -> %+v: %v", usageBefore, usageAfter, err)
			}
			journal, _, err = OpenOrCreateCustodyJournalWithLimits(root, fixture.manifest, fixture.receipt, fixture.policy, exact)
			if err != nil {
				t.Fatal(err)
			}
			if _, created, err := journal.Append(fixture.record); err != nil || !created {
				t.Fatalf("exact budget append created=%t error=%v", created, err)
			}
		})
	}
}

func TestCustodyJournalLowerLimitsPreserveReplayAndCommittedRetry(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	root := filepath.Join(t.TempDir(), "journal")
	journal, _, err := OpenOrCreateCustodyJournal(root, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := journal.Append(fixture.record)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := journal.State()
	usageBefore, _ := journal.Usage()
	limits := CustodyJournalLimits{MaximumBytes: 2 * MaximumCustodyJournalHeaderBytes, MaximumPaths: 9}
	journal, reopened, err := OpenOrCreateCustodyJournalWithLimits(root, fixture.manifest, fixture.receipt, fixture.policy, limits)
	if err != nil || reopened != before {
		t.Fatalf("lowered limits invalidated evidence: %+v %v", reopened, err)
	}
	usage, err := journal.Usage()
	if err != nil || !usage.OverBudget(limits) || usage != usageBefore {
		t.Fatalf("over-budget usage=%+v error=%v", usage, err)
	}
	for _, action := range []string{"head", "retry", "append", "rotate"} {
		switch action {
		case "head":
			head, found, err := journal.Head()
			wantID, _ := first.ID()
			gotID, _ := head.ID()
			if err != nil || !found || gotID != wantID {
				t.Fatalf("head at capacity found=%t error=%v", found, err)
			}
		case "retry":
			retried, created, err := journal.Append(fixture.answerChallenge(t, fixture.record.Challenge, 1_003))
			if err != nil || created || retried.Record.Proof != first.Record.Proof {
				t.Fatalf("committed retry at capacity created=%t error=%v", created, err)
			}
		case "append":
			second := nextCustodyJournalRecord(t, fixture, first.Record.RenewedReceipt, 181, 1_004, 1_005, 30_000)
			if _, _, err := journal.Append(second); !errors.Is(err, ErrCustodyJournalBudget) {
				t.Fatalf("fresh append above lowered cap: %v", err)
			}
		case "rotate":
			if changed, err := journal.Rotate(); changed || !errors.Is(err, ErrCustodyJournalBudget) {
				t.Fatalf("rotation above lowered cap changed=%t error=%v", changed, err)
			}
		}
		if after, err := journal.State(); err != nil || after != before {
			t.Fatalf("%s changed state: %+v %v", action, after, err)
		}
		if after, err := journal.Usage(); err != nil || after != usageBefore {
			t.Fatalf("%s changed storage: %+v %v", action, after, err)
		}
	}
}

func TestCustodyJournalBudgetRecountsAfterAnotherHandlePublishes(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	root := filepath.Join(t.TempDir(), "journal")
	first, _, err := OpenOrCreateCustodyJournal(root, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	limits, _ := custodyJournalFirstAppendBudget(t, fixture, first)
	first, _, err = OpenOrCreateCustodyJournalWithLimits(root, fixture.manifest, fixture.receipt, fixture.policy, limits)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := OpenOrCreateCustodyJournalWithLimits(root, fixture.manifest, fixture.receipt, fixture.policy, limits)
	if err != nil {
		t.Fatal(err)
	}
	secondRecord := nextCustodyJournalRecord(t, fixture, fixture.record.RenewedReceipt, 182, 1_004, 1_005, 30_000)
	bodyReady := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	firstDone := make(chan error, 1)
	go func() {
		_, _, err := first.append(fixture.record, custodyJournalHooks{afterBody: func() {
			close(bodyReady)
			<-release
		}})
		firstDone <- err
	}()
	select {
	case <-bodyReady:
	case <-time.After(5 * time.Second):
		t.Fatal("first writer did not publish its body")
	}
	secondDone := make(chan error, 1)
	go func() {
		_, _, err := second.Append(secondRecord)
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		t.Fatalf("second writer bypassed the first writer's lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first writer did not finish")
	}
	select {
	case err := <-secondDone:
		if !errors.Is(err, ErrCustodyJournalBudget) {
			t.Fatalf("second writer did not account for first publication: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second writer did not finish")
	}
	if state, err := second.State(); err != nil || state.Sequence != 1 {
		t.Fatalf("second writer changed the head: %+v %v", state, err)
	}
	if usage, err := second.Usage(); err != nil || usage.Paths != 11 || usage.PendingFiles != 0 {
		t.Fatalf("second writer left new paths: %+v %v", usage, err)
	}
}

func TestCustodyJournalBudgetReservesCrashCompletionWithAbandonedLink(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	root := filepath.Join(t.TempDir(), "journal")
	journal, _, err := OpenOrCreateCustodyJournal(root, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	limits, bodyBytes := custodyJournalFirstAppendBudget(t, fixture, journal)
	journal, _, err = OpenOrCreateCustodyJournalWithLimits(root, fixture.manifest, fixture.receipt, fixture.policy, limits)
	if err != nil {
		t.Fatal(err)
	}
	entry := CustodyJournalEntry{Sequence: 1, PreviousReceipt: fixture.receipt, Record: fixture.record}
	entryID, _ := entry.ID()
	pending := filepath.Join(root, custodyJournalPendingName, ".outcomemesh-custody-journal-interrupted-body")
	mustPanicCustodyJournal(t, func() {
		_, _, err := journal.append(fixture.record, custodyJournalHooks{afterBody: func() {
			// Model a killed process that did not unlink its published temp inode.
			if err := os.Link(filepath.Join(journal.activePath(), custodyJournalBodyName(entryID)), pending); err != nil {
				t.Fatal(err)
			}
			panicCustodyJournalHook()
		}})
		if err != nil {
			t.Fatal(err)
		}
	})
	journal, recovered, err := OpenOrCreateCustodyJournalWithLimits(root, fixture.manifest, fixture.receipt, fixture.policy, limits)
	if err != nil || recovered.Sequence != 0 {
		t.Fatalf("interrupted state=%+v error=%v", recovered, err)
	}
	usageBefore, err := journal.Usage()
	if err != nil || usageBefore.PendingFiles != 1 || usageBefore.PendingBytes != bodyBytes {
		t.Fatalf("abandoned link not charged: %+v %v", usageBefore, err)
	}
	if _, created, err := journal.Append(fixture.record); err != nil || !created {
		t.Fatalf("reserved completion created=%t error=%v", created, err)
	}
	usageAfter, err := journal.Usage()
	if err != nil || usageAfter.OverBudget(limits) || usageAfter.PendingFiles != 1 ||
		usageAfter.PendingBytes != bodyBytes || usageAfter.Paths != usageBefore.Paths+2 {
		t.Fatalf("completion usage=%+v error=%v", usageAfter, err)
	}
	if _, err := os.Stat(pending); err != nil {
		t.Fatalf("completion removed abandoned evidence: %v", err)
	}
}

func TestCustodyJournalUsageCountsRotationsEmptyFilesAndDuplicateBodies(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	root := filepath.Join(t.TempDir(), "journal")
	journal, _, err := OpenOrCreateCustodyJournal(root, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	header, _ := journal.header.CanonicalBytes()
	usage, err := journal.Usage()
	if err != nil || usage != (CustodyJournalUsage{Bytes: uint64(len(header)), Paths: 8}) {
		t.Fatalf("initial usage=%+v error=%v", usage, err)
	}
	entry, _, err := journal.Append(fixture.record)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := journal.Usage()
	if rotated, err := journal.Rotate(); err != nil || !rotated {
		t.Fatalf("rotation=%t error=%v", rotated, err)
	}
	after, err := journal.Usage()
	if err != nil || after.Bytes != before.Bytes || after.Paths != before.Paths+1 {
		t.Fatalf("rotation usage=%+v -> %+v error=%v", before, after, err)
	}
	id, _ := entry.ID()
	segments, _ := os.ReadDir(journal.segmentsPath())
	if err := os.Link(filepath.Join(journal.segmentsPath(), segments[0].Name(), custodyJournalBodyName(id)),
		filepath.Join(journal.activePath(), custodyJournalBodyName(id))); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(root, custodyJournalPendingName, ".outcomemesh-custody-journal-empty")
	if err := os.WriteFile(pending, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, _ := entry.CanonicalBytes()
	want := after
	want.Paths += 2
	want.Bytes += uint64(len(encoded))
	want.PendingFiles = 1
	if usage, err := journal.Usage(); err != nil || usage != want {
		t.Fatalf("duplicate/empty-file usage=%+v want=%+v error=%v", usage, want, err)
	}
	if state, err := journal.State(); err != nil || state.Sequence != 1 {
		t.Fatalf("duplicate body replay=%+v error=%v", state, err)
	}
}

func TestCustodyJournalRotationAdmitsOneAdditionalPath(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	root := filepath.Join(t.TempDir(), "journal")
	journal, _, err := OpenOrCreateCustodyJournal(root, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Append(fixture.record); err != nil {
		t.Fatal(err)
	}
	usage, _ := journal.Usage()
	limits := CustodyJournalLimits{MaximumBytes: usage.Bytes, MaximumPaths: usage.Paths}
	journal, _, err = OpenOrCreateCustodyJournalWithLimits(root, fixture.manifest, fixture.receipt, fixture.policy, limits)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := journal.Rotate(); changed || !errors.Is(err, ErrCustodyJournalBudget) {
		t.Fatalf("rotation without path reserve changed=%t error=%v", changed, err)
	}
	limits.MaximumPaths++
	journal, _, err = OpenOrCreateCustodyJournalWithLimits(root, fixture.manifest, fixture.receipt, fixture.policy, limits)
	if err != nil {
		t.Fatal(err)
	}
	mustPanicCustodyJournal(t, func() {
		if _, err := journal.rotate(custodyJournalHooks{afterSeal: panicCustodyJournalHook}); err != nil {
			t.Fatal(err)
		}
	})
	journal, state, err := OpenOrCreateCustodyJournalWithLimits(root, fixture.manifest, fixture.receipt, fixture.policy, limits)
	if err != nil || state.Sequence != 1 {
		t.Fatalf("rotation repair at capacity state=%+v error=%v", state, err)
	}
	if after, err := journal.Usage(); err != nil || after.Paths != limits.MaximumPaths || after.Bytes != usage.Bytes {
		t.Fatalf("rotation repair usage=%+v error=%v", after, err)
	}
	if changed, err := journal.Rotate(); err != nil || changed {
		t.Fatalf("empty rotation at capacity changed=%t error=%v", changed, err)
	}
}

func TestCustodyJournalBoundedInventory(t *testing.T) {
	root := t.TempDir()
	for index := range 260 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("file-%03d", index)), []byte{1}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if usage, err := inventoryCustodyJournalBounded(root, 261); err != nil || usage.Paths != 261 || usage.Bytes != 260 {
		t.Fatalf("batched inventory=%+v error=%v", usage, err)
	}
	if _, err := inventoryCustodyJournalBounded(root, 260); !errors.Is(err, ErrCustodyJournalBudget) {
		t.Fatalf("replay ceiling ignored: %v", err)
	}
	if err := os.Symlink(root, filepath.Join(root, "recursive-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := inventoryCustodyJournal(root); !errors.Is(err, ErrCustodyJournal) {
		t.Fatalf("inventory followed symlink: %v", err)
	}
}

func TestCustodyJournalLimitsValidateAndAdmissionDoesNotOverflow(t *testing.T) {
	defaults := DefaultCustodyJournalLimits()
	if err := defaults.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []CustodyJournalLimits{
		{}, {MaximumBytes: 1, MaximumPaths: defaults.MaximumPaths},
		{MaximumBytes: defaults.MaximumBytes, MaximumPaths: 8},
		{MaximumBytes: MaximumCustodyJournalBytes + 1, MaximumPaths: defaults.MaximumPaths},
		{MaximumBytes: defaults.MaximumBytes, MaximumPaths: MaximumCustodyJournalPaths + 1},
	} {
		if err := invalid.Validate(); !errors.Is(err, ErrCustodyJournalBudget) {
			t.Fatalf("invalid limits accepted: %+v %v", invalid, err)
		}
	}
	for _, usage := range []CustodyJournalUsage{{Bytes: ^uint64(0)}, {Paths: ^uint64(0)}} {
		if err := usage.admit(defaults, 1, 1); !errors.Is(err, ErrCustodyJournalBudget) {
			t.Fatalf("usage overflow accepted: %+v %v", usage, err)
		}
	}
	if err := (CustodyJournalUsage{Bytes: 1, Paths: 1}).admit(defaults, ^uint64(0), ^uint64(0)); !errors.Is(err, ErrCustodyJournalBudget) {
		t.Fatalf("reserve overflow accepted: %v", err)
	}
}

func TestCustodyJournalExistingPublicationNeedsNoTemporaryDirectory(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "header.omcj")
	encoded := []byte("already durable")
	if err := os.WriteFile(destination, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	// A regular file cannot act as a temp directory, so any allocation fails.
	if created, err := publishCustodyJournalBytes(destination, destination, encoded); err != nil || created {
		t.Fatalf("existing publication allocated a temp file: created=%t error=%v", created, err)
	}
	current, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(current, encoded) {
		t.Fatalf("existing publication changed: %v", err)
	}
}
