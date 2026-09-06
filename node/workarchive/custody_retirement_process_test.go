//go:build integration

package workarchive

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCustodyRetirementProcessCrashAtomicity(t *testing.T) {
	f := newCustodyRebaselineFixture(t)
	proposal, err := f.propose()
	if err != nil {
		t.Fatal(err)
	}
	for _, boundary := range []string{"locked", "before-commit", "auditor-temp", "auditor", "replica-temp", "replica"} {
		t.Run(boundary, func(t *testing.T) {
			local := retirementTestLocal(t, f, false)
			marker := filepath.Join(t.TempDir(), "reached")
			command := exec.Command(os.Args[0], "-test.run=^TestCustodyRetirementCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(), "OUTCOMEMESH_CUSTODY_RETIREMENT_CRASH="+boundary,
				"OUTCOMEMESH_CUSTODY_RETIREMENT_AUDITOR="+local.AuditorJournal,
				"OUTCOMEMESH_CUSTODY_RETIREMENT_ARTIFACTS="+local.AuditorArtifacts,
				"OUTCOMEMESH_CUSTODY_RETIREMENT_REPLICA="+local.ReplicaJournal,
				"OUTCOMEMESH_CUSTODY_RETIREMENT_MARKER="+marker)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waitForArchiveCrashMarker(t, marker, command)
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = command.Wait()
			a, aExists, err := loadCustodyRetirement(local.AuditorJournal)
			if err != nil {
				t.Fatal(err)
			}
			_, rExists, err := loadCustodyRetirement(local.ReplicaJournal)
			if err != nil {
				t.Fatal(err)
			}
			wantA := boundary == "auditor" || boundary == "replica-temp" || boundary == "replica"
			if aExists != wantA || rExists != (boundary == "replica") {
				t.Fatalf("bad killed state %t/%t", aExists, rExists)
			}
			for _, item := range []struct {
				path    string
				retired bool
			}{{local.AuditorJournal, aExists}, {local.ReplicaJournal, rExists}} {
				_, _, err := OpenOrCreateCustodyJournal(item.path, f.fixture.manifest, f.fixture.receipt, f.fixture.policy)
				if item.retired && !errors.Is(err, ErrCustodyJournalRetired) {
					t.Fatal("retirement lost on process restart", err)
				}
				if !item.retired && err != nil {
					t.Fatal("uncommitted intent altered journal", err)
				}
			}
			at := int64(30_002)
			if wantA {
				at = 50_000
			}
			pair, _, err := f.retire(context.Background(), local, proposal, rebaselineTestClock(at), custodyRetirementHooks{})
			if err != nil {
				t.Fatal("crash retry", err)
			}
			if wantA && pair.Auditor != a {
				t.Fatal("retry replaced first retirement")
			}
			if err := f.verifyRetirement(local, proposal, pair); err != nil {
				t.Fatal(err)
			}
			assertReconciliationBackupsUnchanged(t, f.fixture, f.aPath, f.a, f.rPath, f.r)
		})
	}
}

func TestCustodyRetirementCrashHelper(t *testing.T) {
	boundary := os.Getenv("OUTCOMEMESH_CUSTODY_RETIREMENT_CRASH")
	if boundary == "" {
		t.Skip("subprocess helper")
	}
	f := newCustodyRebaselineFixture(t)
	proposal, err := f.propose()
	if err != nil {
		t.Fatal(err)
	}
	local := CustodyLocalParticipants{os.Getenv("OUTCOMEMESH_CUSTODY_RETIREMENT_AUDITOR"),
		os.Getenv("OUTCOMEMESH_CUSTODY_RETIREMENT_ARTIFACTS"), os.Getenv("OUTCOMEMESH_CUSTODY_RETIREMENT_REPLICA")}
	hook := func() error {
		blockAtArchiveCrashMarker(os.Getenv("OUTCOMEMESH_CUSTODY_RETIREMENT_MARKER"))
		return nil
	}
	hooks := custodyRetirementHooks{}
	switch boundary {
	case "locked":
		hooks.afterLocks = hook
	case "before-commit":
		hooks.beforeCommit = hook
	case "auditor-temp", "replica-temp":
		hooks.afterTemporary = func(role string) error {
			if role+"-temp" == boundary {
				return hook()
			}
			return nil
		}
	case "auditor":
		hooks.afterAuditor = hook
	case "replica":
		hooks.afterReplica = hook
	default:
		t.Fatal("unknown crash boundary")
	}
	_, _, err = f.retire(context.Background(), local, proposal, rebaselineTestClock(30_001), hooks)
	t.Fatalf("crash hook returned: %v", err)
}
