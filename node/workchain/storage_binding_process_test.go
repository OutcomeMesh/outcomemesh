//go:build integration

package workchain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/v2"
)

func TestBoundStorageProcessCrashAtomicity(t *testing.T) {
	for _, stage := range []string{"initialize-before", "initialize-after", "effect-before", "effect-decision", "effect-after", "effect-unsynced"} {
		t.Run(stage, func(t *testing.T) {
			parameters := testParameters()
			base := testBase(t, parameters)
			policy := DefaultPolicy()
			policy.CanonicalRetention = 1
			path := filepath.Join(t.TempDir(), "chain")
			var boundary CanonicalFloor
			var before, after processCrashSummary
			var want CanonicalPruneEffect
			initializing := strings.HasPrefix(stage, "initialize-")
			if !initializing {
				s, actualPath, _, _, _, b := canonicalAuthorizationFixtureWithStorageID(t, testStorageID())
				path, boundary = actualPath, b
				before = crashStoreSummary(t, s)
				_ = s.Close()
				expected, _, _, _, _, _ := canonicalAuthorizationFixtureWithStorageID(t, testStorageID())
				op := pruneOperation(boundary, "bound-process")
				op.StorageID = testStorageID()
				commit, err := expected.PruneCanonicalPrefixOnce(op, func() (uint64, error) { return 200, nil })
				if err != nil {
					t.Fatal(err)
				}
				want, after = commit.Effect, crashStoreSummary(t, expected)
				_ = expected.Close()
			}
			marker := filepath.Join(t.TempDir(), "reached")
			encoded, _ := boundary.CanonicalBytes()
			command := exec.Command(os.Args[0], "-test.run=^TestBoundStorageCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(), "OUTCOMEMESH_BOUND_CHAIN_STAGE="+stage,
				"OUTCOMEMESH_BOUND_CHAIN_PATH="+path, "OUTCOMEMESH_BOUND_CHAIN_MARKER="+marker,
				"OUTCOMEMESH_BOUND_CHAIN_BOUNDARY="+hex.EncodeToString(encoded))
			killBoundStorageProcess(t, command, marker)
			opened, err := OpenBoundWithPolicy(path, base, parameters, policy, testStorageID())
			if stage == "initialize-before" {
				if opened != nil || err == nil {
					t.Fatal("incomplete initializer bootstrapped on reopen")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			if err := opened.VerifyStorageID(testStorageID()); err != nil {
				t.Fatal(err)
			}
			if initializing {
				if got, err := opened.Tip(); err != nil || got.ID != base.Tip.ID {
					t.Fatal("initializer changed chain state", err)
				}
				return
			}
			actual := crashStoreSummary(t, opened)
			committed := stage == "effect-after" || (stage == "effect-unsynced" && equalCrashSummary(actual, after))
			expected := before
			if committed {
				expected = after
			}
			if !equalCrashSummary(actual, expected) {
				t.Fatal("partial bound prune survived process death")
			}
			got, found, err := opened.CanonicalPruneEffect(want.Operation.TicketID)
			if err != nil || found != committed || (found && !equalPruneEffect(got, want)) {
				t.Fatal("effect/identity/floor lost atomicity", found, err)
			}
			// Absence remains an unknown executor outcome, not a retry directive.
		})
	}
}

func killBoundStorageProcess(t *testing.T, command *exec.Cmd, marker string) {
	t.Helper()
	killBoundStorageProcessWithCheck(t, command, marker, nil)
}

func killBoundStorageProcessWithCheck(t *testing.T, command *exec.Cmd, marker string, check func()) {
	t.Helper()
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var exitErr error
	go func() { exitErr = command.Wait(); close(done) }()
	t.Cleanup(func() { _ = command.Process.Kill(); <-done })
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			t.Fatalf("bound helper exited before boundary: %v\n%s", exitErr, output.String())
		case <-timer.C:
			_ = command.Process.Kill()
			<-done
			t.Fatalf("bound helper missed boundary\n%s", output.String())
		case <-ticker.C:
			if _, err := os.Stat(marker); err == nil {
				if check != nil {
					check()
				}
				if err := command.Process.Kill(); err != nil {
					_ = command.Process.Kill()
					<-done
					t.Fatal(err)
				}
				<-done
				if exitErr == nil {
					t.Fatal("helper was not killed")
				}
				return
			}
		}
	}
}

func TestBoundStorageCrashHelper(t *testing.T) {
	stage := os.Getenv("OUTCOMEMESH_BOUND_CHAIN_STAGE")
	if stage == "" {
		t.Skip("subprocess helper")
	}
	path, marker := os.Getenv("OUTCOMEMESH_BOUND_CHAIN_PATH"), os.Getenv("OUTCOMEMESH_BOUND_CHAIN_MARKER")
	p := testParameters()
	b := testBase(t, p)
	policy := DefaultPolicy()
	policy.CanonicalRetention = 1
	stop := func() { blockAtCrashMarker(marker) }
	if strings.HasPrefix(stage, "initialize-") {
		_, err := createBoundWithPolicy(path, b, p, policy, testStorageID(), func(batch *pebble.Batch) error {
			if stage == "initialize-after" {
				if err := batch.Commit(pebble.Sync); err != nil {
					return err
				}
			}
			stop()
			return errors.New("unreachable initializer")
		})
		t.Fatal("initializer returned", err)
	}
	s, err := OpenBoundWithPolicy(path, b, p, policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	encoded, err := hex.DecodeString(os.Getenv("OUTCOMEMESH_BOUND_CHAIN_BOUNDARY"))
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := DecodeCanonicalFloor(encoded)
	if err != nil {
		t.Fatal(err)
	}
	switch stage {
	case "effect-before":
		s.persistence.commitHook = func() error { stop(); return nil }
	case "effect-after":
		s.persistence.afterCommitHook = stop
	case "effect-unsynced":
		s.persistence.pruneCommitHook = func(batch *pebble.Batch) error {
			if err := batch.Commit(pebble.NoSync); err != nil {
				return err
			}
			stop()
			return nil
		}
	}
	op := pruneOperation(boundary, "bound-process")
	op.StorageID = testStorageID()
	_, err = s.PruneCanonicalPrefixOnce(op, func() (uint64, error) {
		if stage == "effect-decision" {
			stop()
		}
		return 200, nil
	})
	t.Fatal("bound effect returned before kill", err)
}
