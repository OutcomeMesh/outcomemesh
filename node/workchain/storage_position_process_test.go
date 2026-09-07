//go:build integration

package workchain

import (
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockroachdb/pebble/v2"
)

func TestPositionStorageProcessCrashAtomicity(t *testing.T) {
	for _, kind := range []string{"block", "checkpoint", "fork-prune", "canonical-prune"} {
		expected := newPositionFixture(t, 5)
		if err := positionAction(t, expected, kind)(); err != nil {
			t.Fatal(err)
		}
		after := positionDatabaseSummary(t, expected.chain)
		_ = expected.chain.Close()
		stages := positionFaultStages()
		if kind == "canonical-prune" {
			stages = append(stages, "database-unsynced")
		}
		for _, stage := range stages {
			t.Run(kind+"/"+stage, func(t *testing.T) {
				f := newPositionFixture(t, 5)
				_ = positionAction(t, f, kind) // prepare side branch, but do not mutate target
				before := positionDatabaseSummary(t, f.chain)
				old, _ := f.chain.StorageProtection()
				if err := f.chain.Close(); err != nil {
					t.Fatal(err)
				}
				killPositionChild(t, f, kind, stage)
				var err error
				f.chain, err = OpenPositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID())
				if err != nil {
					t.Fatal(err)
				}
				intent, committed, confirmed := positionFaultOutcome(stage)
				actual := positionDatabaseSummary(t, f.chain)
				if stage == "database-unsynced" {
					committed = actual == after
				}
				want, sequence := before, old.Database.Sequence
				if committed {
					want = after
					sequence++
				}
				if actual != want {
					t.Fatal("process death left a partial logical batch")
				}
				requirePosition(t, f.chain, sequence, intent && !confirmed)
				if intent && !confirmed {
					if _, err := f.chain.Tip(); !errors.Is(err, ErrStoragePinPending) {
						t.Fatal("open automatically confirmed work", err)
					}
					err := f.chain.ResumeStorageConfirmation()
					if committed {
						if err != nil {
							t.Fatal(err)
						}
						requirePosition(t, f.chain, sequence, false)
					} else if !errors.Is(err, ErrStoragePinPending) {
						t.Fatal("missing mutation resolved", err)
					}
					if positionDatabaseSummary(t, f.chain) != want {
						t.Fatal("resume executed work")
					}
				}
			})
		}
	}
	for _, phase := range []string{"identity", "ready", "initialize"} {
		suffixes := []string{"before-temp", "temp-created", "before-file-sync", "file-synced", "linked", "directory-synced"}
		if phase == "initialize" {
			suffixes = []string{"before", "after"}
		}
		for _, suffix := range suffixes {
			stage := phase + "-" + suffix
			t.Run("initialize/"+stage, func(t *testing.T) {
				f := &positionFixture{parameters: testParameters(), policy: DefaultPolicy()}
				f.base = testBase(t, f.parameters)
				f.policy.CanonicalRetention, f.policy.ForkRetention, f.policy.CheckpointEvery = 1, 1, 1
				f.path, f.pins = filepath.Join(t.TempDir(), "chain"), filepath.Join(t.TempDir(), "pins")
				killPositionChild(t, f, "initialize", stage)
				s, err := OpenPositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID())
				if stage == "ready-linked" || stage == "ready-directory-synced" {
					if err != nil {
						t.Fatal(err)
					}
					defer s.Close()
					requirePosition(t, s, 0, false)
				} else if s != nil || err == nil {
					t.Fatal("incomplete creation reconstructed")
				}
			})
		}
	}
	stages := []string{"resume-before-flush", "resume-after-flush"}
	for _, stage := range positionFaultStages() {
		if strings.HasPrefix(stage, "confirmation-") {
			stages = append(stages, stage)
		}
	}
	for _, stage := range stages {
		t.Run("resume/"+stage, func(t *testing.T) {
			f := newPositionFixture(t, 5)
			f.chain.persistence.pins.hook = func(at string) error {
				if at == "database-after" {
					return errors.New("lost confirmation")
				}
				return nil
			}
			if err := positionAction(t, f, "canonical-prune")(); !errors.Is(err, ErrUncertain) {
				t.Fatal(err)
			}
			want := positionDatabaseSummary(t, f.chain)
			if err := f.chain.Close(); err != nil {
				t.Fatal(err)
			}
			killPositionChild(t, f, "resume", stage)
			var err error
			f.chain, err = OpenPositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID())
			if err != nil {
				t.Fatal(err)
			}
			confirmed := stage == "confirmation-linked" || stage == "confirmation-directory-synced"
			requirePosition(t, f.chain, 6, !confirmed)
			if err := f.chain.ResumeStorageConfirmation(); err != nil {
				t.Fatal(err)
			}
			requirePosition(t, f.chain, 6, false)
			if positionDatabaseSummary(t, f.chain) != want {
				t.Fatal("resume changed database")
			}
		})
	}
}

func killPositionChild(t *testing.T, f *positionFixture, kind, stage string) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "reached")
	boundary, _ := f.boundary.CanonicalBytes()
	command := exec.Command(os.Args[0], "-test.run=^TestPositionStorageCrashHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OUTCOMEMESH_POSITION_CHAIN_KIND="+kind, "OUTCOMEMESH_POSITION_CHAIN_STAGE="+stage,
		"OUTCOMEMESH_POSITION_CHAIN_PATH="+f.path, "OUTCOMEMESH_POSITION_CHAIN_PINS="+f.pins,
		"OUTCOMEMESH_POSITION_CHAIN_MARKER="+marker, "OUTCOMEMESH_POSITION_CHAIN_BOUNDARY="+hex.EncodeToString(boundary))
	killBoundStorageProcessWithCheck(t, command, marker, func() {
		// Pebble's native ownership must be tested from another process: some
		// OS file locks are reentrant within the same process.
		if second, err := openPositionLock(f.pins, false); second != nil || !errors.Is(err, ErrStoragePinBusy) {
			if second != nil {
				_ = second.Close()
			}
			t.Fatal("independent journal lock not held by child", err)
		}
		if _, err := os.Stat(f.path); err == nil {
			if second, err := pebble.Open(f.path, &pebble.Options{ErrorIfNotExists: true}); second != nil || err == nil {
				if second != nil {
					_ = second.Close()
				}
				t.Fatal("database lock not held by child")
			}
		}
	})
}

func TestPositionStorageCrashHelper(t *testing.T) {
	kind := os.Getenv("OUTCOMEMESH_POSITION_CHAIN_KIND")
	if kind == "" {
		t.Skip("subprocess helper")
	}
	f := &positionFixture{parameters: testParameters(), policy: DefaultPolicy()}
	f.base = testBase(t, f.parameters)
	f.policy.CanonicalRetention, f.policy.ForkRetention, f.policy.CheckpointEvery = 1, 1, 1
	f.path, f.pins = os.Getenv("OUTCOMEMESH_POSITION_CHAIN_PATH"), os.Getenv("OUTCOMEMESH_POSITION_CHAIN_PINS")
	stage, marker := os.Getenv("OUTCOMEMESH_POSITION_CHAIN_STAGE"), os.Getenv("OUTCOMEMESH_POSITION_CHAIN_MARKER")
	stop := func() { blockAtCrashMarker(marker) }
	hook := func(at string) error {
		if at == stage {
			stop()
		}
		return nil
	}
	if kind == "initialize" {
		_, err := createPositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID(), hook)
		t.Fatal("initializer returned", err)
	}
	var err error
	f.chain, err = OpenPositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
	defer f.chain.Close()
	// Both lifetime owners must remain held at every mutation/recovery boundary.
	if second, err := openPositionLock(f.pins, false); second != nil || !errors.Is(err, ErrStoragePinBusy) {
		t.Fatal("independent lock not held", err)
	}
	f.chain.persistence.pins.hook = hook
	if kind == "resume" {
		t.Fatal("resume returned before kill", f.chain.ResumeStorageConfirmation())
	}
	if encoded, err := hex.DecodeString(os.Getenv("OUTCOMEMESH_POSITION_CHAIN_BOUNDARY")); err == nil {
		f.boundary, err = DecodeCanonicalFloor(encoded)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatal(err)
	}
	if stage == "database-unsynced" {
		f.chain.persistence.pruneCommitHook = func(batch *pebble.Batch) error {
			if err := batch.Commit(pebble.NoSync); err != nil {
				return err
			}
			stop()
			return nil
		}
	}
	var action func() error
	if kind == "fork-prune" {
		action = func() error { _, err := f.chain.PruneStaleForks(); return err }
	} else {
		action = positionAction(t, f, kind)
	}
	t.Fatal("mutation returned before kill", action())
}
