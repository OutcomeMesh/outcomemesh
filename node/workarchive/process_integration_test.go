//go:build integration

package workarchive

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

const (
	archiveCrashModeEnvironment          = "OUTCOMEMESH_ARCHIVE_CRASH_MODE"
	archiveCrashSourceEnvironment        = "OUTCOMEMESH_ARCHIVE_CRASH_SOURCE"
	archiveCrashDestinationEnvironment   = "OUTCOMEMESH_ARCHIVE_CRASH_DESTINATION"
	archiveCrashMarkerEnvironment        = "OUTCOMEMESH_ARCHIVE_CRASH_MARKER"
	custodyCrashModeEnvironment          = "OUTCOMEMESH_CUSTODY_CRASH_MODE"
	custodyCrashPathEnvironment          = "OUTCOMEMESH_CUSTODY_CRASH_PATH"
	custodyCrashMarkerEnvironment        = "OUTCOMEMESH_CUSTODY_CRASH_MARKER"
	custodyJournalCrashModeEnvironment   = "OUTCOMEMESH_CUSTODY_JOURNAL_CRASH_MODE"
	custodyJournalCrashPathEnvironment   = "OUTCOMEMESH_CUSTODY_JOURNAL_CRASH_PATH"
	custodyJournalCrashMarkerEnvironment = "OUTCOMEMESH_CUSTODY_JOURNAL_CRASH_MARKER"
)

func TestArchiveRestoreProcessCrashAtomicity(t *testing.T) {
	fixture := newArchiveFixture(t)
	for _, boundary := range []string{"before", "after"} {
		t.Run(boundary, func(t *testing.T) {
			parent := t.TempDir()
			destination := filepath.Join(parent, "restored")
			marker := filepath.Join(t.TempDir(), "reached")
			command := exec.Command(
				os.Args[0], "-test.run=^TestArchiveRestoreCrashHelper$", "-test.count=1",
			)
			command.Env = append(os.Environ(),
				archiveCrashModeEnvironment+"="+boundary,
				archiveCrashSourceEnvironment+"="+fixture.archivePath,
				archiveCrashDestinationEnvironment+"="+destination,
				archiveCrashMarkerEnvironment+"="+marker,
			)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waitForArchiveCrashMarker(t, marker, command)
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = command.Wait()

			if boundary == "before" {
				if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("pre-rename crash destination error=%v", err)
				}
				if _, err := RestoreDirectory(
					fixture.archivePath, destination, fixture.checkpoint, fixture.policy,
					fixture.base, fixture.parameters, DefaultLimits(), workchain.DefaultPolicy(),
				); err != nil {
					t.Fatalf("restore retry after pre-rename crash: %v", err)
				}
			} else if _, err := os.Stat(destination); err != nil {
				t.Fatalf("post-rename crash destination: %v", err)
			}
			verifyCrashRestoredChain(t, destination, fixture)
		})
	}
}

func TestCustodyRecordProcessCrashAtomicity(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	for _, boundary := range []string{"before", "after"} {
		t.Run(boundary, func(t *testing.T) {
			recordPath := filepath.Join(t.TempDir(), "custody.omcr")
			marker := filepath.Join(t.TempDir(), "reached")
			command := exec.Command(
				os.Args[0], "-test.run=^TestCustodyRecordCrashHelper$", "-test.count=1",
			)
			command.Env = append(os.Environ(),
				custodyCrashModeEnvironment+"="+boundary,
				custodyCrashPathEnvironment+"="+recordPath,
				custodyCrashMarkerEnvironment+"="+marker,
			)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waitForArchiveCrashMarker(t, marker, command)
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = command.Wait()

			if boundary == "before" {
				if _, err := os.Stat(recordPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("pre-link custody record error=%v", err)
				}
				if _, created, err := PublishCustodyRecordFile(
					recordPath, fixture.record, fixture.manifest,
					fixture.receipt, fixture.policy,
				); err != nil || !created {
					t.Fatalf("custody retry created=%t error=%v", created, err)
				}
			}
			loaded, err := LoadCustodyRecordFile(
				recordPath, fixture.manifest, fixture.receipt, fixture.policy,
			)
			if err != nil {
				t.Fatal(err)
			}
			loadedBytes, _ := loaded.CanonicalBytes()
			expectedBytes, _ := fixture.record.CanonicalBytes()
			if !bytes.Equal(loadedBytes, expectedBytes) {
				t.Fatal("crash-recovered custody record differs from signed response")
			}
		})
	}
}

func TestCustodyJournalProcessCrashAtomicity(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	for _, boundary := range []string{"body", "slot", "seal"} {
		t.Run(boundary, func(t *testing.T) {
			journalPath := filepath.Join(t.TempDir(), "custody-journal")
			marker := filepath.Join(t.TempDir(), "reached")
			command := exec.Command(
				os.Args[0], "-test.run=^TestCustodyJournalCrashHelper$", "-test.count=1",
			)
			command.Env = append(os.Environ(),
				custodyJournalCrashModeEnvironment+"="+boundary,
				custodyJournalCrashPathEnvironment+"="+journalPath,
				custodyJournalCrashMarkerEnvironment+"="+marker,
			)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waitForArchiveCrashMarker(t, marker, command)
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = command.Wait()

			journal, state, err := OpenOrCreateCustodyJournal(
				journalPath, fixture.manifest, fixture.receipt, fixture.policy,
			)
			if err != nil {
				t.Fatal(err)
			}
			wantSequence := uint64(0)
			if boundary != "body" {
				wantSequence = 1
			}
			if state.Sequence != wantSequence {
				t.Fatalf("post-%s crash sequence=%d want=%d", boundary, state.Sequence, wantSequence)
			}
			entry, created, err := journal.Append(fixture.record)
			if err != nil || entry.Sequence != 1 || created != (boundary == "body") {
				t.Fatalf("post-%s append entry=%+v created=%t error=%v", boundary, entry, created, err)
			}
			if state, err := journal.State(); err != nil || state.Sequence != 1 ||
				state.CurrentReceipt != fixture.record.RenewedReceipt {
				t.Fatalf("post-%s recovered state=%+v error=%v", boundary, state, err)
			}
		})
	}
}

func TestArchiveRestoreCrashHelper(t *testing.T) {
	mode := os.Getenv(archiveCrashModeEnvironment)
	if mode == "" {
		t.Skip("subprocess helper")
	}
	archivePath := os.Getenv(archiveCrashSourceEnvironment)
	destination := os.Getenv(archiveCrashDestinationEnvironment)
	marker := os.Getenv(archiveCrashMarkerEnvironment)
	manifestBytes, err := readRegularArchiveFile(
		filepath.Join(archivePath, manifestFileName), MaximumManifestBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := DecodeManifest(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, policy := processArchiveCheckpoint(t, manifest)
	hooks := restoreHooks{}
	switch mode {
	case "before":
		hooks.beforePublish = func() error {
			blockAtArchiveCrashMarker(marker)
			return ErrArchivePublish
		}
	case "after":
		hooks.afterPublish = func() { blockAtArchiveCrashMarker(marker) }
	default:
		t.Fatalf("unknown archive crash mode %q", mode)
	}
	_, err = restoreDirectory(
		archivePath, destination, checkpoint, policy, archiveTestBase(),
		archiveTestParameters(), DefaultLimits(), workchain.DefaultPolicy(), hooks,
	)
	t.Fatalf("archive crash hook returned: %v", err)
}

func TestCustodyRecordCrashHelper(t *testing.T) {
	mode := os.Getenv(custodyCrashModeEnvironment)
	if mode == "" {
		t.Skip("subprocess helper")
	}
	recordPath := os.Getenv(custodyCrashPathEnvironment)
	marker := os.Getenv(custodyCrashMarkerEnvironment)
	fixture := newCustodyRecordFixture(t)
	hooks := custodyRecordHooks{}
	switch mode {
	case "before":
		hooks.beforePublish = func() { blockAtArchiveCrashMarker(marker) }
	case "after":
		hooks.afterPublish = func() { blockAtArchiveCrashMarker(marker) }
	default:
		t.Fatalf("unknown custody crash mode %q", mode)
	}
	_, _, err := publishCustodyRecordFile(
		recordPath, fixture.record, fixture.manifest, fixture.receipt,
		fixture.policy, hooks,
	)
	t.Fatalf("custody crash hook returned: %v", err)
}

func TestCustodyJournalCrashHelper(t *testing.T) {
	mode := os.Getenv(custodyJournalCrashModeEnvironment)
	if mode == "" {
		t.Skip("subprocess helper")
	}
	journalPath := os.Getenv(custodyJournalCrashPathEnvironment)
	marker := os.Getenv(custodyJournalCrashMarkerEnvironment)
	fixture := newCustodyRecordFixture(t)
	journal, _, err := OpenOrCreateCustodyJournal(
		journalPath, fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	hooks := custodyJournalHooks{}
	switch mode {
	case "body":
		hooks.afterBody = func() { blockAtArchiveCrashMarker(marker) }
		_, _, err = journal.append(fixture.record, hooks)
	case "slot":
		hooks.afterSlot = func() { blockAtArchiveCrashMarker(marker) }
		_, _, err = journal.append(fixture.record, hooks)
	case "seal":
		if _, _, err = journal.Append(fixture.record); err == nil {
			hooks.afterSeal = func() { blockAtArchiveCrashMarker(marker) }
			_, err = journal.rotate(hooks)
		}
	default:
		t.Fatalf("unknown custody journal crash mode %q", mode)
	}
	t.Fatalf("custody journal crash hook returned: %v", err)
}

func processArchiveCheckpoint(t testing.TB, manifest Manifest) (Checkpoint, Policy) {
	t.Helper()
	statement, err := manifest.ArchiveStatement(1, types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	keys := []ed25519.PrivateKey{
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{51}, ed25519.SeedSize)),
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{52}, ed25519.SeedSize)),
	}
	checkpoint := signedCheckpoint(t, statement, keys)
	return checkpoint, Policy{
		Binding: manifest.Binding, TrustedAttestors: sortedPublicKeys(keys),
		RequiredAttestations: 2,
	}
}

func verifyCrashRestoredChain(t testing.TB, path string, fixture archiveFixture) {
	t.Helper()
	chain, err := workchain.Open(path, fixture.base, fixture.parameters)
	if err != nil {
		t.Fatal(err)
	}
	tip, err := chain.Tip()
	if err != nil || !storage.EqualTips(tip, fixture.manifest.Anchor) {
		_ = chain.Close()
		t.Fatalf("crash-restored tip=%+v want=%+v err=%v", tip, fixture.manifest.Anchor, err)
	}
	extension, _ := mineArchiveChild(
		t, chain, tip.ID, tip.Timestamp+fixture.parameters.TargetSpacing, "crash-restored-extension",
	)
	if _, _, err := chain.Commit(extension, extension.Header.Seal.Timestamp); err != nil {
		_ = chain.Close()
		t.Fatalf("crash-restored extension: %v", err)
	}
	if err := chain.Close(); err != nil {
		t.Fatal(err)
	}
}

func blockAtArchiveCrashMarker(path string) {
	if err := os.WriteFile(path, []byte("ready"), 0o600); err != nil {
		panic(err)
	}
	select {}
}

func waitForArchiveCrashMarker(t testing.TB, path string, command *exec.Cmd) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if command.ProcessState != nil && command.ProcessState.Exited() {
			t.Fatal("archive crash helper exited before durability boundary")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = command.Process.Kill()
	_ = command.Wait()
	t.Fatal("archive crash helper did not reach durability boundary")
}
