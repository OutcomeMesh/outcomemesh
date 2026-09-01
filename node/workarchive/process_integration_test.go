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
	archiveCrashModeEnvironment        = "OUTCOMEMESH_ARCHIVE_CRASH_MODE"
	archiveCrashSourceEnvironment      = "OUTCOMEMESH_ARCHIVE_CRASH_SOURCE"
	archiveCrashDestinationEnvironment = "OUTCOMEMESH_ARCHIVE_CRASH_DESTINATION"
	archiveCrashMarkerEnvironment      = "OUTCOMEMESH_ARCHIVE_CRASH_MARKER"
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
