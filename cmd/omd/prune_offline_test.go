package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPruneOfflineDispatchBoundary(t *testing.T) {
	if err := runPruneOffline(nil, []string{pruneSigningCommand}, io.Discard); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := runPruneOffline(t.Context(), []string{pruneSigningCommand}, nil); err == nil {
		t.Fatal("nil output accepted")
	}
	for _, args := range [][]string{nil, {"unknown"}, {pruneServeCommand}, {pruneAdmissionCommand}, {pruneCompletionCommand}} {
		if err := runPruneOffline(t.Context(), args, io.Discard); err == nil {
			t.Fatal("offline entry point accepted missing or network command", args)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, name := range []string{pruneAuthorityBootstrapCommand, pruneExecutorPrepareCommand, pruneSigningCommand, pruneCosigningCommand, pruneAdmissionPrepareCommand, pruneCompletionPrepareCommand} {
		if err := runPruneOffline(ctx, []string{name}, io.Discard); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled command inspected inputs", name, err)
		}
	}
}

func TestPruneOfflineSeedIsExplicitBoundedAndRegular(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "seed")
	if _, err := loadPruneOfflineKey(path); err == nil {
		t.Fatal("missing key accepted")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing key was generated")
	}
	for _, size := range []int{0, 31, 33, 64} {
		writePruneCLIFile(t, path, make([]byte, size))
		if _, err := loadPruneOfflineKey(path); err == nil {
			t.Fatal("non-seed length accepted", size)
		}
	}
	writePruneCLIFile(t, path, pruneCLIKey(4).Seed())
	key, err := loadPruneOfflineKey(path)
	if err != nil || !key.Equal(pruneCLIKey(4)) {
		t.Fatal("raw seed changed key", err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPruneOfflineKey(alias); err == nil {
		t.Fatal("final-path symlink accepted")
	}
}
