package workarchive

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Both trees have already passed bounded inventories, and their locks remain
// held. Only the fixed constructor-supplied overlay is permitted to differ.
// Unchanged subtrees are compared by complete path/byte digests, not inclusion.
func verifyCustodyApplicationDelta(source, target string, delta map[string][]byte) error {
	if encoded, replacesFile := delta[""]; replacesFile {
		if len(delta) != 1 {
			return ErrCustodyHistoricalApplication
		}
		actual, err := readRegularArchiveFile(target, len(encoded))
		if err != nil || !bytes.Equal(actual, encoded) {
			return errors.Join(ErrCustodyHistoricalApplication, err)
		}
		return nil
	}
	info, err := os.Lstat(source)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(delta) == 0 {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return custodyPinnedTreePreserved(source, target)
		}
		left, err := digestCustodyEvidenceTree(source, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
		if err != nil {
			return err
		}
		right, err := digestCustodyEvidenceTree(target, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
		if err != nil || left != right {
			return errors.Join(ErrCustodyHistoricalApplication, err)
		}
		return nil
	}
	if err == nil && !info.IsDir() {
		return ErrCustodyHistoricalApplication
	}
	if err := requireCustodyJournalDirectory(target); err != nil {
		return err
	}
	names := make(map[string]struct{})
	if info != nil {
		if err := visitCustodyApplicationNames(source, func(name string) error { names[name] = struct{}{}; return nil }); err != nil {
			return err
		}
	}
	children := make(map[string]map[string][]byte)
	for path, encoded := range delta {
		parts := strings.SplitN(path, string(filepath.Separator), 2)
		if parts[0] == "" || parts[0] == "." || parts[0] == ".." {
			return ErrCustodyHistoricalApplication
		}
		names[parts[0]] = struct{}{}
		if uint64(len(names)) > MaximumCustodyJournalPaths {
			return ErrCustodyHistoricalApplication
		}
		child := children[parts[0]]
		if child == nil {
			child = make(map[string][]byte)
			children[parts[0]] = child
		}
		suffix := ""
		if len(parts) == 2 {
			suffix = parts[1]
		}
		child[suffix] = encoded
	}
	if err := visitCustodyApplicationNames(target, func(name string) error {
		if _, exists := names[name]; !exists {
			return ErrCustodyHistoricalApplication
		}
		delete(names, name)
		return verifyCustodyApplicationDelta(filepath.Join(source, name), filepath.Join(target, name), children[name])
	}); err != nil {
		return err
	}
	if len(names) != 0 {
		return ErrCustodyHistoricalApplication
	}
	return nil
}

func visitCustodyApplicationNames(path string, visit func(string) error) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	var count uint64
	for {
		entries, err := directory.ReadDir(128)
		for _, entry := range entries {
			count++
			if count > MaximumCustodyJournalPaths || entry.Type()&os.ModeSymlink != 0 {
				return ErrCustodyHistoricalApplication
			}
			if err := visit(entry.Name()); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
