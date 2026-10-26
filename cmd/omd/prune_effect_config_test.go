package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func pruneEffectRootDescriptor() []byte {
	id := pruneCLIHash(1).String()
	return []byte(`{"authorities":[{"assignment_id":"` + id + `","authority":"original authority","authority_pins":"original pins"}],"replicas":[{"assignment_id":"` + id + `","directory":"replica archive"}]}`)
}

func TestPruneEffectRootsStrictDecoder(t *testing.T) {
	good := pruneEffectRootDescriptor()
	authorities, replicas, err := decodePruneEffectRoots(good)
	if err != nil || len(authorities) != 1 || len(replicas) != 1 || authorities[0].AssignmentID != pruneCLIHash(1) ||
		authorities[0].AuthorityPath != "original authority" || authorities[0].AuthorityPinsPath != "original pins" || replicas[0].Directory != "replica archive" {
		t.Fatal("valid descriptor changed", err)
	}
	for name, encoded := range map[string][]byte{
		"null":              []byte("null"),
		"array":             []byte("[]"),
		"empty":             []byte("{}"),
		"missing-list":      []byte(`{"authorities":[]}`),
		"empty-lists":       []byte(`{"authorities":[],"replicas":[]}`),
		"null-list":         bytes.Replace(good, []byte(`"replicas":[`), []byte(`"replicas":null,"ignored":[`), 1),
		"wrong-root-case":   bytes.Replace(good, []byte(`"authorities":`), []byte(`"Authorities":`), 1),
		"unknown-root":      bytes.Replace(good, []byte(`"authorities":`), []byte(`"unknown":0,"authorities":`), 1),
		"duplicate-list":    append([]byte(`{"authorities":[],`), good[1:]...),
		"unknown-field":     bytes.Replace(good, []byte(`"authority":`), []byte(`"extra":"x","authority":`), 1),
		"wrong-case":        bytes.Replace(good, []byte(`"authority":`), []byte(`"Authority":`), 1),
		"duplicate-key":     bytes.Replace(good, []byte(`"authority":`), []byte(`"authority":"wrong","authority":`), 1),
		"escaped-duplicate": bytes.Replace(good, []byte(`"authority":`), []byte(`"authorit\u0079":"wrong","authority":`), 1),
		"null-path":         bytes.Replace(good, []byte(`"original authority"`), []byte(`null`), 1),
		"object-path":       bytes.Replace(good, []byte(`"original authority"`), []byte(`{}`), 1),
		"number-path":       bytes.Replace(good, []byte(`"original authority"`), []byte(`12`), 1),
		"boolean-path":      bytes.Replace(good, []byte(`"original authority"`), []byte(`true`), 1),
		"empty-path":        bytes.Replace(good, []byte(`"original authority"`), []byte(`""`), 1),
		"nul-path":          bytes.Replace(good, []byte(`"original authority"`), []byte(`"bad\u0000path"`), 1),
		"invalid-utf8":      bytes.Replace(good, []byte("original authority"), []byte{0xff}, 1),
		"wrong-id":          bytes.Replace(good, []byte(pruneCLIHash(1).String()), []byte("x"), 1),
		"uppercase-id":      bytes.Replace(good, []byte(pruneCLIHash(1).String()), []byte(strings.ToUpper(pruneCLIHash(1).String())), 1),
		"zero-id":           bytes.Replace(good, []byte(pruneCLIHash(1).String()), []byte((types.Hash{}).String()), 1),
		"trailing":          append(bytes.Clone(good), []byte(" {}")...),
		"oversized":         bytes.Repeat([]byte(" "), maximumPruneEffectRootsBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if a, r, err := decodePruneEffectRoots(encoded); err == nil || a != nil || r != nil {
				t.Fatal("malformed metadata returned usable roots", err)
			}
		})
	}
	for _, array := range []string{"authorities", "replicas"} {
		var shape map[string][]map[string]string
		if err := json.Unmarshal(good, &shape); err != nil {
			t.Fatal(err)
		}
		fields := []string{"assignment_id", "directory"}
		if array == "authorities" {
			fields = []string{"assignment_id", "authority", "authority_pins"}
		}
		for _, field := range fields {
			var changed map[string][]map[string]string
			_ = json.Unmarshal(good, &changed)
			delete(changed[array][0], field)
			encoded, _ := json.Marshal(changed)
			if _, _, err := decodePruneEffectRoots(encoded); err == nil {
				t.Fatal("missing field accepted", array, field)
			}
		}
		shape[array] = append(shape[array], shape[array][0])
		encoded, _ := json.Marshal(shape)
		if _, _, err := decodePruneEffectRoots(encoded); err == nil {
			t.Fatal("duplicate assignment accepted", array)
		}
	}
	for _, count := range []int{workarchive.MaximumReplicas, workarchive.MaximumReplicas + 1} {
		var shape struct {
			Authorities []map[string]string `json:"authorities"`
			Replicas    []map[string]string `json:"replicas"`
		}
		for i := range count {
			id := pruneCLIHash(byte(i + 1)).String()
			shape.Authorities = append(shape.Authorities, map[string]string{"assignment_id": id, "authority": "a", "authority_pins": "p"})
			shape.Replicas = append(shape.Replicas, map[string]string{"assignment_id": id, "directory": "r"})
		}
		encoded, _ := json.Marshal(shape)
		_, _, err := decodePruneEffectRoots(encoded)
		if (err == nil) != (count == workarchive.MaximumReplicas) {
			t.Fatal("assignment count boundary changed", count, err)
		}
	}
}

func FuzzDecodePruneEffectRootsNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{pruneEffectRootDescriptor(), []byte("null"), []byte(`{"authorities":[],"replicas":[]}`), {0xff}, {}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		authorities, replicas, err := decodePruneEffectRoots(encoded)
		if err != nil {
			if authorities != nil || replicas != nil {
				t.Fatal("invalid metadata leaked usable roots")
			}
			return
		}
		if len(authorities) == 0 || len(authorities) != len(replicas) || len(authorities) > workarchive.MaximumReplicas {
			t.Fatal("accepted metadata escaped count bounds")
		}
	})
}

func replacePruneEffectConfigArg(arguments []string, name, value string) []string {
	copy := append([]string(nil), arguments...)
	for i := 1; i+1 < len(copy); i += 2 {
		if copy[i] == name {
			copy[i+1] = value
			return copy
		}
	}
	return append(copy, name, value)
}

func TestPruneEffectConfigLoadsRealActivationWithoutMutation(t *testing.T) {
	for _, lineage := range []bool{false, true} {
		t.Run(strconv.FormatBool(lineage), func(t *testing.T) {
			fixture := newPruneEffectCLIFixture(t, lineage)
			before, sourceBefore := fixture.snapshot(t), prunePrepareTree(t, fixture.data)
			options, err := loadPruneArchiveEffectOptions(t.Context(), fixture.args(""))
			if err != nil {
				t.Fatal(err)
			}
			if options.mode != "review" || options.config.InventoryID != fixture.config.InventoryID || options.config.PolicyID != fixture.config.PolicyID ||
				options.config.Base.State.Root() != fixture.config.Base.State.Root() || !reflect.DeepEqual(options.config.Base.Tip, fixture.config.Base.Tip) ||
				!reflect.DeepEqual(options.config.Base.RecentTimestamps, fixture.config.Base.RecentTimestamps) || options.config.Parameters != fixture.config.Parameters ||
				options.config.StoragePolicy != fixture.config.StoragePolicy || options.config.Limits != fixture.config.Limits {
				t.Fatal("loader changed activation/configuration or defaulted to an effect", err)
			}
			if lineage && options.config.LineageID != fixture.config.LineageID {
				t.Fatal("loader lost external lineage pin")
			}
			if !reflect.DeepEqual(before, fixture.snapshot(t)) || !reflect.DeepEqual(sourceBefore, prunePrepareTree(t, fixture.data)) {
				t.Fatal("read-only activation loading mutated source or effect owners")
			}
			withoutHistory := []string{pruneArchiveEffectCommand}
			fixtureArgs := fixture.args("")
			for i := 1; i+1 < len(fixtureArgs); i += 2 {
				if fixtureArgs[i] != "--max-history-bytes" {
					withoutHistory = append(withoutHistory, fixtureArgs[i:i+2]...)
				}
			}
			defaultPolicy, err := loadPruneArchiveEffectOptions(t.Context(), withoutHistory)
			if err != nil || defaultPolicy.config.StoragePolicy.MaxHistoryBytes != minimumHistoryBytes {
				t.Fatal("default history budget did not come from the source activation policy", err)
			}
			// Root descriptor paths are anchored to its own canonical parent,
			// independently of the current process working directory.
			var shape map[string][]map[string]string
			encoded, err := os.ReadFile(fixture.rootsPath)
			if err != nil || json.Unmarshal(encoded, &shape) != nil {
				t.Fatal("read fixture metadata", err)
			}
			for name, entries := range shape {
				for _, entry := range entries {
					for key, path := range entry {
						if key != "assignment_id" {
							entry[key], err = filepath.Rel(filepath.Dir(fixture.rootsPath), path)
							if err != nil {
								t.Fatal(err)
							}
						}
					}
				}
				shape[name] = entries
			}
			encoded, _ = json.Marshal(shape)
			writePruneCLIFile(t, fixture.rootsPath, encoded)
			relative, err := loadPruneArchiveEffectOptions(t.Context(), fixture.args("control"))
			if err != nil || relative.mode != "control" || !reflect.DeepEqual(relative.config.Authorities, options.config.Authorities) ||
				!reflect.DeepEqual(relative.config.Replicas, options.config.Replicas) {
				t.Fatal("relative source paths changed owner/replica binding", err)
			}
		})
	}
}

func TestPruneEffectConfigRejectsBeforeAnyEffect(t *testing.T) {
	fixture := newPruneEffectCLIFixture(t, false)
	before, sourceBefore := fixture.snapshot(t), prunePrepareTree(t, fixture.data)
	base := fixture.args("")
	for name, arguments := range map[string][]string{
		"nil-args":      nil,
		"wrong-command": {"other"},
		"execute-mode":  replacePruneEffectConfigArg(base, "--mode", "execute"),
		"data-missing":  replacePruneEffectConfigArg(base, "--data", filepath.Join(fixture.root, "missing")),
		"data-empty":    replacePruneEffectConfigArg(base, "--data", ""),
		"roots-missing": replacePruneEffectConfigArg(base, "--roots", filepath.Join(fixture.root, "missing.json")),
		"inventory-pin": replacePruneEffectConfigArg(base, "--inventory-id", pruneCLIHash(99).String()),
		"policy-pin":    replacePruneEffectConfigArg(base, "--policy-id", pruneCLIHash(99).String()),
		"history-zero":  replacePruneEffectConfigArg(base, "--max-history-bytes", "0"),
		"no-retention":  replacePruneEffectConfigArg(base, "--canonical-retention", "0"),
		"keep-overflow": replacePruneEffectConfigArg(base, "--checkpoint-keep", "4294967296"),
		"chunks-wide":   replacePruneEffectConfigArg(base, "--max-archive-chunks", "4294967296"),
		"blocks-zero":   replacePruneEffectConfigArg(base, "--max-archive-blocks", "0"),
		"lineage-empty": append(append([]string(nil), base...), "--lineage-evidence", ""),
		"lineage-pin":   append(append([]string(nil), base...), "--lineage-evidence-id", ""),
		"duplicate-pin": append(append([]string(nil), base...), "--inventory-id", fixture.config.InventoryID.String()),
		"positional":    append(append([]string(nil), base...), "ignored"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadPruneArchiveEffectOptions(t.Context(), arguments); err == nil {
				t.Fatal("invalid scope accepted")
			}
		})
	}
	if _, err := loadPruneArchiveEffectOptions(nil, base); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := loadPruneArchiveEffectOptions(ctx, base); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled context advanced loading", err)
	}
	// This valid existing source path would otherwise be opened as the base
	// ledger. The overlap must be rejected before any database open attempt.
	arguments := replacePruneEffectConfigArg(base, "--chain", filepath.Join(fixture.data, ledgerDirectory))
	if _, err := loadPruneArchiveEffectOptions(t.Context(), arguments); err == nil || !strings.Contains(err.Error(), "activation source") {
		t.Fatal("overlapping source reached database opening", err)
	}
	// A source with genesis/profile but no database cannot bootstrap a ledger.
	source := filepath.Join(fixture.root, "incomplete-source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{genesisFilename, workActivationFilename} {
		encoded, err := os.ReadFile(filepath.Join(fixture.data, name))
		if err != nil {
			t.Fatal(err)
		}
		writePruneCLIFile(t, filepath.Join(source, name), encoded)
	}
	incompleteBefore := prunePrepareTree(t, source)
	if _, err := loadPruneArchiveEffectOptions(t.Context(), replacePruneEffectConfigArg(base, "--data", source)); err == nil {
		t.Fatal("missing source database bootstrapped")
	}
	if !reflect.DeepEqual(incompleteBefore, prunePrepareTree(t, source)) {
		t.Fatal("failed read-only load created source data")
	}
	if !reflect.DeepEqual(before, fixture.snapshot(t)) || !reflect.DeepEqual(sourceBefore, prunePrepareTree(t, fixture.data)) {
		t.Fatal("invalid input changed source or protected effect state")
	}
}
