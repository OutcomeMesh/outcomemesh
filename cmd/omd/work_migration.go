package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/storage"
	pebblestore "github.com/outcomemesh/outcomemesh/storage/pebble"
)

const maximumMigrationBytes uint64 = 64 << 20
const maximumMigrationBlocks = 4096
const maximumMigrationResourceVersions = 1_000_000

type radixMigrationReview struct {
	Source, Destination                                string
	GenesisID, OldProfileID, NewProfileID, InventoryID types.Hash
	SourceTip                                          storage.Tip
	RadixActivationHeight, MaximumRetainedHeight       uint64
	BlockCount                                         int
	LedgerHistoryBudget                                uint64
	// Preview changes only the representation of the current tip's resources.
	PreviewRadixRoot types.Hash
}

func runWorkMigrateRadix(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return workMigrateRadix(ctx, args, os.Stdout, nil)
}

// hook is an in-process fault boundary, never an operator bypass.
func workMigrateRadix(ctx context.Context, args []string, out io.Writer, hook func(string) error) (retErr error) {
	f := flag.NewFlagSet("work-migrate-radix", flag.ContinueOnError)
	source := f.String("source", "", "stopped original WorkGraph node directory")
	destination := f.String("out", "", "fresh destination directory")
	height := f.Uint64("radix-height", 0, "future first v3 block, above every retained fork")
	mode := f.String("mode", "review", "review or run")
	expected := f.String("expected-review-id", "", "exact review ID; run only")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || ctx == nil || out == nil || (*mode != "review" && *mode != "run") || *height == 0 {
		return errors.New("source, out, radix-height and mode review or run are required")
	}
	src, dst, e := migrationPaths(*source, *destination)
	if e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if _, e = os.Lstat(filepath.Join(src, workActivationPending)); !errors.Is(e, os.ErrNotExist) {
		return errors.New("source has an incomplete activation; retain it and resolve the original attempt")
	}
	doc, e := loadGenesis(src)
	if e != nil {
		return e
	}
	profile, e := loadWorkActivation(src, doc)
	if e != nil {
		return e
	}
	if profile.RadixActivationHeight != 0 {
		return errors.New("source already pins a radix schedule; it cannot be rescheduled")
	}
	policy, e := migrationLedgerPolicy(src)
	if e != nil {
		return e
	}
	sourceStore, e := pebblestore.OpenExistingReadOnly(filepath.Join(src, ledgerDirectory), doc, policy)
	if e != nil {
		return e
	}
	defer func() { retErr = errors.Join(retErr, sourceStore.Close()) }()
	sourceRouter, e := openWorkRouterMode(sourceStore, doc, profile, src, nil, true)
	if e != nil {
		return e
	}
	defer func() { retErr = errors.Join(retErr, sourceRouter.Close()) }()
	tip, e := sourceRouter.Tip()
	if e != nil {
		return e
	}
	legacy, e := sourceStore.MigrationBlocks(maximumMigrationBytes)
	if e != nil {
		return e
	}
	var size uint64
	for _, b := range legacy {
		size += uint64(len(b.CanonicalBytes()))
	}
	work, e := sourceRouter.MigrationWorkBlocks(maximumMigrationBytes - size)
	if e != nil {
		return e
	}
	if len(legacy)+len(work) > maximumMigrationBlocks {
		return errors.New("migration block ceiling exceeded")
	}
	blocks := make([]activation.Block, 0, len(legacy)+len(work))
	maxHeight := uint64(0)
	resources := uint64(len(doc.Allocations))
	for _, b := range legacy {
		v, e := activation.Legacy(b, profile.ActivationHeight)
		if e != nil {
			return e
		}
		blocks = append(blocks, v)
		resources++
		for _, tx := range b.Transactions {
			resources += uint64(len(tx.Outputs))
		}
	}
	for _, v := range work {
		blocks = append(blocks, v)
		b, _ := v.WorkBlock()
		resources += uint64(len(b.Shares) + 1)
		for _, tx := range b.Transactions {
			resources += uint64(len(tx.Outputs))
		}
	}
	if resources > maximumMigrationResourceVersions/uint64(max(1, len(blocks))) {
		return errors.New("migration resource-work ceiling exceeded")
	}
	inventory := types.DomainHash("OMESH/workgraph/migration/inventory/v1")
	for _, b := range blocks {
		if b.Height() > maxHeight {
			maxHeight = b.Height()
		}
		raw := b.CanonicalBytes()
		inventory = types.DomainHash("OMESH/workgraph/migration/block/v1", inventory[:], raw)
	}
	if *height <= maxHeight || *height < profile.ActivationHeight {
		return errors.New("radix-height must be above every retained block and at or after WorkGraph activation")
	}
	next := profile
	next.RadixActivationHeight = *height
	if e = validateWorkActivation(next, doc); e != nil {
		return e
	}
	current, e := sourceRouter.Snapshot()
	if e != nil {
		return e
	}
	preview, e := state.NewVersion(current.Resources(), state.CommitmentRadixV1)
	if e != nil {
		return e
	}
	gid, _ := doc.ID()
	review := radixMigrationReview{
		Source: src, Destination: dst, GenesisID: gid,
		OldProfileID: types.DomainHash("OMESH/workgraph/migration/profile/v1", profile.canonicalBytes()),
		NewProfileID: types.DomainHash("OMESH/workgraph/migration/profile/v1", next.canonicalBytes()),
		InventoryID:  inventory, SourceTip: tip,
		RadixActivationHeight: *height, MaximumRetainedHeight: maxHeight,
		BlockCount: len(blocks), LedgerHistoryBudget: policy.MaxHistoryBytes,
		PreviewRadixRoot: preview.Root(),
	}
	raw, e := json.Marshal(review)
	if e != nil {
		return e
	}
	reviewID := types.DomainHash("OMESH/workgraph/migration/review/v1", raw)
	if _, e = fmt.Fprintf(out, "%s\nreview_id=%s\n", raw, reviewID); e != nil {
		return e
	}
	if *mode == "review" {
		return nil
	}
	pin, e := parseHash(*expected)
	if e != nil || pin != reviewID {
		return errors.New("migration requires the exact current review ID")
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	// Reserve the final path exclusively. The pending profile blocks normal node
	// commands until full replay and cold reconstruction have succeeded.
	if e = os.Mkdir(dst, 0700); e != nil {
		return e
	}
	if e = syncCommandDirectory(filepath.Dir(dst)); e != nil {
		return e
	}
	if e = migrationWrite(filepath.Join(dst, workActivationPending), next.canonicalBytes()); e != nil {
		return e
	}
	if e = migrationWrite(filepath.Join(dst, genesisFilename), doc.CanonicalBytes()); e != nil {
		return e
	}
	if e = writeStoragePolicy(dst, policy.MaxHistoryBytes); e != nil {
		return e
	}
	if e = syncCommandDirectory(dst); e != nil {
		return e
	}
	if hook != nil {
		if e = hook("prepared"); e != nil {
			return e
		}
	}
	if e = replayMigration(ctx, dst, doc, next, blocks, tip, hook); e != nil {
		return fmt.Errorf("destination remains incomplete at %s: %w", dst, e)
	}
	if e = checkMigrationDestination(dst, doc, next, blocks, tip); e != nil {
		return e
	}
	if e = migrationWrite(filepath.Join(dst, "radix-migration.json"), append(raw, '\n')); e != nil {
		return e
	}
	if hook != nil {
		if e = hook("before-publish"); e != nil {
			return e
		}
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = writeWorkActivation(dst, next); e != nil {
		return e
	}
	if hook != nil {
		if e = hook("published"); e != nil {
			return e
		}
	}
	_, e = fmt.Fprintf(out, "migration_complete source_tip=%s radix_height=%d destination=%s\n", tip.ID, *height, dst)
	return e
}

func migrationPaths(source, destination string) (string, string, error) {
	if source == "" || destination == "" {
		return "", "", errors.New("source and out are required")
	}
	src, e := filepath.Abs(source)
	if e != nil {
		return "", "", e
	}
	info, e := os.Lstat(src)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("source must be an existing directory")
	}
	src, e = filepath.EvalSymlinks(src)
	if e != nil {
		return "", "", e
	}
	dst, e := filepath.Abs(destination)
	if e != nil {
		return "", "", e
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(dst))
	if e != nil {
		return "", "", e
	}
	dst = filepath.Join(parent, filepath.Base(dst))
	contains := func(a, b string) bool { return a == b || strings.HasPrefix(b, a+string(os.PathSeparator)) }
	if contains(src, dst) || contains(dst, src) {
		return "", "", errors.New("source and destination must be disjoint")
	}
	if _, e = os.Lstat(dst); !errors.Is(e, os.ErrNotExist) {
		return "", "", errors.New("destination must not exist; retain incomplete attempts and use a fresh path")
	}
	return src, dst, nil
}
func migrationLedgerPolicy(data string) (pebblestore.Policy, error) {
	p := pebblestore.DefaultPolicy()
	b, e := os.ReadFile(filepath.Join(data, storagePolicyFilename))
	if errors.Is(e, os.ErrNotExist) {
		return p, nil
	}
	if e != nil {
		return p, e
	}
	if len(b) != len(storagePolicyMagic)+8 || string(b[:len(storagePolicyMagic)]) != string(storagePolicyMagic[:]) {
		return p, errors.New("invalid source storage policy")
	}
	p.MaxHistoryBytes = binary.BigEndian.Uint64(b[len(storagePolicyMagic):])
	if p.MaxHistoryBytes < minimumHistoryBytes {
		return p, storage.ErrHistoryLimit
	}
	return p, nil
}
func migrationWrite(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	n, writeErr := f.Write(b)
	if n != len(b) && writeErr == nil {
		writeErr = io.ErrShortWrite
	}
	syncErr := f.Sync()
	return errors.Join(writeErr, syncErr, f.Close())
}
func replayMigration(ctx context.Context, path string, g genesis.Document, p workActivationProfile, blocks []activation.Block, want storage.Tip, hook func(string) error) (retErr error) {
	ledger, e := openStore(path, g)
	if e != nil {
		return e
	}
	defer func() { retErr = errors.Join(retErr, ledger.Close()) }()
	r, e := openWorkRouter(ledger, g, p, path, nil)
	if e != nil {
		return e
	}
	defer func() { retErr = errors.Join(retErr, r.Close()) }()
	for _, b := range blocks {
		if e = ctx.Err(); e != nil {
			return e
		}
		if _, e = r.Submit(b); e != nil {
			return e
		}
		if hook != nil {
			if e = hook("block"); e != nil {
				return e
			}
		}
	}
	got, e := r.Tip()
	if e != nil {
		return e
	}
	if !storage.EqualTips(want, got) {
		return errors.New("replay changed selected tip")
	}
	return nil
}
func checkMigrationDestination(path string, g genesis.Document, p workActivationProfile, blocks []activation.Block, want storage.Tip) (retErr error) {
	policy, e := migrationLedgerPolicy(path)
	if e != nil {
		return e
	}
	ledger, e := pebblestore.OpenExistingReadOnly(filepath.Join(path, ledgerDirectory), g, policy)
	if e != nil {
		return e
	}
	defer func() { retErr = errors.Join(retErr, ledger.Close()) }()
	r, e := openWorkRouterMode(ledger, g, p, path, nil, true)
	if e != nil {
		return e
	}
	defer func() { retErr = errors.Join(retErr, r.Close()) }()
	got, e := r.Tip()
	if e != nil || !storage.EqualTips(got, want) {
		return errors.New("cold destination tip differs")
	}
	for _, b := range blocks {
		id, _ := b.ID()
		stored, e := r.BlockByID(id)
		if e != nil || string(stored.CanonicalBytes()) != string(b.CanonicalBytes()) {
			return errors.New("cold destination lost or changed a retained block")
		}
	}
	return nil
}
