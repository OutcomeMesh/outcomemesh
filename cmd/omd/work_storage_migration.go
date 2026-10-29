package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	pebblestore "github.com/outcomemesh/outcomemesh/storage/pebble"
)

func runWorkStorageMigrateRadix(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return workStorageMigrateRadix(ctx, args, os.Stdout)
}

// This command owns only an existing storage pair. The base node is read-only;
// no activation profile, executor, receipt, admission or signing key is replaced.
func workStorageMigrateRadix(ctx context.Context, args []string, out io.Writer) (retErr error) {
	f := flag.NewFlagSet("work-storage-migrate-radix", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	data := f.String("data", "", "stopped original node containing the verified activation base")
	chainPath := f.String("chain", "", "existing protected WorkChain root")
	pinsPath := f.String("chain-pins", "", "original independent position journal")
	baseText := f.String("base-id", "", "original activation parent ID")
	storageText := f.String("storage-id", "", "original storage ID")
	height := f.Uint64("radix-height", 0, "future first v3 block, above every retained fork")
	mode := f.String("mode", "review", "review, run, inspect, confirm, or inspect-original")
	expectedText := f.String("expected-review-id", "", "independently retained review ID")
	if err := f.Parse(args); err != nil {
		return err
	}
	if ctx == nil || out == nil || f.NArg() != 0 || *height == 0 {
		return errors.New("explicit radix-height and no positional arguments required")
	}
	switch *mode {
	case "review", "run", "inspect", "confirm", "inspect-original":
	default:
		return errors.New("invalid migration mode")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	needsID := *mode == "run" || *mode == "inspect" || *mode == "confirm"
	if needsID != (*expectedText != "") {
		return errors.New("run, inspect and confirm require expected-review-id; review and inspect-original forbid it")
	}
	var expected types.Hash
	var err error
	if needsID {
		expected, err = pruneExternalID("expected-review-id", *expectedText)
		if err != nil {
			return err
		}
	}
	storageID, err := pruneExternalID("storage-id", *storageText)
	if err != nil {
		return err
	}
	baseID, err := pruneExternalID("base-id", *baseText)
	if err != nil {
		return err
	}
	paths := []string{*data, *chainPath, *pinsPath}
	for i, p := range paths {
		paths[i], err = canonicalPruneLineageDirectory(p)
		if err != nil {
			return err
		}
	}
	for i := range paths {
		for j := 0; j < i; j++ {
			if pruneEffectPathsOverlap(paths[i], paths[j]) {
				return errors.New("base node, protected chain and position journal must be disjoint")
			}
		}
	}
	source := paths[0]
	if _, err = os.Lstat(filepath.Join(source, workActivationPending)); !errors.Is(err, os.ErrNotExist) {
		return errors.New("activation source is incomplete")
	}
	doc, err := loadGenesis(source)
	if err != nil {
		return err
	}
	profile, err := loadWorkActivation(source, doc)
	if err != nil {
		return err
	}
	if profile.RadixActivationHeight != 0 {
		return errors.New("use the retained original activation source with zero radix height")
	}
	ledgerPolicy, err := migrationLedgerPolicy(source)
	if err != nil {
		return err
	}
	ledger, err := pebblestore.OpenExistingReadOnly(filepath.Join(source, ledgerDirectory), doc, ledgerPolicy)
	if err != nil {
		return err
	}
	base, baseErr := archiveBaseFromLedger(ledger, baseID, profile.ActivationHeight)
	if err = errors.Join(baseErr, ledger.Close(), ctx.Err()); err != nil {
		return err
	}
	legacy := legacyblock.ParametersFromGenesis(doc)
	parameters := workblock.Parameters{NetworkID: doc.NetworkID, BlockSubsidy: doc.BlockSubsidy, RewardMaturity: legacy.RewardMaturity,
		ActivationHeight: profile.ActivationHeight, DifficultyAnchorTimestamp: doc.Timestamp, DifficultyAnchorTarget: doc.Target,
		TargetSpacing: legacy.TargetSpacing, ASERTHalfLife: legacy.ASERTHalfLife, FeeDelay: profile.FeeDelay}
	policy := workchain.DefaultPolicy()
	policy.MaxHistoryBytes = profile.MaxHistoryBytes
	var chain *workchain.Store
	if *mode == "inspect" || *mode == "confirm" {
		parameters.RadixActivationHeight = *height
		chain, err = workchain.OpenRadixMigratedPositionPinnedWithPolicy(paths[1], paths[2], base, parameters, policy, storageID, expected)
	} else {
		chain, err = workchain.OpenPositionPinnedWithPolicy(paths[1], paths[2], base, parameters, policy, storageID)
	}
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, chain.Close()) }()
	switch *mode {
	case "review":
		review, err := chain.ReviewRadixSchedule(ctx, *height)
		if err != nil {
			return err
		}
		if err = json.NewEncoder(out).Encode(review); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "review_id=%s\n", review.ID())
		return err
	case "run":
		if _, err = chain.MigrateRadixSchedule(ctx, *height, expected); err != nil {
			return err
		}
	case "confirm":
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = chain.ResumeStorageConfirmation(); err != nil {
			return err
		}
	}
	protection, err := chain.StorageProtection()
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(protection)
}
