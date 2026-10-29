package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func runWorkArchiveMigrateRadix(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return workArchiveMigrateRadix(ctx, args, os.Stdout)
}

func workArchiveMigrateRadix(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("work-archive-migrate-radix", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	values := addArchiveVerificationFlags(f)
	mode := f.String("mode", "review", "review or run")
	height := f.Uint64("radix-height", 0, "future first v3 block")
	proposalOut := f.String("statement-out", "", "new canonical proposal file (review only)")
	signed := f.String("new-checkpoint", "", "independently signed exact proposal (run only)")
	destination := f.String("out", "", "new archive directory (run only)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if ctx == nil || out == nil || f.NArg() != 0 || *height == 0 {
		return errors.New("radix-height is required; positional arguments are forbidden")
	}
	if (*mode != "review" && *mode != "run") || (*mode == "review" && (*signed != "" || *destination != "")) || (*mode == "run" && (*proposalOut != "" || *signed == "" || *destination == "")) {
		return errors.New("review allows statement-out; run requires out and new-checkpoint")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	v, err := values.load()
	if err != nil {
		return err
	}
	source := filepath.Dir(*values.manifest)
	manifest, statement, err := workarchive.PrepareRadixArchiveMigration(source, v.checkpoint, v.policy, v.base, v.parameters, *height, v.limits)
	if err != nil {
		return err
	}
	expected, err := v.manifest.CanonicalBytes()
	if err != nil {
		return err
	}
	retained, err := loadArchiveManifest(filepath.Join(source, "manifest.omwm"))
	if err != nil {
		return err
	}
	actual, err := retained.CanonicalBytes()
	if err != nil || !bytes.Equal(expected, actual) {
		return errors.New("manifest must identify the exact source directory")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if *mode == "review" {
		if *proposalOut != "" {
			src, err := canonicalPruneLineageDirectory(source)
			if err != nil {
				return err
			}
			output, err := canonicalPruneLineageOutput(*proposalOut)
			if err != nil {
				return err
			}
			if pruneEffectPathsOverlap(src, output) {
				return errors.New("proposal must be outside the immutable source archive")
			}
			encoded, err := statement.CanonicalBytes()
			if err != nil {
				return err
			}
			if err = writeNewTieCommandFile(output, encoded, workarchive.MaximumStatementBytes, workarchive.ErrStatement, ".radix-proposal-*"); err != nil {
				return err
			}
		}
	} else {
		cp, err := loadArchiveCheckpoint(*signed)
		if err != nil {
			return err
		}
		if cp.Statement.RadixActivationHeight != *height {
			return errors.New("checkpoint does not match requested radix height")
		}
		manifest, _, err = workarchive.MigrateRadixArchiveDirectory(source, *destination, v.checkpoint, cp, v.policy, v.base, v.parameters, v.limits)
		if err != nil {
			return err
		}
	}
	manifestID, err := manifest.ID()
	if err != nil {
		return err
	}
	statementID, err := statement.ID()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "manifest_id=%s\nstatement_id=%s\nprevious_statement_id=%s\nsequence=%d\nradix_height=%d\n", manifestID, statementID, statement.PreviousID, statement.Sequence, *height)
	return err
}
