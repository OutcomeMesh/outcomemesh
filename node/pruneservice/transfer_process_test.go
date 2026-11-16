//go:build integration && (linux || darwin)

package pruneservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

// The integration driver holds the original journals. This helper runs an
// independent transfer process and announces the selected cut on a private pipe.
func TestPruneServiceTransferBarrier(t *testing.T) {
	if os.Getenv("OUTCOMEMESH_TEST_PRUNE_TRANSFER_BARRIER") != "1" {
		t.Skip("subprocess-only transfer barrier")
	}
	var cfg struct {
		Source, Target, Stage, Report string
		DescriptorID, ReviewID        types.Hash
		Position                      wire.Position
		Inputs                        []string
		Bundle                        TransferBundle
	}
	if err := json.NewDecoder(os.Stdin).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	ready := os.NewFile(3, "transfer barrier")
	if ready == nil {
		t.Fatal("missing parent pipe")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	barrier := func(stage string) error {
		if stage != cfg.Stage {
			return nil
		}
		if _, err := io.WriteString(ready, stage); err != nil {
			return err
		}
		if err := ready.Close(); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}
	hooks := ownerHooks{at: barrier}
	if cfg.Stage == "transfer-record-partial" {
		hooks.write = func(f *os.File, p []byte) (int, error) {
			n, err := f.Write(p[:len(p)/2])
			if err != nil {
				return n, err
			}
			return n, errors.Join(io.ErrShortWrite, barrier(cfg.Stage))
		}
	}
	_, err := transfer(ctx, cfg.Source, cfg.Target, cfg.DescriptorID, cfg.Position, cfg.ReviewID, cfg.Bundle, cfg.Report, cfg.Inputs, hooks)
	t.Fatal("transfer escaped selected cut", cfg.Stage, err)
}
