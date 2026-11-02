//go:build integration && (linux || darwin)

package pruneservice

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

// This test-only executable accepts disposable fixture coordinates. There is no
// production environment variable, exported hook or network fault command.
func TestPruneServicePublicationBarrier(t *testing.T) {
	path := os.Getenv("OUTCOMEMESH_PRUNE_PUBLICATION_FIXTURE")
	if path == "" {
		t.Skip("subprocess-only publication barrier")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Root, Request, Key, Stage, Marker string
		DescriptorID, ContinuationID      types.Hash
		Before                            wire.Position
		Settlement                        *SettlementInput
		SettlementReviewID                types.Hash
	}
	if err = json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(c.Request)
	if err != nil {
		t.Fatal(err)
	}
	q, err := wire.DecodeRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	barrier := func(stage string) error {
		if stage != c.Stage {
			return nil
		}
		f, err := os.OpenFile(c.Marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if _, err = f.Write([]byte(stage)); err != nil {
			f.Close()
			return err
		}
		if err = f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}
	h := ownerHooks{at: barrier, write: func(f *os.File, b []byte) (int, error) {
		if strings.HasSuffix(c.Stage, "-partial") && filepath.Base(f.Name()) == strings.TrimSuffix(c.Stage, "-partial") {
			n, err := f.Write(b[:len(b)/2])
			if err != nil {
				return n, err
			}
			return n, barrier(c.Stage)
		}
		return f.Write(b)
	}}
	if !c.ContinuationID.IsZero() {
		_, err = continuePublication(ctx, c.Root, c.DescriptorID, c.Before, q, c.ContinuationID, h)
		t.Fatal("escaped continuation barrier", err)
	}
	var intent *wire.Request
	if c.Settlement != nil {
		intent = &q
	}
	o, err := Open(ctx, c.Root, c.DescriptorID, c.Before, intent)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	o.hooks = h
	if c.Settlement != nil {
		r, e := o.ReviewSettlement(ctx, q, *c.Settlement)
		if e != nil || r.Review.ReviewID != c.SettlementReviewID {
			raw, _ := json.Marshal(r.Review)
			t.Fatalf("settlement fixture changed: %v expected=%s got=%s review=%s", e, c.SettlementReviewID, r.Review.ReviewID, raw)
		}
		_, err = o.Settle(ctx, q, *c.Settlement, c.SettlementReviewID)
		if err == nil {
			err = barrier("response-ready")
		}
		t.Fatal("escaped settlement barrier", err)
	}
	seed, err := os.ReadFile(c.Key)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatal("fixture consumer key", err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	defer clear(key)
	_, err = o.Execute(ctx, q, func(_ context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		_, draft, err := ch.Candidate.Draft()
		if err != nil {
			return custodyfence.Command{}, err
		}
		return draft.Sign(key)
	})
	if err == nil {
		err = barrier("response-ready")
	}
	t.Fatal("escaped publication barrier", err)
}
