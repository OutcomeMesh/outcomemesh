package chainsession

import (
	"context"
	"errors"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/storage"
	"net"
	"testing"
	"time"
)

func TestSessionRadixBoundaryAndVersion2Base(t *testing.T) {
	for _, v := range []uint16{0, 2} {
		t.Run(string(rune('0'+v)), func(t *testing.T) {
			h := uint64(3)
			if v == 2 {
				h = 2
			}
			config := DefaultSessionConfig()
			config.BatchSize = 2
			config.MaxSyncBatches = 8
			source := newChainFixtureWithCommitments(t, 10733, 2, config, h, v)
			dest := newChainFixtureWithCommitments(t, 10733, 2, config, h, v)
			defer source.router.Close()
			defer source.ledger.Close()
			defer dest.router.Close()
			defer dest.ledger.Close()
			extendChain(t, source, "source", 5)
			extendChain(t, dest, "fork", 1)
			client, server := net.Pipe()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- source.node.Serve(ctx, server) }()
			tip, e := dest.node.Synchronize(ctx, client)
			if e != nil {
				t.Fatal(e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			want, _ := source.router.Tip()
			if !storage.EqualTips(want, tip) {
				t.Fatal("tip mismatch")
			}
			snapshot, e := dest.router.Snapshot()
			if e != nil || snapshot.CommitmentVersion() != state.CommitmentRadixV1 {
				t.Fatal("commitment", e)
			}
			for height := uint64(1); height <= tip.Height; height++ {
				b, e := dest.router.BlockByID(sourceChainIDAt(t, source, height))
				wantVersion := v
				if height >= 2 {
					wantVersion = 1
				}
				if height >= h {
					wantVersion = 3
				}
				if e != nil || b.Version() != wantVersion {
					t.Fatal("version", height, b.Version(), e)
				}
			}
		})
	}
}
func TestSessionRejectsRadixScheduleBeforeBlockExchange(t *testing.T) {
	for _, h := range []uint64{0, 4} {
		left := newChainFixtureWithCommitments(t, 10734, 2, DefaultSessionConfig(), 3, 0)
		right := newChainFixtureWithCommitments(t, 10734, 2, DefaultSessionConfig(), h, 0)
		client, server := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		done := make(chan error, 1)
		go func() { done <- left.node.Serve(ctx, server) }()
		_, e := right.node.Synchronize(ctx, client)
		if e == nil {
			t.Fatal("accepted incompatible schedule")
		}
		if e = <-done; !errors.Is(e, ErrActivation) {
			t.Fatal(e)
		}
		cancel()
		tip, _ := right.router.Tip()
		if tip.Height != 0 {
			t.Fatal("changed peer before negotiation")
		}
		left.router.Close()
		right.router.Close()
		left.ledger.Close()
		right.ledger.Close()
	}
}
