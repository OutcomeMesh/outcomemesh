//go:build integration

package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestPruneCompletionQUICProcessCrashAtomicity(t *testing.T) {
	boundaries := map[string]string{
		"completion-request":    "intent-before-write",
		"intent-after-apply":    "intent-after-apply",
		"authority-after-apply": "authority-after-apply",
		"confirm-after-apply":   "confirm-after-apply",
		"completion-confirmed":  "confirm-after-apply",
		"completion-replied":    "confirm-after-apply",
	}
	for _, outcome := range []string{"succeeded", "cancelled"} {
		for stage, recovery := range boundaries {
			t.Run(outcome+"/"+stage, func(t *testing.T) {
				f := newPruneFixtureWithStorageID(t, testHash(91))
				finishPruneForCompletion(t, f, outcome)
				entry := pruneCompletionEntry(t, f)
				before := testCoordination(t, f.coordinator).Authority
				terminal := pruneSnapshot(t, f.executor)
				_ = f.executor.Close()
				_ = f.coordinator.Close()
				_ = f.chain.Close()
				client, err := libp2ptransport.New(t.Context(), testKey(46), libp2ptransport.DefaultConfig(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				address, marker, stop := startCompletionQUICChild(t, f, stage)
				serverPublic := testPublic(45)
				serverID := types.DomainHash("OMESH/p2p/ed25519/v0", serverPublic[:])
				reply := make(chan error, 1)
				go func() {
					_, err := client.CompletePrune(t.Context(), address, serverID, entry, 10*time.Second)
					reply <- err
				}()
				waitCompletionMarker(t, marker+".reached")
				if opened, err := OpenPinnedPruneExecutor(f.executorPath, f.executorPinsPath, testAssignment(), f.id); !errors.Is(err, ErrBusy) {
					if opened != nil {
						_ = opened.Close()
					}
					t.Fatal("child lost executor lock", err)
				}
				if opened, err := OpenCoordinator(f.authorityPath, f.pinsPath, testAssignment(), testAssignmentID(t)); !errors.Is(err, ErrBusy) {
					if opened != nil {
						_ = opened.Close()
					}
					t.Fatal("child lost authority lock", err)
				}
				stop()
				// Retire the client's dead connection explicitly as part of this
				// crash/restart drill; do not wait for QUIC idle-loss detection.
				_ = client.Close()
				if err := <-reply; stage != "completion-replied" && !errors.Is(err, completionwire.ErrUnconfirmed) {
					t.Fatal("pre-reply crash acknowledged completion", err)
				}
				f.reopen(t)
				assertPruneCompletionRecovery(t, f, entry, before, terminal, recovery)
				f.reopen(t)
				assertPruneCompletionRecovery(t, f, entry, before, terminal, recovery)
				_ = f.executor.Close()
				_ = f.coordinator.Close()
				_ = f.chain.Close()
				address, _, stop = startCompletionQUICChild(t, f, "retry")
				client, err = libp2ptransport.New(t.Context(), testKey(46), libp2ptransport.DefaultConfig(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				ack, err := client.CompletePrune(t.Context(), address, serverID, entry, 10*time.Second)
				id, _ := entry.ID()
				if err != nil || ack.EntryID != id {
					t.Fatal("remote restart failed exact retry", err)
				}
				stop()
				f.reopen(t)
				current := testCoordination(t, f.coordinator)
				if current.Pending != nil || current.Authority.Sequence != 2 || current.Authority.Pending != 0 {
					t.Fatal("remote retry lost or repeated completion")
				}
			})
		}
	}
}

func waitCompletionMarker(t testing.TB, path string) {
	t.Helper()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("completion process missed marker", path)
		case <-ticker.C:
		}
	}
}

func startCompletionQUICChild(t *testing.T, f *pruneFixture, stage string) (string, string, func()) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "completion")
	request, _ := f.request.CanonicalBytes()
	command := exec.Command(os.Args[0], "-test.run=^TestPruneCompletionQUICCrashHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OUTCOMEMESH_COMPLETION_STAGE="+stage, "OUTCOMEMESH_COMPLETION_MARKER="+marker,
		"OUTCOMEMESH_COMPLETION_EXECUTOR="+f.executorPath, "OUTCOMEMESH_COMPLETION_EXECUTOR_PINS="+f.executorPinsPath,
		"OUTCOMEMESH_COMPLETION_AUTHORITY="+f.authorityPath, "OUTCOMEMESH_COMPLETION_PINS="+f.pinsPath, "OUTCOMEMESH_COMPLETION_REQUEST="+hex.EncodeToString(request))
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = command.Wait(); close(done) }()
	var once sync.Once
	stop := func() { once.Do(func() { _ = command.Process.Kill(); <-done }) }
	t.Cleanup(stop)
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if address, err := os.ReadFile(marker + ".ready"); err == nil {
			return string(address), marker, stop
		}
		select {
		case <-done:
			t.Fatalf("completion child exited: %s", output.String())
		case <-deadline.C:
			stop()
			t.Fatalf("completion child not ready: %s", output.String())
		case <-ticker.C:
		}
	}
}

func TestPruneCompletionQUICCrashHelper(t *testing.T) {
	stage := os.Getenv("OUTCOMEMESH_COMPLETION_STAGE")
	if stage == "" {
		t.Skip("subprocess helper")
	}
	requestBytes, err := hex.DecodeString(os.Getenv("OUTCOMEMESH_COMPLETION_REQUEST"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodePruneRequest(requestBytes)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := request.ID()
	executor, err := OpenPinnedPruneExecutor(os.Getenv("OUTCOMEMESH_COMPLETION_EXECUTOR"), os.Getenv("OUTCOMEMESH_COMPLETION_EXECUTOR_PINS"), testAssignment(), id)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close()
	coordinator := testOpenCoordinator(t, os.Getenv("OUTCOMEMESH_COMPLETION_AUTHORITY"), os.Getenv("OUTCOMEMESH_COMPLETION_PINS"))
	marker := os.Getenv("OUTCOMEMESH_COMPLETION_MARKER")
	hooks := storeHooks{at: func(at string) error {
		if at == stage {
			writeTestFile(t, marker+".reached", nil)
			select {}
		}
		return nil
	}}
	setCoordinatorHooks(coordinator, hooks)
	clientPublic := testPublic(46)
	clientID := types.DomainHash("OMESH/p2p/ed25519/v0", clientPublic[:])
	session, err := NewPruneCompletionServer(executor, coordinator, clientID, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	session.hooks = hooks
	host, err := libp2ptransport.New(t.Context(), testKey(45), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if err := host.SetPruneCompletionHandler(clientID, func(ctx context.Context, peer types.Hash, s network.Stream) {
		_, err := session.Serve(ctx, peer, s)
		if err != nil {
			t.Log(err)
		}
		writeTestFile(t, marker+".returned", nil)
	}); err != nil {
		t.Fatal(err)
	}
	// Publish a complete endpoint in one no-replace step; readers never see the
	// empty create/write interval of a directly written readiness marker.
	if err := writeExclusive(marker+".staged", []byte(host.Addresses()[0])); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(marker+".staged", marker+".ready"); err != nil {
		t.Fatal(err)
	}
	select {}
}
