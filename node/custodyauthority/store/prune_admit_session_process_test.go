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
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestPruneAdmissionQUICProcessCrashAtomicity(t *testing.T) {
	stages := append(pruneAdmissionStages(), "admission-request", "admission-confirmed", "admission-replied")
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admission = pruneAdmissionEntry(t, f)
			usage, _, err := f.chain.HistoryUsage()
			if err != nil {
				t.Fatal(err)
			}
			_ = f.executor.Close()
			_ = f.coordinator.Close()
			_ = f.chain.Close()
			client, err := libp2ptransport.New(t.Context(), testKey(46), libp2ptransport.DefaultConfig(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			address, marker, stop := startAdmissionQUICChild(t, f, stage)
			serverPublic := testPublic(45)
			serverID := types.DomainHash("OMESH/p2p/ed25519/v0", serverPublic[:])
			reply := make(chan error, 1)
			go func() {
				_, err := client.AdmitPrune(t.Context(), address, serverID, f.admission, 10*time.Second)
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
			_ = client.Close()
			if err := <-reply; stage != "admission-replied" && !errors.Is(err, admissionwire.ErrUnconfirmed) {
				t.Fatal("pre-reply crash acknowledged admission", err)
			}
			recovery := stage
			switch stage {
			case "admission-request":
				recovery = "intent-before-write"
			case "admission-confirmed", "admission-replied":
				recovery = "pins-admission-confirm-after-apply"
			}
			for range 2 {
				f.reopen(t)
				assertPruneAdmissionRecovery(t, f, recovery)
			}
			_ = f.executor.Close()
			_ = f.coordinator.Close()
			_ = f.chain.Close()
			address, _, stop = startAdmissionQUICChild(t, f, "retry")
			client, err = libp2ptransport.New(t.Context(), testKey(46), libp2ptransport.DefaultConfig(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ack, err := client.AdmitPrune(t.Context(), address, serverID, f.admission, 10*time.Second)
			id, _ := f.admission.ID()
			if err != nil || ack.EntryID != id {
				t.Fatal("remote restart failed exact retry", err)
			}
			stop()
			f.reopen(t)
			assertPruneAdmissionConfirmed(t, f)
			if after, _, err := f.chain.HistoryUsage(); err != nil || after != usage {
				t.Fatal("admission process changed chain", err)
			}
		})
	}
}

func startAdmissionQUICChild(t *testing.T, f *pruneFixture, stage string) (string, string, func()) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "admission")
	request, _ := f.request.CanonicalBytes()
	command := exec.Command(os.Args[0], "-test.run=^TestPruneAdmissionQUICCrashHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OUTCOMEMESH_ADMISSION_STAGE="+stage, "OUTCOMEMESH_ADMISSION_MARKER="+marker,
		"OUTCOMEMESH_ADMISSION_EXECUTOR="+f.executorPath, "OUTCOMEMESH_ADMISSION_EXECUTOR_PINS="+f.executorPinsPath,
		"OUTCOMEMESH_ADMISSION_AUTHORITY="+f.authorityPath, "OUTCOMEMESH_ADMISSION_PINS="+f.pinsPath, "OUTCOMEMESH_ADMISSION_REQUEST="+hex.EncodeToString(request))
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
			t.Fatalf("admission child exited: %s", output.String())
		case <-deadline.C:
			stop()
			t.Fatalf("admission child not ready: %s", output.String())
		case <-ticker.C:
		}
	}
}

func TestPruneAdmissionQUICCrashHelper(t *testing.T) {
	stage := os.Getenv("OUTCOMEMESH_ADMISSION_STAGE")
	if stage == "" {
		t.Skip("subprocess helper")
	}
	requestBytes, err := hex.DecodeString(os.Getenv("OUTCOMEMESH_ADMISSION_REQUEST"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodePruneRequest(requestBytes)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := request.ID()
	executor, err := OpenPinnedPruneExecutor(os.Getenv("OUTCOMEMESH_ADMISSION_EXECUTOR"), os.Getenv("OUTCOMEMESH_ADMISSION_EXECUTOR_PINS"), testAssignment(), id)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close()
	coordinator := testOpenCoordinator(t, os.Getenv("OUTCOMEMESH_ADMISSION_AUTHORITY"), os.Getenv("OUTCOMEMESH_ADMISSION_PINS"))
	marker := os.Getenv("OUTCOMEMESH_ADMISSION_MARKER")
	hooks := storeHooks{at: func(at string) error {
		if at == stage {
			writeTestFile(t, marker+".reached", nil)
			select {}
		}
		return nil
	}}
	setCoordinatorHooks(coordinator, hooks)
	executor.hooks, executor.pins.hooks = hooks, hooks
	clientPublic := testPublic(46)
	clientID := types.DomainHash("OMESH/p2p/ed25519/v0", clientPublic[:])
	session, err := NewPruneAdmissionServer(executor, coordinator, clientID, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	session.hooks = hooks
	host, err := libp2ptransport.New(t.Context(), testKey(45), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if err := host.SetPruneAdmissionHandler(clientID, func(ctx context.Context, peer types.Hash, s network.Stream) {
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
